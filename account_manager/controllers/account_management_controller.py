# coding: utf-8

import connexion, time

from account_manager.models.delete_type import DeleteType  # noqa: E501
from account_manager.models.error import Error  # noqa: E501
from account_manager.models.register_request import RegisterRequest  # noqa: E501
from account_manager.models.user import User  # noqa: E501

from account_manager.models.dbmodels import (
    db,
    DBUser,
    DBUserSettings,
    DBNotDisturb,
    DBConfirmationToken,
    DBEvent,
    DBMeterIdApiKeyMapping,
    DBAccountRecoveryToken,
)
from account_manager.models.account_recovery_request import AccountRecoveryRequest
from account_manager.models.not_disturb import NotDisturb
from account_manager.models.period_of_day import PeriodOfDay
from account_manager.models.events import (
    UserAccountSchema,
    UserAddedDongleApiKeyEventType,
    UserUpdatedDongleApiKeyEventType,
    UserLocationSchema,
    UserRegisteredEventType,
    UserConfirmedEventType,
    UserUpdatedEventType,
    UserSoftDeletedEventType,
    UserHardDeletedEventType,
    UserRecoveredAccountEventType,
    UserFilledPostalCodeEventType,
    UserRegisteredNotificationSchema,
    UserRegisteredNotificationType,
)

from account_manager import logger, generalLogger, Config, bcrypt, auth, app

import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from email.header import Header
from email.utils import formataddr

import hashlib

from flask import render_template, send_from_directory

from datetime import datetime, timezone, timedelta
import uuid


def logErrorResponse(error, endText, response, corId):
    logger.error(error, extra=corId)
    logResponse(endText, response, corId)


def logResponse(endText, response, corId):
    logger.info(endText, extra=corId)
    if response is not None:
        logger.debug("Sending the following response: ", extra=corId)
        logger.debug(response, extra=corId)


@app.route('/api/account/confirm-account/<token>', methods=['GET'])
def confirm_account_token_get(token):  # noqa: E501
    """Endpoint to get the webpage with the button to confirm account by clicking the link sent to the e-mail.

     # noqa: E501

    :param token:
    :type token: str

    :rtype: None
    """
    corId = {"X-Correlation-ID": "confirmation-token-" + token}
    logger.info("Processing GET /confirm-account request", extra=corId)
    endText = "Processed GET /confirm-account request"

    data = DBConfirmationToken.query.filter_by(token=token).first()
    if data is None:
        # logger.error("confirmation token " + token + " not found", extra=corId)
        message = "confirmation token " + token + " not found"
        response = Error(message)
        logErrorResponse(message, endText, response, corId)
        return render_template("confirm.html", confirm_not_found=True), 404

    if data.expiration_timestamp.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        # logger.error("confirmation token " + token + " expired", extra=corId)
        message = "confirmation token " + token + " expired"
        response = Error(message)
        logErrorResponse(message, endText, response, corId)
        return render_template("confirm.html", confirm_expired=True), 404

    user = DBUser.query.filter_by(user_id=data.user_id, deleted=False).first()
    if user is None:
        logger.error(
            "Confirmation token valid but user_id " + data.user_id + " not found",
            extra=corId,
        )
        message = "confirmation token not found"
        response = Error(message)
        logErrorResponse(message, endText, response, corId)
        return render_template("confirm.html", confirm_not_found=True), 404

    logger.info("Sending webpage to confirm token " + token, extra=corId)
    logResponse(endText, None, corId)

    return render_template("confirm.html", my_token=token, confirm=True)


@app.route('/api/account/static/<path:filename>', methods=['GET'])
def static_filename_get(filename):  # noqa: E501
    """Endpoint to get the static webpages.

     # noqa: E501

    :param filename: 
    :type filename: str

    :rtype: None
    """
    response = send_from_directory('static', filename)
    response.direct_passthrough = False

    return response


@app.route('/api/account/confirm-account/<token>', methods=['POST'])
def confirm_account_token_post(token):  # noqa: E501
    """Endpoint to confirm account by clicking the button on the webpage of the link sent to the e-mail.

     # noqa: E501

    :param token:
    :type token: str

    :rtype: None
    """
    corId = {"X-Correlation-ID": "confirmation-token-" + token}

    logger.info("Processing POST /confirm-account request", extra=corId)
    endText = "Processed POST /confirm-account request"

    data = DBConfirmationToken.query.filter_by(token=token).first()
    if data is None:
        # logger.error("confirmation token " + token + " not found", extra=corId)
        message = "confirmation token " + token + " not found"
        response = Error(message)
        logErrorResponse(message, endText, response, corId)
        return render_template("confirm.html", confirm_not_found=True), 404

    if data.expiration_timestamp.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        # logger.error("confirmation token " + token + " expired", extra=corId)
        message = "confirmation token " + token + " expired"
        response = Error(message)
        logErrorResponse(message, endText, response, corId)
        return render_template("confirm.html", confirm_expired=True), 404

    user = DBUser.query.filter_by(user_id=data.user_id, deleted=False).first()
    if user is None:
        logger.error(
            "Confirmation token valid but user_id " + data.user_id + " not found",
            extra=corId,
        )
        message = "confirmation token not found"
        response = Error(message)
        logErrorResponse(message, endText, response, corId)
        return render_template("confirm.html", confirm_not_found=True), 404

    user.is_active = True

    # Check if registration is complete
    if (
        (user.meter_id is not None)
        and (user.settings.postal_code is not None)
        and (user.settings.tarif_type is not None)
        and (user.settings.contracted_power is not None)
    ):
        user.settings.permissions = "Full"
    else:
        user.settings.permissions = "Minimal"

    DBConfirmationToken.query.filter_by(user_id=user.user_id).delete()

    not_disturb = {
        "sunday": [],
        "monday": [],
        "tuesday": [],
        "wednesday": [],
        "thursday": [],
        "friday": [],
        "saturday": [],
    }
    for nd in user.settings.not_disturb:
        not_disturb[nd.day_of_week].append(
            PeriodOfDay(nd.start_timestamp, nd.end_timestamp)
        )
    response = User(
        user_id=user.user_id,
        first_name=user.first_name,
        last_name=user.last_name,
        email=user.email,
        is_active=user.is_active,
        schedule_type=user.settings.schedule_type,
        meter_id=user.meter_id,
        api_key=user.api_key,
        country=user.settings.country,
        postal_code=user.settings.postal_code,
        tarif_type=user.settings.tarif_type,
        contracted_power=user.settings.contracted_power,
        not_disturb=not_disturb,
        global_optimizer=user.settings.global_optimizer,
        permissions=user.settings.permissions,
        is_google_account=user.is_google_account,
        modified_timestamp=user.modified_timestamp,
    )

    userSchema = UserAccountSchema()
    payload = userSchema.dump(response)

    event = DBEvent(
        aggregateid=uuid.uuid4(), type=UserConfirmedEventType, payload=payload
    )
    db.session.add(event)
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(e, extra=corId)
        return "", 500, corId

    logger.info(
        "Successfully confirmed account with user_id "
        + user.user_id
        + " and email "
        + user.email,
        extra=corId,
    )
    logResponse(endText, None, corId)

    return render_template("confirm.html", confirm_sucess=True)


def register_post():  # noqa: E501
    """Register account.

     # noqa: E501

    :rtype: User
    """
    if connexion.request.is_json:
        register_request = RegisterRequest.from_dict(
            connexion.request.get_json()
        )  # noqa: E501

    corId = {"X-Correlation-ID": connexion.request.headers["X-Correlation-ID"]}

    try:
        expo_token = connexion.request.headers["expo-token"]
    except KeyError:
        logger.warning(
            f"User {register_request.email} register has no expo token.", extra=corId
        )
        expo_token = None

    logger.info("Processing POST /register request", extra=corId)
    endText = "Processed POST /register request"

    # The queries to the DB on this endpoint do not have "deleted=False" because
    # a user might activate his account after the soft delete

    res = DBUser.query.filter_by(email=register_request.email).first()
    if res is not None:
        message = "email " + register_request.email + " already registered"
        response = Error(message)
        logErrorResponse(message, endText, response, corId)
        return response, 409, corId

    if register_request.password != register_request.password_repeat:
        message = '"password" and "passwordRepeat" fields do not match'
        response = Error(message)
        logErrorResponse(message, endText, response, corId)
        return response, 400, corId

    res = DBMeterIdApiKeyMapping.query.filter_by(meter_id=register_request.meter_id).first()
    if res is None:
        message = "meterId " + register_request.meter_id + " not found"
        response = Error(message)
        logErrorResponse(message, endText, response, corId)
        return response, 404, corId
    api_key = res.api_key

    res = DBUser.query.filter_by(meter_id=register_request.meter_id).first()
    if res is not None:
        message = "meterId " + register_request.meter_id + " already registered"
        response = Error(message)
        logErrorResponse(message, endText, response, corId)
        return response, 409, corId

    settings = DBUserSettings(
        country=register_request.country,
        postal_code=register_request.postal_code,
        schedule_type=register_request.schedule_type,
        tarif_type=register_request.tarif_type,
        contracted_power=register_request.contracted_power,
        permissions="None",
    )

    dbUser = DBUser(
        first_name=register_request.first_name,
        last_name=register_request.last_name,
        email=register_request.email,
        password=bcrypt.generate_password_hash(register_request.password).decode(),
        meter_id=register_request.meter_id,
        api_key=api_key,
        expo_token=expo_token,
        settings=settings,
    )
    db.session.add(dbUser)

    try:
        db.session.flush()
    except Exception as e:
        db.session.rollback()
        logger.error(e, extra=corId)
        return "", 500, corId

    # Postal code event
    if register_request.postal_code is not None:
        if register_request.contracted_power is not None:
            user_location = {
                "user_id": dbUser.user_id,
                "postal_code": register_request.postal_code,
                "contracted_power": float(
                    register_request.contracted_power.split(" ")[0]
                ),
            }

            location_schema = UserLocationSchema()
            payload = location_schema.dump(user_location)

            logger.info(f"Location schema payload:\n{payload}", extra=corId)

            event = DBEvent(
                aggregateid=uuid.uuid4(),
                type=UserFilledPostalCodeEventType,
                payload=payload,
            )
            db.session.add(event)
            try:
                db.session.flush()
            except Exception as e:
                db.session.rollback()
                logger.error(e, extra=corId)
                return "", 500, corId
        else:
            logger.error(
                f"Contracted power is missing.\nWhen user fills the postal code, it MUST also fill the contracted power.\nForecast installation was NOT registered...\n",
                extra=corId,
            )
            return Error("Missing contracted power"), 400, corId

    # Add new dongle api_key event
    if api_key is not None:
        # payload = set([dbUser.user_id, api_key])

        user_dongle = {
            "user_id": dbUser.user_id,
            "api_key": dbUser.api_key,
        }
        payload = user_dongle

        logger.info(
            f"User added new dongle api_key event payload:\n{payload}", extra=corId
        )

        event = DBEvent(
            aggregateid=uuid.uuid4(),
            type=UserAddedDongleApiKeyEventType,
            payload=payload,
        )
        db.session.add(event)

        try:
            db.session.flush()
        except Exception as e:
            db.session.rollback()
            logger.error(e, extra=corId)
            return "", 500, corId

    nd = NotDisturb(
        sunday=[],
        monday=[],
        tuesday=[],
        wednesday=[],
        thursday=[],
        friday=[],
        saturday=[],
    ).to_dict()

    user = User(
        user_id=dbUser.user_id,
        first_name=dbUser.first_name,
        last_name=dbUser.last_name,
        email=dbUser.email,
        is_active=dbUser.is_active,
        schedule_type=dbUser.settings.schedule_type,
        meter_id=dbUser.meter_id,
        api_key=dbUser.api_key,
        expo_token=expo_token,
        country=dbUser.settings.country,
        postal_code=dbUser.settings.postal_code,
        tarif_type=dbUser.settings.tarif_type,
        contracted_power=dbUser.settings.contracted_power,
        not_disturb=nd,
        global_optimizer=dbUser.settings.global_optimizer,
        permissions=dbUser.settings.permissions,
        is_google_account=dbUser.is_google_account,
        modified_timestamp=dbUser.modified_timestamp,
    )

    userSchema = UserAccountSchema()
    payload = userSchema.dump(user)

    logger.info(f"payload: {payload}\n", extra=corId)

    event = DBEvent(
        aggregateid=uuid.uuid4(), type=UserRegisteredEventType, payload=payload
    )
    db.session.add(event)

    userRegisteredNotificationSchema = UserRegisteredNotificationSchema()

    notification = {"notification": "User created."}

    payload = userRegisteredNotificationSchema.dump(notification)

    notification = DBEvent(
        aggregateid=uuid.uuid4(), type=UserRegisteredNotificationType, payload=payload
    )
    db.session.add(notification)

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(e, extra=corId)
        return "", 500, corId

    logger.info("Registed new user", extra=corId)
    logger.info(dbUser, extra=corId)
    logResponse(endText, user, corId)

    return user, 201, corId


def user_delete(user_id, delete_type):  # noqa: E501
    """Delete user.

     # noqa: E501

    :param x_correlation_id:
    :type x_correlation_id:
    :param user_id:
    :type user_id: str
    :param delete_type:
    :type delete_type: dict | bytes
    :param authorization:
    :type authorization: str

    :rtype: None
    """
    corId = {"X-Correlation-ID": connexion.request.headers["X-Correlation-ID"]}

    logger.info("Processing DELETE /user request", extra=corId)
    endText = "Processed DELETE /user request"

    auth_response, auth_response_code = auth.verify_basic_authorization(
        connexion.request.headers
    )

    if auth_response_code != 200:
        if auth_response_code == 402:
            logger.error(f"Blacklisted token {auth_response}", extra=corId)
        else:
            logger.error(
                f"Could not decode authorization token {auth_response}", extra=corId)

        message = "invalid credentials"
        response = Error(message)
        logErrorResponse(message, endText, response, corId)
        return response, 401, corId

    if auth_response is not None:
        user = DBUser.query.filter_by(user_id=auth_response, deleted=False).first()

        if user is None:
            logger.error(
                "Authorization token valid but user_id " + user_id + " not found",
                extra=corId,
            )
            message = "invalid credentials"
            response = Error(message)
            logErrorResponse(message, endText, response, corId)
            return response, 401, corId

        if user.user_id != user_id:
            logger.error(
                "User "
                + user.user_id
                + " does not have permission to delete the user "
                + user_id,
                extra=corId,
            )
            message = "no permission"
            response = Error(message)
            logErrorResponse(message, endText, response, corId)
            return response, 403, corId

    userDb = DBUser.query.filter_by(user_id=user_id).first()
    if userDb is None:
        message = "user with user_id " + user_id + " not found"
        response = Error(message)
        logErrorResponse(message, endText, response, corId)
        return response, 404, corId

    success, error_message = auth.tag_deleted_user(user_id)
    if success == False:
        message = f"Error tagging user for deletion... {error_message}"
        logErrorResponse(message, endText, None, corId)
        return "", 500, corId

    if delete_type == DeleteType.SOFT:
        if userDb.deleted == True:
            message = "user with user_id " + user_id + " not found"
            response = Error(message)
            logErrorResponse(message, endText, response, corId)
            return response, 404, corId

        eventType = UserSoftDeletedEventType
    elif delete_type == DeleteType.HARD:
        eventType = UserHardDeletedEventType
    
    userDb.deleted = True
    userDb.deleted_timestamp = datetime.now(timezone.utc)

    try:
        db.session.flush()
    except Exception as e:
        db.session.rollback()
        logger.error(e, extra=corId)
        return "", 500, corId

    not_disturb = {
        "sunday": [],
        "monday": [],
        "tuesday": [],
        "wednesday": [],
        "thursday": [],
        "friday": [],
        "saturday": [],
    }
    for nd in userDb.settings.not_disturb:
        not_disturb[nd.day_of_week].append(
            PeriodOfDay(nd.start_timestamp, nd.end_timestamp)
        )

    logger.debug(userDb, extra=corId)

    response = User(
        user_id=userDb.user_id,
        first_name=userDb.first_name,
        last_name=userDb.last_name,
        email=userDb.email,
        is_active=userDb.is_active,
        schedule_type=userDb.settings.schedule_type,
        meter_id=userDb.meter_id,
        api_key=userDb.api_key,
        country=userDb.settings.country,
        postal_code=userDb.settings.postal_code,
        tarif_type=userDb.settings.tarif_type,
        contracted_power=userDb.settings.contracted_power,
        not_disturb=not_disturb,
        global_optimizer=userDb.settings.global_optimizer,
        permissions=userDb.settings.permissions,
        is_google_account=userDb.is_google_account,
        modified_timestamp=userDb.modified_timestamp,
    )

    userSchema = UserAccountSchema()
    payload = userSchema.dump(response)

    logger.info(f"payload: {payload}\n", extra=corId)

    event = DBEvent(aggregateid=uuid.uuid4(), type=eventType, payload=payload)
    db.session.add(event)
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(e, extra=corId)
        return "", 500, corId

    return "", 200, corId


def user_post():  # noqa: E501
    """Save new user account settings

     # noqa: E501

    :rtype: User
    """
    if connexion.request.is_json:
        userReq = User.from_dict(connexion.request.get_json())  # noqa: E501

    corId = {"X-Correlation-ID": connexion.request.headers["X-Correlation-ID"]}

    logger.info("Processing POST /user request", extra=corId)
    endText = "Processed POST /user request"

    # -------------------- Verify user authentication -------------------- #

    auth_response, auth_response_code = auth.verify_basic_authorization(
        connexion.request.headers
    )

    if auth_response_code != 200:
        if auth_response_code == 402:
            logger.error(f"Blacklisted token {auth_response}", extra=corId)
        else:
            logger.error(
                f"Could not decode authorization token {auth_response}", extra=corId)

        message = "invalid credentials"
        response = Error(message)

        logErrorResponse(message, endText, response, corId)
        return response, auth_response_code, corId

    else:
        user_id = auth_response

    if auth_response is not None:
        user = DBUser.query.filter_by(user_id=auth_response, deleted=False).first()

        if user is None:

            logger.error(
                f"Authorization token valid but user_id {user_id} not found",
                extra=corId,
            )
            message = "invalid credentials"
            response = Error(message)

            logErrorResponse(message, endText, response, corId)
            return response, 401, corId

        if user.user_id != userReq.user_id:

            logger.error(
                f"User {user.user_id} does not have permission to update the user {userReq.user_id}",
                extra=corId,
            )
            message = "no permission"
            response = Error(message)

            logErrorResponse(message, endText, response, corId)
            return response, 403, corId

    # -------------------- User does not exist in db -------------------- #

    userDb = DBUser.query.filter_by(user_id=userReq.user_id, deleted=False).first()
    if userDb is None:

        message = f"user with user_id {userReq.user_id} not found"
        response = Error(message)

        logErrorResponse(message, endText, response, corId)
        return response, 404, corId

    # -------------------- Update DO NOT disturb values -------------------- #

    for nd in userDb.settings.not_disturb:
        db.session.delete(nd)

    nds = []
    for key in userReq.not_disturb.sunday:
        nd = DBNotDisturb(
            day_of_week="sunday",
            start_timestamp=key.start_timestamp,
            end_timestamp=key.end_timestamp,
        )
        nds.append(nd)

    for key in userReq.not_disturb.monday:
        nd = DBNotDisturb(
            day_of_week="monday",
            start_timestamp=key.start_timestamp,
            end_timestamp=key.end_timestamp,
        )
        nds.append(nd)

    for key in userReq.not_disturb.tuesday:
        nd = DBNotDisturb(
            day_of_week="tuesday",
            start_timestamp=key.start_timestamp,
            end_timestamp=key.end_timestamp,
        )
        nds.append(nd)

    for key in userReq.not_disturb.wednesday:
        nd = DBNotDisturb(
            day_of_week="wednesday",
            start_timestamp=key.start_timestamp,
            end_timestamp=key.end_timestamp,
        )
        nds.append(nd)

    for key in userReq.not_disturb.thursday:
        nd = DBNotDisturb(
            day_of_week="thursday",
            start_timestamp=key.start_timestamp,
            end_timestamp=key.end_timestamp,
        )
        nds.append(nd)

    for key in userReq.not_disturb.friday:
        nd = DBNotDisturb(
            day_of_week="friday",
            start_timestamp=key.start_timestamp,
            end_timestamp=key.end_timestamp,
        )
        nds.append(nd)

    for key in userReq.not_disturb.saturday:
        nd = DBNotDisturb(
            day_of_week="saturday",
            start_timestamp=key.start_timestamp,
            end_timestamp=key.end_timestamp,
        )
        nds.append(nd)


    # -------------------- Meter ID already exists -------------------- #
    api_key = userDb.api_key
    if userDb.meter_id != userReq.meter_id:
        if userReq.meter_id is not None:
            res = DBUser.query.filter_by(meter_id=userReq.meter_id).first()
            if res is not None:
                message = "meterId " + userReq.meter_id + " already registered"
                response = Error(message)
                logErrorResponse(message, endText, response, corId)
                return response, 409, corId
        
            res = DBMeterIdApiKeyMapping.query.filter_by(meter_id=userReq.meter_id).first()
            if res is None:
                message = "meterId " + userReq.meter_id + " not found"
                response = Error(message)
                logErrorResponse(message, endText, response, corId)
                return response, 404, corId

            api_key = res.api_key
        else:
            api_key = None

        user_dongle = {
            "user_id": userReq.user_id,
            "api_key": api_key,
        }
        payload = user_dongle

        logger.info(
            f"User updated a dongle api_key event payload:\n{payload}", extra=corId
        )

        event = DBEvent(
            aggregateid=uuid.uuid4(),
            type=UserUpdatedDongleApiKeyEventType,
            payload=payload,
        )
        db.session.add(event)

        try:
            db.session.flush()

        except Exception as e:
            db.session.rollback()
            logger.error(e, extra=corId)
            return "", 500, corId

    # Postal code event -> Everytime there is a change in the postal code
    if userDb.settings.postal_code != userReq.postal_code:
        if userReq.contracted_power is not None:

            user_location = {
                "user_id": userReq.user_id,
                "postal_code": userReq.postal_code,
                "contracted_power": float(userReq.contracted_power.split(" ")[0]),
            }

            location_schema = UserLocationSchema()
            payload = location_schema.dump(user_location)

            logger.info(f"Location schema payload:\n{payload}", extra=corId)

            event = DBEvent(
                aggregateid=uuid.uuid4(),
                type=UserFilledPostalCodeEventType,
                payload=payload,
            )
            db.session.add(event)

            try:
                db.session.flush()

            except Exception as e:
                db.session.rollback()
                logger.error(e, extra=corId)
                return "", 500, corId

        else:
            logger.error(
                f"Contracted power is missing.\n"
                f"When user fills the postal code, it MUST also fill the contracted power.\n"
                f"Forecast installation was NOT registered...\n",
                extra=corId,
            )

            return Error("Missing contracted power"), 400, corId

    # -------------------- Update USER in DB -------------------- #

    userDb.first_name = userReq.first_name
    userDb.last_name = userReq.last_name
    userDb.meter_id = userReq.meter_id
    userDb.api_key = api_key
    userDb.wp_token = userReq.wp_token
    userDb.settings.country = userReq.country
    userDb.settings.postal_code = userReq.postal_code
    userDb.settings.schedule_type = userReq.schedule_type
    userDb.settings.tarif_type = userReq.tarif_type
    userDb.settings.contracted_power = userReq.contracted_power
    userDb.settings.not_disturb = nds
    userDb.settings.global_optimizer = userReq.global_optimizer

    # Check if registration is complete
    conditions = [
        userDb.meter_id is not None,
        userDb.settings.schedule_type is not None,
        userDb.settings.postal_code is not None,
        userDb.settings.tarif_type is not None,
        userDb.settings.contracted_power is not None,
    ]
    if all(conditions):
        userDb.settings.permissions = "Full"
    else:
        userDb.settings.permissions = "Minimal"

    timeNow = datetime.now(timezone.utc)
    userDb.modified_timestamp = timeNow
    userDb.settings.modified_timestamp = timeNow

    try:
        db.session.flush()

    except Exception as e:
        db.session.rollback()
        logger.error(e, extra=corId)
        return "", 500, corId

    # -------------------- Return User Data Structure -------------------- #

    not_disturb = {
        "sunday": [],
        "monday": [],
        "tuesday": [],
        "wednesday": [],
        "thursday": [],
        "friday": [],
        "saturday": [],
    }

    for nd in userDb.settings.not_disturb:
        not_disturb[nd.day_of_week].append(
            PeriodOfDay(nd.start_timestamp, nd.end_timestamp)
        )

    response = User(
        user_id=userDb.user_id,
        first_name=userDb.first_name,
        last_name=userDb.last_name,
        email=userDb.email,
        is_active=userDb.is_active,
        schedule_type=userDb.settings.schedule_type,
        meter_id=userDb.meter_id,
        api_key=userDb.api_key,
        wp_token=userDb.wp_token,
        country=userDb.settings.country,
        postal_code=userDb.settings.postal_code,
        tarif_type=userDb.settings.tarif_type,
        contracted_power=userDb.settings.contracted_power,
        not_disturb=not_disturb,
        global_optimizer=userDb.settings.global_optimizer,
        permissions=userDb.settings.permissions,
        is_google_account=userDb.is_google_account,
        modified_timestamp=userDb.modified_timestamp,
    )

    # User Update Event
    userSchema = UserAccountSchema()
    payload = userSchema.dump(response)

    logger.info(f"payload: {payload}\n", extra=corId)

    event = DBEvent(
        aggregateid=uuid.uuid4(), type=UserUpdatedEventType, payload=payload
    )
    db.session.add(event)

    try:
        db.session.commit()

    except Exception as e:
        db.session.rollback()
        logger.error(e, extra=corId)
        return "", 500, corId

    logResponse(endText, response, corId)

    return response, 200, corId

def recover_account_post():  # noqa: E501
    """Account recovery after soft delete

     # noqa: E501

    :param x_correlation_id: 
    :type x_correlation_id: str
    :type x_correlation_id: str
    :param account_recovery_request: 
    :type account_recovery_request: dict | bytes

    :rtype: Union[None, Tuple[None, int], Tuple[None, int, Dict[str, str]]
    """
    if connexion.request.is_json:
        account_recovery_request = AccountRecoveryRequest.from_dict(connexion.request.get_json())  # noqa: E501

    corId = {"X-Correlation-ID": connexion.request.headers["X-Correlation-ID"]}

    logger.info("Processing POST /recover-account request", extra=corId)
    endText = "Processed POST /recover-account request"

    email = account_recovery_request.email
    try:
        user = DBUser.query.filter_by(email=email, deleted=True).first()
        if user:
            success = sendAccountRecoveryEmail(user.user_id, user.email, corId)
            if success is True:
                logger.info(
                    "Sucessfully sent account recovery email to user with email "
                    + email,
                    extra=corId,
                )
            else:
                logger.error(
                    "Failed to send account recovery email to user with email "
                    + email,
                    extra=corId,
                )
            logResponse(endText, None, corId)
        else:
            message = "User with email " + email + " not found or acount not deleted"
            logErrorResponse(message, endText, None, corId)

        # So that user enumeration (vulnerability) does not occur, send the same response if the user exists or does not exist
        # The answer in the aplication should be: if the user is registered in the platform, an email was sent
        return "", 200, corId

    except Exception as e:
        message = (
            "Exception caught while processing /recover-account request for user with email "
            + email
        )
        logger.error(e, extra=corId)
        logErrorResponse(message, endText, None, corId)
        return "", 500, corId


@app.route('/api/account/recover-account/<token>', methods=['GET'])
def recover_account_token_get(token):  # noqa: E501
    """Endpoint to get the webpage with the form to recover the account by clicking the link sent to the e-mail.

     # noqa: E501

    :param token: 
    :type token: str

    :rtype: Union[None, Tuple[None, int], Tuple[None, int, Dict[str, str]]
    """
    corId = {"X-Correlation-ID": "confirmation-token-" + token}
    logger.info("Processing GET /recover-account/{{token}} request", extra=corId)
    endText = "Processed GET /recover-account/{{token}} request"

    data = DBAccountRecoveryToken.query.filter_by(token=token).first()
    if data is None:
        message = "account recovery token " + token + " not found"
        response = Error(message)
        logErrorResponse(message, endText, response, corId)
        return render_template("recover-account.html", recovery_not_found=True), 404

    if data.expiration_timestamp.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        message = "account recovery token " + token + " expired"
        response = Error(message)
        logErrorResponse(message, endText, response, corId)
        return render_template("recover-account.html", recovery_expired=True), 404

    user = DBUser.query.filter_by(user_id=data.user_id, deleted=True).first()
    if user is None:
        logger.error(
            "account recovery token valid but user_id " + data.user_id + " not found or not deleted",
            extra=corId,
        )
        message = "account recovery token not found"
        response = Error(message)
        logErrorResponse(message, endText, response, corId)
        return render_template("recover-account.html", recovery_not_found=True), 404

    logger.info("Sending webpage to recover account for token " + token, extra=corId)
    logResponse(endText, None, corId)

    return render_template("recover-account.html", my_token=token, recover=True)


@app.route('/api/account/recover-account/<token>', methods=['POST'])
def recover_account_token_post(token):  # noqa: E501
    """Endpoint to set the user as non deleted. This endpoint will be used by the webpage to recover the account (get endpoint of this request).

     # noqa: E501

    :param token: 
    :type token: str

    :rtype: Union[None, Tuple[None, int], Tuple[None, int, Dict[str, str]]
    """
    # new_password = connexion.request.form.get("new_password")
    # new_password_repeat = connexion.request.form.get("new_password_repeat")

    corId = {"X-Correlation-ID": "recover-account-" + token}
    logger.info("Processing POST /recover-account{{token}} request", extra=corId)
    endText = "Processed POST /recover-account/{{token}} request"

    data = DBAccountRecoveryToken.query.filter_by(token=token).first()
    if data is None:
        message = "account recovery token " + token + " not found"
        response = Error(message)
        logErrorResponse(message, endText, response, corId)
        return render_template("recover-account.html", recovery_not_found=True), 404

    if data.expiration_timestamp.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        message = "account recovery token " + token + " expired"
        response = Error(message)
        logErrorResponse(message, endText, response, corId)
        return render_template("recover-account.html", recovery_expired=True), 404

    # if new_password != new_password_repeat:
    #     message = "passwords fields do not match"
    #     response = Error(message)
    #     logErrorResponse(message, endText, response, corId)
    #     return (
    #         render_template("recover-account.html", reset_passwords_not_match=True),
    #         400,
    #     )

    user = DBUser.query.filter_by(user_id=data.user_id, deleted=True).first()
    if user is None:
        logger.error(
            "account recovery token valid but user_id " + data.user_id + " not found",
            extra=corId,
        )
        message = "account recovery token not found"
        response = Error(message)
        logErrorResponse(message, endText, response, corId)
        return render_template("recover-account.html", recovery_not_found=True), 404

    # if bcrypt.check_password_hash(user.password, new_password):
    #     message = "old password is equal to the new password"
    #     response = Error(message)
    #     logErrorResponse(message, endText, response, corId)
    #     return (
    #         render_template(
    #             "recover-account.html", reset_password_equal_old_password=True
    #         ),
    #         400,
    #     )

    DBAccountRecoveryToken.query.filter_by(user_id=data.user_id).delete()

    user.deleted = False
    user.deleted_timestamp = None

    try:
        db.session.flush()
    except Exception as e:
        db.session.rollback()
        logger.error(e, extra=corId)
        return "", 500, corId

    not_disturb = {
        "sunday": [],
        "monday": [],
        "tuesday": [],
        "wednesday": [],
        "thursday": [],
        "friday": [],
        "saturday": [],
    }
    for nd in user.settings.not_disturb:
        not_disturb[nd.day_of_week].append(
            PeriodOfDay(nd.start_timestamp, nd.end_timestamp)
        )

    response = User(
        user_id=user.user_id,
        first_name=user.first_name,
        last_name=user.last_name,
        email=user.email,
        is_active=user.is_active,
        schedule_type=user.settings.schedule_type,
        meter_id=user.meter_id,
        api_key=user.api_key,
        country=user.settings.country,
        postal_code=user.settings.postal_code,
        tarif_type=user.settings.tarif_type,
        contracted_power=user.settings.contracted_power,
        not_disturb=not_disturb,
        global_optimizer=user.settings.global_optimizer,
        permissions=user.settings.permissions,
        is_google_account=user.is_google_account,
        modified_timestamp=user.modified_timestamp,
    )

    userSchema = UserAccountSchema()
    payload = userSchema.dump(response)

    event = DBEvent(
        aggregateid=uuid.uuid4(), type=UserRecoveredAccountEventType, payload=payload
    )
    db.session.add(event)

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(e, extra=corId)
        return "", 500, corId

    logger.info(
        "Successfully recovered account with user_id "
        + user.user_id
        + " and email "
        + user.email,
        extra=corId,
    )
    logResponse(endText, None, corId)

    return render_template("recover-account.html", recovery_sucess=True)


def sendAccountRecoveryEmail(user_id, email, corId):
    # Create and send account recovery token
    m = hashlib.sha256()
    m.update(uuid.uuid4().bytes)
    m.hexdigest()

    try:
        DBAccountRecoveryToken.query.filter_by(user_id=user_id).delete()
    except Exception as e:
        generalLogger.info(e)

    accountRecoveryToken = DBAccountRecoveryToken(
        user_id=user_id,
        token=m.hexdigest(),
        expiration_timestamp=datetime.now(timezone.utc)
        + timedelta(seconds=Config.CONFIRMATION_TOKEN_EXPIRATION_TIME_SECONDS),
    )

    db.session.add(accountRecoveryToken)
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(e, extra=corId)
        return False

    success = True
    if (
        Config.GITLAB_CI_TEST == "False"
        and Config.EMAIL is not None
        and Config.EMAIL_PASSWORD is not None
    ):
        # Create a secure SSL context
        context = ssl.create_default_context()
        # Context with secure TLS protocol
        # context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        # ssl.SSLContext(ssl.PROTOCOL_SSLv3)
        generalLogger.info(f"SSL context: {context.protocol}")

        # Loop to secure the connection (sometimes fails when stating tls)
        max_retries = 5
        attempt = 0
        while attempt < max_retries:
            try:
                server = smtplib.SMTP("mail.inesctec.pt", 587)
                # server.ehlo()  # identify ourselves as inesctec mail client
                generalLogger.info("SMTP connection.. OK!")

                server.starttls(context=context)  # Secure the connection
                # server.ehlo()  # re-identify ourselves as an encrypted tls connection
                generalLogger.info("TLS connection.. OK!")
                break
            except Exception as e:
                attempt += 1
                generalLogger.info(e)
                time.sleep(2)  # Wait before attempting another tls connection

        # Failed to connect to SMTP inesctec mail client
        if attempt == max_retries:
            generalLogger.error(
                "Failed to open secure tls connection to SMTP mail client..."
            )
            return False

        sender_email = Config.EMAIL
        try:
            server.login(sender_email, Config.EMAIL_PASSWORD)
            generalLogger.info("Login.. OK!")

            # Create a multipart message and set headers
            receiver_email = email

            message = MIMEMultipart()
            message["From"] = formataddr(
                (str(Header("Aplicação InterConnect", "utf-8")), sender_email)
            )
            message["To"] = receiver_email
            message[
                "Subject"
            ] = "Recuperação de conta na aplicação do projeto InterConnect"

            link = (
                "https://interconnect-dev.inesctec.pt/api/account/recover-account/"
                + m.hexdigest()
            )

            # For local test
            # link = "http://127.0.0.1:8080/api/account/forgot-password/" + m.hexdigest()

            f = open(
                "account_manager/templates/email-recover.html", "r", encoding="utf-8"
            )
            body = f.read()
            f.close()
            body_aux = body.replace("LINK_LINK", link)

            f = open(
                "account_manager/static/img/INESCTECLogotipo_CORPositivo_RGB.png", "rb"
            )
            inesc_logo = f.read()
            f.close()

            message.attach(MIMEText(body_aux, "html", "utf-8"))
            img = MIMEImage(inesc_logo)
            img.add_header("Content-ID", "INESCTECLogotipo_CORPositivo_RGB.png")
            message.attach(img)

            text = message.as_string()

            server.sendmail(sender_email, receiver_email, text)

            generalLogger.info(
                "Successfully sent email with account recovery link to " + email
            )
            success = True
        except Exception as e:
            # Print any error messages to stdout
            generalLogger.error(
                "Error in sending email with account recovery link to " + email
            )
            generalLogger.error(e)
            success = False
        finally:
            server.quit()
            generalLogger.info("Quit... OK!")

    return success
