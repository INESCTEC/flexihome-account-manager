import connexion

from account_manager.models.change_password_request import ChangePasswordRequest  # noqa: E501
from account_manager.models.delete_type import DeleteType  # noqa: E501
from account_manager.models.error import Error  # noqa: E501
from account_manager.models.forgot_password_request import ForgotPasswordRequest  # noqa: E501
from account_manager.models.google_user_register_request import GoogleUserRegisterRequest  # noqa: E501
from account_manager.models.login_request import LoginRequest  # noqa: E501
from account_manager.models.dongles import Dongles  # noqa: E501
from account_manager.models.meter_id_to_user_id import MeterIdToUserId  # noqa: E501
from account_manager.models.register_request import RegisterRequest  # noqa: E501
from account_manager.models.user import User  # noqa: E501

from account_manager.models.dbmodels import db, DBUser, DBUserSettings, DBNotDisturb, DBConfirmationToken, DBForgotPasswordToken, DBEvent
from account_manager.models.not_disturb import NotDisturb
from account_manager.models.period_of_day import PeriodOfDay
from account_manager.models.events import UserAccountSchema, UserAddedDongleApiKeyEventType, UserUpdatedDongleApiKeyEventType, UserLocationSchema, UserRegisteredEventType, UserConfirmedEventType, UserUpdatedEventType, UserSoftDeletedEventType, UserHardDeletedEventType, UserFilledPostalCodeEventType, UserRegisteredNotificationSchema, UserRegisteredNotificationType
from account_manager import app, logger, generalLogger, Config, bcrypt, auth, TokenBlacklist

from flask import render_template, send_from_directory

import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from email.header import Header
from email.utils import formataddr

import hashlib

from datetime import datetime, timedelta, timezone
import time
import uuid


def logErrorResponse(error, endText, response, corId):
    logger.error(error, extra=corId)
    logResponse(endText, response, corId)


def logResponse(endText, response, corId):
    logger.info(endText, extra=corId)
    if response is not None:
        logger.debug("Sending the following response: ", extra=corId)
        logger.debug(response, extra=corId)


def change_password_post():  # noqa: E501
    """Change password

     # noqa: E501

    :param x_correlation_id: 
    :type x_correlation_id: str
    :param authorization: 
    :type authorization: str
    :param change_password_request: 
    :type change_password_request: dict | bytes

    :rtype: None
    """
    if connexion.request.is_json:
        change_password_request = ChangePasswordRequest.from_dict(connexion.request.get_json())  # noqa: E501

    corId = {'X-Correlation-ID': connexion.request.headers["X-Correlation-ID"]}

    logger.info("Processing POST /change-password request", extra=corId)
    endText = "Processed POST /change-password request"

    if change_password_request.new_password != change_password_request.new_password_repeat:
        message = "\"new_password\" and \"new_password_repeat\" fields do not match"
        response = Error(message)
        logErrorResponse(message, endText, response, corId)
        return response, 400, corId

    if change_password_request.new_password == change_password_request.old_password:
        message = "\"new_password\" and \"old_password\" fields cannot be equal"
        response = Error(message)
        logErrorResponse(message, endText, response, corId)
        return response, 400, corId

    auth_response, auth_response_code = auth.verify_basic_authorization(
        connexion.request.headers)

    if auth_response_code != 200 or auth_response is None:
        if auth_response_code == 402:
            logger.error(f"Blacklisted token {auth_response}", extra=corId)
        else:
            logger.error(
                f"Could not decode authorization token {auth_response}", extra=corId)

        message = "invalid credentials"
        response = Error(message)
        logErrorResponse(message, endText, response, corId)
        return response, 401, corId

    user = DBUser.query.filter_by(user_id=auth_response, deleted=False).first()

    if user is None:
        logger.error("Authorization token valid but user_id " +
                     response + " not found", extra=corId)
        message = "invalid credentials"
        response = Error(message)
        logErrorResponse(message, endText, response, corId)
        return response, 401, corId

    if user.is_google_account:
        message = "Cannot change password from Google account!"
        response = Error(message)
        logErrorResponse(message, endText, response, corId)
        return response, 401, corId

    try:
        if bcrypt.check_password_hash(user.password, change_password_request.old_password):
            user.password = bcrypt.generate_password_hash(
                change_password_request.new_password).decode()
            try:
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                logger.error(e, extra=corId)
                return '', 500, corId

            logger.info("User " + user.user_id +
                        " successfully changed password", extra=corId)
            logResponse(endText, None, corId)
            return '', 200, corId
        else:
            logger.error(
                "old_password does not match with saved password for user with email " + user.email, extra=corId)
            message = "old_password does not match with saved password"
            response = Error(message)
            logErrorResponse(message, endText, response, corId)
            return response, 401, corId

    except Exception as e:
        logger.error(e, extra=corId)
        return '', 500, corId

    # This code should never be reached
    return '', 500, corId


@app.route('/api/account/confirm-account/<token>', methods=['GET'])
def confirm_account_token_get(token):  # noqa: E501
    """Endpoint to get the webpage with the button to confirm account by clicking the link sent to the e-mail.

     # noqa: E501

    :param token: 
    :type token: str

    :rtype: None
    """
    corId = {'X-Correlation-ID': "confirmation-token-" + token}
    logger.info("Processing GET /confirm-account request", extra=corId)
    endText = "Processed GET /confirm-account request"

    data = DBConfirmationToken.query.filter_by(token=token).first()
    if data is None:
        # logger.error("confirmation token " + token + " not found", extra=corId)
        message = "confirmation token " + token + " not found"
        response = Error(message)
        logErrorResponse(message, endText, response, corId)
        return render_template('confirm.html', confirm_not_found=True), 404

    if data.expiration_timestamp < datetime.now(timezone.utc):
        # logger.error("confirmation token " + token + " expired", extra=corId)
        message = "confirmation token " + token + " expired"
        response = Error(message)
        logErrorResponse(message, endText, response, corId)
        return render_template('confirm.html', confirm_expired=True), 404

    user = DBUser.query.filter_by(user_id=data.user_id, deleted=False).first()
    if user is None:
        logger.error("Confirmation token valid but user_id " +
                     data.user_id + " not found", extra=corId)
        message = "confirmation token not found"
        response = Error(message)
        logErrorResponse(message, endText, response, corId)
        return render_template('confirm.html', confirm_not_found=True), 404

    logger.info("Sending webpage to confirm token " + token, extra=corId)
    logResponse(endText, None, corId)

    return render_template('confirm.html', my_token=token, confirm=True)


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
    corId = {'X-Correlation-ID': "confirmation-token-" + token}

    logger.info("Processing POST /confirm-account request", extra=corId)
    endText = "Processed POST /confirm-account request"

    data = DBConfirmationToken.query.filter_by(token=token).first()
    if data is None:
        # logger.error("confirmation token " + token + " not found", extra=corId)
        message = "confirmation token " + token + " not found"
        response = Error(message)
        logErrorResponse(message, endText, response, corId)
        return render_template('confirm.html', confirm_not_found=True), 404

    if data.expiration_timestamp < datetime.now(timezone.utc):
        # logger.error("confirmation token " + token + " expired", extra=corId)
        message = "confirmation token " + token + " expired"
        response = Error(message)
        logErrorResponse(message, endText, response, corId)
        return render_template('confirm.html', confirm_expired=True), 404

    user = DBUser.query.filter_by(user_id=data.user_id, deleted=False).first()
    if user is None:
        logger.error("Confirmation token valid but user_id " +
                     data.user_id + " not found", extra=corId)
        message = "confirmation token not found"
        response = Error(message)
        logErrorResponse(message, endText, response, corId)
        return render_template('confirm.html', confirm_not_found=True), 404

    user.is_active = True

    # Check if registration is complete
    if (user.cpe is not None) and (user.meter_id is not None) and (user.settings.schedule_type is not None) and (user.settings.postal_code is not None) and (user.settings.tarif_type is not None) and (user.settings.contracted_power is not None):
        user.settings.permissions = "Full"
    else:
        user.settings.permissions = "Minimal"

    DBConfirmationToken.query.filter_by(user_id=user.user_id).delete()

    not_disturb = {"sunday": [], "monday": [], "tuesday": [],
                   "wednesday": [], "thursday": [], "friday": [], "saturday": []}
    for nd in user.settings.not_disturb:
        not_disturb[nd.day_of_week].append(
            PeriodOfDay(nd.start_timestamp, nd.end_timestamp))
    response = User(user_id=user.user_id, first_name=user.first_name, last_name=user.last_name, email=user.email, is_active=user.is_active, schedule_type=user.settings.schedule_type,
                    cpe=user.cpe, meter_id=user.meter_id, api_key=user.api_key, country=user.settings.country, postal_code=user.settings.postal_code, tarif_type=user.settings.tarif_type,
                    contracted_power=user.settings.contracted_power, not_disturb=not_disturb, global_optimizer=user.settings.global_optimizer, permissions=user.settings.permissions, is_google_account=user.is_google_account, modified_timestamp=user.modified_timestamp)

    userSchema = UserAccountSchema()
    payload = userSchema.dump(response)

    event = DBEvent(aggregateid=uuid.uuid4(),
                    type=UserConfirmedEventType, payload=payload)
    db.session.add(event)
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(e, extra=corId)
        return '', 500, corId

    logger.info("Successfully confirmed account with user_id " +
                user.user_id + " and email " + user.email, extra=corId)
    logResponse(endText, None, corId)

    return render_template('confirm.html', confirm_sucess=True)


def forgot_password_post():  # noqa: E501
    """Forgot password

     # noqa: E501

    :param x_correlation_id: 
    :type x_correlation_id: str
    :param forgot_password_request: 
    :type forgot_password_request: dict | bytes

    :rtype: None
    """
    if connexion.request.is_json:
        forgot_password_request = ForgotPasswordRequest.from_dict(connexion.request.get_json())  # noqa: E501

    corId = {'X-Correlation-ID': connexion.request.headers["X-Correlation-ID"]}

    logger.info("Processing POST /forgot-password request", extra=corId)
    endText = "Processed POST /forgot-password request"

    email = forgot_password_request.email
    try:
        user = DBUser.query.filter_by(email=email, deleted=False).first()
        if user:
            if user.is_google_account is False:
                success = sendForgotPasswordEmail(
                    user.user_id, user.email, corId)
                if success is True:
                    logger.info(
                        "Sucessfully sent forgot-password email to user with email " + email, extra=corId)
                else:
                    logger.error(
                        "Failed to send forgot-password email to user with email " + email, extra=corId)
                logResponse(endText, None, corId)
            else:
                message = "User with email" + email + " is a google account"
                logErrorResponse(message, endText, None, corId)
        else:
            message = "User with email" + email + " not found"
            logErrorResponse(message, endText, None, corId)

        # So that user enumeration (vulnerability) does not occur, send the same response if the user exists or does not exist
        # The answer in the aplication should be: if the user is registered in the platform, an email was sent
        return '', 200, corId

    except Exception as e:
        message = "Exception caught while processing forgot-password request for user with email " + email
        logger.error(e, extra=corId)
        logErrorResponse(message, endText, None, corId)
        return '', 500, corId


@app.route('/api/account/forgot-password/<token>', methods=['GET'])
def forgot_password_token_get(token):  # noqa: E501
    """Endpoint to get the webpage with the form to reset password by clicking the link sent to the e-mail.

     # noqa: E501

    :param token: 
    :type token: str

    :rtype: None
    """
    corId = {'X-Correlation-ID': "confirmation-token-" + token}
    logger.info(
        "Processing GET /forgot-password/{{token}} request", extra=corId)
    endText = "Processed GET /forgot-password/{{token}} request"

    data = DBForgotPasswordToken.query.filter_by(token=token).first()
    if data is None:
        message = "forgot-password token " + token + " not found"
        response = Error(message)
        logErrorResponse(message, endText, response, corId)
        return render_template('forgot-password.html', reset_not_found=True), 404

    if data.expiration_timestamp < datetime.now(timezone.utc):
        message = "forgot-password token " + token + " expired"
        response = Error(message)
        logErrorResponse(message, endText, response, corId)
        return render_template('forgot-password.html', reset_expired=True), 404

    user = DBUser.query.filter_by(user_id=data.user_id, deleted=False).first()
    if user is None:
        logger.error("forgot-password token valid but user_id " +
                     data.user_id + " not found", extra=corId)
        message = "forgot-password token not found"
        response = Error(message)
        logErrorResponse(message, endText, response, corId)
        return render_template('forgot-password.html', reset_not_found=True), 404

    logger.info("Sending webpage to reset password for token " +
                token, extra=corId)
    logResponse(endText, None, corId)

    return render_template('forgot-password.html', my_token=token, reset=True)


@app.route('/api/account/forgot-password/<token>', methods=['POST'])
def forgot_password_token_post(token):  # noqa: E501
    """Endpoint to set the new password. This endpoint will be used by the webpage to reset the password (get endpoint of this request).

     # noqa: E501

    :param token: 
    :type token: str
    :param new_password: 
    :type new_password: str
    :param new_password_repeat: 
    :type new_password_repeat: str

    :rtype: None
    """
    new_password = connexion.request.form.get("new_password")
    new_password_repeat = connexion.request.form.get("new_password_repeat")

    corId = {'X-Correlation-ID': "forgot-password-" + token}
    logger.info(
        "Processing POST /forgot-password{{token}} request", extra=corId)
    endText = "Processed POST /forgot-password/{{token}} request"

    data = DBForgotPasswordToken.query.filter_by(token=token).first()
    if data is None:
        message = "forgot-password token " + token + " not found"
        response = Error(message)
        logErrorResponse(message, endText, response, corId)
        return render_template('forgot-password.html', reset_not_found=True), 404

    if data.expiration_timestamp < datetime.now(timezone.utc):
        message = "forgot-password token " + token + " expired"
        response = Error(message)
        logErrorResponse(message, endText, response, corId)
        return render_template('forgot-password.html', reset_expired=True), 404

    if new_password != new_password_repeat:
        message = "passwords fields do not match"
        response = Error(message)
        logErrorResponse(message, endText, response, corId)
        return render_template('forgot-password.html', reset_passwords_not_match=True), 400

    user = DBUser.query.filter_by(user_id=data.user_id, deleted=False).first()
    if user is None:
        logger.error("forgot-password token valid but user_id " +
                     data.user_id + " not found", extra=corId)
        message = "forgot-password token not found"
        response = Error(message)
        logErrorResponse(message, endText, response, corId)
        return render_template('forgot-password.html', reset_not_found=True), 404

    if bcrypt.check_password_hash(user.password, new_password):
        message = "old password is equal to the new password"
        response = Error(message)
        logErrorResponse(message, endText, response, corId)
        return render_template('forgot-password.html', reset_password_equal_old_password=True), 400

    DBForgotPasswordToken.query.filter_by(user_id=data.user_id).delete()

    wasActive = user.is_active

    user.password = bcrypt.generate_password_hash(new_password).decode()
    user.is_active = True

    try:
        db.session.flush()
    except Exception as e:
        db.session.rollback()
        logger.error(e, extra=corId)
        return '', 500, corId

    if wasActive is False:
        not_disturb = {"sunday": [], "monday": [], "tuesday": [],
                       "wednesday": [], "thursday": [], "friday": [], "saturday": []}
        for nd in user.settings.not_disturb:
            not_disturb[nd.day_of_week].append(
                PeriodOfDay(nd.start_timestamp, nd.end_timestamp))

        response = User(user_id=user.user_id, first_name=user.first_name, last_name=user.last_name, email=user.email, is_active=user.is_active, schedule_type=user.settings.schedule_type,
                        cpe=user.cpe, meter_id=user.meter_id, api_key=user.api_key, country=user.settings.country, postal_code=user.settings.postal_code, tarif_type=user.settings.tarif_type,
                        contracted_power=user.settings.contracted_power, not_disturb=not_disturb, global_optimizer=user.settings.global_optimizer, permissions=user.settings.permissions, is_google_account=user.is_google_account, modified_timestamp=user.modified_timestamp)

        userSchema = UserAccountSchema()
        payload = userSchema.dump(response)

        event = DBEvent(aggregateid=uuid.uuid4(),
                        type=UserConfirmedEventType, payload=payload)
        db.session.add(event)

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(e, extra=corId)
        return '', 500, corId

    logger.info("Successfully updated password for account with user_id " +
                user.user_id + " and email " + user.email, extra=corId)
    logResponse(endText, None, corId)

    return render_template('forgot-password.html', reset_sucess=True)


def login_post():

    if connexion.request.is_json:
        login_request = LoginRequest.from_dict(connexion.request.get_json())  # noqa: E501

    corId = {'X-Correlation-ID': connexion.request.headers["X-Correlation-ID"]}

    try:
        expo_token = connexion.request.headers["expo-token"]
    except KeyError:
        logger.warning(
            f"User {login_request.email} login has no expo token.", extra=corId)
        expo_token = None

    logger.info("Processing POST /login request", extra=corId)
    endText = "Processed POST /login request"

    try:
        user = DBUser.query.filter_by(
            email=login_request.email, deleted=False).first()

        # ----------------- User exists ----------------- #
        if user:

            # ----------------- Confirmed account ----------------- #
            if user.is_active is True:

                # ------ Google accounts use /register-google endpoint ------ #
                if user.is_google_account is False:

                    if bcrypt.check_password_hash(user.password, login_request.password):
                        auth_token = user.encode_auth_token()

                        # ----------------- Successful Login ----------------- #
                        if auth_token:

                            authorizationHeader = {
                                'Authorization': "Bearer " + auth_token
                            }
                            headers = dict(
                                list(corId.items()) +
                                list(authorizationHeader.items())
                            )

                            logger.info(
                                f"User {login_request.email} successfully loggedin",
                                extra=corId
                            )

                            if expo_token is not None:
                                user.expo_token = expo_token
                                logger.debug(
                                    f"User logged in with expo token: {user.expo_token}",
                                    extra=corId
                                )

                                db.session.flush()
                                db.session.commit()

                            logResponse(endText, None, corId)
                            return '', 200, headers

                    else:
                        logger.error(
                            f"Wrong password for user with email {login_request.email}",
                            extra=corId
                        )

                        message = "invalid credentials"
                        response = Error(message)
                        logErrorResponse(message, endText, response, corId)

                        return response, 401, corId

                else:
                    logger.error(
                        f"User with email {login_request.email} is associated with a google account.\n"
                        f"The login must be made through the google integration button.",
                        extra=corId
                    )

                    message = "Account is associated with Google"
                    response = Error(message)
                    logErrorResponse(message, endText, response, corId)

                    return response, 400, corId

            else:
                logger.error(
                    f"User with email {login_request.email} did not activate its account",
                    extra=corId
                )

                message = "invalid credentials"
                response = Error(message)
                logErrorResponse(message, endText, response, corId)

                return response, 401, corId

        else:
            logger.error(
                f"User with email {login_request.email} not found",
                extra=corId
            )

            message = "invalid credentials"
            response = Error(message)
            logErrorResponse(message, endText, response, corId)

            return response, 401, corId

    except Exception as e:
        logger.error(e, extra=corId)
        return Error(repr(e)), 500, corId

    # This code should never be reached
    return '', 500, corId


def logout_post():  # noqa: E501
    """Logout

     # noqa: E501

    :param x_correlation_id: 
    :type x_correlation_id: str
    :param authorization: 
    :type authorization: str

    :rtype: None
    """
    corId = {'X-Correlation-ID': connexion.request.headers["X-Correlation-ID"]}

    logger.info("Processing POST /logout request", extra=corId)
    endText = "Processed POST /logout request"

    auth_response, auth_response_code = auth.verify_basic_authorization(
        connexion.request.headers)

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

    token = TokenBlacklist(token=connexion.request.headers["Authorization"])

    db.session.add(token)

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(e, extra=corId)
        return '', 500, corId

    logger.info("Logged out user with user_id " + user_id, extra=corId)
    logger.debug(token, extra=corId)
    # logResponse(endText, user, corId)

    return '', 200, corId


def meter_to_user_get(meter_ids):

    corId = {'X-Correlation-ID': connexion.request.headers["X-Correlation-ID"]}

    logger.info("Processing GET /meter-to-user request", extra=corId)
    endText = "Processed GET /meter-to-user request"

    my_set = set(meter_ids)
    meter_ids = list(my_set)

    auth_response, auth_response_code = auth.verify_basic_authorization(
        connexion.request.headers)

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

    else:
        user_id = auth_response

    if auth_response is not None:
        user = DBUser.query.filter_by(
            user_id=auth_response, deleted=False).first()

        if user is None:

            logger.error(
                f"Authorization token valid but user_id {user_id} not found", extra=corId)
            message = "invalid credentials"
            response = Error(message)

            logErrorResponse(message, endText, response, corId)
            return response, 401, corId

        for mId in meter_ids:
            if mId != user.meter_id:

                logger.error(
                    f"User with meterId {user.meter_id}"
                    f"does not have permission to see user with meterId {mId}",
                    extra=corId
                )
                message = "no permission"
                response = Error(message)

                logErrorResponse(message, endText, response, corId)
                return response, 403, corId

    response = []
    for mId in meter_ids:
        user = DBUser.query.filter_by(meter_id=mId, deleted=False).first()

        if user is None:
            message = f"user with meter_id {mId} not found"
            response = Error(message)

            logErrorResponse(message, endText, response, corId)
            return response, 404, corId

        response.append(MeterIdToUserId(user.meter_id, user.user_id))

    logResponse(endText, response, corId)

    return response, 200, corId


def refresh_token_post():  # noqa: E501
    """Refresh authentication token (needed if the token is about to expire)

     # noqa: E501

    :param x_correlation_id: 
    :type x_correlation_id: str
    :param authorization: 
    :type authorization: str

    :rtype: None
    """
    corId = {'X-Correlation-ID': connexion.request.headers["X-Correlation-ID"]}

    logger.info("Processing POST /refresh-token request", extra=corId)
    endText = "Processed POST /refresh-token request"

    auth_response, auth_response_code = auth.verify_basic_authorization(
        connexion.request.headers)

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
    else:
        user_id = auth_response

    if auth_response is not None:
        user = DBUser.query.filter_by(
            user_id=auth_response, deleted=False).first()

        if user is None:
            logger.error("Authorization token valid but user_id " +
                         user_id + " not found", extra=corId)
            message = "invalid credentials"
            response = Error(message)
            logErrorResponse(message, endText, response, corId)
            return response, 401, corId

    try:
        newToken = user.encode_auth_token()
    except Exception as e:
        logger.error(e, extra=corId)
        return '', 500, corId

    if newToken is None:
        # This code should never be reached
        return '', 500, corId

    authorizationHeader = {
        'Authorization': "Bearer " + newToken
    }
    headers = dict(list(corId.items()) +
                   list(authorizationHeader.items()))
    logger.info("User " + user.user_id +
                " successfully refreshed authorization token", extra=corId)
    logResponse(endText, None, corId)
    return '', 200, headers


def register_google_post():

    if connexion.request.is_json:
        google_user_register_request = GoogleUserRegisterRequest.from_dict(connexion.request.get_json())  # noqa: E501

    corId = {'X-Correlation-ID': connexion.request.headers["X-Correlation-ID"]}

    try:
        expo_token = connexion.request.headers["expo-token"]
    except KeyError:
        logger.warning(
            f"User {google_user_register_request.email} login has no expo token.",
            extra=corId
        )
        expo_token = None

    logger.info("Processing POST /register request", extra=corId)
    endText = "Processed POST /register request"

    # ------------------------------ AUTHORIZATION PART ------------------------------ #

    auth_response, auth_response_code = auth.verify_google_authorization(
        connexion.request.headers)

    if auth_response_code != 200:
        message = auth_response
        response = Error(message)
        logErrorResponse(message, endText, response, corId)
        return response, auth_response_code, corId

    else:
        logger.info("Google Authentication... OK!", extra=corId)
        email = auth_response

    # Check if email already exists in DB
    user = DBUser.query.filter_by(email=email).first()
    if user is not None:

        not_disturb = {
            "sunday": [], "monday": [], "tuesday": [], "wednesday": [],
            "thursday": [], "friday": [], "saturday": []
        }

        for nd in user.settings.not_disturb:
            not_disturb[nd.day_of_week].append(
                PeriodOfDay(nd.start_timestamp, nd.end_timestamp))

        response = User(
            user_id=user.user_id,
            first_name=user.first_name,
            last_name=user.last_name,
            email=user.email,
            is_active=user.is_active,
            schedule_type=user.settings.schedule_type,
            cpe=user.cpe,
            meter_id=user.meter_id,
            api_key=user.api_key,
            expo_token=user.expo_token,
            wp_token=user.wp_token,
            country=user.settings.country,
            postal_code=user.settings.postal_code,
            tarif_type=user.settings.tarif_type,
            contracted_power=user.settings.contracted_power,
            not_disturb=not_disturb,
            global_optimizer=user.settings.global_optimizer,
            permissions=user.settings.permissions,
            is_google_account=user.is_google_account,
            modified_timestamp=user.modified_timestamp
        )

        try:
            auth_token = user.encode_auth_token()

            if auth_token:
                authorizationHeader = {
                    'Authorization': "Bearer " + auth_token
                }
                headers = dict(
                    list(corId.items()) + list(authorizationHeader.items())
                )
                logger.info(
                    f"Google User {auth_response} successfully loggedin", extra=corId)

                if expo_token is not None:
                    user.expo_token = expo_token
                    logger.debug(
                        f"User logged in with expo token: {user.expo_token}", extra=corId)

                    db.session.flush()
                    db.session.commit()

                logResponse(endText, None, corId)
                return '', 200, headers

            else:
                logger.error(
                    f"Failed to encode auth token: {auth_token}\n", extra=corId)

                return Error("Failed to encode auth token"), 500, corId

        except Exception as e:
            logger.error(e, extra=corId)
            return '', 500, corId

    # Add minimal user to DB
        # Registry through google gives Minimal permissions,
        # because user does not need to confirm account,
        # but still needs to fill in the rest of the fields
    settings = DBUserSettings(permissions="Minimal")

    dbUser = DBUser(
        first_name=google_user_register_request.first_name,
        last_name=google_user_register_request.last_name,
        email=auth_response,
        expo_token=expo_token,
        is_active=True,
        is_google_account=True,
        settings=settings
    )

    db.session.add(dbUser)
    try:
        db.session.flush()

    except Exception as e:
        db.session.rollback()

        logger.error(e, extra=corId)
        return '', 500, corId

    # Return User data structure
    nd = NotDisturb(
        sunday=[], monday=[], tuesday=[], wednesday=[], thursday=[], friday=[], saturday=[]
    ).to_dict()

    user = User(
        user_id=dbUser.user_id,
        first_name=dbUser.first_name,
        last_name=dbUser.last_name,
        email=dbUser.email,
        is_active=dbUser.is_active,
        schedule_type=dbUser.settings.schedule_type,
        cpe=dbUser.cpe,
        meter_id=dbUser.meter_id,
        api_key=dbUser.api_key,
        expo_token=dbUser.expo_token,
        wp_token=dbUser.wp_token,
        country=dbUser.settings.country,
        postal_code=dbUser.settings.postal_code,
        tarif_type=dbUser.settings.tarif_type,
        contracted_power=dbUser.settings.contracted_power,
        not_disturb=nd,
        global_optimizer=dbUser.settings.global_optimizer,
        permissions=dbUser.settings.permissions,
        is_google_account=dbUser.is_google_account,
        modified_timestamp=dbUser.modified_timestamp
    )

    try:
        auth_token = dbUser.encode_auth_token()

        if auth_token:
            authorizationHeader = {
                'Authorization': "Bearer " + auth_token
            }
            headers = dict(list(corId.items()) +
                           list(authorizationHeader.items()))

            logger.info(
                f"Google User {auth_response} successfully loggedin", extra=corId)
            logResponse(endText, None, corId)

        else:
            logger.error(
                f"Failed to encode auth token: {auth_token}\n", extra=corId)
            return Error("Failed to encode auth token"), 500, corId

    except Exception as e:
        logger.error(e, extra=corId)
        return '', 500, corId

    userSchema = UserAccountSchema()
    payload = userSchema.dump(user)
    logger.info(f"payload: {payload}\n", extra=corId)

    event = DBEvent(aggregateid=uuid.uuid4(),
                    type=UserRegisteredEventType, payload=payload)
    db.session.add(event)

    event = DBEvent(aggregateid=uuid.uuid4(),
                    type=UserConfirmedEventType, payload=payload)
    db.session.add(event)

    try:
        db.session.commit()

    except Exception as e:
        db.session.rollback()

        logger.error(e, extra=corId)
        return '', 500, corId

    logger.info(f"Registered new Google account user: {dbUser}\n", extra=corId)
    logResponse(endText, user, corId)

    return user, 201, headers


def register_post():  # noqa: E501
    """Register account.

     # noqa: E501

    :param x_correlation_id: 
    :type x_correlation_id: str
    :param register_request: 
    :type register_request: dict | bytes

    :rtype: User
    """
    if connexion.request.is_json:
        register_request = RegisterRequest.from_dict(connexion.request.get_json())  # noqa: E501

    corId = {'X-Correlation-ID': connexion.request.headers["X-Correlation-ID"]}

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

    if register_request.meter_id is not None:
        res = DBUser.query.filter_by(
            meter_id=register_request.meter_id).first()
        if res is not None:
            message = "meterId " + register_request.meter_id + " already registered"
            response = Error(message)
            logErrorResponse(message, endText, response, corId)
            return response, 409, corId

    if register_request.cpe is not None:
        res = DBUser.query.filter_by(cpe=register_request.cpe).first()
        if res is not None:
            message = "cpe " + register_request.cpe + " already registered"
            response = Error(message)
            logErrorResponse(message, endText, response, corId)
            return response, 409, corId

    if register_request.password != register_request.password_repeat:
        message = "\"password\" and \"passwordRepeat\" fields do not match"
        response = Error(message)
        logErrorResponse(message, endText, response, corId)
        return response, 400, corId

    settings = DBUserSettings(country=register_request.country, postal_code=register_request.postal_code, schedule_type=register_request.schedule_type,
                              tarif_type=register_request.tarif_type, contracted_power=register_request.contracted_power, permissions="None")

    dbUser = DBUser(first_name=register_request.first_name, last_name=register_request.last_name, email=register_request.email, password=bcrypt.generate_password_hash(
        register_request.password).decode(), cpe=register_request.cpe, meter_id=register_request.meter_id, api_key=register_request.api_key, settings=settings)
    db.session.add(dbUser)

    try:
        db.session.flush()
    except Exception as e:
        db.session.rollback()
        logger.error(e, extra=corId)
        return '', 500, corId

    # Postal code event
    if register_request.postal_code is not None:
        # GARANTIR QUE EXISTE O CONTRACTED POWER
        # Fazer um erro 400 para obrigar o postal code a vir acompanhado do contracted power
        if register_request.contracted_power is not None:
            user_location = {
                "user_id": dbUser.user_id,
                "postal_code": register_request.postal_code,
                "contracted_power": float(register_request.contracted_power.split(" ")[0])
            }

            location_schema = UserLocationSchema()
            payload = location_schema.dump(user_location)

            logger.info(f"Location schema payload:\n{payload}", extra=corId)

            event = DBEvent(aggregateid=uuid.uuid4(),
                            type=UserFilledPostalCodeEventType, payload=payload)
            db.session.add(event)
            try:
                db.session.flush()
            except Exception as e:
                db.session.rollback()
                logger.error(e, extra=corId)
                return '', 500, corId
        else:
            logger.error(f"Contracted power is missing.\nWhen user fills the postal code, it MUST also fill the contracted power.\nForecast installation was NOT registered...\n", extra=corId)
            return Error("Missing contracted power"), 400, corId

    # Add new dongle api_key event
    if register_request.api_key is not None:
        # payload = set([dbUser.user_id, register_request.api_key])

        user_dongle = {
            "user_id": dbUser.user_id,
            "api_key": dbUser.api_key,
        }
        payload = user_dongle

        logger.info(
            f"User added new dongle api_key event payload:\n{payload}", extra=corId)

        event = DBEvent(aggregateid=uuid.uuid4(),
                        type=UserAddedDongleApiKeyEventType, payload=payload)
        db.session.add(event)

        try:
            db.session.flush()
        except Exception as e:
            db.session.rollback()
            logger.error(e, extra=corId)
            return '', 500, corId

    nd = NotDisturb(sunday=[], monday=[], tuesday=[], wednesday=[],
                    thursday=[], friday=[], saturday=[]).to_dict()

    user = User(user_id=dbUser.user_id, first_name=dbUser.first_name, last_name=dbUser.last_name, email=dbUser.email, is_active=dbUser.is_active, schedule_type=dbUser.settings.schedule_type,
                cpe=dbUser.cpe, meter_id=dbUser.meter_id, api_key=dbUser.api_key, country=dbUser.settings.country, postal_code=dbUser.settings.postal_code, tarif_type=dbUser.settings.tarif_type,
                contracted_power=dbUser.settings.contracted_power, not_disturb=nd, global_optimizer=dbUser.settings.global_optimizer, permissions=dbUser.settings.permissions, is_google_account=dbUser.is_google_account, modified_timestamp=dbUser.modified_timestamp)

    userSchema = UserAccountSchema()
    payload = userSchema.dump(user)

    logger.info(f"payload: {payload}\n", extra=corId)

    event = DBEvent(aggregateid=uuid.uuid4(),
                    type=UserRegisteredEventType, payload=payload)
    db.session.add(event)

    userRegisteredNotificationSchema = UserRegisteredNotificationSchema()

    notification = {
        "notification": "User created."
    }

    payload = userRegisteredNotificationSchema.dump(notification)

    notification = DBEvent(aggregateid=uuid.uuid4(),
                           type=UserRegisteredNotificationType, payload=payload)
    db.session.add(notification)

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(e, extra=corId)
        return '', 500, corId

    logger.info("Registed new user", extra=corId)
    logger.info(dbUser, extra=corId)
    logResponse(endText, user, corId)

    return user, 201, corId


def user_delete(user_id, delete_type):  # noqa: E501
    """Delete user.

     # noqa: E501

    :param x_correlation_id: 
    :type x_correlation_id: str
    :param user_id: 
    :type user_id: str
    :param delete_type: 
    :type delete_type: dict | bytes
    :param authorization: 
    :type authorization: str

    :rtype: None
    """
    corId = {'X-Correlation-ID': connexion.request.headers["X-Correlation-ID"]}

    logger.info("Processing DELETE /user request", extra=corId)
    endText = "Processed DELETE /user request"

    auth_response, auth_response_code = auth.verify_basic_authorization(
        connexion.request.headers)

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
        user = DBUser.query.filter_by(
            user_id=auth_response, deleted=False).first()

        if user is None:
            logger.error("Authorization token valid but user_id " +
                         user_id + " not found", extra=corId)
            message = "invalid credentials"
            response = Error(message)
            logErrorResponse(message, endText, response, corId)
            return response, 401, corId

        if user.user_id != user_id:
            logger.error(
                "User " + user.user_id + " does not have permission to delete the user " + user_id, extra=corId)
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

    if delete_type == DeleteType.SOFT:
        if userDb.deleted == True:
            message = "user with user_id " + user_id + " not found"
            response = Error(message)
            logErrorResponse(message, endText, response, corId)
            return response, 404, corId
        else:
            userDb.deleted = True

            try:
                db.session.flush()
            except Exception as e:
                db.session.rollback()
                logger.error(e, extra=corId)
                return '', 500, corId

            eventType = UserSoftDeletedEventType
    elif delete_type == DeleteType.HARD:
        settings = DBUserSettings.query.filter_by(user_id=user_id).first()
        DBNotDisturb.query.filter_by(settings_id=settings.id).delete()
        DBUserSettings.query.filter_by(user_id=user_id).delete()
        DBUser.query.filter_by(user_id=user_id).delete()
        eventType = UserHardDeletedEventType

    not_disturb = {"sunday": [], "monday": [], "tuesday": [],
                   "wednesday": [], "thursday": [], "friday": [], "saturday": []}
    for nd in userDb.settings.not_disturb:
        not_disturb[nd.day_of_week].append(
            PeriodOfDay(nd.start_timestamp, nd.end_timestamp))

    response = User(user_id=userDb.user_id, first_name=userDb.first_name, last_name=userDb.last_name, email=userDb.email, is_active=userDb.is_active, schedule_type=userDb.settings.schedule_type,
                    cpe=userDb.cpe, meter_id=userDb.meter_id, api_key=userDb.api_key, country=userDb.settings.country, postal_code=userDb.settings.postal_code, tarif_type=userDb.settings.tarif_type,
                    contracted_power=userDb.settings.contracted_power, not_disturb=not_disturb, global_optimizer=userDb.settings.global_optimizer, permissions=userDb.settings.permissions, is_google_account=userDb.is_google_account, modified_timestamp=userDb.modified_timestamp)

    userSchema = UserAccountSchema()
    payload = userSchema.dump(response)

    logger.info(f"payload: {payload}\n", extra=corId)

    event = DBEvent(aggregateid=uuid.uuid4(),
                    type=eventType, payload=payload)
    db.session.add(event)
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(e, extra=corId)
        return '', 500, corId

    return '', 200, corId


def list_dongles_get():  # noqa: E501
    """Get information about dongles from users

     # noqa: E501

    :param x_correlation_id: 
    :type x_correlation_id: 

    :rtype: List[Dongles]
    """
    corId = {'X-Correlation-ID': connexion.request.headers["X-Correlation-ID"]}

    logger.info("Processing GET /dongles-list request", extra=corId)
    endText = "Processed GET /dongles-list request"

    users = DBUser.query.filter(
        DBUser.deleted == False, DBUser.api_key != None)
    response = []
    for user in users:
        response.append(Dongles(user.user_id, user.api_key))

    logResponse(endText, response, corId)

    # return response, 401, corId

    return response, 200, corId


def user_get(user_ids):

    corId = {'X-Correlation-ID': connexion.request.headers["X-Correlation-ID"]}

    logger.info("Processing GET /user request", extra=corId)
    endText = "Processed GET /user request"

    my_set = set(user_ids)
    user_ids = list(my_set)

    auth_response, auth_response_code = auth.verify_basic_authorization(
        connexion.request.headers)

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

    else:
        user_id = auth_response

    if auth_response is not None:
        user = DBUser.query.filter_by(
            user_id=auth_response, deleted=False).first()

        if user is None:

            logger.error(
                f"Authorization token valid but user_id {user_id} not found", extra=corId)
            message = "invalid credentials"
            response = Error(message)

            logErrorResponse(message, endText, response, corId)
            return response, 401, corId

        for uId in user_ids:
            if uId != user.user_id:

                logger.error(
                    f"User {user.user_id} does not have permission to see user {uId}",
                    extra=corId
                )
                message = "no permission"
                response = Error(message)

                logErrorResponse(message, endText, response, corId)
                return response, 403, corId

    response = []
    for uId in user_ids:

        user = DBUser.query.filter_by(user_id=uId, deleted=False).first()
        if user is None:

            logger.error(f"User with user_id {uId} not found", extra=corId)
            message = "User not found"
            response = Error(message)

            logErrorResponse(message, endText, response, corId)
            return response, 404, corId

        not_disturb = {
            "sunday": [], "monday": [], "tuesday": [], "wednesday": [],
            "thursday": [], "friday": [], "saturday": []
        }

        for nd in user.settings.not_disturb:
            not_disturb[nd.day_of_week].append(
                PeriodOfDay(nd.start_timestamp, nd.end_timestamp))

        response.append(User(
            user_id=user.user_id,
            first_name=user.first_name,
            last_name=user.last_name,
            email=user.email,
            is_active=user.is_active,
            schedule_type=user.settings.schedule_type,
            cpe=user.cpe,
            meter_id=user.meter_id,
            api_key=user.api_key,
            expo_token=user.expo_token,
            wp_token=user.wp_token,
            country=user.settings.country,
            postal_code=user.settings.postal_code,
            tarif_type=user.settings.tarif_type,
            contracted_power=user.settings.contracted_power,
            not_disturb=not_disturb,
            global_optimizer=user.settings.global_optimizer,
            permissions=user.settings.permissions,
            is_google_account=user.is_google_account,
            modified_timestamp=user.modified_timestamp
        ))

    logResponse(endText, response, corId)

    return response, 200, corId


def user_list_get():  # noqa: E501
    """Retrieve list of all users ids

     # noqa: E501

    :param x_correlation_id: 
    :type x_correlation_id: str
    :param authorization: 
    :type authorization: str

    :rtype: List[str]
    """
    corId = {'X-Correlation-ID': connexion.request.headers["X-Correlation-ID"]}

    logger.info("Processing GET /user-list request", extra=corId)
    endText = "Processed GET /user-list request"

    auth_response, auth_response_code = auth.verify_basic_authorization(
        connexion.request.headers)

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
        logger.error(
            "User " + auth_response + " does not have permission to see user list", extra=corId)
        message = "no permission"
        response = Error(message)
        logErrorResponse(message, endText, response, corId)
        return response, 403, corId

    users = DBUser.query.all()
    response = []
    for user in users:
        response.append(user.user_id)

    logResponse(endText, response, corId)

    return response, 200, corId


def user_post():
    if connexion.request.is_json:
        userReq = User.from_dict(connexion.request.get_json())  # noqa: E501

    corId = {'X-Correlation-ID': connexion.request.headers["X-Correlation-ID"]}

    logger.info("Processing POST /user request", extra=corId)
    endText = "Processed POST /user request"

    # -------------------- Verify user authentication -------------------- #

    auth_response, auth_response_code = auth.verify_basic_authorization(
        connexion.request.headers)

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
        user = DBUser.query.filter_by(
            user_id=auth_response, deleted=False).first()

        if user is None:

            logger.error(
                f"Authorization token valid but user_id {user_id} not found", extra=corId)
            message = "invalid credentials"
            response = Error(message)

            logErrorResponse(message, endText, response, corId)
            return response, 401, corId

        if user.user_id != userReq.user_id:

            logger.error(
                f"User {user.user_id} does not have permission to update the user {userReq.user_id}",
                extra=corId
            )
            message = "no permission"
            response = Error(message)

            logErrorResponse(message, endText, response, corId)
            return response, 403, corId

    # -------------------- User does not exist in db -------------------- #

    userDb = DBUser.query.filter_by(
        user_id=userReq.user_id, deleted=False).first()
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
            end_timestamp=key.end_timestamp
        )
        nds.append(nd)

    for key in userReq.not_disturb.monday:
        nd = DBNotDisturb(
            day_of_week="monday",
            start_timestamp=key.start_timestamp,
            end_timestamp=key.end_timestamp
        )
        nds.append(nd)

    for key in userReq.not_disturb.tuesday:
        nd = DBNotDisturb(
            day_of_week="tuesday",
            start_timestamp=key.start_timestamp,
            end_timestamp=key.end_timestamp
        )
        nds.append(nd)

    for key in userReq.not_disturb.wednesday:
        nd = DBNotDisturb(
            day_of_week="wednesday",
            start_timestamp=key.start_timestamp,
            end_timestamp=key.end_timestamp
        )
        nds.append(nd)

    for key in userReq.not_disturb.thursday:
        nd = DBNotDisturb(
            day_of_week="thursday",
            start_timestamp=key.start_timestamp,
            end_timestamp=key.end_timestamp
        )
        nds.append(nd)

    for key in userReq.not_disturb.friday:
        nd = DBNotDisturb(
            day_of_week="friday",
            start_timestamp=key.start_timestamp,
            end_timestamp=key.end_timestamp
        )
        nds.append(nd)

    for key in userReq.not_disturb.saturday:
        nd = DBNotDisturb(
            day_of_week="saturday",
            start_timestamp=key.start_timestamp,
            end_timestamp=key.end_timestamp
        )
        nds.append(nd)

    # TODO: Remove this when deprecating CPE
    # -------------------- CPE already exists -------------------- #

    if userReq.cpe is not None:
        userAux = DBUser.query.filter_by(
            cpe=userReq.cpe, deleted=False).first()

        if userAux is not None:
            if userAux.user_id != userReq.user_id:

                message = f"cpe {userReq.cpe} already registered"
                response = Error(message)

                logErrorResponse(message, endText, response, corId)
                return response, 409, corId

    # -------------------- Meter ID already exists -------------------- #

    if userReq.meter_id is not None:
        userAux = DBUser.query.filter_by(
            meter_id=userReq.meter_id, deleted=False).first()

        if userAux is not None:
            if userAux.user_id != userReq.user_id:

                message = f"meter_id {userReq.meter_id} already registered"
                response = Error(message)

                logErrorResponse(message, endText, response, corId)
                return response, 409, corId

    # Postal code event -> Everytime there is a change in the postal code
    if userDb.settings.postal_code != userReq.postal_code:
        if userReq.contracted_power is not None:

            user_location = {
                "user_id": userReq.user_id,
                "postal_code": userReq.postal_code,
                "contracted_power": float(userReq.contracted_power.split(" ")[0])
            }

            location_schema = UserLocationSchema()
            payload = location_schema.dump(user_location)

            logger.info(f"Location schema payload:\n{payload}", extra=corId)

            event = DBEvent(
                aggregateid=uuid.uuid4(), type=UserFilledPostalCodeEventType, payload=payload
            )
            db.session.add(event)

            try:
                db.session.flush()

            except Exception as e:
                db.session.rollback()
                logger.error(e, extra=corId)
                return '', 500, corId

        else:
            logger.error(
                f"Contracted power is missing.\n"
                f"When user fills the postal code, it MUST also fill the contracted power.\n"
                f"Forecast installation was NOT registered...\n",
                extra=corId
            )

            return Error("Missing contracted power"), 400, corId

    # Update dongle api_key event
    if userDb.api_key != userReq.api_key:

        user_dongle = {
            "user_id": userReq.user_id,
            "api_key": userReq.api_key,
        }
        payload = user_dongle

        logger.info(
            f"User updated a dongle api_key event payload:\n{payload}", extra=corId)

        event = DBEvent(
            aggregateid=uuid.uuid4(), type=UserUpdatedDongleApiKeyEventType, payload=payload
        )
        db.session.add(event)

        try:
            db.session.flush()

        except Exception as e:
            db.session.rollback()
            logger.error(e, extra=corId)
            return '', 500, corId

    # -------------------- Update USER in DB -------------------- #

    userDb.first_name = userReq.first_name
    userDb.last_name = userReq.last_name
    userDb.cpe = userReq.cpe
    userDb.meter_id = userReq.meter_id
    userDb.api_key = userReq.api_key
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
        userDb.cpe is not None,
        userDb.meter_id is not None,
        userDb.settings.schedule_type is not None,
        userDb.settings.postal_code is not None,
        userDb.settings.tarif_type is not None,
        userDb.settings.contracted_power is not None
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
        return '', 500, corId

    # -------------------- Return User Data Structure -------------------- #

    not_disturb = {
        "sunday": [], "monday": [], "tuesday": [], "wednesday": [],
        "thursday": [], "friday": [], "saturday": []
    }

    for nd in userDb.settings.not_disturb:
        not_disturb[nd.day_of_week].append(
            PeriodOfDay(nd.start_timestamp, nd.end_timestamp))

    response = User(
        user_id=userDb.user_id,
        first_name=userDb.first_name,
        last_name=userDb.last_name,
        email=userDb.email,
        is_active=userDb.is_active,
        schedule_type=userDb.settings.schedule_type,
        cpe=userDb.cpe,
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
        modified_timestamp=userDb.modified_timestamp
    )

    # User Update Event
    userSchema = UserAccountSchema()
    payload = userSchema.dump(response)

    logger.info(f"payload: {payload}\n", extra=corId)

    event = DBEvent(aggregateid=uuid.uuid4(),
                    type=UserUpdatedEventType, payload=payload)
    db.session.add(event)

    try:
        db.session.commit()

    except Exception as e:
        db.session.rollback()
        logger.error(e, extra=corId)
        return '', 500, corId

    logResponse(endText, response, corId)

    return response, 200, corId


def sendForgotPasswordEmail(user_id, email, corId):
    # Create forgot password token
    m = hashlib.sha256()
    m.update(uuid.uuid4().bytes)
    m.hexdigest()

    try:
        DBForgotPasswordToken.query.filter_by(user_id=user_id).delete()
    except Exception as e:
        generalLogger.info(e)

    forgotPasswordToken = DBForgotPasswordToken(user_id=user_id, token=m.hexdigest(
    ), expiration_timestamp=datetime.now(timezone.utc) + timedelta(seconds=Config.CONFIRMATION_TOKEN_EXPIRATION_TIME_SECONDS))

    db.session.add(forgotPasswordToken)
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(e, extra=corId)
        return False

    success = True
    if Config.GITLAB_CI_TEST == 'False' and Config.EMAIL is not None and Config.EMAIL_PASSWORD is not None:
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
                "Failed to open secure tls connection to SMTP mail client...")
            return False

        sender_email = Config.EMAIL
        try:
            server.login(sender_email, Config.EMAIL_PASSWORD)
            generalLogger.info("Login.. OK!")

            # Create a multipart message and set headers
            receiver_email = email

            message = MIMEMultipart()
            message["From"] = formataddr(
                (str(Header('Aplicação InterConnect', 'utf-8')), sender_email))
            message["To"] = receiver_email
            message["Subject"] = "Reset de password na aplicação do projeto InterConnect"

            link = "https://interconnect-dev.inesctec.pt/api/account/forgot-password/" + m.hexdigest()

            # For local test
            # link = "http://127.0.0.1:8080/api/account/forgot-password/" + m.hexdigest()

            f = open("account_manager/templates/email-reset.html",
                     "r", encoding="utf-8")
            body = f.read()
            f.close()
            body_aux = body.replace("LINK_LINK", link)

            f = open(
                "account_manager/static/img/INESCTECLogotipo_CORPositivo_RGB.png", "rb")
            inesc_logo = f.read()
            f.close()

            message.attach(MIMEText(body_aux, "html", "utf-8"))
            img = MIMEImage(inesc_logo)
            img.add_header(
                'Content-ID', "INESCTECLogotipo_CORPositivo_RGB.png")
            message.attach(img)

            text = message.as_string()

            server.sendmail(sender_email, receiver_email, text)

            generalLogger.info(
                "Successfully sent email with reset password link to " + email)
            success = True
        except Exception as e:
            # Print any error messages to stdout
            generalLogger.error(
                "Error in sending email with reset password link to " + email)
            generalLogger.error(e)
            success = False
        finally:
            server.quit()
            generalLogger.info("Quit... OK!")

    return success
