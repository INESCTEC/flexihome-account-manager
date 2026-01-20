import connexion

from account_manager.models.change_password_request import (
    ChangePasswordRequest,
)  # noqa: E501
from account_manager.models.error import Error  # noqa: E501
from account_manager.models.forgot_password_request import (
    ForgotPasswordRequest,
)  # noqa: E501
from account_manager.models.user import User  # noqa: E501

from account_manager.models.dbmodels import (
    db,
    DBUser,
    DBForgotPasswordToken,
    DBEvent,
)
from account_manager.models.period_of_day import PeriodOfDay
from account_manager.models.events import (
    UserAccountSchema,
    UserConfirmedEventType,
)
from account_manager import logger, generalLogger, Config, bcrypt, auth, app

from flask import render_template

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

    :rtype: None
    """
    if connexion.request.is_json:
        change_password_request = ChangePasswordRequest.from_dict(
            connexion.request.get_json()
        )  # noqa: E501

    corId = {"X-Correlation-ID": connexion.request.headers["X-Correlation-ID"]}

    logger.info("Processing POST /change-password request", extra=corId)
    endText = "Processed POST /change-password request"

    if (
        change_password_request.new_password
        != change_password_request.new_password_repeat
    ):
        message = '"new_password" and "new_password_repeat" fields do not match'
        response = Error(message)
        logErrorResponse(message, endText, response, corId)
        return response, 400, corId

    if change_password_request.new_password == change_password_request.old_password:
        message = '"new_password" and "old_password" fields cannot be equal'
        response = Error(message)
        logErrorResponse(message, endText, response, corId)
        return response, 400, corId

    auth_response, auth_response_code = auth.verify_basic_authorization(
        connexion.request.headers
    )

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
        logger.error(
            "Authorization token valid but user_id " + response + " not found",
            extra=corId,
        )
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
        if bcrypt.check_password_hash(
            user.password, change_password_request.old_password
        ):
            user.password = bcrypt.generate_password_hash(
                change_password_request.new_password
            ).decode()
            try:
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                logger.error(e, extra=corId)
                return "", 500, corId

            logger.info(
                "User " + user.user_id + " successfully changed password", extra=corId
            )
            logResponse(endText, None, corId)
            return "", 200, corId
        else:
            logger.error(
                "old_password does not match with saved password for user with email "
                + user.email,
                extra=corId,
            )
            message = "old_password does not match with saved password"
            response = Error(message)
            logErrorResponse(message, endText, response, corId)
            return response, 401, corId

    except Exception as e:
        logger.error(e, extra=corId)
        return "", 500, corId

    # This code should neve


def forgot_password_post():  # noqa: E501
    """Forgot password

     # noqa: E501


    :rtype: None
    """
    if connexion.request.is_json:
        forgot_password_request = ForgotPasswordRequest.from_dict(
            connexion.request.get_json()
        )  # noqa: E501

    corId = {"X-Correlation-ID": connexion.request.headers["X-Correlation-ID"]}

    logger.info("Processing POST /forgot-password request", extra=corId)
    endText = "Processed POST /forgot-password request"

    email = forgot_password_request.email
    try:
        user = DBUser.query.filter_by(email=email, deleted=False).first()
        if user:
            if user.is_google_account is False:
                success = sendForgotPasswordEmail(user.user_id, user.email, corId)
                if success is True:
                    logger.info(
                        "Sucessfully sent forgot-password email to user with email "
                        + email,
                        extra=corId,
                    )
                else:
                    logger.error(
                        "Failed to send forgot-password email to user with email "
                        + email,
                        extra=corId,
                    )
                logResponse(endText, None, corId)
            else:
                message = "User with email" + email + " is a google account"
                logErrorResponse(message, endText, None, corId)
        else:
            message = "User with email" + email + " not found"
            logErrorResponse(message, endText, None, corId)

        # So that user enumeration (vulnerability) does not occur, send the same response if the user exists or does not exist
        # The answer in the aplication should be: if the user is registered in the platform, an email was sent
        return "", 200, corId

    except Exception as e:
        message = (
            "Exception caught while processing forgot-password request for user with email "
            + email
        )
        logger.error(e, extra=corId)
        logErrorResponse(message, endText, None, corId)
        return "", 500, corId


@app.route('/api/account/forgot-password/<token>', methods=['GET'])
def forgot_password_token_get(token):  # noqa: E501
    """Endpoint to get the webpage with the form to reset password by clicking the link sent to the e-mail.

     # noqa: E501

    :param token:
    :type token: str

    :rtype: None
    """
    corId = {"X-Correlation-ID": "confirmation-token-" + token}
    logger.info("Processing GET /forgot-password/{{token}} request", extra=corId)
    endText = "Processed GET /forgot-password/{{token}} request"

    data = DBForgotPasswordToken.query.filter_by(token=token).first()
    if data is None:
        message = "forgot-password token " + token + " not found"
        response = Error(message)
        logErrorResponse(message, endText, response, corId)
        return render_template("forgot-password.html", reset_not_found=True), 404

    if data.expiration_timestamp.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        message = "forgot-password token " + token + " expired"
        response = Error(message)
        logErrorResponse(message, endText, response, corId)
        return render_template("forgot-password.html", reset_expired=True), 404

    user = DBUser.query.filter_by(user_id=data.user_id, deleted=False).first()
    if user is None:
        logger.error(
            "forgot-password token valid but user_id " + data.user_id + " not found",
            extra=corId,
        )
        message = "forgot-password token not found"
        response = Error(message)
        logErrorResponse(message, endText, response, corId)
        return render_template("forgot-password.html", reset_not_found=True), 404

    logger.info("Sending webpage to reset password for token " + token, extra=corId)
    logResponse(endText, None, corId)

    return render_template("forgot-password.html", my_token=token, reset=True)


@app.route('/api/account/forgot-password/<token>', methods=['POST'])
def forgot_password_token_post(token):  # noqa: E501
    """Endpoint to set the new password. This endpoint will be used by the webpage to reset the password (get endpoint of this request).

     # noqa: E501

    :param token:
    :type token: str

    :rtype: None
    """
    new_password = connexion.request.form.get("new_password")
    new_password_repeat = connexion.request.form.get("new_password_repeat")

    corId = {"X-Correlation-ID": "forgot-password-" + token}
    logger.info("Processing POST /forgot-password{{token}} request", extra=corId)
    endText = "Processed POST /forgot-password/{{token}} request"

    data = DBForgotPasswordToken.query.filter_by(token=token).first()
    if data is None:
        message = "forgot-password token " + token + " not found"
        response = Error(message)
        logErrorResponse(message, endText, response, corId)
        return render_template("forgot-password.html", reset_not_found=True), 404

    if data.expiration_timestamp.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        message = "forgot-password token " + token + " expired"
        response = Error(message)
        logErrorResponse(message, endText, response, corId)
        return render_template("forgot-password.html", reset_expired=True), 404

    if new_password != new_password_repeat:
        message = "passwords fields do not match"
        response = Error(message)
        logErrorResponse(message, endText, response, corId)
        return (
            render_template("forgot-password.html", reset_passwords_not_match=True),
            400,
        )

    user = DBUser.query.filter_by(user_id=data.user_id, deleted=False).first()
    if user is None:
        logger.error(
            "forgot-password token valid but user_id " + data.user_id + " not found",
            extra=corId,
        )
        message = "forgot-password token not found"
        response = Error(message)
        logErrorResponse(message, endText, response, corId)
        return render_template("forgot-password.html", reset_not_found=True), 404

    if bcrypt.check_password_hash(user.password, new_password):
        message = "old password is equal to the new password"
        response = Error(message)
        logErrorResponse(message, endText, response, corId)
        return (
            render_template(
                "forgot-password.html", reset_password_equal_old_password=True
            ),
            400,
        )

    DBForgotPasswordToken.query.filter_by(user_id=data.user_id).delete()

    wasActive = user.is_active

    user.password = bcrypt.generate_password_hash(new_password).decode()
    user.is_active = True

    try:
        db.session.flush()
    except Exception as e:
        db.session.rollback()
        logger.error(e, extra=corId)
        return "", 500, corId

    if wasActive is False:
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
        "Successfully updated password for account with user_id "
        + user.user_id
        + " and email "
        + user.email,
        extra=corId,
    )
    logResponse(endText, None, corId)

    return render_template("forgot-password.html", reset_sucess=True)


def sendForgotPasswordEmail(user_id, email, corId):
    # Create forgot password token
    m = hashlib.sha256()
    m.update(uuid.uuid4().bytes)
    m.hexdigest()

    try:
        DBForgotPasswordToken.query.filter_by(user_id=user_id).delete()
    except Exception as e:
        generalLogger.info(e)

    forgotPasswordToken = DBForgotPasswordToken(
        user_id=user_id,
        token=m.hexdigest(),
        expiration_timestamp=datetime.now(timezone.utc)
        + timedelta(seconds=Config.CONFIRMATION_TOKEN_EXPIRATION_TIME_SECONDS),
    )

    db.session.add(forgotPasswordToken)
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
            ] = "Reset de password na aplicação do projeto InterConnect"

            link = (
                "https://interconnect-dev.inesctec.pt/api/account/forgot-password/"
                + m.hexdigest()
            )

            # For local test
            # link = "http://127.0.0.1:8080/api/account/forgot-password/" + m.hexdigest()

            f = open(
                "account_manager/templates/email-reset.html", "r", encoding="utf-8"
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
                "Successfully sent email with reset password link to " + email
            )
            success = True
        except Exception as e:
            # Print any error messages to stdout
            generalLogger.error(
                "Error in sending email with reset password link to " + email
            )
            generalLogger.error(e)
            success = False
        finally:
            server.quit()
            generalLogger.info("Quit... OK!")

    return success
