import connexion

from account_manager.models.error import Error  # noqa: E501
from account_manager.models.google_user_register_request import (
    GoogleUserRegisterRequest,
)  # noqa: E501
from account_manager.models.login_request import LoginRequest  # noqa: E501
from account_manager.models.user import User  # noqa: E501

from account_manager.models.dbmodels import (
    db,
    DBUser,
    DBUserSettings,
    DBEvent,
)
from account_manager.models.not_disturb import NotDisturb
from account_manager.models.period_of_day import PeriodOfDay
from account_manager.models.events import (
    UserAccountSchema,
    UserRegisteredEventType,
    UserConfirmedEventType,
)
from account_manager import logger, bcrypt, auth

import uuid


def logErrorResponse(error, endText, response, corId):
    logger.error(error, extra=corId)
    logResponse(endText, response, corId)


def logResponse(endText, response, corId):
    logger.info(endText, extra=corId)
    if response is not None:
        logger.debug("Sending the following response: ", extra=corId)
        logger.debug(response, extra=corId)


def login_post():  # noqa: E501
    """Login

     # noqa: E501

    :rtype: None
    """
    if connexion.request.is_json:
        login_request = LoginRequest.from_dict(
            connexion.request.get_json()
        )  # noqa: E501

    corId = {"X-Correlation-ID": connexion.request.headers["X-Correlation-ID"]}

    try:
        expo_token = connexion.request.headers["expo-token"]
    except KeyError:
        logger.warning(
            f"User {login_request.email} login has no expo token.", extra=corId
        )
        expo_token = None

    logger.info("Processing POST /login request", extra=corId)
    endText = "Processed POST /login request"

    try:
        user = DBUser.query.filter_by(
            email=login_request.email, deleted=False).first()
        
        logger.info(user, extra=corId)

        # ----------------- User exists ----------------- #
        if user:
            
            logger.info("user exists", extra=corId)

            # ----------------- Confirmed account ----------------- #
            if user.is_active is True:
                
                logger.info("account active", extra=corId)

                # ------ Google accounts use /register-google endpoint ------ #
                if user.is_google_account is False:
                    
                    logger.info("not a google account", extra=corId)

                    if bcrypt.check_password_hash(
                        user.password, login_request.password
                    ):
                        
                        logger.info("password is correct", extra=corId)
                        
                        auth_token = user.encode_auth_token()
                        
                        logger.info(f"token encoded: {auth_token}", extra=corId)

                        # ----------------- Successful Login ----------------- #
                        if auth_token:
                            
                            logger.info("login success", extra=corId)

                            authorizationHeader = {
                                "Authorization": "Bearer " + auth_token
                            }
                            headers = dict(
                                list(corId.items()) +
                                list(authorizationHeader.items())
                            )

                            logger.info(
                                f"User {login_request.email} successfully loggedin",
                                extra=corId,
                            )

                            if expo_token is not None:
                                user.expo_token = expo_token
                                logger.debug(
                                    f"User logged in with expo token: {user.expo_token}",
                                    extra=corId,
                                )

                                db.session.flush()
                                db.session.commit()

                            logResponse(endText, None, corId)
                            return "", 200, headers

                    else:
                        logger.error(
                            f"Wrong password for user with email {login_request.email}",
                            extra=corId,
                        )

                        message = "invalid credentials"
                        response = Error(message)
                        logErrorResponse(message, endText, response, corId)

                        return response, 401, corId

                else:
                    logger.error(
                        f"User with email {login_request.email} is associated with a google account.\n"
                        f"The login must be made through the google integration button.",
                        extra=corId,
                    )

                    message = "Account is associated with Google"
                    response = Error(message)
                    logErrorResponse(message, endText, response, corId)

                    return response, 400, corId

            else:
                logger.error(
                    f"User with email {login_request.email} did not activate its account",
                    extra=corId,
                )

                message = "invalid credentials"
                response = Error(message)
                logErrorResponse(message, endText, response, corId)

                return response, 401, corId

        else:
            logger.error(
                f"User with email {login_request.email} not found", extra=corId
            )

            message = "invalid credentials"
            response = Error(message)
            logErrorResponse(message, endText, response, corId)

            return response, 401, corId

    except Exception as e:
        logger.error(e, extra=corId)
        return Error(repr(e)), 500, corId

    # This code should never be reached
    return "", 500, corId


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

    auth_response, auth_response_code = auth.blacklist_token(
        connexion.request.headers)

    if auth_response_code != 200:
        logger.error(
            f"Could not decode authorization token {auth_response}", extra=corId)
        message = "invalid credentials"
        response = Error(message)

        logErrorResponse(message, endText, response, corId)
        return response, auth_response_code, corId

    logger.info("Logged out user with user_id " + user_id, extra=corId)
    logResponse(endText, None, corId)

    return '', 200, corId


def refresh_token_post():  # noqa: E501
    """Refresh authentication token (needed if the token is about to expire)

     # noqa: E501

    :rtype: None
    """
    corId = {"X-Correlation-ID": connexion.request.headers["X-Correlation-ID"]}

    logger.info("Processing POST /refresh-token request", extra=corId)
    endText = "Processed POST /refresh-token request"

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
    else:
        user_id = auth_response

    if auth_response is not None:
        user = DBUser.query.filter_by(
            user_id=auth_response, deleted=False).first()

        if user is None:
            logger.error(
                "Authorization token valid but user_id " + user_id + " not found",
                extra=corId,
            )
            message = "invalid credentials"
            response = Error(message)
            logErrorResponse(message, endText, response, corId)
            return response, 401, corId

    try:
        newToken = user.encode_auth_token()
    except Exception as e:
        logger.error(e, extra=corId)
        return "", 500, corId

    if newToken is None:
        # This code should never be reached
        return "", 500, corId

    authorizationHeader = {"Authorization": "Bearer " + newToken}
    headers = dict(list(corId.items()) + list(authorizationHeader.items()))
    logger.info(
        "User " + user.user_id + " successfully refreshed authorization token",
        extra=corId,
    )
    logResponse(endText, None, corId)
    return "", 200, headers


def register_google_post():  # noqa: E501
    """Register/Login user with google account

     # noqa: E501

    :rtype: None
    """
    if connexion.request.is_json:
        google_user_register_request = GoogleUserRegisterRequest.from_dict(
            connexion.request.get_json()
        )  # noqa: E501

    corId = {"X-Correlation-ID": connexion.request.headers["X-Correlation-ID"]}

    try:
        expo_token = connexion.request.headers["expo-token"]
    except KeyError:
        logger.warning(
            f"User {google_user_register_request.email} login has no expo token.",
            extra=corId,
        )
        expo_token = None

    logger.info("Processing POST /register request", extra=corId)
    endText = "Processed POST /register request"

    # ------------------------------ AUTHORIZATION PART ------------------------------ #

    auth_response, auth_response_code = auth.verify_google_authorization(
        connexion.request.headers
    )

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
        if user.deleted == True:
            logger.error(f"Deleted user trying to login with google: {user.user_id}\n", extra=corId)
            return Error("User is deleted"), 400, corId

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
            modified_timestamp=user.modified_timestamp,
        )

        try:
            auth_token = user.encode_auth_token()

            if auth_token:
                authorizationHeader = {"Authorization": "Bearer " + auth_token}
                headers = dict(list(corId.items()) +
                               list(authorizationHeader.items()))
                logger.info(
                    f"Google User {auth_response} successfully loggedin", extra=corId
                )

                if expo_token is not None:
                    user.expo_token = expo_token
                    logger.debug(
                        f"User logged in with expo token: {user.expo_token}",
                        extra=corId,
                    )

                    db.session.flush()
                    db.session.commit()

                logResponse(endText, None, corId)
                return "", 200, headers

            else:
                logger.error(
                    f"Failed to encode auth token: {auth_token}\n", extra=corId
                )

                return Error("Failed to encode auth token"), 500, corId

        except Exception as e:
            logger.error(e, extra=corId)
            return "", 500, corId

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
        settings=settings,
    )

    db.session.add(dbUser)
    try:
        db.session.flush()

    except Exception as e:
        db.session.rollback()

        logger.error(e, extra=corId)
        return "", 500, corId

    # Return User data structure
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
        modified_timestamp=dbUser.modified_timestamp,
    )

    try:
        auth_token = dbUser.encode_auth_token()

        if auth_token:
            authorizationHeader = {"Authorization": "Bearer " + auth_token}
            headers = dict(list(corId.items()) +
                           list(authorizationHeader.items()))

            logger.info(
                f"Google User {auth_response} successfully loggedin", extra=corId
            )
            logResponse(endText, None, corId)

        else:
            logger.error(
                f"Failed to encode auth token: {auth_token}\n", extra=corId)
            return Error("Failed to encode auth token"), 500, corId

    except Exception as e:
        logger.error(e, extra=corId)
        return "", 500, corId

    userSchema = UserAccountSchema()
    payload = userSchema.dump(user)
    logger.info(f"payload: {payload}\n", extra=corId)

    event = DBEvent(
        aggregateid=uuid.uuid4(), type=UserRegisteredEventType, payload=payload
    )
    db.session.add(event)

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

    logger.info(f"Registered new Google account user: {dbUser}\n", extra=corId)
    logResponse(endText, user, corId)

    return user, 201, headers
