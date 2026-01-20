import connexion

from account_manager.models.error import Error  # noqa: E501
from account_manager.models.dongles import Dongles  # noqa: E501
from account_manager.models.meter_id_to_user_id import MeterIdToUserId  # noqa: E501
from account_manager.models.user import User  # noqa: E501
from account_manager.models.deleted_user import DeletedUser

from account_manager.models.dbmodels import DBUser
from account_manager.models.period_of_day import PeriodOfDay
from account_manager import logger, auth



def logErrorResponse(error, endText, response, corId):
    logger.error(error, extra=corId)
    logResponse(endText, response, corId)


def logResponse(endText, response, corId):
    logger.info(endText, extra=corId)
    if response is not None:
        logger.debug("Sending the following response: ", extra=corId)
        logger.debug(response, extra=corId)


def list_dongles_get():  # noqa: E501
    """Get information about dongles from users

     # noqa: E501


    :rtype: List[Dongles]
    """
    corId = {"X-Correlation-ID": connexion.request.headers["X-Correlation-ID"]}

    logger.info("Processing GET /dongles-list request", extra=corId)
    endText = "Processed GET /dongles-list request"

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
        logger.error(
            "User " + auth_response + " does not have permission to see meter ids list",
            extra=corId,
        )
        message = "no permission"
        response = Error(message)
        logErrorResponse(message, endText, response, corId)
        return response, 403, corId

    users = DBUser.query.filter(DBUser.deleted == False, DBUser.api_key != None)
    response = []
    for user in users:
        response.append(Dongles(user.user_id, user.api_key))

    logResponse(endText, response, corId)

    # return response, 401, corId

    return response, 200, corId


def list_meter_ids_get():  # noqa: E501
    """Get information about meter ids from users

     # noqa: E501

    :param x_correlation_id: 
    :type x_correlation_id: str
    :type x_correlation_id: str

    :rtype: Union[List[str], Tuple[List[str], int], Tuple[List[str], int, Dict[str, str]]
    """
    corId = {'X-Correlation-ID': connexion.request.headers["X-Correlation-ID"]}

    logger.info("Processing GET /dongles-list request", extra=corId)
    endText = "Processed GET /dongles-list request"

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
        logger.error(
            "User " + auth_response + " does not have permission to see meter ids list",
            extra=corId,
        )
        message = "no permission"
        response = Error(message)
        logErrorResponse(message, endText, response, corId)
        return response, 403, corId

    users = DBUser.query.filter(
        DBUser.deleted == False, DBUser.meter_id != None)
    response = []
    for user in users:
        response.append(user.meter_id)

    logResponse(endText, response, corId)

    # return response, 401, corId

    return response, 200, corId


def meter_to_user_get(meter_ids):  # noqa: E501
    """Retrieve the user ids that contains the specified meter ids

     # noqa: E501

    :param meter_ids:
    :type meter_ids: List[str]

    :rtype: List[MeterIdToUserId]
    """
    corId = {"X-Correlation-ID": connexion.request.headers["X-Correlation-ID"]}

    logger.info("Processing GET /meter-to-user request", extra=corId)
    endText = "Processed GET /meter-to-user request"

    my_set = set(meter_ids)
    meter_ids = list(my_set)

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

        for mId in meter_ids:
            if mId != user.meter_id:

                logger.error(
                    f"User with meterId {user.meter_id}"
                    f"does not have permission to see user with meterId {mId}",
                    extra=corId,
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


def user_get(user_ids):  # noqa: E501
    """Retrieve information about users

     # noqa: E501

    :param user_ids:
    :type user_ids: List[str]

    :rtype: List[User]
    """
    corId = {"X-Correlation-ID": connexion.request.headers["X-Correlation-ID"]}

    logger.info("Processing GET /user request", extra=corId)
    endText = "Processed GET /user request"

    my_set = set(user_ids)
    user_ids = list(my_set)

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

        for uId in user_ids:
            if uId != user.user_id:

                logger.error(
                    f"User {user.user_id} does not have permission to see user {uId}",
                    extra=corId,
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

        response.append(
            User(
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
        )

    logResponse(endText, response, corId)

    return response, 200, corId


def user_list_get():  # noqa: E501
    """Retrieve list of all users ids

     # noqa: E501


    :rtype: List[str]
    """
    corId = {"X-Correlation-ID": connexion.request.headers["X-Correlation-ID"]}

    logger.info("Processing GET /user-list request", extra=corId)
    endText = "Processed GET /user-list request"

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
        logger.error(
            "User " + auth_response + " does not have permission to see user list",
            extra=corId,
        )
        message = "no permission"
        response = Error(message)
        logErrorResponse(message, endText, response, corId)
        return response, 403, corId

    users = DBUser.query.filter_by(deleted=False).all()
    response = []
    for user in users:
        response.append(user.user_id)

    logResponse(endText, response, corId)

    return response, 200, corId

def user_deleted_list_get():  # noqa: E501
    """Retrieve list of all deleted users

     # noqa: E501

    :rtype: Union[List[DeletedUser], Tuple[List[DeletedUser], int], Tuple[List[DeletedUser], int, Dict[str, str]]
    """
    corId = {"X-Correlation-ID": connexion.request.headers["X-Correlation-ID"]}

    logger.info("Processing GET /user-deleted-list request", extra=corId)
    endText = "Processed GET /user-deleted-list request"

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
        logger.error(
            "User " + auth_response + " does not have permission to see user deleted list",
            extra=corId,
        )
        message = "no permission"
        response = Error(message)
        logErrorResponse(message, endText, response, corId)
        return response, 403, corId

    users = DBUser.query.filter_by(deleted=True).all()
    response = []
    for user in users:
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

        response.append(
            DeletedUser(
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
                deleted=user.deleted,
                deleted_timestamp=user.deleted_timestamp
            )
        )

    logResponse(endText, response, corId)

    return response, 200, corId
