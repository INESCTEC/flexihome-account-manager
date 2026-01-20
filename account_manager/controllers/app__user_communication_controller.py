import connexion, httplib2,traceback

from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from oauth2client.service_account import ServiceAccountCredentials


from account_manager import logger, auth, Config
from account_manager.models.current_app_version import CurrentAppVersion  # noqa: E501

from account_manager.models.info_messages import InfoMessages 
from account_manager.models.error import Error  # noqa: E501

from account_manager.models.dbmodels import DBUser, DBAppInfo, DBAppInfoMessages, LanguageEnum


def logErrorResponse(error, endText, response, cor_id):
    logger.error(error, extra=cor_id)
    logResponse(endText, response, cor_id)


def logResponse(endText, response, cor_id):
    logger.info(endText, extra=cor_id)
    if response is not None:
        logger.debug("Sending the following response: ", extra=cor_id)
        logger.debug(response, extra=cor_id)


def app_version_get(package_name):  # noqa: E501
    """Retrieve the current build version of the app

     # noqa: E501

    :param x_correlation_id: 
    :type x_correlation_id: 
    :param authorization: 
    :type authorization: str

    :rtype: CurrentAppVersion
    """
    
    cor_id = {"X-Correlation-ID": connexion.request.headers["X-Correlation-ID"]}
    
    logger.info("Processing GET /app/version request", extra=cor_id)
    endText = "/app/version request finished processing with an error."
    

    auth_response, auth_response_code = auth.verify_basic_authorization(
        connexion.request.headers
    )

    if auth_response_code != 200:
        if auth_response_code == 402:
            logger.error(f"Blacklisted token {auth_response}", extra=cor_id)
        else:
            logger.error(
                f"Could not decode authorization token {auth_response}", extra=cor_id)

        message = "invalid credentials"
        response = Error(message)

        logErrorResponse(message, endText, response, cor_id)
        return response, 401, cor_id

    else:
        user_id = auth_response

    if auth_response is not None:
        user = DBUser.query.filter_by(user_id=auth_response, deleted=False).first()

        if user is None:

            logger.error(
                f"Authorization token valid but user_id {user_id} not found",
                extra=cor_id,
            )
            message = "invalid credentials"
            response = Error(message)

            logErrorResponse(message, endText, response, cor_id)
            return response, 401, cor_id

    
    try:
        last_build_version = get_hems_version(package_name, cor_id=cor_id)
    except HttpError as err:
        message = "Error getting version from play store"
        logger.error(message, extra=cor_id)
        logger.error(err._get_reason(), extra=cor_id)
        
        response = Error(err._get_reason())
        return response, err.status_code, cor_id

    except Exception as err:
        logger.error(repr(err), extra=cor_id)
        
        response = Error("Error getting version from play store")
        return response, 500, cor_id
    
    return CurrentAppVersion(last_build_version), 200, cor_id


def get_hems_version(package_name, cor_id):

    key_file = {
        "type": "service_account",
        "project_id": Config.PROJECT_ID,
        "private_key_id": Config.PRIVATE_KEY_ID,
        "private_key": Config.PRIVATE_KEY,
        "client_email": Config.CLIENT_EMAIL,
        "client_id": Config.CLIENT_ID,
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "client_x509_cert_url": Config.CLIENT_CERT_URL,
        "universe_domain": "googleapis.com"
    }
    logger.debug(key_file, extra=cor_id)
    credentials = ServiceAccountCredentials.from_json_keyfile_dict(key_file, scopes='https://www.googleapis.com/auth/androidpublisher')

    http = httplib2.Http()
    credentials.authorize(http)
    service = build('androidpublisher', 'v3', http=http)


    edit_result = service.edits().insert(body={}, packageName=package_name).execute()
    edit_id = edit_result['id']

    bundles = service.edits().bundles().list(editId=edit_id, packageName=package_name).execute()

    last_version = str(bundles['bundles'][-1]['versionCode'])
    logger.info(f"Last bundle version for {package_name} in play store: {last_version}\n", extra=cor_id)
    
    return last_version


def app_info_get(system_language):  # noqa: E501
    """Retrieve the current build version of the app

    # INSERT DATA IN POSTGRES
    INSERT INTO app_info(id, service_name, display) VALUES (1, 'energy_manager.smart_meters', true);
    INSERT INTO app_info_messages(id, service_name, language, title, description, icon, creation_timestamp, app_info_id) VALUES (1, 'energy_manager.smart_meters', 'pt-PT', 'Ligação com contadores inteligentes em manutenção', 'A ligação está em manutenção', 'cloud-off', '2023-11-08 16:36:00+00', '1');
    INSERT INTO app_info_messages(id, service_name, language, title, description, icon, creation_timestamp, app_info_id) VALUES (2, 'energy_manager.smart_meters', 'en-GB', 'Smart meter connection is in maintenance', 'Connection in maintenance', 'cloud-off', '2023-11-08 16:36:00+00', '1');

    INSERT INTO app_info(id, service_name, display) VALUES (2, 'energy_manager.flex_aggregator', false);
    INSERT INTO app_info_messages(id, service_name, language, title, description, icon, creation_timestamp, app_info_id) VALUES (3, 'energy_manager.flex_aggregator', 'pt-PT', 'Ligação com o serviço de flexibilidade está em manutenção', 'A ligação está em manutenção', 'cloud-off', '2023-11-08 16:36:00+00', '2');
  
    :param x_correlation_id: 
    :type x_correlation_id: 
    :param system_language: 
    :type system_language: str
    :param authorization: 
    :type authorization: str

    :rtype: List[ServiceDown]
    """
    cor_id = {"X-Correlation-ID": connexion.request.headers["X-Correlation-ID"]}
    
    logger.info("Processing GET /app/info request", extra=cor_id)
    endText = "/app/info request finished processing with an error."
    logger.debug(f"system_language: {system_language}", extra=cor_id)
    

    auth_response, auth_response_code = auth.verify_basic_authorization(
        connexion.request.headers
    )

    if auth_response_code != 200:
        if auth_response_code == 402:
            logger.error(f"Blacklisted token {auth_response}", extra=cor_id)
        else:
            logger.error(
                f"Could not decode authorization token {auth_response}", extra=cor_id)

        message = "invalid credentials"
        response = Error(message)

        logErrorResponse(message, endText, response, cor_id)
        return response, 401, cor_id

    else:
        user_id = auth_response

    if auth_response is not None:
        user = DBUser.query.filter_by(user_id=auth_response, deleted=False).first()

        if user is None:

            logger.error(
                f"Authorization token valid but user_id {user_id} not found",
                extra=cor_id,
            )
            message = "invalid credentials"
            response = Error(message)

            logErrorResponse(message, endText, response, cor_id)
            return response, 401, cor_id

    if system_language == "pt-PT":
        language = LanguageEnum.pt_PT
    elif system_language == "en-GB":
        language = LanguageEnum.en_GB
    else:
        language = 999
    
    try:
        # Query services that are down
        info_to_display = DBAppInfo.query.filter_by(display=True).all()
        logger.debug(f"app info to display: {info_to_display}", extra=cor_id)

        response = []
        for info in info_to_display:
            logger.debug(f"info id: {info.id}", extra=cor_id)
            app_info_message = DBAppInfoMessages.query.filter_by(app_info_id=info.id, language=language).first()
            logger.debug(f"info message: {app_info_message}", extra=cor_id)

            if app_info_message is not None:
                response.append(InfoMessages(
                    title=app_info_message.title,
                    description=app_info_message.description,
                    icon=app_info_message.icon    
                ))
            else:
                logger.warning(f"App info {info.id} has no message in language {system_language}", extra=cor_id)
    except Exception as e:
        logger.error(repr(e), extra=cor_id)
        traceback.print_exc()
        response = Error("Error getting app info to display")
        return response, 500, cor_id

    return response, 200, cor_id
