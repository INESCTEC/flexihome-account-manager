import os, logging


class Config:

    ### ACCOUNT MANAGER ###

    JWT_SIGN_ALGORITHM = 'HS512'
    JWT_EXPIRATION_TIME_SECONDS = 14 * 24 * 60 * 60
    JWT_SIGN_KEY = os.environ.get('JWT_SIGN_KEY', 'f797b720a53f8e9c71d33700f2a703acea28985dd427369a3f55f48ba171998e408b44c072c1d9dfb06192aa6808c8a9e28b68dbe842d0c1473405fc298f31708ad12168bcdeb642ba619866ae1c0a49fa4fa248818535105ec7931901589de6b4f316273994003db830f23331b12c9da51415d479ead7729bb30c7df54aaf78')

    CONFIRMATION_TOKEN_EXPIRATION_TIME_SECONDS = 2 * 24 * 60 * 60
    USER_ID_SIZE = 10
    DEFAULT_SCHEDULE_TYPE = "economic"

    EMAIL = os.environ.get('EMAIL', None)
    EMAIL_PASSWORD = os.environ.get('EMAIL_PASSWORD', None)
    GITLAB_CI_TEST = os.environ.get('GITLAB_CI_TEST', 'False')
    
    # Google API
    PROJECT_ID = os.environ.get("GOOGLE_PROJECT_ID", "hems_project_id")
    PRIVATE_KEY_ID = os.environ.get("GOOGLE_PRIVATE_KEY_ID", "hems_private_key_id")
    PRIVATE_KEY = os.environ.get("GOOGLE_PRIVATE_KEY", "hems_private_key").replace("\\n", "\n")
    CLIENT_EMAIL = os.environ.get("GOOGLE_CLIENT_EMAIL", "hems_client_email")
    CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "hems_client_id")
    CLIENT_CERT_URL = os.environ.get("GOOGLE_CLIENT_CERT_URL", "hems_client_cert_url")
    GOOGLE_TOKEN = os.environ.get("GOOGLE_TOKEN", "hems_google_token")


    ### DATABASE ###

    DATABASE_IP = os.environ.get('DATABASE_IP', '127.0.0.1')
    DATABASE_PORT = os.environ.get('DATABASE_PORT', '5432')
    DATABASE_USER = os.environ.get('DATABASE_USER', 'postgres')
    DATABASE_PASSWORD = os.environ.get('DATABASE_PASSWORD', 'mysecretpassword')
    AUTH_DATABASE_USER = os.environ.get('AUTH_DATABASE_USER', 'postgres')
    AUTH_DATABASE_PASSWORD = os.environ.get('AUTH_DATABASE_PASSWORD', 'mysecretpassword')

    # FLASK SQLALCHEMY VARIABLES
    SQLALCHEMY_DATABASE_URI = f'postgresql+psycopg2://{DATABASE_USER}:{DATABASE_PASSWORD}@{DATABASE_IP}:{DATABASE_PORT}/account_manager'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    #SQLALCHEMY_ECHO = True
    SQLALCHEMY_ENGINE_OPTIONS = {
        # "max_overflow": int(os.environ.get("SQLALCHEMY_MAX_OVERFLOW", "5")),
        # "pool_size": int(os.environ.get("SQLALCHEMY_POOL_SIZE", "10")),
        "pool_pre_ping": True if os.environ.get("SQLALCHEMY_POOL_PRE_PING", "True").lower() == "true" else False,
        "pool_logging_name": os.environ.get("SQLALCHEMY_POOL_LOGGING_NAME", "pool_log"),
        # "isolation_level": SQLALCHEMY_ISOLATION_LEVEL
        'connect_args': {
            "keepalives": 1,
            "keepalives_idle": 60,
            "keepalives_interval": 30,
            "keepalives_count": 5,
        }
    }

    SQLALCHEMY_ENGINE_LOG_LEVEL = logging.getLevelName(
        os.environ.get('SQLALCHEMY_ENGINE_LOG_LEVEL', 'WARN'))
    SQLALCHEMY_POOL_LOG_LEVEL = logging.getLevelName(
        os.environ.get('SQLALCHEMY_POOL_LOG_LEVEL', 'WARN'))


    ### METRICS ###

    LOG_LEVEL = logging.getLevelName(os.environ.get('LOG_LEVEL', 'DEBUG'))
    LOG_FORMAT = logging.getLevelName(os.environ.get('LOG_FORMAT', 'text'))
    OC_AGENT_ENDPOINT = os.environ.get('OC_AGENT_ENDPOINT', '127.0.0.1:6831')


    ### KAFKA + DEBEZIUM ###

    KAFKA_BROKER_ENDPOINT = os.environ.get('KAFKA_BROKER_ENDPOINT', '127.0.0.1:9092')
    KAFKA_TOPIC_PREFIX = os.environ.get('KAFKA_TOPIC_PREFIX', 'hems.')
    KAFKA_TOPIC_SUFFIX = 'user-account'
    KAFKA_TOPIC = KAFKA_TOPIC_PREFIX + KAFKA_TOPIC_SUFFIX
    KAFKA_GROUP_ID = 'AccountManagerService'
    # How many seconds to wait for an exit event
    KAFKA_WAIT_FOR_EVENT_SECONDS = 0.01
    KAFKA_CONSUMER_TIMEOUT_MS = 100
    KAFKA_RECONNECT_SLEEP_SECONDS = 5


    ### SUPPORT SERVICES ###

    # Endpoints assume the developer is connected to the cluster using telepresence

    # FORECAST
    FORECAST_INSTALLATIONS_URL = os.environ.get('FORECAST_INSTALLATIONS_URL', 'http://forecast-rest-api.default.svc.cluster.local:8080/api/installations')
