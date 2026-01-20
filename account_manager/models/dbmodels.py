from datetime import datetime, timedelta, timezone
from account_manager import db
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy import Enum
import enum
import uuid
from account_manager import Config
import string
import secrets
import jwt


def id_generator(size=Config.USER_ID_SIZE, chars=string.ascii_lowercase + string.digits):
    return ''.join(secrets.SystemRandom().choice(chars) for _ in range(size))


class DBUser(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(32), unique=True, index=True,nullable=False, default=id_generator)
    meter_id = db.Column(db.String(32), unique=True, index=True)

    first_name = db.Column(db.String(32), nullable=False)
    last_name = db.Column(db.String(32), nullable=True)
    email = db.Column(db.String(64), unique=True, index=True, nullable=False)
    password = db.Column(db.String(128), nullable=True)

    is_active = db.Column(db.Boolean, nullable=False, default=False)
    is_google_account = db.Column(db.Boolean, nullable=False, default=False)
    deleted = db.Column(db.Boolean, nullable=False, default=False)
    deleted_timestamp = db.Column(db.DateTime, nullable=True)

    api_key = db.Column(db.String(32), nullable=True)  # Dongle API Key
    wp_token = db.Column(db.String(500), nullable=True)  # WP account token
    expo_token = db.Column(db.String(128), nullable=True)  # Expo notification token

    created_timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    modified_timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    settings = db.relationship("DBUserSettings", back_populates="user", lazy="joined", uselist=False)

    def __repr__(self):
        return (
            f"DBUser('{self.user_id}', '{self.first_name}', " \
            f"'{self.last_name}', '{self.email}', '{self.password}', '{self.is_active}', " \
            f"'{self.deleted}', '{self.deleted_timestamp}', '{self.meter_id}', '{self.api_key}', " \
            f"'{self.expo_token}', '{self.wp_token}', '{self.is_google_account}', " \
            f"'{self.settings}', '{self.created_timestamp}', '{self.modified_timestamp}')"
        )

    def encode_auth_token(self):
        """
        Generates the Auth Token
        :return: string
        """
        try:
            payload = {
                'exp': datetime.now(timezone.utc) + timedelta(seconds=Config.JWT_EXPIRATION_TIME_SECONDS),
                'iat': datetime.now(timezone.utc),
                'sub': self.user_id,
                'email': self.email,
                'meter_id': self.meter_id
            }
            return jwt.encode(
                payload,
                Config.JWT_SIGN_KEY,
                algorithm=Config.JWT_SIGN_ALGORITHM
            )
        except Exception as e:
            print(e)
            return None

    @ staticmethod
    def decode_auth_token(auth_token):
        """
        Validates the auth token
        :param auth_token:
        :return: string
        """
        try:
            payload = jwt.decode(auth_token, Config.JWT_SIGN_KEY, algorithms=[
                Config.JWT_SIGN_ALGORITHM])
            # is_blacklisted_token = TokenBlacklist.check_blacklist(auth_token)
            # if is_blacklisted_token:
            #     raise Exception('Token blacklisted. Please log in again.')
            # else:
            #     return payload['sub']
            return payload['sub']
        except Exception as e:
            raise


class DBUserSettings(db.Model):
    __tablename__ = 'user_settings'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.ForeignKey("users.user_id"), index=True, nullable=False)

    country = db.Column(db.String(32), nullable=True)
    postal_code = db.Column(db.String(32), nullable=True)
    
    schedule_type = db.Column(db.String(32), nullable=True, default=Config.DEFAULT_SCHEDULE_TYPE)
    tarif_type = db.Column(db.String(32), nullable=True)
    contracted_power = db.Column(db.String(32), nullable=True)
    
    global_optimizer = db.Column(db.Boolean, nullable=True, default=True)
    permissions = db.Column(db.String(32), nullable=False, default="None")
    
    modified_timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    user = db.relationship("DBUser", back_populates="settings", lazy="joined")
    not_disturb = db.relationship("DBNotDisturb", lazy="joined", back_populates="settings")


    def __repr__(self):
        return (
            f"DBUserSettings('{self.country}', '{self.postal_code}', " \
            f"'{self.schedule_type}', '{self.tarif_type}', '{self.contracted_power}', " \
            f"'{self.not_disturb}', '{self.global_optimizer}', " \
            f"'{self.permissions}', '{self.modified_timestamp}')"
        )


class DBNotDisturb(db.Model):
    __tablename__ = 'not_disturbs'

    id = db.Column(db.Integer, primary_key=True)
    settings_id = db.Column(db.ForeignKey("user_settings.id"),index=True, nullable=False)
    
    day_of_week = db.Column(db.String(32), nullable=False)
    start_timestamp = db.Column(db.DateTime, nullable=False)
    end_timestamp = db.Column(db.DateTime, nullable=False)

    settings = db.relationship("DBUserSettings", back_populates="not_disturb", lazy="joined")

    def __repr__(self):
        return f"DBNotDisturb('{self.day_of_week}', '{self.start_timestamp}', '{self.end_timestamp}')"


class DBConfirmationToken(db.Model):
    __tablename__ = 'confirmation_tokens'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(32), index=True, nullable=False)

    token = db.Column(db.String(64), unique=True, nullable=False)
    
    expiration_timestamp = db.Column(db.DateTime, nullable=False)

    def __repr__(self):
        return f"DBConfirmationToken('{self.user_id}', '{self.token}', '{self.expiration_timestamp}')"


class DBForgotPasswordToken(db.Model):
    __tablename__ = 'forgot_password_tokens'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(32), index=True, nullable=False)

    token = db.Column(db.String(64), unique=True, nullable=False)
    
    expiration_timestamp = db.Column(db.DateTime, nullable=False)

    def __repr__(self):
        return f"DBForgotPasswordToken('{self.user_id}', '{self.token}', '{self.expiration_timestamp}')"


class DBAccountRecoveryToken(db.Model):
    __tablename__ = 'account_recovery_tokens'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(32), index=True, nullable=False)

    token = db.Column(db.String(64), unique=True, nullable=False)
    
    expiration_timestamp = db.Column(db.DateTime, nullable=False)

    def __repr__(self):
        return f"DBAccountRecoveryToken('{self.user_id}', '{self.token}', '{self.expiration_timestamp}')"


class DBEvent(db.Model):
    __tablename__ = 'events'

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    aggregatetype = db.Column(
        db.String(255),
        nullable=False,
        default=Config.KAFKA_TOPIC_SUFFIX
        )  # Topic name
    aggregateid = db.Column(db.String(255), nullable=False)
    
    type = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    payload = db.Column(JSONB, nullable=False)

    def __repr__(self):
        return (
            f"DBEvent('{self.aggregatetype}', '{self.aggregateid}', " \
            f"'{self.type}', '{self.timestamp}', '{self.payload}')"
        )


class DBProcessedEvent(db.Model):
    __tablename__ = 'processed_events'

    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(255), nullable=False)  # Topic name
    event_id = db.Column(UUID(as_uuid=True), nullable=False, index=True)

    def __repr__(self):
        return f"DBProcessedEvent('{self.event_type}', '{self.event_id}')"


class DBMeterIdApiKeyMapping(db.Model):
    __tablename__ = 'meter_id_api_key_mapping'

    id = db.Column(db.Integer, primary_key=True)
    meter_id = db.Column(db.String(32), index=True, unique=True, nullable=False)
    api_key = db.Column(db.String(32), nullable=True)

    def __repr__(self):
        return f"DBMeterIdApiKeyMapping('{self.meter_id}', '{self.api_key}')"
    

class DBAppInfo(db.Model):
    __tablename__ = 'app_info'

    id = db.Column(db.Integer, primary_key=True)
    service_name = db.Column(db.String(64), unique=True, nullable=False)
    display = db.Column(db.Boolean, nullable=False, default=False)

    def __repr__(self):
        return f"DBAppInfo('{self.service_name}', '{self.display}')"

class LanguageEnum(enum.Enum):
    pt_PT = 1
    en_GB = 2

class DBAppInfoMessages(db.Model):
    __tablename__ = 'app_info_messages'

    id = db.Column(db.Integer, primary_key=True)
    service_name = db.Column(db.String(64), nullable=False)

    language = db.Column(Enum(LanguageEnum, inherit_schema=True), nullable=False)
    title = db.Column(db.String(128), nullable=False)
    description = db.Column(db.String(512), nullable=False)
    icon = db.Column(db.String(64), nullable=False)

    creation_timestamp = db.Column(db.DateTime, nullable=False)

    app_info_id = db.Column(db.ForeignKey("app_info.id"), index=True, nullable=False)

    def __repr__(self):
        return (
            f"DBAppInfoMessages('{self.service_name}', '{self.title}', " \
            f"'{self.description}', '{self.icon}', '{self.creation_timestamp}', '{self.app_info_id}')"
        )


db.create_all()
