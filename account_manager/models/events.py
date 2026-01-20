from marshmallow import Schema, fields, validate
from sqlalchemy import true

UserRegisteredEventType = "UserRegistered"
UserConfirmedEventType = "UserConfirmed"
UserUpdatedEventType = "UserUpdated"
UserSoftDeletedEventType = "UserSoftDeleted"
UserHardDeletedEventType = "UserHardDeleted"
UserRecoveredAccountEventType = "UserAccountRecovered"
UserFilledPostalCodeEventType = "UserFilledPostalCode"
UserAddedDongleApiKeyEventType = "UserAddedDongleApiKey"
UserUpdatedDongleApiKeyEventType = "UserUpdatedDongleApiKey"
UserRegisteredNotificationType = "UserRegisteredNotification"

# JSON schema matching the CounterRecord data structure schema
# Topic: hems.user-account


class PeriodOfDaySchema(Schema):
    day_of_week = fields.String(required=True)
    start_timestamp = fields.DateTime(required=True)
    end_timestamp = fields.DateTime(required=True)


class NotDisturbSchema(Schema):
    sunday = fields.List(fields.Nested(PeriodOfDaySchema))
    monday = fields.List(fields.Nested(PeriodOfDaySchema))
    tuesday = fields.List(fields.Nested(PeriodOfDaySchema))
    wednesday = fields.List(fields.Nested(PeriodOfDaySchema))
    thursday = fields.List(fields.Nested(PeriodOfDaySchema))
    friday = fields.List(fields.Nested(PeriodOfDaySchema))
    saturday = fields.List(fields.Nested(PeriodOfDaySchema))


class UserAccountSchema(Schema):
    user_id = fields.String(required=True)
    first_name = fields.String(required=True)
    last_name = fields.String(required=False, allow_none=True)
    email = fields.String(required=True)
    is_active = fields.Boolean(required=True)
    # deleted = fields.Boolean(required=True, allow_none=True)
    # cpe = fields.String(required=False, allow_none=True)
    meter_id = fields.String(required=True, allow_none=True)
    is_google_account = fields.Boolean(required=True)
    country = fields.String(required=False, allow_none=True)
    postal_code = fields.String(required=True, allow_none=True)
    schedule_type = fields.String(required=False)
    # district = fields.String(required=True)
    # county = fields.String(required=True)
    tarif_type = fields.String(required=True, allow_none=True)
    api_key = fields.String(required=False, allow_none=True)
    contracted_power = fields.String(required=True, allow_none=True)
    not_disturb = fields.Nested(NotDisturbSchema, required=True)
    global_optimizer = fields.Boolean(required=True)
    permissions = fields.String(required=True)
    modified_timestamp = fields.DateTime(required=True)


class UserLocationSchema(Schema):
    user_id = fields.String(required=True)
    postal_code = fields.String(required=True)
    contracted_power = fields.Float(required=False)
    
class UserRegisteredNotificationSchema(Schema):
    notification = fields.String(required=True)
