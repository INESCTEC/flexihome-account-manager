import json
from uuid import uuid4
from time import sleep

from jsonschema import validate

from account_manager.test.json_schemas import UserSchema

from account_manager.models.dbmodels import DBConfirmationToken


METER_IDS_WITH_API_KEY = ["NLV_CLIENT_8585", "NLV_CLIENT_8813", "NLV_CLIENT_8819"]
METER_IDS_WITHOUT_API_KEY = ["NLV_CLIENT_9564", "NLV_CLIENT_9953"]

def register_basic_user(client, email, meter_id=METER_IDS_WITH_API_KEY[0], expo_token="no token", error=False):
    
    register_request = {
        "first_name": "Test",
        "email": email,
        "password": "123456",
        "password_repeat": "123456",
        "meter_id": meter_id,
        "contracted_power": "6.9 kVA",
        "tarif_type": "bi-hourly",
        "postal_code": "4444-001"
    }

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "X-Correlation-ID": str(uuid4()),
    }
    if expo_token != "no token":
        headers['expo-token'] = expo_token
    
    
    response = client.open(
        "/api/account/register",
        method="POST",
        headers=headers,
        data=json.dumps(register_request),
        content_type="application/json",
    )

    if error == True:
        return response, None

    register_response = json.loads(response.data.decode("utf-8"))
    validate(register_response, UserSchema)

    new_user_id = register_response["user_id"]
    print("Registered UserID: " + new_user_id)

    return register_response, new_user_id


def confirm_user_account(client, user_id):

    confirmationToken = None
    tries = 3
    while (confirmationToken is None) & (tries > 0):
        sleep(1)
        confirmationToken = DBConfirmationToken.query.filter_by(
            user_id=user_id
        ).first()
        if confirmationToken is None:
            tries = tries - 1
    
    if (confirmationToken == None) and (tries == 0):
        raise ValueError(f"User's {user_id} account could not be confirmed!")

    
    headers = {"X-Correlation-ID": str(uuid4())}
    confirm_account_response = client.open(
        f"/api/account/confirm-account/{confirmationToken.token}",
        method="POST",
        headers=headers,
        content_type="application/json",
    )

    return confirm_account_response


def user_login(client, email, password):
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "X-Correlation-ID": str(uuid4()),
    }
    post_request_body = {"email": email, "password": password}
    
    login_response = client.open(
        "/api/account/login",
        method="POST",
        headers=headers,
        data=json.dumps(post_request_body),
        content_type="application/json",
    )

    try:
        auth = str(login_response.headers["Authorization"])
        print(f"Auth: {auth}")
    except Exception:
        auth = None

    return login_response, auth
