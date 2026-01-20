# coding: utf-8

from __future__ import absolute_import
import unittest
import uuid

from flask import json

from jsonschema import validate

from account_manager.test.json_schemas import UserSchema
from account_manager.test import BaseTestCase
from account_manager.test.helper_functions import register_basic_user, confirm_user_account, user_login
from account_manager.test.helper_functions import METER_IDS_WITH_API_KEY

from account_manager.models.dbmodels import (
    db,
    DBUser,
    DBUserSettings,
    DBNotDisturb,
    DBConfirmationToken,
    DBForgotPasswordToken,
    DBEvent,
    DBProcessedEvent,
)


def clean_account():
    try:
        DBNotDisturb.query.delete()
        DBUserSettings.query.delete()
        DBUser.query.delete()
        DBConfirmationToken.query.delete()
        DBForgotPasswordToken.query.delete()
        DBEvent.query.delete()
        DBProcessedEvent.query.delete()
        db.session.commit()
    except Exception as e:
        print(repr(e))
        print("MOCK DATABASE - FAILED TO DELETE ACCOUNT DB")
        db.session.rollback()

    db.create_all()


class TestUserInfoManagementController(BaseTestCase):
    """UserInfoManagementController integration test stubs"""

    def test_user_list_without_authorization_find_user(self):
        """Test case that registers a user, gets the user list, and finds the user

        Register account and get user list.
        """
        clean_account()

        email = "riscas.cat1+h@gmail.com"
        _, new_user_id = register_basic_user(self.client, email)


        # User list
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
        }
        response = self.client.open(
            "/api/account/user-list", method="GET", headers=headers
        )

        users = json.loads(response.data.decode("utf-8"))
        found = False
        for user in users:
            if user == new_user_id:
                found = True
                break

        self.assertTrue(found)

    def test_user_list_with_authorization(self):
        """Test case that registers a user, logins and tries to get the user list

        Register account, activate user, login and get user list.
        """
        clean_account()
        email = "riscas.cat1+ha@gmail.com"
        
        _, new_user_id = register_basic_user(self.client, email)
        _ = confirm_user_account(self.client, new_user_id)
        _, auth = user_login(self.client, email, "123456")

        # User list
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
            "Authorization": auth,
        }
        response = self.client.open(
            "/api/account/user-list", method="GET", headers=headers
        )
        self.assert403(response, "Response body is : " + response.data.decode("utf-8"))

    def test_dongles_list_without_authorization_find_user(self):
        """Test case that registers a user, gets the dongles list, and finds the dongle

        Register account and get dongle list.
        """
        clean_account()

        email = "riscas.cat1+h@gmail.com"
        _, new_user_id = register_basic_user(self.client, email, meter_id="NLV_CLIENT_8585")


        # User list
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
        }
        response = self.client.open(
            "/api/account/list-dongles", method="GET", headers=headers
        )

        dongles = json.loads(response.data.decode("utf-8"))
        found = False
        for dongle in dongles:
            if dongle["user_id"] == new_user_id and dongle["api_key"] == "2J3R14CXJ18IWJ4T":
                found = True
                break

        self.assertTrue(found)

    def test_dongles_list_with_authorization(self):
        """Test case that registers a user, logins and tries to get the dongles list

        Register account, activate user, login and get dongle list.
        """
        clean_account()
        email = "riscas.cat1+ha@gmail.com"
        
        _, new_user_id = register_basic_user(self.client, email)
        _ = confirm_user_account(self.client, new_user_id)
        _, auth = user_login(self.client, email, "123456")

        # User list
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
            "Authorization": auth,
        }
        response = self.client.open(
            "/api/account/list-dongles", method="GET", headers=headers
        )
        self.assert403(response, "Response body is : " + response.data.decode("utf-8"))

    def test_meter_ids_list_without_authorization_find_user(self):
        """Test case that registers a user, gets the meter ids list, and finds the meter id

        Register account and get meter ids.
        """
        clean_account()

        email = "riscas.cat1+h@gmail.com"
        _, new_user_id = register_basic_user(self.client, email, meter_id=METER_IDS_WITH_API_KEY[0])

        # User list
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
        }
        response = self.client.open(
            "/api/account/list-meter-ids", method="GET", headers=headers
        )

        meter_ids = json.loads(response.data.decode("utf-8"))
        found = False
        for meter_id in meter_ids:
            if meter_id == METER_IDS_WITH_API_KEY[0]:
                found = True
                break

        self.assertTrue(found)

    def test_meter_ids_list_with_authorization(self):
        """Test case that registers a user, logins and tries to get the meter ids list

        Register account, activate user, login and get meter ids list.
        """
        clean_account()
        email = "riscas.cat1+ha@gmail.com"
        
        _, new_user_id = register_basic_user(self.client, email)
        _ = confirm_user_account(self.client, new_user_id)
        _, auth = user_login(self.client, email, "123456")

        # User list
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
            "Authorization": auth,
        }
        response = self.client.open(
            "/api/account/list-meter-ids", method="GET", headers=headers
        )
        self.assert403(response, "Response body is : " + response.data.decode("utf-8"))
    
    def test_user_deleted_list_without_authorization_find_user(self):
        """Test case that registers a user, gets the user list, and finds the user

        Register account and get user list.
        """
        clean_account()

        email = "riscas.cat1+h@gmail.com"
        _, new_user_id = register_basic_user(self.client, email)

        # Soft Delete user
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4())
        }
        query_string = {"user-id": new_user_id, "delete_type": "soft"}
        response = self.client.open(
            "/api/account/user",
            method="DELETE",
            headers=headers,
            query_string=query_string,
        )
        self.assert200(response, "Response body is : " + response.data.decode("utf-8"))

        # User deleted list
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
        }
        response = self.client.open(
            "/api/account/user-deleted-list", method="GET", headers=headers
        )

        users = json.loads(response.data.decode("utf-8"))
        deleted_user = None
        found = False
        for user in users:
            if user["user_id"] == new_user_id:
                found = True
                deleted_user = user
                break

        self.assertTrue(found)
        self.assertTrue(deleted_user["deleted"])
        self.assertTrue(deleted_user["deleted_timestamp"] != None)

    def test_user_deleted_list_with_authorization(self):
        """Test case that registers a user, logins and tries to get the user list

        Register account, activate user, login and get user list.
        """
        clean_account()
        email = "riscas.cat1+ha@gmail.com"
        
        _, new_user_id = register_basic_user(self.client, email)
        _ = confirm_user_account(self.client, new_user_id)
        _, auth = user_login(self.client, email, "123456")

        # User list
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
            "Authorization": auth,
        }
        response = self.client.open(
            "/api/account/user-deleted-list", method="GET", headers=headers
        )
        self.assert403(response, "Response body is : " + response.data.decode("utf-8"))

    def test_get_user_without_authorization(self):
        """Test case that registers a user and gets it without authorization

        Register account and get user.
        """
        clean_account()
        email = "riscas.cat1+i@gmail.com"
        _, new_user_id = register_basic_user(self.client, email)

        # Get user
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
        }
        query_string = {"user-ids": new_user_id}
        response = self.client.open(
            "/api/account/user",
            method="GET",
            headers=headers,
            query_string=query_string,
        )
        self.assert200(response, "Response body is : " + response.data.decode("utf-8"))

    def test_get_user_without_authorization_single_user_returned(self):
        """Test case that registers a user, gets it without authorization,
            and confirms that a single user is returned

        Register account and get user.
        """
        clean_account()
        email = "riscas.cat1+i@gmail.com"
        register_response, new_user_id = register_basic_user(self.client, email)

        # Get user
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
        }
        query_string = {"user-ids": new_user_id}
        response = self.client.open(
            "/api/account/user",
            method="GET",
            headers=headers,
            query_string=query_string,
        )

        userResponse = json.loads(response.data.decode("utf-8"))
        self.assertEqual(len(userResponse), 1)
        self.assertEqual(userResponse[0], register_response)


    def test_get_user_with_authorization(self):
        """Test case that registers a user, logs in and gets the user

        Register account, activate user, login and get user.
        """
        clean_account()
        email = "riscas.cat1+ia@gmail.com"
        
        register_response, new_user_id = register_basic_user(self.client, email)
        _ = confirm_user_account(self.client, new_user_id)
        _, auth = user_login(self.client, email, "123456")


        # Get user
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
            "Authorization": auth,
        }
        query_string = {"user-ids": new_user_id}
        response = self.client.open(
            "/api/account/user",
            method="GET",
            headers=headers,
            query_string=query_string,
        )
        self.assert200(response, "Response body is : " + response.data.decode("utf-8"))
        userResponse = json.loads(response.data.decode("utf-8"))

        validate(userResponse[0], UserSchema)
        register_response["is_active"] = True
        register_response.pop("modified_timestamp", None)
        register_response["permissions"] = "Full"  # NOTE: Maybe full??
        userResponse[0].pop("modified_timestamp", None)
        self.assertEqual(userResponse[0], register_response)


    def test_meter_to_user_without_authorization_validate_user_id(self):
        """Test case that registers a user, asks its user id though its meter id, and validates response

        Register account and get meter-to-user.
        """
        clean_account()
        email = "riscas.cat1+n@gmail.com"
        
        _, new_user_id = register_basic_user(self.client, email)
        _ = confirm_user_account(self.client, new_user_id)


        # Get userId thought meterId
        query_string = {"meter-ids": [METER_IDS_WITH_API_KEY[0]]}
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
        }
        response = self.client.open(
            "/api/account/meter-to-user",
            method="GET",
            headers=headers,
            query_string=query_string,
        )

        users = json.loads(response.data.decode("utf-8"))
        self.assertEqual(len(users), 1)
        self.assertEqual(users[0]["user_id"], new_user_id)

    def test_meter_to_user_with_authorization(self):
        """Test case that registers a user, asks its user id though its meter id,
            and confirms that a single user is returned

        Register account, activate user, login and get meter-to-user.
        """
        clean_account()
        email = "riscas.cat1+na@gmail.com"
        meter_id = METER_IDS_WITH_API_KEY[0]
        
        _, new_user_id = register_basic_user(self.client, email, meter_id=meter_id)
        _ = confirm_user_account(self.client, new_user_id)
        _, auth = user_login(self.client, email, "123456")

        # Get userId thought meterId
        query_string = {"meter-ids": [meter_id]}
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
            "Authorization": auth,
        }
        response = self.client.open(
            "/api/account/meter-to-user",
            method="GET",
            headers=headers,
            query_string=query_string,
        )

        users = json.loads(response.data.decode("utf-8"))
        self.assertEqual(len(users), 1)
        self.assertEqual(users[0]["user_id"], new_user_id)

if __name__ == "__main__":
    unittest.main()