# coding: utf-8

from __future__ import absolute_import
import unittest
import uuid

from flask import json
from time import sleep

from jsonschema import validate

from account_manager.test.json_schemas import UserSchema
from account_manager.test import BaseTestCase
from account_manager.test import auth as hems_auth
from account_manager.test.helper_functions import register_basic_user, confirm_user_account, user_login
from account_manager.test.helper_functions import METER_IDS_WITH_API_KEY
from account_manager.config import Config

from account_manager.models.dbmodels import (
    db,
    DBUser,
    DBUserSettings,
    DBNotDisturb,
    DBConfirmationToken,
    DBForgotPasswordToken,
    DBAccountRecoveryToken,
    DBEvent,
    DBProcessedEvent,
)

import datetime
from datetime import timezone

import hashlib


def clean_account():
    try:
        DBNotDisturb.query.delete()
        DBUserSettings.query.delete()
        DBUser.query.delete()
        DBConfirmationToken.query.delete()
        DBForgotPasswordToken.query.delete()
        DBAccountRecoveryToken.query.delete()
        DBEvent.query.delete()
        DBProcessedEvent.query.delete()
        db.session.commit()
    except Exception as e:
        print(repr(e))
        print("MOCK DATABASE - FAILED TO DELETE ACCOUNT DB")
        db.session.rollback()

    db.create_all()


class TestAccountManagementController(BaseTestCase):
    """AccountManagementController integration test stubs"""


    def test_register_without_expo_token(self):
        """Test case to register user without expo_token

        Endpoint to register user without expo token (expo_token is not mandatory)
        """
        clean_account()
        email = "riscas.cat1+oa@gmail.com"

        _, _ = register_basic_user(self.client, email, expo_token="no token")

    def test_register_with_none_as_expo_token(self):
        """Test case to register user with expo token equal to None

        Endpoint to register user with expo token equal to None (expo_token is not mandatory)
        """
        clean_account()
        email = "riscas.cat1+oa@gmail.com"

        _, _ = register_basic_user(self.client, email, expo_token=None)

    def test_register_with_random_expo_token(self):
        """Test case to register user with expo token being provided

        Endpoint to register user with expo token equal to random string
        """
        clean_account()
        email = "riscas.cat1+oa@gmail.com"

        _, _ = register_basic_user(self.client, email, expo_token="test_expo_token")

    def test_confirm_account_token_get_verify_if_not_none(self):
        """Test case to confirm that token is not none

        Endpoint to get the webpage with the button to confirm account by clicking the link sent to the e-mail.
        """
        clean_account()
        email = "riscas.cat1+oa@gmail.com"

        _, new_user_id = register_basic_user(self.client, email)


        # Get page to confirm account
        confirmationToken = None
        tries = 3
        while (confirmationToken is None) & (tries > 0):
            sleep(1)
            confirmationToken = DBConfirmationToken.query.filter_by(
                user_id=new_user_id
            ).first()
            if confirmationToken is None:
                tries = tries - 1

        self.assertTrue(confirmationToken is not None)

    def test_confirm_account_token_get_confirm_account(self):
        """Test case for getting confirmation account token

        Endpoint to get the webpage with the button to confirm account by clicking the link sent to the e-mail.
        """
        clean_account()
        email = "riscas.cat1+oa@gmail.com"

        _, new_user_id = register_basic_user(self.client, email)


        # Get page to confirm account
        confirmationToken = None
        tries = 3
        while (confirmationToken is None) & (tries > 0):
            sleep(1)
            confirmationToken = DBConfirmationToken.query.filter_by(
                user_id=new_user_id
            ).first()
            if confirmationToken is None:
                tries = tries - 1

        response = self.client.open(
            f"/api/account/confirm-account/{confirmationToken.token}",
            method="GET",
            content_type="application/json",
        )
        self.assert200(response, "Response body is : " + response.data.decode("utf-8"))

    def test_confirm_account_token_post(self):
        """Test case for confirming account using token

        Endpoint to confirm account by clicking the button on the webpage of the link sent to the e-mail.
        """
        clean_account()
        email = "riscas.cat1+ob@gmail.com"

        _, new_user_id = register_basic_user(self.client, email)


        # Test for expired token
        confirmationToken = None
        tries = 3
        while (confirmationToken is None) & (tries > 0):
            sleep(1)
            confirmationToken = DBConfirmationToken.query.filter_by(
                user_id=new_user_id
            ).first()
            if confirmationToken is None:
                tries = tries - 1

        confirmationToken.expiration_timestamp = datetime.datetime.now(timezone.utc)
        db.session.commit()

        response = self.client.open(
            f"/api/account/confirm-account/{confirmationToken.token}",
            method="POST",
            content_type="application/json",
        )
        self.assert404(response, "Response body is : " + response.data.decode("utf-8"))

    def test_register_normal(self):
        """Test case that registers a user

        Register account.
        """
        clean_account()
        email = "riscas.cat1+a@gmail.com"
        register_response, _ = register_basic_user(self.client, email, error=True)

        self.assertStatus(
            register_response, 201, "Response body is : " + register_response.data.decode("utf-8")
        )


    def test_register_duplicated_email(self):
        """Test case that registers a user and tries to register another with the same e-mail

        Register account.
        """
        clean_account()
        email = "riscas.cat1+a2@gmail.com"

        register_response, _ = register_basic_user(self.client, email, METER_IDS_WITH_API_KEY[0])

        # Register same user
        register_response, _ = register_basic_user(self.client, email, METER_IDS_WITH_API_KEY[1], error=True)
        self.assertStatus(
            register_response, 409, "Response body is : " + register_response.data.decode("utf-8")
        )

        register_response = json.loads(register_response.data.decode("utf-8"))
        self.assertTrue(register_response["error"] != None)


    def test_register_duplicated_meterid(self):
        """Test case that registers a user and tries to register another with the same meterid

        Register account.
        """
        clean_account()
        email = "riscas.cat1+a3@gmail.com"
        meter_id = METER_IDS_WITH_API_KEY[0]

        register_response, _ = register_basic_user(self.client, email, meter_id=meter_id)

        # Register same meter id
        email = "riscas.cat1+a4@gmail.com"
        register_response, _ = register_basic_user(self.client, email, meter_id=meter_id, error=True)
        

        self.assertStatus(
            register_response, 409, "Response body is : " + register_response.data.decode("utf-8")
        )
        register_response = json.loads(register_response.data.decode("utf-8"))
        self.assertTrue(register_response["error"] != None)

    def test_register_non_existing_meterid(self):
        """Test case that registers a user using a non existing (non mapped) meter_id

        Register account.
        """
        clean_account()
        email = "riscas.cat1+a3@gmail.com"

        register_response, _ = register_basic_user(self.client, email, meter_id="abcd1234", error=True)

        self.assertStatus(
            register_response, 404, "Response body is : " + register_response.data.decode("utf-8")
        )
        register_response = json.loads(register_response.data.decode("utf-8"))
        self.assertTrue(register_response["error"] != None)
    
    def test_register_non_existing_apikey(self):
        """Test case that registers a user using a meter_id without a api key mapped

        Register account.
        """
        clean_account()
        email = "riscas.cat1+a3@gmail.com"

        register_response, new_user_id = register_basic_user(self.client, email, meter_id="NLV_CLIENT_9953")

        self.assertNotIn("api_key", register_response)
        
    def test_delete_user_soft_without_authorization(self):
        """Test case that registers a user and soft deletes it

        Register account, soft delete user
        """
        clean_account()
        email = "riscas.cat1+l@gmail.com"

        _, new_user_id = register_basic_user(self.client, email)
        _ = confirm_user_account(self.client, new_user_id)


        # Soft Delete user
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
        }
        query_string = {"user-id": new_user_id, "delete_type": "soft"}
        response = self.client.open(
            "/api/account/user",
            method="DELETE",
            headers=headers,
            query_string=query_string,
        )
        self.assert200(response, "Response body is : " + response.data.decode("utf-8"))


    def test_delete_user_soft_without_authorization_user_settings_not_returned(self):
        """Test case that registers a user and soft deletes it

        Register account, soft delete user, get user
        """
        clean_account()
        email = "riscas.cat1+l@gmail.com"
        meter_id = METER_IDS_WITH_API_KEY[0]

        _, new_user_id = register_basic_user(self.client, email)
        _ = confirm_user_account(self.client, new_user_id)


        # Soft Delete user
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
        }
        query_string = {"user-id": new_user_id, "delete_type": "soft"}
        response = self.client.open(
            "/api/account/user",
            method="DELETE",
            headers=headers,
            query_string=query_string,
        )

        # Get user settings to test if the user is not returned
        query_string = {"user-ids": new_user_id}
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
        }
        response = self.client.open(
            "/api/account/user",
            method="GET",
            headers=headers,
            query_string=query_string,
        )
        self.assert404(response, "Response body is : " + response.data.decode("utf-8"))

        # Get userId thought meterId, where it should return 404
        query_string = {"meter-ids": [meter_id]}
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
        self.assert404(response, "Response body is : " + response.data.decode("utf-8"))

        # Login
        login_response, _ = user_login(self.client, email, "123456")
        self.assert401(login_response, "Response body is : " + login_response.data.decode("utf-8"))


    def test_delete_user_soft_without_authorization_confirm_user_id_from_users_list(
        self,
    ):
        """Test case that registers a user and soft deletes it

        Register account, soft delete user, get user list, confirm user id
        """
        clean_account()
        email = "riscas.cat1+l@gmail.com"

        _, new_user_id = register_basic_user(self.client, email)
        _ = confirm_user_account(self.client, new_user_id)


        # Soft Delete user
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
        }
        query_string = {"user-id": new_user_id, "delete_type": "soft"}
        response = self.client.open(
            "/api/account/user",
            method="DELETE",
            headers=headers,
            query_string=query_string,
        )

        # Get user list to test if the user is returned (it should not be returned)
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
        }
        response = self.client.open(
            "/api/account/user-list",
            method="GET",
            headers=headers,
            query_string=query_string,
        )

        users = json.loads(response.data.decode("utf-8"))
        found = False
        for user in users:
            if user == new_user_id:
                found = True
                break

        self.assertFalse(found)


    def test_delete_user_soft_with_authorization_after_login_successfull(self):
        """Test case that registers a user, logs in and soft deletes it

        Register account, activate user, login, soft delete user
        """
        clean_account()
        email = "riscas.cat1+la@gmail.com"

        _, new_user_id = register_basic_user(self.client, email)
        _ = confirm_user_account(self.client, new_user_id)
        _, auth = user_login(self.client, email, "123456")


        # Soft Delete user
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
            "Authorization": auth,
        }
        query_string = {"user-id": new_user_id, "delete_type": "soft"}
        response = self.client.open(
            "/api/account/user",
            method="DELETE",
            headers=headers,
            query_string=query_string,
        )
        self.assert200(response, "Response body is : " + response.data.decode("utf-8"))


    def test_delete_user_soft_with_authorization_users_list_returned(self):
        """Test case that registers a user, logs in and soft deletes it

        Register account, activate user, login, soft delete user, get user list
        """
        clean_account()
        email = "riscas.cat1+la@gmail.com"

        _, new_user_id = register_basic_user(self.client, email)
        _ = confirm_user_account(self.client, new_user_id)
        _, auth = user_login(self.client, email, "123456")


        # Soft Delete user
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
            "Authorization": auth,
        }
        query_string = {"user-id": new_user_id, "delete_type": "soft"}
        response = self.client.open(
            "/api/account/user",
            method="DELETE",
            headers=headers,
            query_string=query_string,
        )

        # Get user list to test if the user is returned (it should not be returned)
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
        }
        response = self.client.open(
            "/api/account/user-list",
            method="GET",
            headers=headers,
            query_string=query_string,
        )
        self.assert200(response, "Response body is : " + response.data.decode("utf-8"))

        users = json.loads(response.data.decode('utf-8'))
        found = False
        for user in users:
            if user == new_user_id:
                found = True
                break

        self.assertFalse(found)


    def test_delete_user_soft_with_authorization_get_userid_through_meterid_unsuccessful(
        self,
    ):
        """Test case that registers a user, logs in and soft deletes it

        Register account, activate user, login, soft delete user, get meter-to-user
        """
        clean_account()
        email = "riscas.cat1+la@gmail.com"
        meter_id = METER_IDS_WITH_API_KEY[0]

        _, new_user_id = register_basic_user(self.client, email, meter_id=meter_id)
        _ = confirm_user_account(self.client, new_user_id)
        _, auth = user_login(self.client, email, "123456")


        # Soft Delete user
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
            "Authorization": auth,
        }
        query_string = {"user-id": new_user_id, "delete_type": "soft"}
        response = self.client.open(
            "/api/account/user",
            method="DELETE",
            headers=headers,
            query_string=query_string,
        )

        # Get userId thought meterId, where it should return 404
        query_string = {"meter-ids": [meter_id]}
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
        self.assert404(response, "Response body is : " + response.data.decode("utf-8"))


    def test_delete_user_soft_with_authorization_login_unsuccessful(self):
        """Test case that registers a user, logs in and soft deletes it

        Register account, activate user, login, soft delete user, login
        """
        clean_account()
        email = "riscas.cat1+la@gmail.com"

        _, new_user_id = register_basic_user(self.client, email)
        _ = confirm_user_account(self.client, new_user_id)
        _, auth = user_login(self.client, email, "123456")
        

        # Soft Delete user
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
            "Authorization": auth,
        }
        query_string = {"user-id": new_user_id, "delete_type": "soft"}
        _ = self.client.open(
            "/api/account/user",
            method="DELETE",
            headers=headers,
            query_string=query_string,
        )

        # Login
        login_response, auth = user_login(self.client, email, "123456")
        self.assert401(login_response, "Response body is : " + login_response.data.decode("utf-8"))


    def test_delete_user_hard_without_authorization(self):
        """Test case that registers a user and hard deletes it

        Register account, activate user, hard delete user, get user list
        """
        clean_account()
        email = "riscas.cat1+m@gmail.com"
        meter_id = METER_IDS_WITH_API_KEY[0]

        _, new_user_id = register_basic_user(self.client, email)
        _ = confirm_user_account(self.client, new_user_id)


        # Hard Delete user
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
        }
        query_string = {"user-id": new_user_id, "delete_type": "hard"}
        response = self.client.open(
            "/api/account/user",
            method="DELETE",
            headers=headers,
            query_string=query_string,
        )

        # Get user list to test if the user is not returned
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
        }
        response = self.client.open(
            "/api/account/user-list",
            method="GET",
            headers=headers,
            query_string=query_string,
        )
        self.assert200(response, "Response body is : " + response.data.decode("utf-8"))

        # Get userId thought meterId, where it should return 404
        query_string = {"meter-ids": [meter_id]}
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
        self.assert404(response, "Response body is : " + response.data.decode("utf-8"))

        # Login
        login_response, _ = user_login(self.client, email, "123456")
        self.assert401(login_response, "Response body is : " + login_response.data.decode("utf-8"))

        user = DBUser.query.filter_by(user_id=new_user_id).first()
        tries = 3
        while (user is not None) & (tries > 0):
            sleep(1)
            user = DBUser.query.filter_by(user_id=new_user_id).first()
            if user is not None:
                tries = tries - 1

        self.assertTrue(user == None)

        # Check database for any data
        data = DBUserSettings.query.filter_by(user_id=new_user_id).first()
        self.assertTrue(data == None)

        data = DBUserSettings.query.filter_by(user_id=new_user_id).first()
        self.assertTrue(data == None)

        data = DBUser.query.filter_by(user_id=new_user_id).first()
        self.assertTrue(data == None)

        data = DBConfirmationToken.query.filter_by(user_id=new_user_id).first()
        self.assertTrue(data == None)

        data = DBForgotPasswordToken.query.filter_by(user_id=new_user_id).first()
        self.assertTrue(data == None)

        data = DBAccountRecoveryToken.query.filter_by(user_id=new_user_id).first()
        self.assertTrue(data == None)


    def test_delete_user_hard_with_authorization(
        self,
    ):
        """Test case that registers a user, logs in and hard deletes it

        Register account, activate user, login, hard delete user, check if the user is not returned, get meter-to-user
        """
        clean_account()
        email = "riscas.cat1+ma@gmail.com"
        meter_id = METER_IDS_WITH_API_KEY[0]

        _, new_user_id = register_basic_user(self.client, email, meter_id=meter_id)
        _ = confirm_user_account(self.client, new_user_id)
        _, auth = user_login(self.client, email, "123456")


        # Hard Delete user
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
            "Authorization": auth,
        }
        query_string = {"user-id": new_user_id, "delete_type": "hard"}
        response = self.client.open(
            "/api/account/user",
            method="DELETE",
            headers=headers,
            query_string=query_string,
        )
        self.assert200(response, "Response body is : " + response.data.decode("utf-8"))

        # Get userId thought meterId, where it should return 404
        query_string = {"meter-ids": [meter_id]}
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
        self.assert404(response, "Response body is : " + response.data.decode("utf-8"))

        # Login
        login_response, _ = user_login(self.client, email, "123456")
        self.assert401(login_response, "Response body is : " + login_response.data.decode("utf-8"))

        user = DBUser.query.filter_by(user_id=new_user_id).first()
        tries = 3
        while (user is not None) & (tries > 0):
            sleep(1)
            user = DBUser.query.filter_by(user_id=new_user_id).first()
            if user is not None:
                tries = tries - 1

        self.assertTrue(user == None)

        # Check database for any data
        data = DBUserSettings.query.filter_by(user_id=new_user_id).first()
        self.assertTrue(data == None)

        data = DBUserSettings.query.filter_by(user_id=new_user_id).first()
        self.assertTrue(data == None)

        data = DBUser.query.filter_by(user_id=new_user_id).first()
        self.assertTrue(data == None)

        data = DBConfirmationToken.query.filter_by(user_id=new_user_id).first()
        self.assertTrue(data == None)

        data = DBForgotPasswordToken.query.filter_by(user_id=new_user_id).first()
        self.assertTrue(data == None)

        data = DBAccountRecoveryToken.query.filter_by(user_id=new_user_id).first()
        self.assertTrue(data == None)

    def test_post_user_normal(self):
        """Test case that registers a user, logs in, and posts new information about the user

        Register account, activate user, login, cand post new user.
        """
        clean_account()
        email = "riscas.cat1+j@gmail.com"

        _, new_user_id = register_basic_user(self.client, email)
        _ = confirm_user_account(self.client, new_user_id)
        _, auth = user_login(self.client, email, "123456")


        # POST user
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
            "Authorization": auth,
        }
        post_request_body = {
            "contracted_power": "6.9 kVA",
            "country": "PT",
            "email": email,
            "first_name": "TestPOST",
            "global_optimizer": True,
            "last_name": "TestPOST",
            "meter_id": METER_IDS_WITH_API_KEY[0],
            "not_disturb": {
                "friday": [],
                "monday": [],
                "saturday": [],
                "sunday": [],
                "thursday": [
                    {
                        "start_timestamp": datetime.datetime(
                            2021, 1, 1, 1, 0, 0, tzinfo=datetime.timezone.utc
                        ).isoformat(),
                        "end_timestamp": datetime.datetime(
                            2021, 1, 1, 2, 0, 0, tzinfo=datetime.timezone.utc
                        ).isoformat(),
                    }
                ],
                "tuesday": [],
                "wednesday": [],
            },
            "postal_code": "4450-001",
            "schedule_type": "economic",
            "tarif_type": "bi-hourly",
            "user_id": new_user_id,
        }
        response = self.client.open(
            "/api/account/user",
            method="POST",
            headers=headers,
            data=json.dumps(post_request_body),
            content_type="application/json",
        )
        self.assert200(response, "Response body is : " + response.data.decode("utf-8"))

        userResponse = json.loads(response.data.decode("utf-8"))

        validate(userResponse, UserSchema)

        # Remove keys not sent in the request
        userResponse.pop("is_active", None)
        userResponse.pop("api_key", None)
        userResponse.pop("is_google_account", None)
        userResponse.pop("modified_timestamp", None)
        userResponse.pop("permissions", None)

        self.maxDiff = None

        self.assertEqual(userResponse, post_request_body)

    def test_post_user_new_meter_id(self):
        """Test case that registers a user, logs in, and posts new information about the user (new meter_id)

        Register account, activate user, login, and post new user (with new meter_id).
        """
        clean_account()
        email = "riscas.cat1+j@gmail.com"

        _, new_user_id = register_basic_user(self.client, email, meter_id="NLV_CLIENT_8585")
        _ = confirm_user_account(self.client, new_user_id)
        _, auth = user_login(self.client, email, "123456")


        # POST user
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
            "Authorization": auth,
        }
        post_request_body = {
            "contracted_power": "6.9 kVA",
            "country": "PT",
            "email": email,
            "first_name": "TestPOST",
            "global_optimizer": True,
            "last_name": "TestPOST",
            "meter_id": "NLV_CLIENT_8813",
            "not_disturb": {
                "friday": [],
                "monday": [],
                "saturday": [],
                "sunday": [],
                "thursday": [
                    {
                        "start_timestamp": datetime.datetime(
                            2021, 1, 1, 1, 0, 0, tzinfo=datetime.timezone.utc
                        ).isoformat(),
                        "end_timestamp": datetime.datetime(
                            2021, 1, 1, 2, 0, 0, tzinfo=datetime.timezone.utc
                        ).isoformat(),
                    }
                ],
                "tuesday": [],
                "wednesday": [],
            },
            "postal_code": "4450-001",
            "schedule_type": "economic",
            "tarif_type": "bi-hourly",
            "user_id": new_user_id,
        }
        response = self.client.open(
            "/api/account/user",
            method="POST",
            headers=headers,
            data=json.dumps(post_request_body),
            content_type="application/json",
        )
        self.assert200(response, "Response body is : " + response.data.decode("utf-8"))

        userResponse = json.loads(response.data.decode("utf-8"))

        validate(userResponse, UserSchema)

        self.assertEqual(userResponse["meter_id"], "NLV_CLIENT_8813")
        self.assertEqual(userResponse["api_key"], "B7O4USACNRWHA4CQ")

        # Remove keys not sent in the request
        userResponse.pop("is_active", None)
        userResponse.pop("api_key", None)
        userResponse.pop("is_google_account", None)
        userResponse.pop("modified_timestamp", None)
        userResponse.pop("permissions", None)

        self.maxDiff = None

        self.assertEqual(userResponse, post_request_body)

    def test_post_user_new_non_existing_meter_id(self):
        """Test case that registers a user, logs in, and tries to post new information about the user (new non existing meter_id)

        Register account, activate user, login, and post new user (with new non existing meter_id).
        """
        clean_account()
        email = "riscas.cat1+j@gmail.com"

        _, new_user_id = register_basic_user(self.client, email, meter_id=METER_IDS_WITH_API_KEY[0])
        _ = confirm_user_account(self.client, new_user_id)
        _, auth = user_login(self.client, email, "123456")


        # POST user
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
            "Authorization": auth,
        }
        post_request_body = {
            "contracted_power": "6.9 kVA",
            "country": "PT",
            "email": email,
            "first_name": "TestPOST",
            "global_optimizer": True,
            "last_name": "TestPOST",
            "meter_id": "abcd1234",
            "not_disturb": {
                "friday": [],
                "monday": [],
                "saturday": [],
                "sunday": [],
                "thursday": [
                    {
                        "start_timestamp": datetime.datetime(
                            2021, 1, 1, 1, 0, 0, tzinfo=datetime.timezone.utc
                        ).isoformat(),
                        "end_timestamp": datetime.datetime(
                            2021, 1, 1, 2, 0, 0, tzinfo=datetime.timezone.utc
                        ).isoformat(),
                    }
                ],
                "tuesday": [],
                "wednesday": [],
            },
            "postal_code": "4450-001",
            "schedule_type": "economic",
            "tarif_type": "bi-hourly",
            "user_id": new_user_id,
        }
        response = self.client.open(
            "/api/account/user",
            method="POST",
            headers=headers,
            data=json.dumps(post_request_body),
            content_type="application/json",
        )
        self.assert404(response, "Response body is : " + response.data.decode("utf-8"))
    
    def test_post_user_new_duplicated_meter_id(self):
        """Test case that registers two users, logs in, and tries to post new information about one of the users (already existing meter_id)

        Register accounts, activate user, login, and post new user (with already existing meter_id).
        """
        clean_account()
        email1 = "riscas.cat1+a@gmail.com"

        _, new_user_id = register_basic_user(self.client, email1, meter_id=METER_IDS_WITH_API_KEY[0])
        _ = confirm_user_account(self.client, new_user_id)
        _, auth = user_login(self.client, email1, "123456")

        email2 = "riscas.cat1+b@gmail.com"
        _, new_user_id_2 = register_basic_user(self.client, email2, meter_id=METER_IDS_WITH_API_KEY[1])


        # POST user
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
            "Authorization": auth,
        }
        post_request_body = {
            "contracted_power": "6.9 kVA",
            "country": "PT",
            "email": email1,
            "first_name": "TestPOST",
            "global_optimizer": True,
            "last_name": "TestPOST",
            "meter_id": METER_IDS_WITH_API_KEY[1],
            "not_disturb": {
                "friday": [],
                "monday": [],
                "saturday": [],
                "sunday": [],
                "thursday": [
                    {
                        "start_timestamp": datetime.datetime(
                            2021, 1, 1, 1, 0, 0, tzinfo=datetime.timezone.utc
                        ).isoformat(),
                        "end_timestamp": datetime.datetime(
                            2021, 1, 1, 2, 0, 0, tzinfo=datetime.timezone.utc
                        ).isoformat(),
                    }
                ],
                "tuesday": [],
                "wednesday": [],
            },
            "postal_code": "4450-001",
            "schedule_type": "economic",
            "tarif_type": "bi-hourly",
            "user_id": new_user_id,
        }
        response = self.client.open(
            "/api/account/user",
            method="POST",
            headers=headers,
            data=json.dumps(post_request_body),
            content_type="application/json",
        )
        self.assertStatus(
            response, 409, "Response body is : " + response.data.decode("utf-8")
        )

    
    def test_post_user_new_meter_id_no_api_key(self):
        """Test case that registers a user, logs in, and posts new information about the user (new meter_id but without api_key)

        Register account, activate user, login, and post new user (with new meter_id but without api_key).
        """
        clean_account()
        email = "riscas.cat1+j@gmail.com"

        _, new_user_id = register_basic_user(self.client, email, meter_id="NLV_CLIENT_8585")
        _ = confirm_user_account(self.client, new_user_id)
        _, auth = user_login(self.client, email, "123456")


        # POST user
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
            "Authorization": auth,
        }
        post_request_body = {
            "contracted_power": "6.9 kVA",
            "country": "PT",
            "email": email,
            "first_name": "TestPOST",
            "global_optimizer": True,
            "last_name": "TestPOST",
            "meter_id": "NLV_CLIENT_9564",
            "not_disturb": {
                "friday": [],
                "monday": [],
                "saturday": [],
                "sunday": [],
                "thursday": [
                    {
                        "start_timestamp": datetime.datetime(
                            2021, 1, 1, 1, 0, 0, tzinfo=datetime.timezone.utc
                        ).isoformat(),
                        "end_timestamp": datetime.datetime(
                            2021, 1, 1, 2, 0, 0, tzinfo=datetime.timezone.utc
                        ).isoformat(),
                    }
                ],
                "tuesday": [],
                "wednesday": [],
            },
            "postal_code": "4450-001",
            "schedule_type": "economic",
            "tarif_type": "bi-hourly",
            "user_id": new_user_id,
        }
        response = self.client.open(
            "/api/account/user",
            method="POST",
            headers=headers,
            data=json.dumps(post_request_body),
            content_type="application/json",
        )
        self.assert200(response, "Response body is : " + response.data.decode("utf-8"))

        userResponse = json.loads(response.data.decode("utf-8"))

        validate(userResponse, UserSchema)

        self.assertEqual(userResponse["meter_id"], "NLV_CLIENT_9564")
        self.assertNotIn("api_key", userResponse)

        # Remove keys not sent in the request
        userResponse.pop("is_active", None)
        userResponse.pop("api_key", None)
        userResponse.pop("is_google_account", None)
        userResponse.pop("modified_timestamp", None)
        userResponse.pop("permissions", None)

        self.maxDiff = None

        self.assertEqual(userResponse, post_request_body)

    def test_google_register_validate_response(self):
        """Test case that registers a Google account and validates response

        Register and Google login
        """
        # ---- REGISTER USER THAT LOGGED IN WITH GOOGLE ACCOUNT FOR THE FIRST TIME ---- #
        clean_account()
        email = "riscas.cat1+ga@gmail.com"
        register_google_request = {
            "first_name": "Google",
            "last_name": "User",
            "email": email,
        }

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
            "Authorization": f"Bearer {Config.GOOGLE_TOKEN}",
        }
        # Account does not exists, so it will be created
        google_register_response = self.client.open(
            "/api/account/register-google",
            method="POST",
            headers=headers,
            data=json.dumps(register_google_request),
            content_type="application/json",
        )
        self.assertStatus(
            google_register_response,
            201,
            "Response body is : " + google_register_response.data.decode("utf-8"),
        )

    def test_google_login_validate_response(self):
        """Test case that registers a Google account and logs in

        Register and Google login
        """
        # --- REGISTER USER THAT LOGGED IN WITH GOOGLE ACCOUNT FOR THE FIRST TIME --- #
        clean_account()
        email = "riscas.cat1+ga@gmail.com"
        register_google_request = {
            "first_name": "Google",
            "last_name": "User",
            "email": email,
        }

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
            "Authorization": f"Bearer {Config.GOOGLE_TOKEN}",
        }

        # Account does not exists, so it will be created
        google_register_response = self.client.open(
            "/api/account/register-google",
            method="POST",
            headers=headers,
            data=json.dumps(register_google_request),
            content_type="application/json",
        )

        # --- LOGIN WITH GOOGLE --- #

        # Google token is converted to Bearer token
        auth = str(google_register_response.headers["Authorization"])
        # Token is already converted, so is_google=False
        user_id = hems_auth.decode_auth_token(auth.split()[1], is_google=False)
        user = DBUser.query.filter_by(user_id=user_id).first()

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
            "Authorization": auth,
        }

        # Account for this google email already exists, so the
        google_login_response = self.client.open(
            "/api/account/register-google",
            method="POST",
            headers=headers,
            data=json.dumps(register_google_request),
            content_type="application/json",
        )
        self.assertStatus(
            google_login_response,
            200,
            "Response body is : " + google_login_response.data.decode("utf-8"),
        )

    def test_google_login_confirm_account_already_created(self):
        """Test case that registers a Google account, logs in, and checks existing account

        Register and Google login
        """
        # --- REGISTER USER THAT LOGGED IN WITH GOOGLE ACCOUNT FOR THE FIRST TIME --- #
        clean_account()
        email = "riscas.cat1+ga@gmail.com"
        register_google_request = {
            "first_name": "Google",
            "last_name": "User",
            "email": email,
        }

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
            "Authorization": f"Bearer {Config.GOOGLE_TOKEN}",
        }
        # Account does not exists, so it will be created
        google_register_response = self.client.open(
            "/api/account/register-google",
            method="POST",
            headers=headers,
            data=json.dumps(register_google_request),
            content_type="application/json",
        )

        # --- LOGIN WITH GOOGLE --- #

        # Google token is converted to Bearer token
        auth = str(google_register_response.headers["Authorization"])
        # Token is already converted, so is_google=False
        user_id = hems_auth.decode_auth_token(auth.split()[1], is_google=False)
        user = DBUser.query.filter_by(user_id=user_id).first()

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
            "Authorization": auth,
        }

        # Account for this google email already exists, so the
        google_login_response = self.client.open(
            "/api/account/register-google",
            method="POST",
            headers=headers,
            data=json.dumps(register_google_request),
            content_type="application/json",
        )

        response = json.loads(google_login_response.data.decode("utf-8"))

        print(f"\nGoogle user login (account already registered): {response}\n")
        # Login response is supposed to have an empty response body
        self.assertEqual(response, "")

    def test_google_login_validate_token_conversion(self):
        """Test case that registers a Google account, logs in, and validates token conversion from Google to Bearer

        Register and Google login
        """
        # --- REGISTER USER THAT LOGGED IN WITH GOOGLE ACCOUNT FOR THE FIRST TIME --- #
        clean_account()
        email = "riscas.cat1+ga@gmail.com"
        register_google_request = {
            "first_name": "Google",
            "last_name": "User",
            "email": email,
        }

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
            "Authorization": f"Bearer {Config.GOOGLE_TOKEN}",
        }
        # Account does not exists, so it will be created
        google_login_response = self.client.open(
            "/api/account/register-google",
            method="POST",
            headers=headers,
            data=json.dumps(register_google_request),
            content_type="application/json",
        )

        # Google token is converted to Bearer token
        auth = str(google_login_response.headers["Authorization"])
        
        # Verify if user is correctly authenticated
        # Google token is converted to Bearer token
        auth = str(google_login_response.headers["Authorization"])
        # Token is already converted, so is_google=False
        user_id = hems_auth.decode_auth_token(auth.split()[1], is_google=False)
        user = DBUser.query.filter_by(user_id=user_id).first()

        # Verify if transformed token is associated with correct user
        self.assertEqual(user_id, user.user_id)

    def test_recover_account_post(self):
        """Test case for recover_account_post, with all working

        Account recovery after soft delete
        """
        clean_account()
        email = "riscas.cat1+sa@gmail.com"

        _, new_user_id = register_basic_user(self.client, email)

        _ = confirm_user_account(self.client, new_user_id)

        # Soft Delete user
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
        }
        query_string = {"user-id": new_user_id, "delete_type": "soft"}
        response = self.client.open(
            "/api/account/user",
            method="DELETE",
            headers=headers,
            query_string=query_string,
        )
        self.assert200(response, "Response body is : " + response.data.decode("utf-8"))

        # Recover account
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
        }
        post_request_body = {"email": email}
        response = self.client.open(
            "/api/account/recover-account",
            method="POST",
            headers=headers,
            data=json.dumps(post_request_body),
            content_type="application/json",
        )

        accountRecoveryToken = None
        tries = 3
        while (accountRecoveryToken is None) & (tries > 0):
            sleep(1)
            accountRecoveryToken = DBAccountRecoveryToken.query.filter_by(
                user_id=new_user_id
            ).first()
            if accountRecoveryToken is None:
                tries = tries - 1

        self.assertTrue(accountRecoveryToken != None)


    def test_recover_account_token_post_non_deleted_account(self):
        """Test case that registers a user, and tries to recover the account
        which fails because the user is not soft deleted

        Register account and try to recover account
        """
        clean_account()
        email = "riscas.cat1+sa@gmail.com"

        _, new_user_id = register_basic_user(self.client, email)

        _ = confirm_user_account(self.client, new_user_id)

        # Recover account
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
        }
        post_request_body = {"email": email}
        response = self.client.open(
            "/api/account/recover-account",
            method="POST",
            headers=headers,
            data=json.dumps(post_request_body),
            content_type="application/json",
        )
        self.assert200(response, "Response body is : " + response.data.decode("utf-8"))

        accountRecoveryToken = DBAccountRecoveryToken.query.filter_by(user_id=new_user_id).first()

        self.assertTrue(accountRecoveryToken == None)
        

    def test_recover_account_token_get(self):
        """Test case that registers a user, soft deletes it and checks the account recovery page

        Register account, soft delete user, and get account recover page.
        """
        clean_account()
        email = "riscas.cat1+sa@gmail.com"

        _, new_user_id = register_basic_user(self.client, email)

        _ = confirm_user_account(self.client, new_user_id)

        # Soft Delete user
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
        }
        query_string = {"user-id": new_user_id, "delete_type": "soft"}
        response = self.client.open(
            "/api/account/user",
            method="DELETE",
            headers=headers,
            query_string=query_string,
        )
        self.assert200(response, "Response body is : " + response.data.decode("utf-8"))

        # Recover account
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
        }
        post_request_body = {"email": email}
        response = self.client.open(
            "/api/account/recover-account",
            method="POST",
            headers=headers,
            data=json.dumps(post_request_body),
            content_type="application/json",
        )

        accountRecoveryToken = None
        tries = 3
        while (accountRecoveryToken is None) & (tries > 0):
            sleep(1)
            accountRecoveryToken = DBAccountRecoveryToken.query.filter_by(
                user_id=new_user_id
            ).first()
            if accountRecoveryToken is None:
                tries = tries - 1

        self.assertTrue(accountRecoveryToken != None)

        # Get page to recover account
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
        }
        response = self.client.open(
            f"/api/account/recover-account/{accountRecoveryToken.token}",
            method="GET",
            headers=headers,
            content_type="application/json",
        )
        self.assert200(response, "Response body is : " + response.data.decode("utf-8"))

    def test_recover_account_token_get_expired_token(self):
        """Test case that registers a user, soft deletes it and checks the account recovery page using an expired token.

        Register account, soft delete user, and get account recover page.
        """
        clean_account()
        email = "riscas.cat1+sa@gmail.com"

        _, new_user_id = register_basic_user(self.client, email)

        _ = confirm_user_account(self.client, new_user_id)

        # Soft Delete user
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
        }
        query_string = {"user-id": new_user_id, "delete_type": "soft"}
        response = self.client.open(
            "/api/account/user",
            method="DELETE",
            headers=headers,
            query_string=query_string,
        )
        self.assert200(response, "Response body is : " + response.data.decode("utf-8"))

        # Recover account
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
        }
        post_request_body = {"email": email}
        response = self.client.open(
            "/api/account/recover-account",
            method="POST",
            headers=headers,
            data=json.dumps(post_request_body),
            content_type="application/json",
        )

        accountRecoveryToken = None
        tries = 3
        while (accountRecoveryToken is None) & (tries > 0):
            sleep(1)
            accountRecoveryToken = DBAccountRecoveryToken.query.filter_by(
                user_id=new_user_id
            ).first()
            if accountRecoveryToken is None:
                tries = tries - 1

        self.assertTrue(accountRecoveryToken != None)

        # Test for expired token
        accountRecoveryToken.expiration_timestamp = datetime.datetime.now(timezone.utc)
        db.session.commit()

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
        }
        response = self.client.open(
            f"/api/account/recover-account/{accountRecoveryToken.token}",
            method="GET",
            headers=headers,
            content_type="application/json",
        )
        self.assert404(response, "Response body is : " + response.data.decode("utf-8"))

    def test_recover_account_token_get_wrong_token(self):
        """Test case that registers a user, soft deletes it and checks the account recovery page using a wrong token.

        Register account, soft delete user, and get account recover page.
        """
        clean_account()
        email = "riscas.cat1+sa@gmail.com"

        _, new_user_id = register_basic_user(self.client, email)

        _ = confirm_user_account(self.client, new_user_id)

        # Soft Delete user
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
        }
        query_string = {"user-id": new_user_id, "delete_type": "soft"}
        response = self.client.open(
            "/api/account/user",
            method="DELETE",
            headers=headers,
            query_string=query_string,
        )
        self.assert200(response, "Response body is : " + response.data.decode("utf-8"))

        # Recover account
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
        }
        post_request_body = {"email": email}
        response = self.client.open(
            "/api/account/recover-account",
            method="POST",
            headers=headers,
            data=json.dumps(post_request_body),
            content_type="application/json",
        )

        accountRecoveryToken = None
        tries = 3
        while (accountRecoveryToken is None) & (tries > 0):
            sleep(1)
            accountRecoveryToken = DBAccountRecoveryToken.query.filter_by(
                user_id=new_user_id
            ).first()
            if accountRecoveryToken is None:
                tries = tries - 1
        
        self.assertTrue(accountRecoveryToken != None)

        # Recover account (wrong token)
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
        }
        token = hashlib.sha256()
        token.update(uuid.uuid4().bytes)
        token.hexdigest()
        response = self.client.open(
            f"/api/account/recover-account/{token.hexdigest()}",
            method="GET",
            headers=headers,
            content_type="application/json",
        )
        self.assert404(response, "Response body is : " + response.data.decode("utf-8"))


    def test_recover_account_token_post(self):
        """Test case that registers a user, soft deletes it and recovers the account successfully

        Register account, soft delete user, and recover account.
        """
        clean_account()
        email = "riscas.cat1+sa@gmail.com"

        _, new_user_id = register_basic_user(self.client, email)

        _ = confirm_user_account(self.client, new_user_id)

        # Soft Delete user
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
        }
        query_string = {"user-id": new_user_id, "delete_type": "soft"}
        response = self.client.open(
            "/api/account/user",
            method="DELETE",
            headers=headers,
            query_string=query_string,
        )
        self.assert200(response, "Response body is : " + response.data.decode("utf-8"))

        # Recover account
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
        }
        post_request_body = {"email": email}
        response = self.client.open(
            "/api/account/recover-account",
            method="POST",
            headers=headers,
            data=json.dumps(post_request_body),
            content_type="application/json",
        )

        accountRecoveryToken = None
        tries = 3
        while (accountRecoveryToken is None) & (tries > 0):
            sleep(1)
            accountRecoveryToken = DBAccountRecoveryToken.query.filter_by(
                user_id=new_user_id
            ).first()
            if accountRecoveryToken is None:
                tries = tries - 1

        self.assertTrue(accountRecoveryToken != None)

        # Recover account last step
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
        }
        response = self.client.open(
            f"/api/account/recover-account/{accountRecoveryToken.token}",
            method="POST",
            headers=headers,
            content_type="application/json",
        )
        self.assert200(response, "Response body is : " + response.data.decode("utf-8"))

    def test_recover_account_token_post_expired_token(self):
        """Test case that registers a user, soft deletes it and tries to recover the account using an expired token.

        Register account, soft delete user, and recover account.
        """
        clean_account()
        email = "riscas.cat1+sa@gmail.com"

        _, new_user_id = register_basic_user(self.client, email)

        _ = confirm_user_account(self.client, new_user_id)

        # Soft Delete user
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
        }
        query_string = {"user-id": new_user_id, "delete_type": "soft"}
        response = self.client.open(
            "/api/account/user",
            method="DELETE",
            headers=headers,
            query_string=query_string,
        )
        self.assert200(response, "Response body is : " + response.data.decode("utf-8"))

        # Recover account
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
        }
        post_request_body = {"email": email}
        response = self.client.open(
            "/api/account/recover-account",
            method="POST",
            headers=headers,
            data=json.dumps(post_request_body),
            content_type="application/json",
        )

        accountRecoveryToken = None
        tries = 3
        while (accountRecoveryToken is None) & (tries > 0):
            sleep(1)
            accountRecoveryToken = DBAccountRecoveryToken.query.filter_by(
                user_id=new_user_id
            ).first()
            if accountRecoveryToken is None:
                tries = tries - 1

        self.assertTrue(accountRecoveryToken != None)

        # Test for expired token
        accountRecoveryToken.expiration_timestamp = datetime.datetime.now(timezone.utc)
        db.session.commit()

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
        }
        response = self.client.open(
            f"/api/account/recover-account/{accountRecoveryToken.token}",
            method="POST",
            headers=headers,
            content_type="application/json",
        )
        self.assert404(response, "Response body is : " + response.data.decode("utf-8"))

    def test_recover_account_token_post_wrong_token(self):
        """Test case that registers a user, soft deletes it and tries to recover the account using a wrong token.

        Register account, soft delete user, and recover account.
        """
        clean_account()
        email = "riscas.cat1+sa@gmail.com"

        _, new_user_id = register_basic_user(self.client, email)

        _ = confirm_user_account(self.client, new_user_id)

        # Soft Delete user
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
        }
        query_string = {"user-id": new_user_id, "delete_type": "soft"}
        response = self.client.open(
            "/api/account/user",
            method="DELETE",
            headers=headers,
            query_string=query_string,
        )
        self.assert200(response, "Response body is : " + response.data.decode("utf-8"))

        # Recover account
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
        }
        post_request_body = {"email": email}
        response = self.client.open(
            "/api/account/recover-account",
            method="POST",
            headers=headers,
            data=json.dumps(post_request_body),
            content_type="application/json",
        )

        accountRecoveryToken = None
        tries = 3
        while (accountRecoveryToken is None) & (tries > 0):
            sleep(1)
            accountRecoveryToken = DBAccountRecoveryToken.query.filter_by(
                user_id=new_user_id
            ).first()
            if accountRecoveryToken is None:
                tries = tries - 1
        
        self.assertTrue(accountRecoveryToken != None)

        # Recover account (wrong token)
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
        }
        token = hashlib.sha256()
        token.update(uuid.uuid4().bytes)
        token.hexdigest()
        response = self.client.open(
            f"/api/account/recover-account/{token.hexdigest()}",
            method="POST",
            headers=headers,
            content_type="application/json",
        )
        self.assert404(response, "Response body is : " + response.data.decode("utf-8"))
    
    def test_post_recover_account_full_flow(self):
        """Test case that registers a user, soft deletes it, recovers the account, and logs in with it.

        Register account, soft delete user, recovers account using the two POSTs, and login
        """
        clean_account()
        email = "riscas.cat1+sa@gmail.com"

        _, new_user_id = register_basic_user(self.client, email)

        _ = confirm_user_account(self.client, new_user_id)

        # Soft Delete user
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
        }
        query_string = {"user-id": new_user_id, "delete_type": "soft"}
        response = self.client.open(
            "/api/account/user",
            method="DELETE",
            headers=headers,
            query_string=query_string,
        )
        self.assert200(response, "Response body is : " + response.data.decode("utf-8"))

        # Recover account
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
        }
        post_request_body = {"email": email}
        response = self.client.open(
            "/api/account/recover-account",
            method="POST",
            headers=headers,
            data=json.dumps(post_request_body),
            content_type="application/json",
        )

        accountRecoveryToken = None
        tries = 3
        while (accountRecoveryToken is None) & (tries > 0):
            sleep(1)
            accountRecoveryToken = DBAccountRecoveryToken.query.filter_by(
                user_id=new_user_id
            ).first()
            if accountRecoveryToken is None:
                tries = tries - 1

        self.assertTrue(accountRecoveryToken != None)

        # Recover account last step
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
        }
        response = self.client.open(
            f"/api/account/recover-account/{accountRecoveryToken.token}",
            method="POST",
            headers=headers,
            content_type="application/json",
        )
        self.assert200(response, "Response body is : " + response.data.decode("utf-8"))

        # Login
        login_response, auth = user_login(self.client, email, "123456")
        self.assert200(login_response, "Response body is : " + login_response.data.decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
