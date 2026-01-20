# coding: utf-8

from __future__ import absolute_import
import unittest
import uuid

from flask import json
from time import sleep

from jsonschema import validate

from account_manager.test import BaseTestCase
from account_manager.test.helper_functions import register_basic_user, confirm_user_account, user_login
from account_manager.test.helper_functions import METER_IDS_WITH_API_KEY, METER_IDS_WITHOUT_API_KEY
from account_manager.config import Config

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

from account_manager.test import auth as hems_auth


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


class TestSessionManagementController(BaseTestCase):
    """SessionManagementController integration test stubs"""

    def test_login_normal(self):
        """Test case that registers a user and logs in

        Register account and login.
        """
        clean_account()
        email = "riscas.cat1+b@gmail.com"

        _, new_user_id = register_basic_user(self.client, email)
        _ = confirm_user_account(self.client, new_user_id)
        login_response, _ = user_login(self.client, email, "123456")

        self.assert200(login_response, "Response body is : " +
                       login_response.data.decode("utf-8"))

    def test_login_wrong_credentials(self):
        """Test case that registers a user and tries to login with wrong credentials

        Register account and login.
        """
        clean_account()
        email = "riscas.cat1+b1@gmail.com"

        _, new_user_id = register_basic_user(self.client, email)
        _ = confirm_user_account(self.client, new_user_id)
        login_response, _ = user_login(self.client, email, "bad_password")

        self.assert401(login_response, "Response body is : " +
                       login_response.data.decode("utf-8"))

    def test_login_user_not_active(self):
        """Test case that registers a user and tries to login with a user that is not active

        Register account and login.
        """
        clean_account()
        email = "riscas.cat1+b2@gmail.com"

        _, _ = register_basic_user(self.client, email)
        login_response, _ = user_login(self.client, email, "bad_password")

        self.assert401(login_response, "Response body is : " +
                       login_response.data.decode("utf-8"))

    def test_logout_normal(self):
        """Test case that registers a user, logs in, and logs out

        Register account, activate user, login and logout.
        """
        clean_account()
        email = "riscas.cat1+c@gmail.com"

        _, new_user_id = register_basic_user(self.client, email)
        _ = confirm_user_account(self.client, new_user_id)
        _, auth = user_login(self.client, email, "123456")

        # Logout
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
            "Authorization": auth,
        }
        response = self.client.open(
            "/api/account/logout",
            method="POST",
            headers=headers,
            content_type="application/json",
        )
        self.assert200(response, "Response body is : " +
                       response.data.decode("utf-8"))

    def test_refresh_token_normal(self):
        """Test case that registers a user, logs in, and refreshes the token

        Register account, activate user, login, and refresh token
        """
        clean_account()
        email = "riscas.cat1+d@gmail.com"

        _, new_user_id = register_basic_user(self.client, email)
        _ = confirm_user_account(self.client, new_user_id)
        _, auth = user_login(self.client, email, "123456")

        # Refresh Token
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
            "Authorization": auth,
        }
        response = self.client.open(
            "/api/account/refresh-token",
            method="POST",
            headers=headers,
            content_type="application/json",
        )
        self.assert200(response, "Response body is : " +
                       response.data.decode("utf-8"))

    def test_refresh_token_normal_get_user_settings(self):
        """Test case that registers a user, logs in, refreshes the
        token, and tests if the new token is valid by sending a
        request to view the user settings

        Register account, activate user, login, refresh token, and get user settings.
        """
        clean_account()
        email = "riscas.cat1+d@gmail.com"

        _, new_user_id = register_basic_user(self.client, email)
        _ = confirm_user_account(self.client, new_user_id)
        _, auth = user_login(self.client, email, "123456")

        # Refresh Token
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
            "Authorization": auth,
        }
        response = self.client.open(
            "/api/account/refresh-token",
            method="POST",
            headers=headers,
            content_type="application/json",
        )

        # Get user settings to test if the new token is accepted
        query_string = {"user-ids": new_user_id}
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
            "Authorization": auth,
        }
        response = self.client.open(
            "/api/account/user",
            method="GET",
            headers=headers,
            query_string=query_string,
        )
        self.assert200(response, "Response body is : " +
                       response.data.decode("utf-8"))

    def test_logout_normal_get_user_settings(self):
        """Test case that registers a user, logs in, logs out, and tests if the new token is valid by sending a
        request to view the user settings

        Register account, activate user, login, logout, and get user settings.
        """
        clean_account()
        email = "riscas.cat1+d@gmail.com"

        _, new_user_id = register_basic_user(self.client, email)
        _ = confirm_user_account(self.client, new_user_id)
        _, auth = user_login(self.client, email, "123456")

        # Logout
        headers = {
            "Accept": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
            "Authorization": auth,
        }
        response = self.client.open(
            "/api/account/logout",
            method="POST",
            headers=headers,
        )
        self.assert200(response, "Response body is : " +
                       response.data.decode("utf-8"))

        # Get user settings to test if the old token is accepted
        query_string = {"user-ids": new_user_id}
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
            "Authorization": auth,
        }
        response = self.client.open(
            "/api/account/user",
            method="GET",
            headers=headers,
            query_string=query_string,
        )
        self.assert401(response, "Response body is : " +
                       response.data.decode("utf-8"))

    def test_delete_user_soft_authotization_login(self):
        """Test case that registers a user, soft deletes it, and tries to perform 
        actions with the previous token and also to login

        Register account, soft delete user, get user data, and login.
        """
        clean_account()
        email = "riscas.cat1+b@gmail.com"

        _, new_user_id = register_basic_user(self.client, email)
        _ = confirm_user_account(self.client, new_user_id)

        login_response, auth = user_login(self.client, email, "123456")

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

        # Get user info to test if the authorization error happens
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
            "Authorization": auth,
        }
        query_string = {"user-ids": [new_user_id]}
        response = self.client.open(
            "/api/account/user",
            method="GET",
            headers=headers,
            query_string=query_string,
        )
        self.assert401(response, "Response body is : " + response.data.decode("utf-8"))

        # Login to test for 404 not found
        login_response, _ = user_login(self.client, email, "123456")

        self.assert401(login_response, "Response body is : " +
                       login_response.data.decode("utf-8"))


    def test_delete_user_soft_authotization_login_google(self):
        """Test case that registers a user using Google, soft deletes it, and tries to perform 
        actions with the previous token and also to login

        Register account with Google, soft delete user, get user data, and login.
        """
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

        # Google token is converted to Bearer token
        auth = str(google_register_response.headers["Authorization"])
        # Token is already converted, so is_google=False
        user_id = hems_auth.decode_auth_token(auth.split()[1], is_google=False)


        # Soft Delete user
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
        }
        query_string = {"user-id": user_id, "delete_type": "soft"}
        response = self.client.open(
            "/api/account/user",
            method="DELETE",
            headers=headers,
            query_string=query_string,
        )
        self.assert200(response, "Response body is : " + response.data.decode("utf-8"))

        # Get user info to test if the authorization error happens
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
            "Authorization": auth,
        }
        query_string = {"user-ids": [user_id]}
        response = self.client.open(
            "/api/account/user",
            method="GET",
            headers=headers,
            query_string=query_string,
        )
        self.assert401(response, "Response body is : " + response.data.decode("utf-8"))

        # Login to test for 404 not found
        login_response, _ = user_login(self.client, email, "123456")

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
            400,
            "Response body is : " + google_register_response.data.decode("utf-8"),
        )

if __name__ == "__main__":
    unittest.main()
