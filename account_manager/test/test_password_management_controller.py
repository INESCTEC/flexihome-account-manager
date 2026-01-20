# coding: utf-8

from __future__ import absolute_import
import unittest
import uuid
import datetime
import hashlib

from flask import json
from time import sleep
from datetime import timezone

from account_manager.test import BaseTestCase
from account_manager.test.helper_functions import register_basic_user, confirm_user_account, user_login

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


class TestPasswordManagementController(BaseTestCase):
    """PasswordManagementController integration test stubs"""

    def test_change_password_normal_passwords_mismatch(self):
        """Test case that registers a user, logs in, and tries to change password

        Register account, activate user, login, change password
        """
        clean_account()
        email = "riscas.cat1+f@gmail.com"
        
        _, new_user_id = register_basic_user(self.client, email)
        _ = confirm_user_account(self.client, new_user_id)
        _, auth = user_login(self.client, email, "123456")


        # Test for password and repeat_password mismatch
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
            "Authorization": auth,
        }
        post_request_body = {
            "old_password": "123456",
            "new_password": "1234567",
            "new_password_repeat": "12345678",
        }
        response = self.client.open(
            "/api/account/change-password",
            method="POST",
            headers=headers,
            data=json.dumps(post_request_body),
            content_type="application/json",
        )
        self.assert400(response, "Response body is : " + response.data.decode("utf-8"))

    def test_change_password_normal_wrong_current_password(self):
        """Test case that registers a user, logs in, and tries to change password

        Register account, activate user, login, change password
        """
        clean_account()
        email = "riscas.cat1+f@gmail.com"
        
        _, new_user_id = register_basic_user(self.client, email)
        _ = confirm_user_account(self.client, new_user_id)
        _, auth = user_login(self.client, email, "123456")


        # Test for wrong current password
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
            "Authorization": auth,
        }
        post_request_body = {
            "old_password": "1234567",
            "new_password": "1234567",
            "new_password_repeat": "1234567",
        }
        response = self.client.open(
            "/api/account/change-password",
            method="POST",
            headers=headers,
            data=json.dumps(post_request_body),
            content_type="application/json",
        )
        self.assert400(response, "Response body is : " + response.data.decode("utf-8"))

    def test_change_password_normal_change_password(self):
        """Test case that registers a user, logs in, and changes password

        Register account, activate user, login, change password
        """
        clean_account()
        email = "riscas.cat1+f@gmail.com"
        
        _, new_user_id = register_basic_user(self.client, email)
        _ = confirm_user_account(self.client, new_user_id)
        _, auth = user_login(self.client, email, "123456")


        # Change password
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
            "Authorization": auth,
        }
        post_request_body = {
            "old_password": "123456",
            "new_password": "1234567",
            "new_password_repeat": "1234567",
        }
        response = self.client.open(
            "/api/account/change-password",
            method="POST",
            headers=headers,
            data=json.dumps(post_request_body),
            content_type="application/json",
        )
        self.assert200(response, "Response body is : " + response.data.decode("utf-8"))

    def test_change_password_normal_login_new_password(self):
        """Test case that registers a user, logs in, changes password, and logs in with new password

        Register account, activate user, login, change password and login
        """
        clean_account()
        email = "riscas.cat1+f@gmail.com"
        
        _, new_user_id = register_basic_user(self.client, email)
        _ = confirm_user_account(self.client, new_user_id)
        _, auth = user_login(self.client, email, "123456")


        # Change password
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
            "Authorization": auth,
        }
        post_request_body = {
            "old_password": "123456",
            "new_password": "1234567",
            "new_password_repeat": "1234567",
        }
        cp_response = self.client.open(
            "/api/account/change-password",
            method="POST",
            headers=headers,
            data=json.dumps(post_request_body),
            content_type="application/json",
        )
        self.assert200(cp_response, "Response body is : " + cp_response.data.decode("utf-8"))

        # Login with new password
        login_response, auth = user_login(self.client, email, "1234567")
        self.assert200(login_response, "Response body is : " + login_response.data.decode("utf-8"))


    def test_forgot_password_normal(self):
        """Test case that registers a user and sends a forgot password request

        Register account and forgot password
        """
        clean_account()
        email = "riscas.cat1+gf@gmail.com"

        _, _ = register_basic_user(self.client, email)


        # Forgot password
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
        }
        post_request_body = {"email": email}
        response = self.client.open(
            "/api/account/forgot-password",
            method="POST",
            headers=headers,
            data=json.dumps(post_request_body),
            content_type="application/json",
        )
        self.assert200(response, "Response body is : " + response.data.decode("utf-8"))

    def test_forgot_password_normal_verify_token(self):
        """Test case that registers a user and sends a forgot password request

        Register account and forgot password
        """
        clean_account()
        email = "riscas.cat1+gf@gmail.com"

        _, new_user_id = register_basic_user(self.client, email)


        # Forgot password
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
        }
        post_request_body = {"email": email}
        _ = self.client.open(
            "/api/account/forgot-password",
            method="POST",
            headers=headers,
            data=json.dumps(post_request_body),
            content_type="application/json",
        )

        forgotPasswordToken = None
        tries = 3
        while (forgotPasswordToken is None) & (tries > 0):
            sleep(1)
            forgotPasswordToken = DBForgotPasswordToken.query.filter_by(
                user_id=new_user_id
            ).first()
            if forgotPasswordToken is None:
                tries = tries - 1

        self.assertTrue(forgotPasswordToken is not None)

    def test_get_forgot_password(self):
        """Test case that registers a user and checks the forgot password page

        Register account and get forgot password page.
        """
        clean_account()
        email = "riscas.cat1+sa@gmail.com"

        _, new_user_id = register_basic_user(self.client, email)


        # Forgot password
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
        }
        post_request_body = {"email": email}
        response = self.client.open(
            "/api/account/forgot-password",
            method="POST",
            headers=headers,
            data=json.dumps(post_request_body),
            content_type="application/json",
        )

        forgotPasswordToken = None
        tries = 3
        while (forgotPasswordToken is None) & (tries > 0):
            sleep(1)
            forgotPasswordToken = DBForgotPasswordToken.query.filter_by(
                user_id=new_user_id
            ).first()
            if forgotPasswordToken is None:
                tries = tries - 1

        # Get page to confirm account
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
        }
        response = self.client.open(
            f"/api/account/forgot-password/{forgotPasswordToken.token}",
            method="GET",
            headers=headers,
            content_type="application/json",
        )
        self.assert200(response, "Response body is : " + response.data.decode("utf-8"))

    def test_get_forgot_password_expired_token(self):
        """Test case that registers a user and gets the forgot password token

        Register account and get forgot password page.
        """
        clean_account()
        email = "riscas.cat1+sa@gmail.com"

        _, new_user_id = register_basic_user(self.client, email)


        # Forgot password
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
        }
        post_request_body = {"email": email}
        response = self.client.open(
            "/api/account/forgot-password",
            method="POST",
            headers=headers,
            data=json.dumps(post_request_body),
            content_type="application/json",
        )

        forgotPasswordToken = None
        tries = 3
        while (forgotPasswordToken is None) & (tries > 0):
            sleep(1)
            forgotPasswordToken = DBForgotPasswordToken.query.filter_by(
                user_id=new_user_id
            ).first()
            if forgotPasswordToken is None:
                tries = tries - 1

        # Test for expired token
        forgotPasswordToken.expiration_timestamp = datetime.datetime.now(timezone.utc)
        db.session.commit()

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
        }
        response = self.client.open(
            f"/api/account/forgot-password/{forgotPasswordToken.token}",
            method="GET",
            headers=headers,
            content_type="application/json",
        )
        self.assert404(response, "Response body is : " + response.data.decode("utf-8"))

    def test_get_forgot_password_wrong_token(self):
        """Test case that registers a user and posts forgot password where new_password and new_repeat_password mismatch

        Register account and get forgot password page.
        """
        clean_account()
        email = "riscas.cat1+sa@gmail.com"

        _, new_user_id = register_basic_user(self.client, email)


        # Forgot password
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
        }
        post_request_body = {"email": email}
        response = self.client.open(
            "/api/account/forgot-password",
            method="POST",
            headers=headers,
            data=json.dumps(post_request_body),
            content_type="application/json",
        )

        forgotPasswordToken = None
        tries = 3
        while (forgotPasswordToken is None) & (tries > 0):
            sleep(1)
            forgotPasswordToken = DBForgotPasswordToken.query.filter_by(
                user_id=new_user_id
            ).first()
            if forgotPasswordToken is None:
                tries = tries - 1

        # Forgot password (wrong token)
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
        }
        token = hashlib.sha256()
        token.update(uuid.uuid4().bytes)
        token.hexdigest()
        response = self.client.open(
            f"/api/account/forgot-password/{token.hexdigest()}",
            method="GET",
            headers=headers,
            content_type="application/json",
        )
        self.assert404(response, "Response body is : " + response.data.decode("utf-8"))

    def test_post_forgot_password_passwords_mismatch(self):
        """Test case that registers a user and oosts forgot password where new_password and new_repeat_password mismatch

        Register account and post forgot password page.
        """
        clean_account()
        email = "riscas.cat1+sb@gmail.com"

        _, new_user_id = register_basic_user(self.client, email)


        # Forgot password
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
        }
        post_request_body = {"email": email}
        _ = self.client.open(
            "/api/account/forgot-password",
            method="POST",
            headers=headers,
            data=json.dumps(post_request_body),
            content_type="application/json",
        )

        forgotPasswordToken = None
        tries = 3
        while (forgotPasswordToken is None) & (tries > 0):
            sleep(1)
            forgotPasswordToken = DBForgotPasswordToken.query.filter_by(
                user_id=new_user_id
            ).first()
            if forgotPasswordToken is None:
                tries = tries - 1

        # Post forgot password where new_password and new_repeat_password mismatch
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": "Bearer special-key",
        }
        data = dict(new_password="123456", new_password_repeat="1234567")
        fp_response = self.client.open(
            f"/api/account/forgot-password/{forgotPasswordToken.token}",
            method="POST",
            headers=headers,
            data=data,
            content_type="application/x-www-form-urlencoded",
        )
        self.assert400(fp_response, "Response body is : " + fp_response.data.decode("utf-8"))


    def test_post_forgot_password_equal_new_and_old_password(self):
        """Test case that registers a user and posts forgot password where old password is equal to new password

        Register account and post forgot password page.
        """
        clean_account()
        email = "riscas.cat1+sb@gmail.com"

        _, new_user_id = register_basic_user(self.client, email)


        # Forgot password
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
        }
        post_request_body = {"email": email}
        response = self.client.open(
            "/api/account/forgot-password",
            method="POST",
            headers=headers,
            data=json.dumps(post_request_body),
            content_type="application/json",
        )

        forgotPasswordToken = None
        tries = 3
        while (forgotPasswordToken is None) & (tries > 0):
            sleep(1)
            forgotPasswordToken = DBForgotPasswordToken.query.filter_by(
                user_id=new_user_id
            ).first()
            if forgotPasswordToken is None:
                tries = tries - 1

        # Old password equal to new password
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": "Bearer special-key",
        }
        data = dict(new_password="123456", new_password_repeat="123456")
        response = self.client.open(
            f"/api/account/forgot-password/{forgotPasswordToken.token}",
            method="POST",
            headers=headers,
            data=data,
            content_type="application/x-www-form-urlencoded",
        )
        self.assert400(response, "Response body is : " + response.data.decode("utf-8"))

    def test_post_forgot_password_new_password(self):
        """Test case that registers a user, forgots password, and creates new password

        Register account and post forgot password page.
        """
        clean_account()
        email = "riscas.cat1+sb@gmail.com"

        _, new_user_id = register_basic_user(self.client, email)


        # Forgot password
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
        }
        post_request_body = {"email": email}
        response = self.client.open(
            "/api/account/forgot-password",
            method="POST",
            headers=headers,
            data=json.dumps(post_request_body),
            content_type="application/json",
        )

        forgotPasswordToken = None
        tries = 3
        while (forgotPasswordToken is None) & (tries > 0):
            sleep(1)
            forgotPasswordToken = DBForgotPasswordToken.query.filter_by(
                user_id=new_user_id
            ).first()
            if forgotPasswordToken is None:
                tries = tries - 1

        # Post forgot password
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": "Bearer special-key",
        }
        data = dict(new_password="1234567", new_password_repeat="1234567")
        response = self.client.open(
            f"/api/account/forgot-password/{forgotPasswordToken.token}",
            method="POST",
            headers=headers,
            data=data,
            content_type="application/x-www-form-urlencoded",
        )
        self.assert200(response, "Response body is : " + response.data.decode("utf-8"))

    def test_post_forgot_password_login_new_password(self):
        """Test case that registers a user, forgots password, creates new password, and logs in with it

        Register account and post forgot password page.
        """
        clean_account()
        email = "riscas.cat1+sb@gmail.com"

        _, new_user_id = register_basic_user(self.client, email)
        

        # Forgot password
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
        }
        post_request_body = {"email": email}
        _ = self.client.open(
            "/api/account/forgot-password",
            method="POST",
            headers=headers,
            data=json.dumps(post_request_body),
            content_type="application/json",
        )

        forgotPasswordToken = None
        tries = 3
        while (forgotPasswordToken is None) & (tries > 0):
            sleep(1)
            forgotPasswordToken = DBForgotPasswordToken.query.filter_by(
                user_id=new_user_id
            ).first()
            if forgotPasswordToken is None:
                tries = tries - 1

        # Post forgot password
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": "Bearer special-key",
        }
        data = dict(new_password="1234567", new_password_repeat="1234567")
        _ = self.client.open(
            f"/api/account/forgot-password/{forgotPasswordToken.token}",
            method="POST",
            headers=headers,
            data=data,
            content_type="application/x-www-form-urlencoded",
        )

        login_response, _ = user_login(self.client, email, "1234567")
        self.assert200(login_response, "Response body is : " + login_response.data.decode("utf-8"))


if __name__ == "__main__":
    unittest.main()