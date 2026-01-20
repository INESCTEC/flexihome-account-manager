# coding: utf-8

from __future__ import absolute_import
import unittest

import uuid, os

from account_manager import Config
from account_manager.test import BaseTestCase

from account_manager.test.helper_functions import register_basic_user, confirm_user_account, user_login
from account_manager.test.helper_functions import METER_IDS_WITH_API_KEY, METER_IDS_WITHOUT_API_KEY

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


class TestAppUserCommunicationController(BaseTestCase):
    """AppUserCommunicationController integration test stubs"""

    def test_app_version_get(self):
        """Test case for app_version_get

        Retrieve the current build version of the app
        """
        
        clean_account()
        email = "riscas.cat1+ia@gmail.com"
        
        _, new_user_id = register_basic_user(self.client, email)
        _ = confirm_user_account(self.client, new_user_id)
        _, auth = user_login(self.client, email, "123456")
        
        Config.PRIVATE_KEY = os.environ.get("GOOGLE_PRIVATE_KEY").replace("\\n", "\n")
        
        headers = { 
            'Accept': 'application/json',
            'x_correlation_id': str(uuid.uuid4()),
            'Authorization': auth,
        }
        query_string = {'package_name': 'pt.inesctec.interconnect.hems'}
        response = self.client.open(
            '/api/account/app/version',
            method='GET',
            headers=headers,
            query_string=query_string
        )
        self.assert200(response,'Response body is : ' + response.data.decode('utf-8'))
        
    
    def test_app_version_get_no_auth(self):
        """Test case for app_version_get

        Retrieve the current build version of the app
        """
        
        Config.PRIVATE_KEY = os.environ.get("GOOGLE_PRIVATE_KEY").replace("\\n", "\n")
        
        headers = { 
            'Accept': 'application/json',
            'x_correlation_id': str(uuid.uuid4())
        }
        query_string = {'package_name': 'pt.inesctec.interconnect.hems'}
        response = self.client.open(
            '/api/account/app/version',
            method='GET',
            headers=headers,
            query_string=query_string
        )
        self.assert200(response,'Response body is : ' + response.data.decode('utf-8'))
    
    
    def test_app_version_get_unauthorized(self):
        """Test case for app_version_get

        Retrieve the current build version of the app
        """
        
        headers = { 
            'Accept': 'application/json',
            'x_correlation_id': str(uuid.uuid4()),
            "Authorization": "bad_token"
        }
        query_string = {'package_name': 'pt.inesctec.interconnect.hems'}
        response = self.client.open(
            '/api/account/app/version',
            method='GET',
            headers=headers,
            query_string=query_string
        )
        self.assert401(response,'Response body is : ' + response.data.decode('utf-8'))
        
    
    def test_app_version_get_wrong_package_name(self):
        """Test case for app_version_get

        Retrieve the current build version of the app
        """
        
        clean_account()
        email = "riscas.cat1+ia@gmail.com"
        
        _, new_user_id = register_basic_user(self.client, email)
        _ = confirm_user_account(self.client, new_user_id)
        _, auth = user_login(self.client, email, "123456")
        
        Config.PRIVATE_KEY = os.environ.get("GOOGLE_PRIVATE_KEY").replace("\\n", "\n")
        
        headers = { 
            'Accept': 'application/json',
            'x_correlation_id': str(uuid.uuid4()),
            'Authorization': auth,
        }
        query_string = {'package_name': 'wrong_name'}
        response = self.client.open(
            '/api/account/app/version',
            method='GET',
            headers=headers,
            query_string=query_string
        )
        self.assert400(response,'Response body is : ' + response.data.decode('utf-8'))
    
    
    def test_app_version_get_google_authentication_fail(self):
        """Test case for app_version_get

        Retrieve the current build version of the app
        """
        
        clean_account()
        email = "riscas.cat1+ia@gmail.com"
        
        _, new_user_id = register_basic_user(self.client, email)
        _ = confirm_user_account(self.client, new_user_id)
        _, auth = user_login(self.client, email, "123456")
        
        Config.PRIVATE_KEY = "wrong_key"
        
        headers = {
            'Accept': 'application/json',
            'x_correlation_id': str(uuid.uuid4()),
            'Authorization': auth,
        }
        query_string = {'package_name': 'pt.inesctec.interconnect.hems'}
        response = self.client.open(
            '/api/account/app/version',
            method='GET',
            headers=headers,
            query_string=query_string
        )
        self.assert500(response,'Response body is : ' + response.data.decode('utf-8'))


if __name__ == '__main__':
    unittest.main()
