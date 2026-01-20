import logging

import connexion
from flask_testing import TestCase

from flask_sqlalchemy import SQLAlchemy

from account_manager.encoder import JSONEncoder
from account_manager.config import Config
from account_manager.eventConsumers import EventConsumers
import unittest
import os

from hems_auth.auth import Auth

from account_manager.save_meter_id_api_key_mapping import saveMeterIdApiKeyMapping

auth = Auth(jwt_sign_key=Config.JWT_SIGN_KEY,
            jwt_sign_algorithm=Config.JWT_SIGN_ALGORITHM,
            DATABASE_IP=Config.DATABASE_IP,
            DATABASE_PORT=Config.DATABASE_PORT,
            DATABASE_USER=Config.AUTH_DATABASE_USER,
            DATABASE_PASSWORD=Config.AUTH_DATABASE_PASSWORD)


class BaseTestCase(TestCase):

    def create_app(self):
        logging.getLogger('connexion.operation').setLevel('ERROR')

        print("Connexion app")

        # Setup Flask app
        connexionApp = connexion.App(__name__,
                                     specification_dir='../openapi/',
                                     options={"swagger_ui": False},
                                     server_args={'template_folder': os.path.dirname(os.path.realpath(__file__)) + '/../templates/'})
        connexionApp.app.json_encoder = JSONEncoder

        app = connexionApp.app
        app.config.from_object(Config)

        connexionApp.add_api('openapi.yaml',
                             arguments={'title': 'Account Manager Service'},
                             pythonic_params=True,
                             validate_responses=True)

        db = SQLAlchemy(app)

        db.create_all()

        saveMeterIdApiKeyMapping("account_manager/meter_id_api_key_mapping.csv")

        return app

    @classmethod
    def setUpClass(cls):
        print("Event consumers")
        cls.ec = EventConsumers()
        print("Event consumers start")
        cls.ec.start()

    @classmethod
    def tearDownClass(cls):
        print("Event consumers stop")
        cls.ec.stop()
