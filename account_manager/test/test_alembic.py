# coding: utf-8

from __future__ import absolute_import
import unittest

from account_manager.test import BaseTestCase

from alembic.config import Config
from alembic.script import ScriptDirectory

class TestAlembic(BaseTestCase):
    """Alembic integration test stubs"""


    def test_only_single_head_revision_in_migrations(self):
        """Test case to register user without expo_token
        """
        config = Config()
        config.set_main_option("script_location", "account_manager:alembic")
        script = ScriptDirectory.from_config(config)

        # This will raise if there are multiple heads
        script.get_current_head()

if __name__ == "__main__":
    unittest.main()
