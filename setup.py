# coding: utf-8

import sys
from setuptools import setup, find_packages

NAME = "account_manager"
VERSION = "1.2.0"

# To install the library, run the following
#
# python setup.py install
#
# prerequisite: setuptools
# http://pypi.python.org/pypi/setuptools

REQUIRES = [
    "connexion>=2.0.2",
    "swagger-ui-bundle>=0.0.2",
    "python_dateutil>=2.6.0"
]

setup(
    name=NAME,
    version=VERSION,
    description="User Account Manager Service",
    author_email="vasco.m.campos@inesctec.pt",
    url="",
    keywords=["OpenAPI", "User Account Manager Service"],
    install_requires=REQUIRES,
    packages=find_packages(),
    package_data={'': ['openapi/openapi.yaml']},
    include_package_data=True,
    entry_points={
        'console_scripts': ['account_manager=account_manager.__main__:main']},
    long_description="""\
    User Account Manager Service OpenAPI definition. This service has the following functions: register, login, change user credentials and update it&#39;s profile settings. Find out more: [User Account Manager Service documentation](https://gitlab.inesctec.pt/cpes/european-projects/interconnect/hems/hems-documentation/-/blob/master/Microservices/User-Account-Manager-Service.adoc)
    """
)

