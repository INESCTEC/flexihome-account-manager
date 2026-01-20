#!/bin/sh

cd account_manager/
alembic upgrade head
cd ../

python3 -m account_manager
