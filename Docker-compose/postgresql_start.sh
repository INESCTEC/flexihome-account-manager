#!/bin/bash
set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    CREATE DATABASE account_manager;
    CREATE DATABASE jwt_token_management;
    CREATE SCHEMA IF NOT EXISTS data;
EOSQL

