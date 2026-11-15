#!/bin/sh
# Runs once, on first initialization of the postgres data volume.
# Creates:
#   pathos_owner  - owns the pathos database, runs migrations (pathosctl)
#   pathos_app    - least-privilege runtime role used by the API and jobs
#   keycloak      - owns the keycloak database
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
  -v owner_pw="$PATHOS_DB_OWNER_PASSWORD" -v app_pw="$PATHOS_DB_APP_PASSWORD" -v kc_pw="$KEYCLOAK_DB_PASSWORD" <<'SQL'
CREATE ROLE pathos_owner LOGIN PASSWORD :'owner_pw';
CREATE ROLE pathos_app LOGIN PASSWORD :'app_pw';
CREATE ROLE keycloak LOGIN PASSWORD :'kc_pw';
CREATE DATABASE pathos OWNER pathos_owner;
CREATE DATABASE keycloak OWNER keycloak;
REVOKE ALL ON DATABASE pathos FROM PUBLIC;
REVOKE ALL ON DATABASE keycloak FROM PUBLIC;
GRANT CONNECT ON DATABASE pathos TO pathos_app;
\connect pathos
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
ALTER SCHEMA public OWNER TO pathos_owner;
SQL
