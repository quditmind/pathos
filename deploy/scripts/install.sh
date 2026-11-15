#!/usr/bin/env bash
# Creates .env with freshly generated secrets. Safe to re-run: an existing
# .env is never overwritten.
set -euo pipefail
cd "$(dirname "$0")/../.."

if [ -f .env ]; then
  echo ".env already exists; leaving it unchanged." >&2
  exit 0
fi
command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 1; }

hex() { openssl rand -hex 32; }
# Readable admin password that satisfies the realm password policy (>= 12 chars).
admin_pw="$(openssl rand -base64 18 | tr -d '/+=' | cut -c1-20)"

email="${PATHOS_BOOTSTRAP_ADMIN_EMAIL:-}"
if [ -z "$email" ] && [ -t 0 ]; then
  read -r -p "Bootstrap administrator email [admin@example.com]: " email
fi
email="$(echo "${email:-admin@example.com}" | tr '[:upper:]' '[:lower:]')"

umask 077
sed \
  -e "s|^PATHOS_BOOTSTRAP_ADMIN_EMAIL=.*|PATHOS_BOOTSTRAP_ADMIN_EMAIL=${email}|" \
  -e "s|^PATHOS_BOOTSTRAP_ADMIN_PASSWORD=.*|PATHOS_BOOTSTRAP_ADMIN_PASSWORD=${admin_pw}|" \
  -e "s|^PATHOS_MASTER_KEY=.*|PATHOS_MASTER_KEY=$(openssl rand -base64 32)|" \
  -e "s|^POSTGRES_SUPERUSER_PASSWORD=.*|POSTGRES_SUPERUSER_PASSWORD=$(hex)|" \
  -e "s|^PATHOS_DB_OWNER_PASSWORD=.*|PATHOS_DB_OWNER_PASSWORD=$(hex)|" \
  -e "s|^PATHOS_DB_APP_PASSWORD=.*|PATHOS_DB_APP_PASSWORD=$(hex)|" \
  -e "s|^KEYCLOAK_DB_PASSWORD=.*|KEYCLOAK_DB_PASSWORD=$(hex)|" \
  -e "s|^VALKEY_PASSWORD=.*|VALKEY_PASSWORD=$(hex)|" \
  -e "s|^KEYCLOAK_ADMIN_PASSWORD=.*|KEYCLOAK_ADMIN_PASSWORD=$(hex)|" \
  -e "s|^PATHOS_OIDC_CLIENT_SECRET=.*|PATHOS_OIDC_CLIENT_SECRET=$(hex)|" \
  -e "s|^PATHOS_KEYCLOAK_PROVISIONER_CLIENT_SECRET=.*|PATHOS_KEYCLOAK_PROVISIONER_CLIENT_SECRET=$(hex)|" \
  -e "s|^PATHOS_WORKER_BOOTSTRAP_TOKEN=.*|PATHOS_WORKER_BOOTSTRAP_TOKEN=$(hex)|" \
  .env.example > .env

cat <<MSG
Created .env (mode 600).

  Admin login:    ${email}
  Temporary pass: ${admin_pw}   (you must change it at first login)

IMPORTANT: back up PATHOS_MASTER_KEY from .env somewhere safe. Without it,
stored credentials cannot be decrypted.

Next: docker compose up -d   then open the PATHOS_PUBLIC_URL from .env
MSG
