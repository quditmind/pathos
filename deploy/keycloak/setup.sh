#!/bin/bash
# Idempotent configuration of the PATHOS realm that the realm import does not
# cover (the import runs only when the realm does not exist yet, so existing
# installations get these settings here too). Runs once after Keycloak is
# healthy, with the bootstrap administrator; PATHOS's own service account
# keeps only user-management rights.
set -euo pipefail
KCADM=/opt/keycloak/bin/kcadm.sh
REALM=pathos
SERVER=${KEYCLOAK_URL:-http://keycloak:8080/auth}

for i in $(seq 1 30); do
  if "$KCADM" config credentials --server "$SERVER" --realm master \
      --user "$KC_BOOTSTRAP_ADMIN_USERNAME" --password "$KC_BOOTSTRAP_ADMIN_PASSWORD" >/dev/null 2>&1; then
    break
  fi
  [ "$i" = 30 ] && { echo "keycloak-setup: cannot sign in to Keycloak" >&2; exit 1; }
  sleep 2
done

# set_requirement FLOW PROVIDER REQUIREMENT: set an execution's requirement.
# The update must carry the execution's priority: Keycloak treats a missing
# priority as 0 and would move the execution to the top of its sub-flow.
set_requirement() {
  local flow="$1" provider="$2" want="$3" line id cur prio
  line=$("$KCADM" get "authentication/flows/$flow/executions" -r "$REALM" --format csv --noquotes \
    --fields id,providerId,priority,requirement | grep ",$provider," || true)
  if [ -z "$line" ]; then
    echo "keycloak-setup: $provider not found in the $flow flow; skipped"
    return
  fi
  IFS=, read -r id _ prio cur <<<"$line"
  if [ "$cur" = "$want" ]; then
    echo "keycloak-setup: $provider already $want"
    return
  fi
  "$KCADM" update "authentication/flows/$flow/executions" -r "$REALM" \
    -b "{\"id\":\"$id\",\"requirement\":\"$want\",\"priority\":$prio}"
  echo "keycloak-setup: $provider $cur -> $want (priority $prio kept)"
}

flow=$("$KCADM" get "realms/$REALM" --fields browserFlow --format csv --noquotes)

# MFA recovery codes: a user who lost the authenticator signs in with a
# one-time recovery code instead of the TOTP code ("Try another way").
set_requirement "$flow" auth-recovery-authn-code-form ALTERNATIVE

# The recovery-codes enrolment action must be registered and enabled (it is
# by default). Only checked: an update would replace the whole registration.
ra=$("$KCADM" get authentication/required-actions -r "$REALM" --format csv --noquotes --fields providerId,alias,enabled \
  | grep '^CONFIGURE_RECOVERY_AUTHN_CODES,' || true)
if [ "$ra" != "CONFIGURE_RECOVERY_AUTHN_CODES,CONFIGURE_RECOVERY_AUTHN_CODES,true" ]; then
  echo "keycloak-setup: WARNING: the recovery codes required action is not registered and enabled ($ra);" \
    "enable 'Recovery Authentication Codes' in the realm's Required actions" >&2
fi
# Multi-tenancy: the ID token carries the user's group paths in "groups";
# PATHOS maps /pathos/<slug> to organization memberships
# (docs/MULTI_TENANCY.md). Ignored by single-organization installs.
cid=$("$KCADM" get clients -r "$REALM" -q clientId=pathos-web --fields id --format csv --noquotes 2>/dev/null || true)
if [ -n "$cid" ]; then
  if "$KCADM" get "clients/$cid/protocol-mappers/models" -r "$REALM" --fields name --format csv --noquotes 2>/dev/null | grep -qx groups; then
    echo "keycloak-setup: groups claim mapper present"
  elif "$KCADM" create "clients/$cid/protocol-mappers/models" -r "$REALM" -s name=groups -s protocol=openid-connect \
      -s protocolMapper=oidc-group-membership-mapper -s 'config."claim.name"=groups' -s 'config."full.path"=true' \
      -s 'config."id.token.claim"=true' -s 'config."access.token.claim"=false' -s 'config."userinfo.token.claim"=false' >/dev/null; then
    echo "keycloak-setup: groups claim mapper added to pathos-web"
  else
    echo "keycloak-setup: WARNING: could not add the groups claim mapper; add it to the pathos-web client (docs/MULTI_TENANCY.md)" >&2
  fi
fi
echo "keycloak-setup: done"
