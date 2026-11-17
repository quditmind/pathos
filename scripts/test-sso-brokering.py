#!/usr/bin/env python3
"""End-to-end test of single sign-on through external identity providers.

Creates a throwaway realm in the stack's Keycloak that plays an external
identity provider (OIDC and SAML 2.0), registers it in the PATHOS realm the
way docs/user-guide/authentication.md describes, signs in to PATHOS through
each provider like a browser, checks that PATHOS provisions the user, and
removes everything it created (identity providers, realm, users).

  scripts/test-sso-brokering.py            # run against the local stack

Requires the stack (docker compose) to be running. Uses the Keycloak
bootstrap administrator from .env; never touches existing users or settings.
"""
import importlib.util
import json
import os
import re
import subprocess
import sys
import html
import uuid

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location("smoke", os.path.join(ROOT, "scripts", "smoke-test.py"))
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)

ENV = smoke.ENV
BASE = smoke.BASE
EXT = "pathos-sso-test-" + uuid.uuid4().hex[:6]
REALM = "pathos"
PW = "Ext-" + uuid.uuid4().hex[:10] + "!A1"
INTERNAL = "http://localhost:8080/auth"  # Keycloak calling itself (back channel)
failures = []


def kc(*args, body=None, check=True):
    cmd = ["docker", "compose", "exec", "-T", "keycloak", "/opt/keycloak/bin/kcadm.sh", *args]
    if body is not None:
        cmd += ["-f", "-"]
    r = subprocess.run(cmd, cwd=ROOT, input=json.dumps(body) if body is not None else None,
                       capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"kcadm {' '.join(args[:3])}: {r.stderr.strip()[:300]}")
    return r.stdout


def ok(cond, what):
    print(("  ok   " if cond else "  FAIL ") + what)
    if not cond:
        failures.append(what)


def login_kcadm():
    kc("config", "credentials", "--server", INTERNAL, "--realm", "master",
       "--user", ENV.get("KEYCLOAK_ADMIN_USER", "kcadmin"), "--password", ENV["KEYCLOAK_ADMIN_PASSWORD"])


def setup():
    kc("create", "realms", body={"realm": EXT, "enabled": True, "displayName": "External IdP (test)"})
    for name in ("oidc", "saml"):
        uid = kc("create", "users", "-r", EXT, "-i", body={
            "username": f"{name}-user", "email": f"sso-{name}-{EXT}@partner.test", "emailVerified": True,
            "firstName": "Sso", "lastName": name.upper(), "enabled": True}).strip()
        kc("set-password", "-r", EXT, "--userid", uid, "--new-password", PW)
    # OIDC: a confidential client in the external realm; an OIDC identity
    # provider in the PATHOS realm pointing at it.
    secret = uuid.uuid4().hex
    kc("create", "clients", "-r", EXT, body={
        "clientId": "pathos-broker", "protocol": "openid-connect", "publicClient": False, "secret": secret,
        "standardFlowEnabled": True, "redirectUris": [f"{BASE}/auth/realms/{REALM}/broker/{EXT}-oidc/endpoint"]})
    ext = f"{BASE}/auth/realms/{EXT}/protocol/openid-connect"
    back = f"{INTERNAL}/realms/{EXT}/protocol/openid-connect"
    kc("create", "identity-provider/instances", "-r", REALM, body={
        "alias": f"{EXT}-oidc", "displayName": "Partner OIDC (test)", "providerId": "oidc", "enabled": True,
        "trustEmail": False, "firstBrokerLoginFlowAlias": "first broker login",
        "config": {"clientId": "pathos-broker", "clientSecret": secret, "clientAuthMethod": "client_secret_post",
                   "authorizationUrl": f"{ext}/auth", "tokenUrl": f"{back}/token", "userInfoUrl": f"{back}/userinfo",
                   "jwksUrl": f"{back}/certs", "validateSignature": "true", "useJwksUrl": "true",
                   "issuer": f"{BASE}/auth/realms/{EXT}", "defaultScope": "openid email profile", "syncMode": "IMPORT",
                   "pkceEnabled": "true", "pkceMethod": "S256"}})
    # SAML: the PATHOS realm is the service provider; a SAML client for it in
    # the external realm sends the e-mail and names as attributes.
    sp = f"{BASE}/auth/realms/{REALM}"
    acs = f"{BASE}/auth/realms/{REALM}/broker/{EXT}-saml/endpoint"
    kc("create", "clients", "-r", EXT, body={
        "clientId": sp, "protocol": "saml", "enabled": True, "redirectUris": [acs],
        "attributes": {"saml_assertion_consumer_url_post": acs, "saml.client.signature": "false",
                       "saml.authnstatement": "true", "saml_name_id_format": "email", "saml.force.name.id.format": "true",
                       "saml.server.signature": "true", "saml.assertion.signature": "true"},
        "protocolMappers": [
            {"name": m, "protocol": "saml", "protocolMapper": "saml-user-property-mapper",
             "config": {"user.attribute": m, "attribute.name": m, "attribute.nameformat": "Basic"}}
            for m in ("email", "firstName", "lastName")]})
    keys = json.loads(kc("get", "keys", "-r", EXT)).get("keys", [])
    cert = next((k.get("certificate") for k in keys if k.get("algorithm") == "RS256" and k.get("use") == "SIG" and k.get("certificate")), "")
    kc("create", "identity-provider/instances", "-r", REALM, body={
        "alias": f"{EXT}-saml", "displayName": "Partner SAML (test)", "providerId": "saml", "enabled": True,
        "trustEmail": False, "firstBrokerLoginFlowAlias": "first broker login",
        "config": {"entityId": sp, "idpEntityId": f"{BASE}/auth/realms/{EXT}",
                   "singleSignOnServiceUrl": f"{BASE}/auth/realms/{EXT}/protocol/saml",
                   "nameIDPolicyFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
                   "principalType": "ATTRIBUTE", "principalAttribute": "email",
                   "postBindingResponse": "true", "postBindingAuthnRequest": "false",
                   "validateSignature": "true", "signingCertificate": cert,
                   "wantAssertionsSigned": "true", "syncMode": "IMPORT"}})
    for alias, attr in ((f"{EXT}-saml", "email"), (f"{EXT}-saml", "firstName"), (f"{EXT}-saml", "lastName")):
        kc("create", f"identity-provider/instances/{alias}/mappers", "-r", REALM, body={
            "name": attr, "identityProviderAlias": alias, "identityProviderMapper": "saml-user-attribute-idp-mapper",
            "config": {"syncMode": "INHERIT", "attribute.name": attr, "user.attribute": attr}})


def hidden(page):
    return {html.unescape(n): html.unescape(v) for n, v in re.findall(r'<input[^>]*name="([^"]+)"[^>]*value="([^"]*)"', page)}


def broker_login(kind):
    """Sign in to PATHOS through the external provider like a browser."""
    c = smoke.Client()
    st, url, page = c.req("GET", "/api/auth/login?return_to=/")
    link = re.search(r'href="([^"]*/broker/' + re.escape(f"{EXT}-{kind}") + r'/login[^"]*)"', page)
    ok(bool(link), f"{kind}: the PATHOS sign-in page offers the provider")
    if not link:
        return None, None
    st, url, page = c.req("GET", html.unescape(link.group(1)))
    ok(f"/realms/{EXT}/" in url, f"{kind}: redirected to the external provider")
    st, url, page = c.req("POST", smoke.form_action(page), {"username": f"{kind}-user", "password": PW}, form=True)
    # SAML returns an auto-submitting form that posts the response back.
    for _ in range(3):
        if "SAMLResponse" in page:
            act = re.search(r'<form[^>]*action="([^"]+)"', page)
            st, url, page = c.req("POST", html.unescape(act.group(1)), hidden(page), form=True)
        elif "kc-update-profile-form" in page or "kc-idp-review-profile-form" in page:
            f = hidden(page)
            f.update({"email": f"sso-{kind}-{EXT}@partner.test", "firstName": "Sso", "lastName": kind.upper(),
                      "username": f"sso-{kind}-{EXT}@partner.test"})
            st, url, page = c.req("POST", smoke.form_action(page), f, form=True)
        else:
            break
    ok(url.rstrip("/") == BASE or url.startswith(BASE + "/?") or url.startswith(BASE + "/#"), f"{kind}: back in PATHOS ({url[:80]})")
    st, me = c.api("GET", "/api/v1/me")
    email = me.get("user", {}).get("email") if isinstance(me, dict) else None
    ok(st == 200 and email == f"sso-{kind}-{EXT}@partner.test", f"{kind}: PATHOS session for the brokered user ({st} {email})")
    perms = (me.get("permissions") or []) if isinstance(me, dict) else []
    ok(st == 200 and not [p for p in perms if p not in ("users.read",)], f"{kind}: a new brokered user has no access until a role is granted")
    return c, (me.get("user", {}).get("id") if isinstance(me, dict) else None)


def cleanup(pathos_users):
    admin = smoke.Client()
    good, _ = smoke.login(admin, smoke.ADMIN, [smoke.NEW_PW, smoke.TEMP_PW])
    if good:
        _, me = admin.api("GET", "/api/v1/me")
        admin.csrf = me["csrf_token"]
        # By this run's unique realm name, so users from an interrupted
        # sign-in are found too.
        _, page = admin.api("GET", f"/api/v1/users?q={EXT}&status=active")
        ids = {u["id"] for u in (page or {}).get("items", []) if EXT in u.get("email", "")} | {u for u in pathos_users if u}
        for uid in ids:
            admin.api("POST", f"/api/v1/users/{uid}/deactivate")
    for kind in ("oidc", "saml"):
        kc("delete", f"identity-provider/instances/{EXT}-{kind}", "-r", REALM, check=False)
        for uid in re.findall(r'"id"\s*:\s*"([^"]+)"', kc("get", "users", "-r", REALM, "-q", f"email=sso-{kind}-{EXT}@partner.test", check=False)):
            kc("delete", f"users/{uid}", "-r", REALM, check=False)
    kc("delete", f"realms/{EXT}", check=False)


def main():
    login_kcadm()
    created = []
    try:
        setup()
        for kind in ("oidc", "saml"):
            print(f"== {kind.upper()}")
            _, uid = broker_login(kind)
            created.append(uid)
    finally:
        cleanup(created)
    print("cleaned up")
    if failures:
        print(f"{len(failures)} check(s) failed")
        sys.exit(1)
    print("all checks passed")


if __name__ == "__main__":
    main()
