#!/usr/bin/env python3
"""End-to-end smoke test against a running PATHOS stack (docker compose up -d).

Drives a real browser-style OIDC login through Keycloak (including the forced
password change on first login), then exercises the user-management API,
RBAC, CSRF protection, session revocation and the audit log.

Usage:
  scripts/smoke-test.py                      # reads .env for URL and admin creds
  PATHOS_ADMIN_NEW_PASSWORD=... scripts/smoke-test.py

Standard library only. TLS verification is disabled because the default
deployment uses Caddy's internal CA.
"""
import html
import http.cookiejar
import json
import os
import re
import secrets
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_env():
    env = {}
    path = os.path.join(ROOT, ".env")
    if os.path.exists(path):
        for line in open(path):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env[k] = v
    env.update({k: v for k, v in os.environ.items() if k.startswith("PATHOS_")})
    return env


ENV = load_env()
BASE = ENV.get("PATHOS_PUBLIC_URL", "https://localhost").rstrip("/")
ADMIN = ENV.get("PATHOS_BOOTSTRAP_ADMIN_EMAIL", "admin@example.com")
TEMP_PW = ENV.get("PATHOS_BOOTSTRAP_ADMIN_PASSWORD", "")
NEW_PW = ENV.get("PATHOS_ADMIN_NEW_PASSWORD") or "Smoke-" + TEMP_PW[::-1] + "!9"
MAILPIT = ENV.get("PATHOS_MAILPIT_URL", "http://127.0.0.1:8025")

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

passed = failed = 0


def check(name, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print(f"  PASS  {name}")
    else:
        failed += 1
        print(f"  FAIL  {name} {detail}")


class Client:
    def __init__(self):
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar), urllib.request.HTTPSHandler(context=CTX)
        )
        self.csrf = ""

    def req(self, method, url, data=None, headers=None, form=False):
        if not url.startswith("http"):
            url = BASE + url
        h = dict(headers or {})
        body = None
        if data is not None:
            if form:
                body = urllib.parse.urlencode(data).encode()
                h["Content-Type"] = "application/x-www-form-urlencoded"
            else:
                body = json.dumps(data).encode()
                h["Content-Type"] = "application/json"
        r = urllib.request.Request(url, data=body, method=method, headers=h)
        try:
            resp = self.opener.open(r, timeout=20)
            return resp.status, resp.geturl(), resp.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.geturl(), e.read().decode()

    def api(self, method, path, data=None, csrf=True, extra=None):
        h = {"Accept": "application/json"}
        if csrf and method not in ("GET", "HEAD"):
            h["X-CSRF-Token"] = self.csrf
        h.update(extra or {})
        status, _, body = self.req(method, path, data, h)
        try:
            return status, json.loads(body) if body else None
        except json.JSONDecodeError:
            return status, body


def form_action(page):
    m = re.search(r'<form[^>]*action="([^"]+)"', page)
    return html.unescape(m.group(1)) if m else None


def login(c, email, passwords):
    status, url, page = c.req("GET", "/api/auth/login?return_to=/admin/users")
    if status != 200 or "/auth/realms/pathos/" not in url:
        return False, f"login redirect failed: {status} {url}"
    for pw in passwords:
        action = form_action(page)
        if not action:
            return False, "no login form"
        status, url, page2 = c.req("POST", action, {"username": email, "password": pw}, form=True)
        if "password-new" in page2:  # forced password change
            action = form_action(page2)
            status, url, page2 = c.req("POST", action, {"password-new": passwords[-1], "password-confirm": passwords[-1]}, form=True)
        if url.startswith(BASE + "/admin/users"):
            return True, ""
        page = page2
    return False, f"login did not complete: {status} {url}"


def main():
    print(f"PATHOS smoke test against {BASE}\n")

    print("Unauthenticated access")
    anon = Client()
    s, body = anon.api("GET", "/api/v1/me")
    check("GET /api/v1/me without session -> 401", s == 401, s)
    s, _ = anon.api("POST", "/api/v1/users", {"email": "x@example.com"})
    check("POST /api/v1/users without session -> 401", s == 401, s)

    print("\nOIDC login (Authorization Code + PKCE through Keycloak)")
    admin = Client()
    ok, why = login(admin, ADMIN, [TEMP_PW, NEW_PW])
    check("bootstrap admin can log in (forced password change handled)", ok, why)
    if not ok:
        return
    cookies = {ck.name: ck for ck in admin.jar}
    sess = cookies.get("__Host-pathos_session") or cookies.get("pathos_session")
    check("session cookie is HttpOnly + Secure", sess is not None and sess.has_nonstandard_attr("HttpOnly") and sess.secure)
    check("no OIDC tokens in PATHOS cookies", not any(ck.value.startswith("eyJ") for ck in admin.jar if not ck.path.startswith("/auth")))

    s, me = admin.api("GET", "/api/v1/me")
    check("GET /api/v1/me -> 200", s == 200, s)
    admin.csrf = me.get("csrf_token", "")
    check("bootstrap admin holds super_admin org-wide", any(a["role_key"] == "super_admin" and a["scope_type"] == "organization" for a in me["role_assignments"]))
    check("CSRF token issued", len(admin.csrf) >= 32)

    print("\nCSRF protection")
    email = f"smoke-{secrets.token_hex(4)}@example.com"
    s, _ = admin.api("POST", "/api/v1/users", {"email": email}, csrf=False)
    check("unsafe request without CSRF token -> 403", s == 403, s)
    s, _ = admin.api("POST", "/api/v1/users", {"email": email}, extra={"Origin": "https://evil.example"})
    check("unsafe request with foreign Origin -> 403", s == 403, s)

    print("\nUser management")
    s, regions = admin.api("GET", "/api/v1/regions")
    check("regions seeded (AMER, EMEA, APAC)", s == 200 and {r["code"] for r in regions["items"]} >= {"AMER", "EMEA", "APAC"})
    emea = next(r["id"] for r in regions["items"] if r["code"] == "EMEA")
    s, created = admin.api("POST", "/api/v1/users", {
        "email": email, "display_name": "Smoke Analyst",
        "roles": [{"role_key": "security_analyst", "scope_type": "region", "scope_id": emea}],
    })
    check("invite user with region-scoped role -> 201", s == 201, f"{s} {created}")
    uid = created["user"]["id"] if s == 201 else None
    if uid:
        check("invited user status = invited", created["user"]["status"] == "invited")
        check("Keycloak account provisioned", created["provisioning"]["status"] in ("created", "linked_existing"), created["provisioning"])
        s, _ = admin.api("POST", "/api/v1/users", {"email": email})
        check("duplicate email -> 409", s == 409, s)
        s, bad = admin.api("POST", "/api/v1/users", {"email": "not-an-email"})
        check("invalid email -> 400", s == 400, s)
        s, bad = admin.api("POST", "/api/v1/users", {"email": "y@example.com", "bogus": 1})
        check("unknown JSON field rejected -> 400", s == 400, s)
        s, bad = admin.api("POST", f"/api/v1/users/{uid}/role-assignments", {"role_key": "super_admin", "scope_type": "region", "scope_id": emea})
        check("super_admin at region scope rejected -> 400", s == 400, s)
        s, a = admin.api("POST", f"/api/v1/users/{uid}/role-assignments", {"role_key": "viewer", "scope_type": "organization"})
        check("grant viewer org-wide -> 201", s == 201, s)
        s, lst = admin.api("GET", f"/api/v1/users/{uid}/role-assignments")
        check("user has 2 assignments", s == 200 and len(lst["items"]) == 2, lst)
        s, _ = admin.api("DELETE", f"/api/v1/role-assignments/{a['id']}")
        check("revoke assignment -> 204", s == 204, s)
        s, users = admin.api("GET", f"/api/v1/users?q={urllib.parse.quote(email[:12])}")
        check("search finds invited user", s == 200 and any(u["id"] == uid for u in users["items"]))
        s, u = admin.api("POST", f"/api/v1/users/{uid}/deactivate")
        check("deactivate user -> 200", s == 200 and u["status"] == "deactivated", s)
        s, u = admin.api("POST", f"/api/v1/users/{uid}/reactivate")
        check("reactivate never-logged-in user -> invited", s == 200 and u["status"] == "invited", u)

    s, _ = admin.api("POST", f"/api/v1/users/{me['user']['id']}/deactivate")
    check("cannot deactivate yourself -> 400", s == 400, s)
    sa = next(a for a in me["role_assignments"] if a["role_key"] == "super_admin")
    s, _ = admin.api("DELETE", f"/api/v1/role-assignments/{sa['id']}")
    check("cannot remove the last super admin -> 409", s == 409, s)

    print("\nInvitation email (Mailpit, dev profile)")
    try:
        with urllib.request.urlopen(f"{MAILPIT}/api/v1/search?query=to:{urllib.parse.quote(email)}", timeout=5) as r:
            msgs = json.load(r).get("messages", [])
        check("set-password email delivered", len(msgs) >= 1, msgs)
    except Exception as e:  # noqa: BLE001
        print(f"  SKIP  mailpit not reachable ({e})")

    print("\nAudit log")
    s, logs = admin.api("GET", "/api/v1/audit-logs")
    actions = {l["action"] for l in logs.get("items", [])} if s == 200 else set()
    for act in ("auth.login", "user.invite", "role_assignment.create", "role_assignment.delete", "user.deactivate", "user.reactivate"):
        check(f"audit entry {act}", act in actions)

    print("\nDashboard & search")
    s, dash = admin.api("GET", "/api/v1/dashboard?days=7")
    check("dashboard returns 24 KPIs", s == 200 and len(dash.get("kpis", [])) == 24, s)
    if s == 200:
        st = {k["key"]: k for k in dash["kpis"]}
        check("future KPIs are not_yet_available without values",
              st["open_findings"]["status"] == "not_yet_available" and st["open_findings"]["value"] is None)
        check("active_users has a value", st["active_users"]["status"] == "ok" and st["active_users"]["value"] >= 1)
    s, _ = admin.api("GET", "/api/v1/dashboard?days=3")
    check("invalid dashboard period -> 400", s == 400, s)
    s, res = admin.api("GET", "/api/v1/search?q=germ")
    check("global search finds Germany", s == 200 and any(r["title"] == "Germany" for r in res["items"]), res)

    print("\nRepositories & SCM (Phase 3)")
    sfx = secrets.token_hex(3)
    s, cat = admin.api("POST", "/api/v1/tag-categories", {"name": f"Smoke{sfx}", "allow_multiple": False})
    check("create tag category -> 201", s == 201, s)
    if s == 201:
        s, _ = admin.api("POST", f"/api/v1/tag-categories/{cat['id']}/tags", {"name": "Alpha", "color": "teal"})
        check("create tag -> 201", s == 201, s)
    s, conn = admin.api("POST", "/api/v1/scm-connections",
                        {"name": f"Smoke GitHub {sfx}", "provider": "github", "auth_type": "pat", "token": "ghp_" + "x" * 36})
    check("create GitHub connection -> 201", s == 201, s)
    if s == 201:
        check("credential never returned", "ghp_" not in json.dumps(conn))
        # A bogus token proves egress to api.github.com and the error path.
        check("connection test reaches GitHub and reports bad credentials",
              conn["status"] == "error" and "authentication failed" in conn["status_message"], conn.get("status_message"))
        hook = f"/api/webhooks/github/{conn['id']}"
        st, _, _ = anon.req("POST", hook, {"zen": "x"}, {"X-GitHub-Event": "ping", "X-Hub-Signature-256": "sha256=" + "0" * 64})
        check("unsigned webhook rejected through the proxy -> 401", st == 401, st)
        s, _ = admin.api("DELETE", f"/api/v1/scm-connections/{conn['id']}")
        check("delete empty connection -> 204", s == 204, s)
    s, _ = admin.api("POST", "/api/v1/scm-connections", {"name": "meta", "provider": "github_enterprise",
                     "base_url": "https://169.254.169.254/api/v3", "auth_type": "pat", "token": "x"})
    check("SSRF: metadata address rejected -> 400", s == 400, s)
    s, lst = admin.api("GET", "/api/v1/repositories")
    check("repository list -> 200", s == 200 and "items" in lst, s)
    s, dash = admin.api("GET", "/api/v1/dashboard")
    if s == 200:
        st = {k["key"]: k for k in dash["kpis"]}
        check("repositories KPI is live", st["repositories"]["status"] == "ok", st["repositories"]["status"])

    print("\nLogout")
    s, out = admin.api("POST", "/api/auth/logout")
    check("logout returns Keycloak end-session URL", s == 200 and "/protocol/openid-connect/logout" in out.get("logout_url", ""), out)
    s, _ = admin.api("GET", "/api/v1/me")
    check("session invalid after logout -> 401", s == 401, s)


if __name__ == "__main__":
    main()
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
