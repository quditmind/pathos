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
import time
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
        s, mfa = admin.api("GET", f"/api/v1/users/{uid}/mfa")
        check("MFA status read from Keycloak -> not set up", s == 200 and mfa.get("configured") is False, f"{s} {mfa}")
        s, req = admin.api("POST", f"/api/v1/users/{uid}/require-mfa")
        check("require MFA -> enrolment pending in Keycloak", s == 200 and req.get("changed") and req["mfa"]["pending"], f"{s} {req}")
        s, req = admin.api("POST", f"/api/v1/users/{uid}/require-mfa")
        check("require MFA again is a no-op", s == 200 and req.get("changed") is False, f"{s} {req}")
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
        check("every KPI has a live data source (phases 1-6)", all(k["status"] == "ok" for k in dash["kpis"]),
              [k["key"] for k in dash["kpis"] if k["status"] != "ok"])
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

    print("\nScanning engine (Phase 4)")
    s, cat = admin.api("GET", "/api/v1/scanners")
    check("scanner catalog lists 55 integrations + Syft + 3 built-in checks", s == 200 and len(cat["items"]) == 59, s)
    if s == 200:
        avail = sorted(x["key"] for x in cat["items"] if x["adapter_available"])
        check("16 scanners runnable (7 core, zizmor, actionlint, licensecheck, clamav, binary-hardening, image and DAST targets, endpoint checks, cosign)",
              avail == sorted(["gitleaks", "opengrep", "trivy-fs", "grype", "osv-scanner", "checkov", "syft", "zizmor", "actionlint",
                               "licensecheck", "clamav", "binary-hardening", "trivy-image", "nuclei", "pathos-endpoints", "cosign"]), avail)
        cats = {x["key"]: x["category"] for x in cat["items"]}
        check("content scanners in their finding categories", cats.get("clamav") == "malware" and cats.get("binary-hardening") == "binary"
              and cats.get("licensecheck") == "license", cats)
    s, profs = admin.api("GET", "/api/v1/scan-profiles")
    check("default scan profile seeded", s == 200 and any(p["is_default"] for p in profs["items"]), s)
    if s == 200:
        d = next(p for p in profs["items"] if p["is_default"])
        check("default profile includes Gitleaks", any(x["key"] == "gitleaks" for x in d["current"]["scanners"]))
    s, workers = admin.api("GET", "/api/v1/workers")
    online = [w for w in workers.get("items", []) if w["online"]] if s == 200 else []
    check("at least one scan worker online", len(online) >= 1, workers)
    if online:
        # 15 tools, plus ClamAV when PATHOS_CLAMAV_ADDRESS is set and clamd answers.
        check("worker reports all tool versions", len(online[0]["scanners"]) in (15, 16) and "licensecheck" in online[0]["scanners"]
              and "binary-hardening" in online[0]["scanners"] and "pathos-endpoints" in online[0]["scanners"]
              and "cosign" in online[0]["scanners"], online[0]["scanners"])
    s, fl = admin.api("GET", "/api/v1/findings?category=misconfiguration")
    check("findings filter accepts the misconfiguration category", s == 200, s)
    st, _, _ = anon.req("POST", "/internal/worker/v1/lease", {})
    check("internal worker API not reachable through the proxy -> 404", st == 404, st)
    st, _, body = anon.req("GET", "/api")
    check("GET /api answers with the API's JSON 404 (not the web app)", st == 404 and '"not_found"' in body, st)
    s, fs = admin.api("GET", "/api/v1/findings")
    check("findings API -> 200", s == 200 and "items" in fs, s)
    s, feeds = admin.api("GET", "/api/v1/intel/feeds")
    check("endoflife.date feed listed", s == 200 and any(f["feed"] == "endoflife" for f in feeds.get("items", [])), s)
    repos_now = lst.get("items", []) if isinstance(lst, dict) else []
    if repos_now:
        rid = repos_now[0]["id"]
        s, ev = admin.api("GET", f"/api/v1/repositories/{rid}/endpoint-verification")
        check("endpoint verification state -> 200", s == 200 and "endpoints" in ev, s)
        s, eolv = admin.api("GET", f"/api/v1/repositories/{rid}/eol")
        check("repository end-of-life view -> 200", s == 200 and "items" in eolv, s)

    print("\nAI review & MCP (Phase 5)")
    s, pv = admin.api("POST", "/api/v1/ai/providers", {"name": f"Smoke Claude {sfx}", "kind": "anthropic", "api_key": "sk-ant-invalid-smoke-key"})
    check("create AI provider -> 201", s == 201, s)
    if s == 201:
        check("invalid Anthropic key reported (live call through the SDK)", pv["status"] == "error" and "rejected the API key" in pv["status_message"], pv.get("status_message"))
        check("API key never returned", "sk-ant-invalid" not in json.dumps(pv))
        admin.api("DELETE", f"/api/v1/ai/providers/{pv['id']}")
    s, tok = admin.api("POST", "/api/v1/me/tokens", {"name": "smoke", "days": 1})
    check("create personal API token -> 201", s == 201 and tok["secret"].startswith("pathos_pat_"), s)
    if s == 201:
        def rpc(method, params=None, token=tok["secret"]):
            return anon.req("POST", "/mcp", {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}},
                            {"Authorization": f"Bearer {token}"})
        st, _, body = rpc("initialize", {"protocolVersion": "2025-06-18"})
        check("MCP initialize through the proxy", st == 200 and '"pathos"' in body, st)
        st, _, body = rpc("tools/list")
        check("MCP lists 3 tools", st == 200 and body.count('"name"') == 3, body[:200])
        st, _, _ = rpc("tools/list", token="pathos_pat_bogus")
        check("MCP rejects an unknown token -> 401", st == 401, st)
        admin.api("DELETE", f"/api/v1/me/tokens/{tok['token']['id']}")
        st, _, _ = rpc("tools/list")
        check("revoked token stops working -> 401", st == 401, st)
    s, reg = admin.api("GET", "/api/v1/mcp-servers")
    check("MCP registry has the built-in PATHOS server", s == 200 and any(x["built_in"] and x["status"] == "approved" for x in reg["items"]), s)

    print("\nVulnerability management (Phase 6)")
    s, sla = admin.api("GET", "/api/v1/sla-policies")
    check("default SLA policy seeded (critical 7 days)", s == 200 and sla.get("critical") == 7, sla)
    s, lic = admin.api("GET", "/api/v1/license-policies")
    check("default license policy denies AGPL-3.0", s == 200 and any(x["spdx_id"].startswith("AGPL-3.0") and x["decision"] == "deny" for x in lic["items"]), s)
    s, comps = admin.api("GET", "/api/v1/sbom/components?license=violations")
    check("SBOM component inventory -> 200", s == 200 and "items" in comps, s)
    s, fs = admin.api("GET", "/api/v1/findings?sla=breached&assignee=none")
    check("findings SLA/assignee filters -> 200", s == 200, s)
    s, fs = admin.api("GET", "/api/v1/findings?severity=low,medium,high")
    if s == 200 and fs["items"]:
        f = fs["items"][0]
        s, _ = admin.api("POST", f"/api/v1/findings/{f['id']}/status", {"status": "false_positive"})
        check("false positive without a reason -> 400", s == 400, s)
        s, _ = admin.api("POST", f"/api/v1/findings/{f['id']}/status", {"status": "accepted_risk", "reason": "smoke"})
        check("accepted_risk only via the approval workflow -> 409", s == 409, s)
        s, _ = admin.api("POST", f"/api/v1/findings/{f['id']}/assign", {"assignee_id": admin.api("GET", "/api/v1/me")[1]["user"]["id"]})
        check("assign finding -> 204", s == 204, s)
        s, ra = admin.api("POST", f"/api/v1/findings/{f['id']}/risk-acceptance",
                          {"justification": "Smoke test: compensating WAF rule in place", "expires_at": "2099-01-01T00:00:00Z"})
        check("risk acceptance beyond 365 days rejected -> 400", s == 400, s)
        s, h = admin.api("GET", f"/api/v1/findings/{f['id']}/history")
        # A finding has history once its status first changes (new findings have none yet).
        check("status history readable", s == 200 and isinstance(h.get("items"), list), s)
        admin.api("POST", f"/api/v1/findings/{f['id']}/assign", {"assignee_id": None})
    else:
        print("  (no open findings to exercise triage; run a scan first)")

    print("\nScheduling & notifications (Phase 7)")
    deadline = time.time() + 45
    while True:
        s, st = admin.api("GET", "/api/v1/scheduler/status")
        if (s == 200 and st.get("healthy")) or time.time() > deadline:
            break
        time.sleep(3)
    check("scheduler elected leader and heartbeating", s == 200 and st.get("healthy") and st.get("leader"), st)
    s, _ = admin.api("POST", "/api/v1/schedules", {"name": "too fast", "cron": "*/5 * * * *", "target_type": "organization"})
    check("schedule more often than hourly rejected -> 400", s == 400, s)
    s, sch = admin.api("POST", "/api/v1/schedules", {"name": f"Smoke nightly {sfx}", "cron": "0 3 * * *", "timezone": "Europe/Berlin",
                                                   "target_type": "organization", "enabled": False})
    check("create schedule -> 201", s == 201 and sch.get("next_run_at"), s)
    if s == 201:
        s, pv = admin.api("POST", "/api/v1/schedules/preview", {"cron": "0 3 * * *", "timezone": "Europe/Berlin", "target_type": "organization"})
        check("schedule preview lists next runs", s == 200 and len(pv.get("next_runs", [])) == 5, s)
        s, _ = admin.api("DELETE", f"/api/v1/schedules/{sch['id']}")
        check("delete schedule -> 204", s == 204, s)
    s, rules = admin.api("GET", "/api/v1/notifications/rules")
    check("19 built-in notification rules seeded", s == 200 and sum(1 for r in rules["items"] if r["system"]) == 19, s)
    s, smtp = admin.api("GET", "/api/v1/notifications/smtp")
    check("SMTP seeded from environment (Mailpit in dev)", s == 200 and smtp.get("enabled") and smtp.get("host"), smtp)
    s, tst = admin.api("POST", "/api/v1/notifications/smtp/test", {})
    check("queue test email -> 202", s == 202, s)
    if s == 202:
        deadline, status = time.time() + 45, ""
        while time.time() < deadline:
            s, d = admin.api("GET", f"/api/v1/notifications/deliveries/{tst['id']}")
            status = d.get("status", "") if s == 200 else ""
            if status in ("sent", "failed", "suppressed"):
                break
            time.sleep(3)
        check("jobs service delivered the test email over SMTP", status == "sent", d.get("last_error") or status)
        mp = os.environ.get("MAILPIT_URL", f"http://127.0.0.1:{ENV.get('MAILPIT_UI_PORT', '8025')}")
        try:
            with urllib.request.urlopen(mp + "/api/v1/search?query=" + urllib.parse.quote('subject:"[PATHOS] Test email"'), timeout=5) as r:
                found = json.loads(r.read().decode()).get("messages_count", 0)
            check("test email arrived in Mailpit", found >= 1, found)
        except Exception as e:  # Mailpit only runs with the dev profile
            print(f"  (Mailpit not reachable, skipped: {e})")
    s, inbox = admin.api("GET", "/api/v1/me/notifications")
    check("in-app inbox -> 200", s == 200 and "unread" in inbox, s)

    print("\nLogout")
    s, out = admin.api("POST", "/api/auth/logout")
    check("logout returns Keycloak end-session URL", s == 200 and "/protocol/openid-connect/logout" in out.get("logout_url", ""), out)
    s, _ = admin.api("GET", "/api/v1/me")
    check("session invalid after logout -> 401", s == 401, s)

    print("\nRate limiting (Phase 8)")
    burst = Client()
    codes = [burst.req("GET", "/api/auth/login?return_to=/")[0] for _ in range(40)]
    limited = codes.count(429)
    check("login endpoint throttles a burst from one address (429)", limited > 0, codes[-5:])
    st, _, _ = burst.req("GET", "/api/auth/login?return_to=/")
    if st == 429:
        print("  (login is throttled for ~20 s from this address; re-run the smoke test after that)")

if __name__ == "__main__":
    main()
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
