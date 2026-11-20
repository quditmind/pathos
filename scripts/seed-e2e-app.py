#!/usr/bin/env python3
"""Seed a running PATHOS stack with an application whose repository is the
PATHOS source itself, for the CodeGraph browser test
(e2e/tests/codegraph.spec.ts builds the graph through the real worker-graph).

Creates the application (default name "PATHOS") unless it exists, uploads a
zip of the repository as a Local PC source (`git archive HEAD`, or the zip
given with --zip) and imports it without starting a scan. Idempotent: an
application that already has a repository is left as it is.

Usage:
  scripts/seed-e2e-app.py                     # zip of HEAD of this checkout
  scripts/seed-e2e-app.py --zip source.zip    # an existing zip instead
  scripts/seed-e2e-app.py --github-env        # CI: export E2E_CODEGRAPH_APP
  E2E_CODEGRAPH_APP=$(scripts/seed-e2e-app.py | tail -1) scripts/e2e.sh -g CodeGraph

Signs in like scripts/smoke-test.py (URL and administrator from .env or
PATHOS_* variables; the forced first-login password change is handled).
Prints the application id on the last line. Standard library only.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMPORT_DONE = ("completed", "failed", "cancelled", "needs_attention")


def fail(msg):
    print(f"seed-e2e-app: {msg}", file=sys.stderr)
    sys.exit(1)


def load_smoke():
    spec = importlib.util.spec_from_file_location("smoke_test", os.path.join(ROOT, "scripts", "smoke-test.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def git_zip(repo):
    try:
        return subprocess.run(["git", "-C", repo, "archive", "--format=zip", "HEAD"], check=True, capture_output=True).stdout
    except FileNotFoundError:
        fail("git is not installed: pass --zip")
    except subprocess.CalledProcessError as e:
        fail(f"git archive HEAD in {repo} failed: {e.stderr.decode().strip()}")


class Seeder:
    def __init__(self, smoke):
        self.smoke = smoke
        self.c = smoke.Client()

    def login(self):
        s = self.smoke
        if not s.TEMP_PW:
            fail("no administrator password: set PATHOS_BOOTSTRAP_ADMIN_PASSWORD (.env)")
        # The bootstrap password first, then the one smoke-test/e2e set.
        ok, why = s.login(self.c, s.ADMIN, [s.TEMP_PW, s.NEW_PW])
        if not ok:
            ok, why = s.login(self.c, s.ADMIN, [s.NEW_PW, s.TEMP_PW])
        if not ok:
            fail(f"login to {s.BASE} as {s.ADMIN} failed: {why}")
        me = self.api("GET", "/api/v1/me")
        self.c.csrf = me["csrf_token"]
        return me

    def api(self, method, path, data=None):
        try:
            status, body = self.c.api(method, path, data)
        except (urllib.error.URLError, OSError) as e:
            fail(f"{method} {path}: {e}")
        if status >= 300:
            fail(f"{method} {path}: HTTP {status}: {body}")
        return body

    def upload(self, data, filename):
        up = self.api("POST", "/api/v1/source-uploads",
                      {"filename": filename, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
        cs = up["chunk_size"]
        for n in range((len(data) + cs - 1) // cs):
            part = data[n * cs:(n + 1) * cs]
            req = urllib.request.Request(
                f"{self.smoke.BASE}/api/v1/source-uploads/{up['id']}/parts/{n}", data=part, method="PUT",
                headers={"X-CSRF-Token": self.c.csrf, "X-Content-SHA256": hashlib.sha256(part).hexdigest(),
                         "Content-Type": "application/octet-stream"})
            try:
                self.c.opener.open(req, timeout=120).read()
            except urllib.error.HTTPError as e:
                fail(f"upload part {n}: HTTP {e.code}: {e.read().decode()}")
            except (urllib.error.URLError, OSError) as e:
                fail(f"upload part {n}: {e}")
        self.api("POST", f"/api/v1/source-uploads/{up['id']}/complete", {})
        u = self.api("GET", f"/api/v1/source-uploads/{up['id']}")
        if u["status"] != "complete":
            fail(f"upload {up['id']} is {u['status']}, expected complete")
        return up["id"]

    def metadata(self, app_id, user_id, display):
        bus = self.api("GET", "/api/v1/business-units").get("items") or []
        bu = bus[0] if bus else self.api("POST", "/api/v1/business-units", {"name": "Example engineering (e2e)"})
        regions = self.api("GET", "/api/v1/regions").get("items") or []
        if not regions:
            fail("no regions configured")
        cls = (self.api("GET", "/api/v1/asset-settings") or {}).get("classifications") or {}
        dc = cls.get("data_classification") or [{"key": "internal"}]
        return {"application_id": app_id, "display_name": display, "business_owner_id": user_id,
                "technical_owner_id": user_id, "business_unit_id": bu["id"], "business_region_id": regions[0]["id"],
                "criticality": "high", "data_classification": dc[0].get("key"), "public_exposure": "no",
                "environment": "development"}

    def import_upload(self, upload_id, meta, display, timeout):
        job = self.api("POST", "/api/v1/repository-imports", {
            "source": "upload", "idempotency_key": "e2e-seed-" + upload_id, "start_scan": False,
            "metadata": meta, "items": [{"upload_id": upload_id, "display_name": display}],
        })
        deadline = time.monotonic() + timeout
        while True:
            j = self.api("GET", f"/api/v1/repository-imports/{job['id']}")
            if j["status"] in IMPORT_DONE:
                break
            if time.monotonic() > deadline:
                fail(f"import {job['id']} still {j['status']} after {timeout} s")
            time.sleep(2)
        items = [(i.get("status"), i.get("error_message")) for i in j.get("items", [])]
        print(f"import {j['status']} {json.dumps(items)}", flush=True)
        if j["status"] != "completed":
            fail(f"import {job['id']} ended {j['status']}")


def main():
    ap = argparse.ArgumentParser(
        description="Seed a running PATHOS stack with an application holding the PATHOS repository "
                    "(for e2e/tests/codegraph.spec.ts). Prints the application id on the last line.")
    ap.add_argument("--name", default="PATHOS", help="application name (default: %(default)s)")
    ap.add_argument("--zip", metavar="PATH", help="source zip to upload (default: git archive HEAD of --repo)")
    ap.add_argument("--repo", default=ROOT, help="repository to archive (default: this checkout)")
    ap.add_argument("--import-timeout", type=int, default=600, metavar="S", help="seconds to wait for the import (default: %(default)s)")
    ap.add_argument("--github-env", action="store_true",
                    help="append E2E_CODEGRAPH_APP=<id> to the file named by $GITHUB_ENV (GitHub Actions)")
    args = ap.parse_args()

    if args.github_env and not os.environ.get("GITHUB_ENV"):
        fail("--github-env given but GITHUB_ENV is not set")
    if args.zip and not os.path.isfile(args.zip):
        fail(f"no such file: {args.zip}")

    smoke = load_smoke()
    print(f"seeding {smoke.BASE}", flush=True)
    s = Seeder(smoke)
    me = s.login()

    apps = s.api("GET", "/api/v1/applications").get("items") or []
    app = next((a for a in apps if a["name"] == args.name), None)
    if app:
        print(f"application {app['id']} exists", flush=True)
    else:
        app = s.api("POST", "/api/v1/applications", {
            "name": args.name, "criticality": "high",
            "description": "e2e CodeGraph fixture: the PATHOS repository's own source"})
        print(f"application {app['id']} created", flush=True)

    repos = s.api("GET", f"/api/v1/repositories?application_id={app['id']}").get("items") or []
    if repos:
        print("repository present, nothing to import", flush=True)
    else:
        if args.zip:
            data = open(args.zip, "rb").read()
        else:
            data = git_zip(args.repo)
        display = args.name.lower()
        print(f"uploading {len(data)} bytes", flush=True)
        upload_id = s.upload(data, display + ".zip")
        meta = s.metadata(app["id"], me["user"]["id"], display)
        s.import_upload(upload_id, meta, display, args.import_timeout)
        repos = s.api("GET", f"/api/v1/repositories?application_id={app['id']}").get("items") or []
        if not repos:
            fail("the import completed but the application has no repository")
    print("repositories " + ", ".join(r.get("full_name") or r.get("name") or r["id"] for r in repos), flush=True)

    if args.github_env:
        with open(os.environ["GITHUB_ENV"], "a") as f:
            f.write(f"E2E_CODEGRAPH_APP={app['id']}\n")
    print(app["id"])


if __name__ == "__main__":
    main()
