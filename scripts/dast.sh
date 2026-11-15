#!/usr/bin/env bash
# Authenticated active DAST: OWASP ZAP API scan of every endpoint in
# backend/api/openapi.yaml, signed in as the bootstrap administrator.
#
#   scripts/dast.sh --destructive-ok [--minutes 20]
#
# THE ACTIVE SCAN SENDS ATTACK PAYLOADS AND MODIFIES DATA (creates, updates
# and deletes through the API). Run it only against a disposable stack:
# CI, or a throwaway compose project. Never against real data. Rate
# limiting should be off for the scan: PATHOS_RATE_LIMIT_SCALE=0 docker compose up -d api
#
# Login/logout endpoints are excluded so the scan keeps its session. Gate:
# any High-risk alert not listed in deploy/security/zap-api.conf fails the
# run. Reports go to reports/dast/<UTC>/.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
ZAP_IMAGE="zaproxy/zap-stable@sha256:9624669db72f54d86c4b46a7064518bd9bf79d8c61a4c31befa9923489f328af"
ok=0 minutes=20
while [ $# -gt 0 ]; do
  case "$1" in
    --destructive-ok) ok=1; shift ;;
    --minutes) minutes="$2"; shift 2 ;;
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
[ "$ok" = 1 ] || { echo "Refusing: the active scan modifies data. Use a disposable stack and pass --destructive-ok." >&2; exit 2; }

out="reports/dast/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$out" && chmod 777 "$out"

# Sign in (same flow and credentials as the smoke test).
session="$(python3 - <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("smoke", "scripts/smoke-test.py")
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
c = m.Client()
ok, why = m.login(c, m.ADMIN, [m.TEMP_PW, m.NEW_PW])
if not ok:
    sys.exit("login failed: " + why)
s, me = c.api("GET", "/api/v1/me")
cookie = next(f"{ck.name}={ck.value}" for ck in c.jar if ck.name.endswith("pathos_session"))
print(cookie, me["csrf_token"], m.BASE)
PY
)"
read -r cookie csrf base <<<"$session"

# The scanned definition: everything except the login flow.
python3 - "$out/openapi.yaml" <<'PY'
import sys, yaml
d = yaml.safe_load(open("backend/api/openapi.yaml"))
d["paths"] = {p: v for p, v in d["paths"].items() if not p.startswith("/api/auth/")}
yaml.safe_dump(d, open(sys.argv[1], "w"), sort_keys=False)
print(f"scanning {len(d['paths'])} paths", file=sys.stderr)
PY

# Headers added to every request: session cookie, CSRF token and a matching
# Origin (PATHOS checks both on state-changing requests).
z=""
i=0
for h in "Cookie=$cookie" "X-CSRF-Token=$csrf" "Origin=$base"; do
  name="${h%%=*}"; value="${h#*=}"
  z+=" -config replacer.full_list($i).description=$name -config replacer.full_list($i).enabled=true"
  z+=" -config replacer.full_list($i).matchtype=REQ_HEADER -config replacer.full_list($i).matchstr=$name"
  z+=" -config replacer.full_list($i).regex=false -config replacer.full_list($i).replacement=$value"
  i=$((i + 1))
done
z+=" -config scanner.maxScanDurationInMins=$minutes -config scanner.threadPerHost=4"

set +e
docker run --rm --network host -v "$ROOT/$out:/zap/wrk:rw" "$ZAP_IMAGE" \
  zap-api-scan.py -t openapi.yaml -f openapi -O "$base" -I -J zap.json -r zap.html -z "$z" > "$out/zap.txt" 2>&1
set -e

python3 - "$out/zap.json" deploy/security/zap-api.conf <<'PY'
import json, sys
report = json.load(open(sys.argv[1]))
accepted = {}
for line in open(sys.argv[2]):
    line = line.strip()
    if line and not line.startswith("#"):
        pid, reason = line.split("\t", 1)
        accepted[pid] = reason
alerts = [a for s in report.get("site", []) for a in s.get("alerts", [])]
risk = {"3": "High", "2": "Medium", "1": "Low", "0": "Info"}
failed = []
for a in sorted(alerts, key=lambda a: -int(a["riskcode"])):
    tag = "accepted" if a["pluginid"] in accepted else ""
    print(f'{risk[a["riskcode"]]:6} {a["pluginid"]:>6} {a["alert"]} ({a["count"]}x) {tag}')
    if a["riskcode"] == "3" and a["pluginid"] not in accepted:
        failed.append(a["alert"])
if failed:
    sys.exit("DAST gate failed: " + ", ".join(failed))
print(f"DAST gate passed ({len(alerts)} alert types, none High outside the accepted list)")
PY
echo "report: $out/zap.html"
