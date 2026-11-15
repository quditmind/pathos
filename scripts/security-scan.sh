#!/usr/bin/env bash
# PATHOS security self-tests. Everything runs in containers.
#
#   scripts/security-scan.sh [--no-code] [--no-images] [--no-zap] [--target https://localhost/]
#
#   gosec        static analysis of the Go code (justified #nosec only)
#   govulncheck  known vulnerabilities in reachable Go dependencies
#   npm audit    frontend dependencies (production and development)
#   trivy        our three images (pathos, proxy, worker-core)
#   zap          OWASP ZAP baseline (passive) against the running stack
#
# Gate: exits 1 on any gosec issue, govulncheck finding, npm advisory of
# high/critical severity, FIXABLE high/critical vulnerability in an image,
# or ZAP FAIL. Unfixed upstream issues are reported, not gated. Reports go
# to reports/security/<timestamp>/.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

GOSEC=v2.30.0
GOVULNCHECK=v1.9.0
ZAP_IMAGE="zaproxy/zap-stable@sha256:9624669db72f54d86c4b46a7064518bd9bf79d8c61a4c31befa9923489f328af"
P="${PATHOS_IMAGE_PREFIX:-}"
IMAGES=("${P}pathos:${PATHOS_VERSION:-dev}" "${P}pathos-proxy:${PATHOS_VERSION:-dev}" "${P}pathos-worker-core:${PATHOS_VERSION:-dev}")

code=1 images=1 zap=1 target="https://localhost/"
while [ $# -gt 0 ]; do
  case "$1" in
    --no-code) code=0; shift ;;
    --no-images) images=0; shift ;;
    --no-zap) zap=0; shift ;;
    --target) target="$2"; shift 2 ;;
    -h|--help) sed -n '2,17p' "$0"; exit 0 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done

out="reports/security/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$out" && chmod 777 "$out"
declare -A result
failed=0
gate() { result[$1]="$2"; [ "$3" = ok ] || failed=1; }

if [ "$code" = 1 ]; then
echo "== gosec $GOSEC"
if "$ROOT/scripts/go.sh" run "github.com/securego/gosec/v2/cmd/gosec@$GOSEC" -fmt=text -exclude-dir=test ./... > "$out/gosec.txt" 2>&1; then
  gate gosec "$(grep -E '^ +(Issues|Nosec)' "$out/gosec.txt" | tr -s ' ' | tr '\n' ' ')" ok
else
  gate gosec "issues found, see $out/gosec.txt" fail
fi

echo "== govulncheck $GOVULNCHECK"
if "$ROOT/scripts/go.sh" run "golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK" ./... > "$out/govulncheck.txt" 2>&1; then
  gate govulncheck "no vulnerabilities" ok
else
  gate govulncheck "findings, see $out/govulncheck.txt" fail
fi

echo "== npm audit"
if (cd frontend && "$ROOT/scripts/npm.sh" audit --audit-level=high) > "$out/npm-audit.txt" 2>&1; then
  gate npm "$(grep -Eo 'found [0-9]+ vulnerabilities|[0-9]+ vulnerabilities.*' "$out/npm-audit.txt" | tail -1)" ok
else
  gate npm "high/critical advisories, see $out/npm-audit.txt" fail
fi
fi

if [ "$images" = 1 ]; then
  tmp="$(mktemp -d)"; chmod 755 "$tmp"
  docker volume create pathos_security_cache >/dev/null
  for img in "${IMAGES[@]}"; do
    name="$(echo "$img" | tr ':/' '__')"
    echo "== trivy $img"
    docker save "$img" -o "$tmp/$name.tar" && chmod 644 "$tmp/$name.tar"
    docker run --rm --entrypoint trivy -v "$tmp:/scan:ro" -v pathos_security_cache:/cache "${P}pathos-worker-core:${PATHOS_VERSION:-dev}" \
      image --cache-dir /cache --input "/scan/$name.tar" --severity HIGH,CRITICAL --scanners vuln --format json --quiet > "$out/trivy-$name.json" 2>/dev/null
    rm -f "$tmp/$name.tar"
    summary="$(python3 - "$out/trivy-$name.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
vs = [v for r in d.get("Results", []) for v in (r.get("Vulnerabilities") or [])]
fix = [v for v in vs if v.get("FixedVersion")]
print(f"{len(fix)} fixable / {len(vs)} total high+critical")
for v in fix[:20]:
    print(f"  {v['Severity']} {v['VulnerabilityID']} {v['PkgName']} {v.get('InstalledVersion')} -> {v['FixedVersion']}", file=sys.stderr)
sys.exit(1 if fix else 0)
PY
)"
    if [ $? -eq 0 ]; then gate "trivy $img" "$summary" ok; else gate "trivy $img" "$summary" fail; fi
  done
  rmdir "$tmp" 2>/dev/null || true
fi

if [ "$zap" = 1 ]; then
  echo "== zap baseline $target"
  cp deploy/security/zap-baseline.conf "$out/zap.conf"
  docker run --rm --network host -v "$ROOT/$out:/zap/wrk:rw" "$ZAP_IMAGE" \
    zap-baseline.py -t "$target" -m 2 -c zap.conf -J zap.json -r zap.html -I > "$out/zap.txt" 2>&1
  line="$(grep -E '^FAIL-NEW' "$out/zap.txt" | tail -1)"
  if [ -z "$line" ]; then
    gate zap "did not complete, see $out/zap.txt" fail
  elif echo "$line" | grep -q 'FAIL-NEW: 0'; then
    gate zap "$(echo "$line" | tr -s '\t ' ' ')" ok
  else
    gate zap "$(echo "$line" | tr -s '\t ' ' ')" fail
  fi
fi

echo
echo "Security self-test summary ($out)"
for k in "${!result[@]}"; do printf '  %-32s %s\n' "$k" "${result[$k]}"; done | sort
exit $failed
