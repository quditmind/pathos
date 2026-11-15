#!/usr/bin/env python3
"""Turn errors in the PATHOS logs into GitHub issues.

    scripts/log-triage.py --since 3h            # draft report only (default)
    scripts/log-triage.py --since 3h --create   # create or update issues

It collects ERROR/WARN entries, HTTP 5xx responses and panics from the
Compose services, groups repeats into one entry per error, and redacts
personal and secret data, because the repository is public. With --create it
opens one issue per new error (labels: bug, from-logs) or comments "seen
again" on the existing issue. Each issue carries a fingerprint, so the same
error never gets two issues. Related errors can be consolidated into one
issue by hand: put all their fingerprint markers in its body.

Always read the draft before using --create: redaction is pattern-based.
Known noise is listed in scripts/log-triage-ignore.txt (one regex per line).
"""
import argparse
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SERVICES = ["api", "jobs", "scheduler", "worker-core", "proxy", "migrate", "keycloak"]
LABEL = "from-logs"

# Redaction, most specific first. Applied to everything that leaves the host.
REDACT = [
    (re.compile(r"-----BEGIN [A-Z ]+-----.*?-----END [A-Z ]+-----", re.S), "[PEM]"),
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"), r"\1 [TOKEN]"),
    (re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|pathos_pat_[A-Za-z0-9_-]{10,}|sk-[A-Za-z0-9_-]{16,}|xox[abp]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16})\b"), "[TOKEN]"),
    (re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), "[JWT]"),
    (re.compile(r"(?i)\b(password|passwd|secret|token|api[_-]?key|authorization|cookie)(\"?\s*[:=]\s*\"?)[^\s\",}]+"), r"\1\2[REDACTED]"),
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "[EMAIL]"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b"), "[IP]"),
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I), "[ID]"),
    (re.compile(r"\b[0-9a-f]{24,}\b", re.I), "[HEX]"),
    (re.compile(r"(https?://[^\s\"?]+)\?[^\s\"]*"), r"\1?[QUERY]"),
    (re.compile(r"/home/[^/\s\"]+"), "/home/[USER]"),
]

# Normalization for grouping only (numbers, durations, line positions).
NORMALIZE = [
    (re.compile(r"\b\d+(\.\d+)?(ms|s|µs|m|h)\b"), "<dur>"),
    (re.compile(r"\b\d+\b"), "<n>"),
]


def redact(s: str) -> str:
    for rx, rep in REDACT:
        s = rx.sub(rep, s)
    return s


def normalize(s: str) -> str:
    s = redact(s)
    for rx, rep in NORMALIZE:
        s = rx.sub(rep, s)
    return s


def compose_logs(since: str) -> list[tuple[str, str]]:
    out = subprocess.run(["docker", "compose", "logs", "--no-color", "--timestamps", "--since", since, *SERVICES],
                         cwd=ROOT, capture_output=True, text=True, check=False)
    if out.returncode != 0 and not out.stdout:
        sys.exit("docker compose logs failed: " + out.stderr.strip())
    lines = []
    for raw in out.stdout.splitlines():
        if " | " not in raw:
            continue
        svc, rest = raw.split(" | ", 1)
        lines.append((svc.strip().rsplit("-", 1)[0], rest))
    return lines


def classify(service: str, rest: str):
    """Return (severity, message, details, path) for interesting lines, else None."""
    ts, _, body = rest.partition(" ")
    if body.lstrip().startswith("{"):
        try:
            e = json.loads(body)
        except json.JSONDecodeError:
            e = None
        if isinstance(e, dict):
            level = str(e.get("level", "")).upper()
            status = e.get("status") or e.get("resp", {}).get("status") if isinstance(e.get("resp"), dict) else e.get("status")
            msg = e.get("msg") or e.get("message") or ""
            if e.get("loggerName") == "org.keycloak.events":
                # Keycloak audit events: keep only the event type and error so
                # repeats group together (each line has unique session IDs).
                kv = dict(re.findall(r'(\w+)="([^"]*)"', msg))
                msg = f'event {kv.get("type", "?")} error={kv.get("error", "")} client={kv.get("clientId", "")}'
            elif service == "keycloak" and e.get("loggerName"):
                msg = f'[{e["loggerName"].rsplit(".", 1)[-1]}] {msg}'
            if isinstance(status, int) and status >= 500:
                path = e.get("path") or (e.get("request") or {}).get("uri", "")
                return ("ERROR", f"HTTP {status} {e.get('method', '')} {route(path)}".strip(), "", ts)
            if level in ("ERROR", "WARN", "WARNING", "FATAL", "PANIC"):
                details = e.get("err") or e.get("error") or ""
                if "panic" in str(e).lower() and e.get("stack"):
                    details = f"{details}\n{e.get('panic', '')}\n{str(e.get('stack'))[:1500]}"
                return ("ERROR" if level in ("ERROR", "FATAL", "PANIC") else "WARN", msg, str(details), ts)
            return None
    m = re.search(r"\b(ERROR|WARN|FATAL)\b(.*)", body)
    if m and service == "keycloak":
        return ("ERROR" if m.group(1) != "WARN" else "WARN", m.group(2).strip()[:200], "", ts)
    if body.startswith("panic:") or "goroutine " in body and "[running]" in body:
        return ("ERROR", "panic: " + body[6:120], "", ts)
    return None


ID_SEGMENT = re.compile(r"/([0-9a-f]{8}-[0-9a-f-]{27}|[0-9]+|[0-9a-f]{16,})(?=/|$)", re.I)


def route(path: str) -> str:
    return ID_SEGMENT.sub("/{id}", path.split("?", 1)[0])


def load_ignores():
    f = ROOT / "scripts" / "log-triage-ignore.txt"
    if not f.exists():
        return []
    return [re.compile(l.strip()) for l in f.read_text().splitlines() if l.strip() and not l.startswith("#")]


def gh(*args, input_text=None):
    r = subprocess.run(["gh", *args], cwd=ROOT, capture_output=True, text=True, input=input_text)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip() or r.stdout.strip())
    return r.stdout


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--since", default="3h", help="time window, e.g. 90m, 3h, 2026-11-16T18:00:00 (default 3h)")
    ap.add_argument("--create", action="store_true", help="create/update GitHub issues (default: draft only)")
    ap.add_argument("--min-level", choices=["WARN", "ERROR"], default="WARN")
    args = ap.parse_args()

    ignores = load_ignores()
    groups = {}
    for service, rest in compose_logs(args.since):
        c = classify(service, rest)
        if not c:
            continue
        sev, msg, details, ts = c
        if args.min_level == "ERROR" and sev != "ERROR":
            continue
        line = f"{service}: {msg} {details}"
        if any(rx.search(line) for rx in ignores):
            continue
        key = f"{service}|{normalize(msg)}|{normalize(details)[:160]}"
        fp = hashlib.sha256(key.encode()).hexdigest()[:12]
        g = groups.setdefault(fp, {"service": service, "severity": sev, "msg": redact(msg), "details": redact(details),
                                    "count": 0, "first": ts, "last": ts})
        g["count"] += 1
        g["last"] = ts
        if sev == "ERROR":
            g["severity"] = "ERROR"

    if not groups:
        print(f"No errors or warnings in the last {args.since}.")
        return
    ordered = sorted(groups.items(), key=lambda kv: (kv[1]["severity"] != "ERROR", -kv[1]["count"]))
    print(f"{len(ordered)} distinct problems in the last {args.since}:\n")
    for fp, g in ordered:
        print(f"[{fp}] {g['severity']:5} {g['service']:12} x{g['count']:<4} {g['msg'][:100]}")
        if g["details"]:
            print(f"        {g['details'][:240].replace(chr(10), ' ')}")
    if not args.create:
        print("\nDraft only. Review the redacted text above, then re-run with --create.")
        return

    try:
        gh("label", "create", LABEL, "--color", "d93f0b", "--description", "Found in runtime logs", "--force")
    except RuntimeError:
        pass
    existing = json.loads(gh("issue", "list", "--label", LABEL, "--state", "all", "--limit", "500", "--json", "number,body,state"))
    by_fp = {}
    for i in existing:
        # One issue may cover several related fingerprints (consolidated by hand).
        for fp in re.findall(r"<!-- log-fingerprint:([0-9a-f]{12}) -->", i.get("body") or ""):
            by_fp[fp] = i
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    for fp, g in ordered:
        seen = f"{g['count']}x between {g['first'][:19]} and {g['last'][:19]} (UTC)"
        if fp in by_fp:
            n = by_fp[fp]["number"]
            if by_fp[fp]["state"] == "CLOSED":
                gh("issue", "reopen", str(n))
            gh("issue", "comment", str(n), "--body", f"Seen again ({now}): {seen}.")
            print(f"updated #{n} ({fp})")
            continue
        title = f"[logs] {g['service']}: {g['msg'][:90]}"
        body = f"""Found automatically in the runtime logs by `scripts/log-triage.py` (redacted).

| | |
|---|---|
| Service | `{g['service']}` |
| Level | {g['severity']} |
| Seen | {seen} |

**Message**
```
{g['msg']}
```
""" + (f"""
**Details**
```
{g['details'][:3000]}
```
""" if g["details"] else "") + f"""
**Next step:** reproduce, find the root cause, fix with a regression test.

<!-- log-fingerprint:{fp} -->"""
        url = gh("issue", "create", "--title", title, "--label", f"bug,{LABEL}", "--body-file", "-", input_text=body).strip()
        print(f"created {url} ({fp})")


if __name__ == "__main__":
    main()
