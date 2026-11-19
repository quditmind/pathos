#!/usr/bin/env python3
"""Run the PATHOS Opengrep rules against their test fixtures.

Fixtures live in workers/rules-tests/. A comment line

    # ruleid: <rule id>      (or // ruleid: ...)

means the next non-comment line must be reported by that rule, and

    # ok: <rule id>

means the next non-comment line must not be. Opengrep runs from the
worker-core image (no local install needed):

    scripts/test-opengrep-rules.py
    PATHOS_WORKER_IMAGE=ghcr.io/quditmind/pathos-worker-core:1.0.0 scripts/test-opengrep-rules.py
    OPENGREP=/usr/local/bin/opengrep scripts/test-opengrep-rules.py

Exit status 0 when every expectation holds.
"""
import json
import os
import re
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES = os.path.join(ROOT, "workers", "rules")
FIXTURES = os.path.join(ROOT, "workers", "rules-tests")
ANNOT = re.compile(r"^\s*(?:#|//|/\*)\s*(ruleid|ok):\s*([\w.-]+(?:\s*,\s*[\w.-]+)*)")
COMMENT = re.compile(r"^\s*(#|//|/\*|\*)")


def expectations():
    want, forbid = set(), set()
    for d, _, files in os.walk(FIXTURES):
        for name in files:
            if name.endswith(".md"):
                continue
            path = os.path.join(d, name)
            rel = os.path.relpath(path, FIXTURES)
            with open(path, encoding="utf-8") as f:
                lines = f.read().split("\n")
            for i, line in enumerate(lines):
                m = ANNOT.match(line)
                if not m:
                    continue
                j = i + 1
                while j < len(lines) and COMMENT.match(lines[j]):
                    j += 1
                for rid in m.group(2).split(","):
                    (want if m.group(1) == "ruleid" else forbid).add((rel, j + 1, rid.strip()))
    return want, forbid


def run_opengrep():
    # Every PATHOS rule pack with fixtures: the framework configuration
    # rules and the crypto, database, AI and CI/CD packs (the baseline rules
    # have no fixtures).
    rule_files = sorted(f for f in os.listdir(RULES)
                        if f.startswith("pathos-") and f.endswith(".yml") and f != "pathos-baseline.yml")
    binary = os.environ.get("OPENGREP") or shutil.which("opengrep")
    if binary:
        cmd = [binary, "scan", "--json", "--quiet", "--disable-version-check"]
        cmd += [a for f in rule_files for a in ("--config", os.path.join(RULES, f))]
        cmd.append(FIXTURES)
        cwd = FIXTURES
    else:
        image = os.environ.get("PATHOS_WORKER_IMAGE", "ghcr.io/quditmind/pathos-worker-core:latest")
        cmd = ["docker", "run", "--rm", "--network", "none", "--entrypoint", "opengrep",
               "-v", RULES + ":/r:ro", "-v", FIXTURES + ":/src:ro", "-w", "/src", "-e", "HOME=/tmp/home",
               image, "scan", "--json", "--quiet", "--disable-version-check"]
        cmd += [a for f in rule_files for a in ("--config", "/r/" + f)]
        cmd.append(".")
        cwd = None
    out = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if out.returncode not in (0, 1):
        sys.exit("opengrep failed (%d): %s" % (out.returncode, out.stderr[-2000:]))
    doc = json.loads(out.stdout)
    for e in doc.get("errors", []):
        print("opengrep error:", json.dumps(e)[:500], file=sys.stderr)
    got = set()
    for r in doc.get("results", []):
        rid = r["check_id"]
        if "pathos." in rid:
            rid = rid[rid.index("pathos."):]
        path = os.path.normpath(r["path"])
        if os.path.isabs(path):
            path = os.path.relpath(path, FIXTURES)
        got.add((path, r["start"]["line"], rid))
    return got, doc.get("errors", [])


def main():
    want, forbid = expectations()
    got, errors = run_opengrep()
    missing = sorted(w for w in want if w not in got)
    unexpected = sorted(f for f in forbid if f in got)
    # Every result must be annotated (no unnoticed false positives).
    extra = sorted(g for g in got if g not in want)
    for m in missing:
        print("MISSING  %s:%d %s" % m)
    for u in unexpected:
        print("FALSE POSITIVE (ok:)  %s:%d %s" % u)
    for e in extra:
        print("UNANNOTATED  %s:%d %s" % e)
    print("%d expected detections, %d ok cases, %d missing, %d false positives, %d unannotated, %d errors"
          % (len(want), len(forbid), len(missing), len(unexpected), len(extra), len(errors)))
    return 1 if missing or unexpected or extra or errors else 0


if __name__ == "__main__":
    sys.exit(main())
