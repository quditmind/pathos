#!/usr/bin/env python3
"""Prints the per-endpoint latency table of a k6-scale.js run.

    scripts/load/summary.py reports/load/<run>/summary.json [more.json ...]
"""
import json
import sys

for path in sys.argv[1:]:
    m = json.load(open(path))["metrics"]
    print(f"\n{path}\n")
    print("| Endpoint | Requests | p50 ms | p95 ms | p99 ms | max ms | Errors |")
    print("|---|---:|---:|---:|---:|---:|---:|")
    for k in sorted(m):
        if not k.startswith("ep_"):
            continue
        t = m[k]
        name = k[3:]
        f = m.get("fail_" + name, {})
        errs = f.get("passes", 0)  # a Rate counts true values as passes
        print(f"| {name} | {t.get('count', 0):.0f} | {t['med']:.0f} | {t['p(95)']:.0f} | {t['p(99)']:.0f} | {t['max']:.0f} | {errs} |")
    req = m.get("http_reqs", {})
    dur = m.get("http_req_duration", {})
    fail = m.get("http_req_failed", {})
    print(f"\nall requests: {req.get('count', 0):.0f} ({req.get('rate', 0):.1f}/s), "
          f"p50 {dur.get('med', 0):.0f} ms, p95 {dur.get('p(95)', 0):.0f} ms, p99 {dur.get('p(99)', 0):.0f} ms, "
          f"failed {fail.get('value', 0) * 100:.2f} %")
