#!/usr/bin/env python3
"""Regenerate labels.json of the SCA suite from the OSV database.

Run by hand (python3 -I osv-labels.py > labels.json); it queries
https://api.osv.dev, so the answer key is OSV's view on the day it ran
(recorded in the file). Every vulnerability OSV lists for a pinned
version is a positive case in the "-vulnerable" project; a vulnerability
that affects the vulnerable version but not the fixed one is a negative
case in the "-fixed" project (a tool reporting it there is a false
positive); one that affects both versions is a positive case in both.
Identifiers that OSV lists as aliases of each other are one case.
"""
import datetime
import json
import urllib.request

# (project pair, ecosystem, OSV package name, names tools use, vulnerable, fixed)
PACKAGES = [
    ("npm", "npm", "lodash", ["lodash"], "4.17.15", "4.17.21"),
    ("npm", "npm", "minimist", ["minimist"], "1.2.5", "1.2.6"),
    ("pypi", "PyPI", "pyyaml", ["pyyaml"], "5.3.1", "5.4"),
    ("pypi", "PyPI", "jinja2", ["jinja2"], "2.11.2", "2.11.3"),
    ("pypi", "PyPI", "urllib3", ["urllib3"], "1.26.4", "1.26.5"),
    ("maven", "Maven", "org.apache.logging.log4j:log4j-core",
     ["org.apache.logging.log4j:log4j-core", "log4j-core"], "2.14.1", "2.17.1"),
    ("go", "Go", "golang.org/x/text", ["golang.org/x/text"], "0.3.5", "0.3.8"),
]


def query(eco, name, version):
    body = json.dumps({"package": {"ecosystem": eco, "name": name}, "version": version}).encode()
    req = urllib.request.Request("https://api.osv.dev/v1/query", data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r).get("vulns", [])


def groups(vulns):
    """Merge each record's ID and aliases into identifier groups."""
    out = []
    for v in vulns:
        ids = {v["id"], *v.get("aliases", [])}
        ids = {i for i in ids if not i.startswith("SNYK-")}
        hit = [g for g in out if g & ids]
        for g in hit:
            out.remove(g)
            ids |= g
        out.append(ids)
    return out


def main():
    cases = []
    for pair, eco, name, names, vuln_v, fixed_v in PACKAGES:
        vg, fg = groups(query(eco, name, vuln_v)), groups(query(eco, name, fixed_v))
        for g in sorted(vg, key=lambda g: sorted(g)):
            ids = sorted(g)
            cid = next((i for i in ids if i.startswith("CVE-")), ids[0])
            cases.append({"id": f"{pair}-vulnerable/{names[-1]}@{vuln_v}/{cid}", "category": pair, "vulnerable": True,
                          "file": f"{pair}-vulnerable", "packages": names, "version": vuln_v, "vulns": ids})
            in_fixed = any(g & f for f in fg)
            cases.append({"id": f"{pair}-fixed/{names[-1]}@{fixed_v}/{cid}", "category": pair, "vulnerable": in_fixed,
                          "file": f"{pair}-fixed", "packages": names, "version": fixed_v, "vulns": ids})
        for g in fg:
            if not any(g & v for v in vg):
                ids = sorted(g)
                cid = next((i for i in ids if i.startswith("CVE-")), ids[0])
                cases.append({"id": f"{pair}-fixed/{names[-1]}@{fixed_v}/{cid}", "category": pair, "vulnerable": True,
                              "file": f"{pair}-fixed", "packages": names, "version": fixed_v, "vulns": ids})
    today = datetime.date.today().isoformat()
    print(json.dumps({"suite": "sca-pinned-versions",
                      "source": f"PATHOS benchmarks/suites/sca (self-made projects); answer key from api.osv.dev on {today}",
                      "license": "Apache-2.0 (PATHOS; self-made)", "match": "sca", "cases": cases}, indent=2))


if __name__ == "__main__":
    main()
