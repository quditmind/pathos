"""Unit tests of the pathos-sca wrapper with stand-in tools.

    python3 -I workers/sca/test/test_pathos_sca.py

Regressions from the benchmark of 2026-11-19 (docs/BENCHMARKS.md):
pip-audit refused a package pinned in two requirements files and the
wrapper reported success with no findings; npm audit (and yarn, pnpm and
Composer audit) read only the root lockfile; govulncheck findings lost
their module directory.
"""

import contextlib
import importlib.machinery
import importlib.util
import io
import json
import os
import stat
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True  # never leave __pycache__ in workers/sca/bin (copied into the image)
HERE = os.path.dirname(os.path.abspath(__file__))
WRAPPER = os.path.join(HERE, "..", "bin", "pathos-sca")


def load():
    loader = importlib.machinery.SourceFileLoader("pathos_sca", WRAPPER)
    spec = importlib.util.spec_from_loader("pathos_sca", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def script(path, body):
    with open(path, "w") as f:
        f.write("#!" + sys.executable + "\n" + body)
    os.chmod(path, stat.S_IRWXU)


# pip-audit stand-in: like pip-audit 2.10, it refuses a package listed in
# two -r files of one run (exit 1, no report), refuses unpinned or wildcard
# requirements and fails on the package "brokenpkg"; otherwise it writes a
# JSON report and exits 1 (vulnerable).
PIP_AUDIT = r'''
import json, sys
args = sys.argv[1:]
reqs = [args[i + 1] for i, a in enumerate(args) if a == "-r"]
out = args[args.index("-o") + 1]
seen, deps = set(), []
for r in reqs:
    for line in open(r):
        name, _, version = line.strip().partition("==")
        if name == "brokenpkg":
            print("ERROR:pip_audit._cli:Connection refused", file=sys.stderr)
            sys.exit(1)
        if not version or "*" in version:
            print("ERROR:pip_audit._cli:requirement %s is not pinned" % name, file=sys.stderr)
            sys.exit(1)
        if name.lower() in seen:
            print("ERROR:pip_audit._cli:package %s has duplicate requirements" % name, file=sys.stderr)
            sys.exit(1)
        seen.add(name.lower())
        deps.append({"name": name, "version": version, "vulns": [{"id": "PYSEC-0", "fix_versions": [], "aliases": []}]})
json.dump({"dependencies": deps, "fixes": []}, open(out, "w"))
sys.exit(1)
'''

# node stand-in for npm audit: a lockfile next to a BROKEN file gives npm's
# error JSON; otherwise a report with one vulnerability and exit 1.
NODE = r'''
import json, os, sys
if os.path.exists("BROKEN"):
    print(json.dumps({"error": {"code": "ENOLOCK", "summary": "lockfile unreadable"}}))
    sys.exit(1)
print(json.dumps({"auditReportVersion": 2, "vulnerabilities": {"lodash": {"name": "lodash", "via": []}}, "metadata": {}}))
sys.exit(1)
'''


class WrapperTest(unittest.TestCase):
    def setUp(self):
        self.mod = load()
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        self.src = os.path.join(self.root, "src")
        tools = os.path.join(self.root, "tools")
        os.makedirs(os.path.join(tools, "bin"))
        os.makedirs(self.src)
        script(os.path.join(tools, "bin", "pip-audit"), PIP_AUDIT)
        script(os.path.join(tools, "node"), NODE)
        self.mod.SCA, self.mod.BIN, self.mod.NODE = tools, os.path.join(tools, "bin"), os.path.join(tools, "node")
        self.out = os.path.join(self.root, "report")
        self.cache = os.path.join(self.root, "cache")

    def tearDown(self):
        self.tmp.cleanup()

    def put(self, rel, body=""):
        p = os.path.join(self.src, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(body)

    def call(self, fn):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = fn(self.src, self.out, self.cache)
        with open(self.out, "rb") as f:
            data = f.read()
        return code, (json.loads(data) if data else None), err.getvalue().strip().splitlines()

    def test_pip_audit_per_file(self):
        self.put("svc-a/requirements.txt", "PyYAML==5.3.1\n")
        self.put("svc-b/requirements.txt", "PyYAML==5.4\n")
        code, rep, _ = self.call(self.mod.pip_audit)
        self.assertEqual(code, 0)
        files = [r["file"] for r in rep["pathos_reports"]]
        self.assertEqual(files, ["svc-a/requirements.txt", "svc-b/requirements.txt"])
        self.assertEqual(rep["pathos_reports"][1]["report"]["dependencies"][0]["version"], "5.4")

    def test_pip_audit_error_fails(self):
        self.put("ok/requirements.txt", "jinja2==2.11.2\n")
        self.put("broken/requirements.txt", "brokenpkg==1.0\n")
        code, rep, err = self.call(self.mod.pip_audit)
        self.assertEqual(code, 3, "an error is a failed run, never success without findings")
        self.assertIn("broken/requirements.txt", err[-1])
        self.assertIn("Connection refused", err[-1])
        # The report of the run that worked is kept.
        self.assertEqual([r["file"] for r in rep["pathos_reports"]], ["ok/requirements.txt"])

    def test_pip_audit_unpinned_requirements(self):
        # Seen on InsecureBankv2 ("flask") and a Bitbucket pipe ("boto3==1.37.*"):
        # pip-audit refused the whole file and the scanner failed.
        self.put("requirements.txt", "# app\nflask\nboto3==1.37.*\nPyYAML==5.3.1 --hash=sha256:abc \\\n    --hash=sha256:def\n"
                 "requests[socks] == 2.25.0 ; python_version >= '3.8'  # pinned\n-r other.txt\n-e git+https://x/y.git#egg=y\n")
        self.put("only-unpinned/requirements.txt", "django>=3\n")
        code, rep, err = self.call(self.mod.pip_audit)
        self.assertEqual(code, 0, err)
        by_file = {r["file"]: r["report"]["dependencies"] for r in rep["pathos_reports"]}
        self.assertEqual([d["name"] for d in by_file["requirements.txt"]], ["PyYAML", "requests[socks] "])
        self.assertEqual(by_file["only-unpinned/requirements.txt"], [])
        self.assertTrue(any("2 requirement(s) without an exact version" in e for e in err), err)

    def test_cdxgen_home_inside_its_temporary_directory(self):
        # cdxgen reads ~/.gradle and ~/.m2 for Gradle and Maven projects; the
        # Node.js permission model allows reads only of the repository, the
        # tool and its temporary directory, so HOME must point inside it.
        script(self.mod.NODE, r'''
import json, os, sys
args = sys.argv[1:]
out = args[args.index("-o") + 1]
allowed = [a.split("=", 1)[1] for a in args if a.startswith("--allow-fs-read=")]
home = os.environ["HOME"]
json.dump({"bomFormat": "CycloneDX", "home": home, "gradle": os.environ.get("GRADLE_USER_HOME", ""),
           "home_readable": any(home.startswith(a.rstrip("/")) for a in allowed)}, open(out, "w"))
''')
        code, rep, err = self.call(self.mod.cdxgen)
        self.assertEqual(code, 0, err)
        self.assertTrue(rep["home_readable"], rep)
        self.assertTrue(rep["gradle"].startswith(rep["home"]), rep)

    def test_govulncheck_module_without_packages(self):
        # alertmanager's internal/tools module only has files with a
        # "tools" build tag: govulncheck exits 1 with "no packages matched".
        script(os.path.join(self.mod.BIN, "govulncheck"), r'''
import json, sys
args = sys.argv[1:]
mod = args[args.index("-C") + 1]
if mod.endswith("tools"):
    print("govulncheck: no packages matched the provided patterns", file=sys.stderr)
    sys.exit(1)
print(json.dumps({"config": {"protocol_version": "v1.0.0"}}))
''')
        self.put("go.mod", "module example.com/app\n")
        self.put("internal/tools/go.mod", "module example.com/tools\n")
        code, _, err = self.call(self.mod.govulncheck)
        self.assertEqual(code, 0, err)
        self.assertTrue(any("no Go packages to check" in e for e in err), err)

    def test_npm_audit_every_lockfile(self):
        self.put("package-lock.json", "{}")
        self.put("services/web/package-lock.json", "{}")
        self.put("node_modules/dep/package-lock.json", "{}")
        self.put("vendor/x/package-lock.json", "{}")
        code, rep, _ = self.call(self.mod.npm_audit)
        self.assertEqual(code, 0)
        self.assertEqual([r["file"] for r in rep["pathos_reports"]], ["package-lock.json", "services/web/package-lock.json"])

    def test_npm_audit_error_fails(self):
        self.put("a/package-lock.json", "{}")
        self.put("b/package-lock.json", "{}")
        self.put("b/BROKEN")
        code, rep, err = self.call(self.mod.npm_audit)
        self.assertEqual(code, 3)
        self.assertIn("b/package-lock.json", err[-1])
        self.assertIn("lockfile unreadable", err[-1])
        self.assertEqual([r["file"] for r in rep["pathos_reports"]], ["a/package-lock.json"])

    def test_nothing_to_audit(self):
        code, rep, _ = self.call(self.mod.npm_audit)
        self.assertEqual((code, rep), (0, None))

    def test_govulncheck_module_dir(self):
        stream = b'{\n  "config": {"scanner_name": "govulncheck"}\n}\n{\n  "finding": {"osv": "GO-1"}\n}\n'
        lines = self.mod.govulncheck_with_dir(stream, "services/api").decode().splitlines()
        self.assertEqual(json.loads(lines[0])["config"]["pathos_module_dir"], "services/api")
        self.assertEqual(json.loads(lines[1]), {"finding": {"osv": "GO-1"}})


if __name__ == "__main__":
    unittest.main()
