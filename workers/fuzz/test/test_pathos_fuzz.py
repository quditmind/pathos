"""Unit tests of the pathos-fuzz wrapper with a stand-in go binary.

    python3 -I workers/fuzz/test/test_pathos_fuzz.py

VALIDATION_REPORT O4: fuzz targets of Go modules whose dependencies are
not vendored did not build ("build-failed"), and the scan still reported
the tool as succeeded with no findings.
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

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
WRAPPER = os.path.join(HERE, "..", "bin", "pathos-fuzz")

FAKE_GO = r'''#!/bin/sh
case "$PWD" in
  *broken*) echo "go: cannot find module providing package github.com/x/y: import lookup disabled by -mod=vendor"; exit 1 ;;
esac
echo "fuzz: elapsed: 1s, execs: 100"; echo PASS; exit 0
'''


def load():
    loader = importlib.machinery.SourceFileLoader("pathos_fuzz", WRAPPER)
    spec = importlib.util.spec_from_loader("pathos_fuzz", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


class GoFuzz(unittest.TestCase):
    def setUp(self):
        self.mod = load()
        self.tmp = tempfile.TemporaryDirectory()
        root = self.tmp.name
        self.src, self.work = os.path.join(root, "src"), os.path.join(root, "work")
        os.makedirs(self.work)
        go = os.path.join(root, "go")
        with open(go, "w") as f:
            f.write(FAKE_GO)
        os.chmod(go, stat.S_IRWXU)
        self.mod.GO, self.mod.SECONDS = go, 1
        self.out = os.path.join(root, "report.json")

    def tearDown(self):
        self.tmp.cleanup()

    def harness(self, pkg):
        d = os.path.join(self.src, pkg)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "x_test.go"), "w") as f:
            f.write("package x\n\nfunc FuzzParse(f *testing.F) {}\n")

    def run_go(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = self.mod.go(self.src, self.out, self.work)
        with open(self.out) as f:
            return code, json.load(f), err.getvalue().strip().splitlines()

    def test_all_targets_run(self):
        self.harness("ok")
        code, rep, err = self.run_go()
        self.assertEqual(code, 0, err)
        self.assertEqual([t["status"] for t in rep["targets"]], ["passed"])

    def test_build_failure_is_not_a_success(self):
        self.harness("ok")
        self.harness("broken")
        code, rep, err = self.run_go()
        self.assertEqual(code, 3, "a target that does not build makes the tool fail (partial execution)")
        self.assertEqual(sorted(t["status"] for t in rep["targets"]), ["build-failed", "passed"])
        self.assertIn("1 of 2 fuzz targets did not run", err[-1])
        self.assertIn("go mod vendor", err[-1])

    def test_outcome_ignores_budget_skips(self):
        self.assertEqual(self.mod.outcome("go-fuzz", [{"name": "a", "status": "passed"}, {"name": "b", "status": "skipped"}], ""), 0)


if __name__ == "__main__":
    unittest.main()
