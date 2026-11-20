"""Unit tests of tflint-tree with a stand-in tflint.

    python3 -I workers/iac/test/test_tflint_tree.py

VALIDATION_REPORT O8: on terragoat TFLint exited 1 with its error inside
the JSON report on standard output, so the scan showed no message and lost
the issues of the modules that loaded.
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
WRAPPER = os.path.join(HERE, "..", "bin", "tflint-tree")

FAKE = r'''
import json, os, sys
mode = open(os.environ["MODE"]).read().strip()
issue = {"rule": {"name": "terraform_required_version"}, "message": "required", "range": {"filename": "a/main.tf"}}
if mode == "ok":
    print(json.dumps({"issues": [issue], "errors": []})); sys.exit(0)
print(json.dumps({"issues": [issue], "errors": [{"message": "Failed to run in /src/aws; exit status 1\n\nFailed to load the root module; "
      "aws/consts.tf:29,13-21: Invalid quoted type constraints\n\n\u001b[31mError\u001b[0m: Invalid quoted type constraints"}]}))
sys.exit(1)
'''


def load():
    loader = importlib.machinery.SourceFileLoader("tflint_tree", WRAPPER)
    spec = importlib.util.spec_from_loader("tflint_tree", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


class TFLintTree(unittest.TestCase):
    def setUp(self):
        self.mod = load()
        self.tmp = tempfile.TemporaryDirectory()
        fake = os.path.join(self.tmp.name, "tflint")
        with open(fake, "w") as f:
            f.write("#!" + sys.executable + "\n" + FAKE)
        os.chmod(fake, stat.S_IRWXU)
        self.mod.TFLINT = fake
        self.mode = os.path.join(self.tmp.name, "mode")
        os.environ["MODE"] = self.mode

    def tearDown(self):
        del os.environ["MODE"]
        self.tmp.cleanup()

    def run_tree(self, mode):
        with open(self.mode, "w") as f:
            f.write(mode)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = self.mod.main(["tflint-tree", self.tmp.name])
        return code, json.loads(out.getvalue()), err.getvalue().strip().splitlines()

    def test_clean_run(self):
        code, rep, _ = self.run_tree("ok")
        self.assertEqual(code, 0)
        self.assertEqual(len(rep["issues"]), 1)

    def test_module_error_is_reported_and_issues_kept(self):
        code, rep, err = self.run_tree("error")
        self.assertEqual(code, 3)
        self.assertEqual(len(rep["issues"]), 1, "the issues of the modules that loaded are kept")
        self.assertIn("1 module(s) could not be checked", err[-1])
        self.assertIn("Invalid quoted type constraints", err[-1])
        self.assertNotIn("\x1b", err[-1])


if __name__ == "__main__":
    unittest.main()
