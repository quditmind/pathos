"""Unit tests of the pathos-ai garak runner with a stand-in garak.

    python3 -I workers/ai/test/test_pathos_ai.py

VALIDATION_REPORT O18: one read timeout of a slow model aborted the whole
garak run without a report.
"""

import contextlib
import importlib.machinery
import importlib.util
import json
import os
import stat
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
WRAPPER = os.path.join(HERE, "..", "bin", "pathos-ai")

# Stand-in "python -m garak": writes a report per run; the probe
# "probes.slow" times out after writing part of its report.
FAKE_PYTHON = r'''
import json, os, sys
args = sys.argv[1:]
spec = args[args.index("--spec") + 1]
prefix = args[args.index("--report_prefix") + 1]
opts = json.load(open(args[args.index("--generator_option_file") + 1]))
runs = os.path.join(os.environ["XDG_DATA_HOME"], "garak", "garak_runs")
os.makedirs(runs, exist_ok=True)
with open(os.path.join(runs, prefix + ".report.jsonl"), "w") as f:
    f.write(json.dumps({"entry_type": "start_run setup", "timeout": opts["rest"]["RestGenerator"]["request_timeout"]}) + "\n")
    if spec == "probes.slow":
        print("requests.exceptions.ReadTimeout: read timed out", file=sys.stderr)
        sys.exit(1)
    f.write(json.dumps({"entry_type": "eval", "probe": spec, "detector": "d", "passed": 0, "total": 1}) + "\n")
'''


def load():
    loader = importlib.machinery.SourceFileLoader("pathos_ai", WRAPPER)
    spec = importlib.util.spec_from_loader("pathos_ai", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


class Garak(unittest.TestCase):
    def setUp(self):
        self.mod = load()
        self.tmp = tempfile.TemporaryDirectory()
        root = self.tmp.name
        bindir = os.path.join(root, "bin")
        os.makedirs(bindir)
        with open(os.path.join(bindir, "python"), "w") as f:
            f.write("#!" + sys.executable + "\n" + FAKE_PYTHON)
        os.chmod(os.path.join(bindir, "python"), stat.S_IRWXU)
        self.mod.BIN = bindir
        self.target = os.path.join(root, "target.json")
        with open(self.target, "w") as f:
            json.dump({"url": "http://llm.test/v1/chat/completions", "model": "m"}, f)
        self.work = os.path.join(root, "work")
        os.makedirs(self.work)
        self.out = os.path.join(root, "report.jsonl")

    def tearDown(self):
        self.tmp.cleanup()

    def run_garak(self, spec):
        self.mod.GARAK_SPEC = spec
        # The wrapper passes its standard error to garak: a real file.
        with tempfile.TemporaryFile("w+") as err, contextlib.redirect_stderr(err):
            code = self.mod.garak(self.target, self.out, self.work)
            err.seek(0)
            text = err.read()
        with open(self.out) as f:
            lines = [json.loads(l) for l in f if l.strip()]
        return code, lines, text.strip().splitlines()

    def test_one_probe_timeout_keeps_the_others(self):
        code, lines, err = self.run_garak("probes.a,probes.slow,probes.b")
        self.assertEqual(code, 3)
        evals = [l["probe"] for l in lines if l["entry_type"] == "eval"]
        self.assertEqual(evals, ["probes.a", "probes.b"])
        self.assertIn("1 of 3 probes failed", err[-1])
        self.assertIn("probes.slow", err[-1])
        self.assertEqual(lines[0]["timeout"], 180, "slow models get a longer request timeout")

    def test_all_probes_succeed(self):
        code, lines, _ = self.run_garak("probes.a,probes.b")
        self.assertEqual(code, 0)
        self.assertEqual(sum(l["entry_type"] == "eval" for l in lines), 2)


if __name__ == "__main__":
    unittest.main()
