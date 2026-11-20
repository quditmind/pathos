"""Unit tests of gosec-tree with a stand-in gosec binary.

    python3 -I workers/sast/test/test_gosec_tree.py

VALIDATION_REPORT O4: `gosec ./...` was OOM-killed (exit 137) at the 4 GB
worker limit on alertmanager and gitlab-cli, and the scan lost every gosec
finding. gosec-tree now scans per module and top-level directory, merges
the reports, and keeps the findings of the chunks that ran.
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
WRAPPER = os.path.join(HERE, "..", "bin", "gosec-tree")

# Stand-in gosec: one issue per package pattern; "./big/..." is killed
# like the kernel OOM killer would; patterns without issues write nothing
# (gosec -quiet).
FAKE_GOSEC = r'''
import json, os, sys
args = sys.argv[1:]
out = [a for a in args if a.startswith("-out=")][0][5:]
pats = [a for a in args if not a.startswith("-")]
with open(os.path.join(os.environ["CALLS"]), "a") as f:
    f.write(json.dumps({"cwd": os.getcwd(), "patterns": pats, "memlimit": os.environ.get("GOMEMLIMIT", "")}) + "\n")
if "./big/..." in pats:
    os.kill(os.getpid(), 9)
if "./clean/..." in pats:
    sys.exit(0)
issues = [{"rule_id": "G101", "file": os.path.join(os.getcwd(), p.strip("./")), "line": "1", "column": "1"} for p in pats]
json.dump({"Issues": issues, "Stats": {"files": 1, "lines": 10, "nosec": 0, "found": len(issues)}, "Golang errors": {}, "GosecVersion": "dev"},
          open(out, "w"))
'''


def load():
    loader = importlib.machinery.SourceFileLoader("gosec_tree", WRAPPER)
    spec = importlib.util.spec_from_loader("gosec_tree", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


class GosecTree(unittest.TestCase):
    def setUp(self):
        self.mod = load()
        self.tmp = tempfile.TemporaryDirectory()
        root = self.tmp.name
        self.src, self.work = os.path.join(root, "src"), os.path.join(root, "work")
        os.makedirs(self.work)
        fake = os.path.join(root, "gosec")
        with open(fake, "w") as f:
            f.write("#!" + sys.executable + "\n" + FAKE_GOSEC)
        os.chmod(fake, stat.S_IRWXU)
        self.mod.GOSEC = fake
        self.calls = os.path.join(root, "calls")
        os.environ["CALLS"] = self.calls
        self.report = os.path.join(root, "report.json")

    def tearDown(self):
        del os.environ["CALLS"]
        self.tmp.cleanup()

    def put(self, rel, body="package x\n"):
        p = os.path.join(self.src, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(body)

    def run_tree(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = self.mod.main(["gosec-tree", self.src, self.report, self.work])
        with open(self.report) as f:
            rep = json.load(f)
        with open(self.calls) as f:
            calls = [json.loads(l) for l in f]
        return code, rep, calls, err.getvalue().strip().splitlines()

    def test_chunks_per_module_and_directory(self):
        self.put("go.mod", "module example.com/app\n")
        self.put("main.go")
        self.put("cmd/app/main.go")
        self.put("internal/a/a.go")
        self.put("internal/b/b.go")
        self.put("vendor/x/x.go")
        self.put("docs/readme.md", "no Go")
        self.put("tools/go.mod", "module example.com/tools\n")
        self.put("tools/tools.go")
        code, rep, calls, err = self.run_tree()
        self.assertEqual(code, 0, err)
        runs = sorted((os.path.relpath(c["cwd"], self.src), tuple(c["patterns"])) for c in calls)
        self.assertEqual(runs, sorted([(".", (".",)), (".", ("./cmd/...",)), (".", ("./internal/...",)), ("tools", (".",))]))
        self.assertEqual(rep["Stats"]["found"], len(rep["Issues"]))
        self.assertEqual(len(rep["Issues"]), 4)

    def test_oom_chunk_keeps_the_others(self):
        self.put("go.mod", "module example.com/app\n")
        self.put("big/huge.go")
        self.put("small/s.go")
        self.put("clean/c.go")
        code, rep, _, err = self.run_tree()
        self.assertEqual(code, 3, "a chunk that was killed makes the tool fail (partial)")
        self.assertIn("out of memory", err[-1])
        self.assertIn("big", err[-1])
        self.assertEqual([i["file"].split(os.sep)[-1] for i in rep["Issues"]], ["small"])


if __name__ == "__main__":
    unittest.main()
