"""Finds the infrastructure-as-code files of a repository for the worker-iac
wrappers (tools that take file names rather than a directory).

Only regular files of at most 2 MiB are considered; symbolic links and the
.git directory are skipped. Nothing in the repository is executed.
"""
import os
import re
import sys

MAX_SIZE = 2 << 20
SKIP_DIRS = {".git", "node_modules", ".terraform"}

_DOCKERFILE = re.compile(r"^(Dockerfile|Containerfile)([._-].*)?$|.*\.(dockerfile|containerfile)$", re.IGNORECASE)
_CFN = re.compile(rb"AWSTemplateFormatVersion|[\"']?Type[\"']?\s*:\s*[\"']?AWS::[A-Za-z0-9]+::")
_K8S_API = re.compile(rb"^apiVersion:\s*\S", re.MULTILINE)
_K8S_KIND = re.compile(rb"^kind:\s*\S", re.MULTILINE)


def files(root):
    """Yields (path, name) of the regular files under root, sorted."""
    for d, dirs, names in os.walk(root):
        dirs[:] = sorted(x for x in dirs if x not in SKIP_DIRS and not os.path.islink(os.path.join(d, x)))
        for n in sorted(names):
            p = os.path.join(d, n)
            try:
                st = os.lstat(p)
            except OSError:
                continue
            if os.path.isfile(p) and not os.path.islink(p) and st.st_size <= MAX_SIZE and "\n" not in p:
                yield p, n


def head(path, n=1 << 20):
    try:
        with open(path, "rb") as f:
            return f.read(n)
    except OSError:
        return b""


def dockerfiles(root):
    return [p for p, n in files(root) if _DOCKERFILE.match(n)]


def cfn_templates(root):
    out = []
    for p, n in files(root):
        if n.lower().endswith((".yaml", ".yml", ".json", ".template")):
            data = head(p)
            if b"Resources" in data and _CFN.search(data):
                out.append(p)
    return out


def k8s_manifests(root):
    """Kubernetes YAML files (not Helm templates, which are not YAML)."""
    out = []
    for p, n in files(root):
        if n.lower().endswith((".yaml", ".yml")):
            data = head(p)
            if _K8S_API.search(data) and _K8S_KIND.search(data) and b"{{" not in data:
                out.append(p)
    return out


def usage(name):
    sys.stderr.write("usage: %s <directory> [output file]\n" % name)
    sys.exit(2)
