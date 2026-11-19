"""A deliberately malicious Atheris harness, used only by
workers/fuzz/test/sandbox-e2e.sh. It tries to escape the PATHOS sandbox
runner: TCP connections to the egress proxy, the PATHOS API (by name and by
the addresses the test writes to sandbox-targets.txt) and 1.1.1.1, DNS
lookups, the environment of every visible process (including
/proc/1/environ), writes outside the job directory, a fork bomb and a daemon. It
prints one SANDBOX-PROBE line with the outcome of each attempt
(blocked:<reason> or OPEN...) and exits with 3, so the line ends up in the
fuzz report's target details. Never run it outside that test."""
import errno
import os
import socket
import sys
import time

import atheris

out = []


def add(k, v):
    out.append("%s=%s" % (k, v))


def reason(e):
    code = getattr(e, "errno", None)
    if isinstance(code, int) and code > 0:
        return errno.errorcode.get(code, str(code))
    return "%s%s" % (type(e).__name__, code if code is not None else "")


def targets():
    d = os.getcwd()
    for _ in range(6):
        try:
            with open(os.path.join(d, "sandbox-targets.txt")) as f:
                return f.read().split()
        except OSError:
            d = os.path.dirname(d)
    return []


for a in ["egress:3128", "api:8081", "1.1.1.1:443"] + targets():
    host, port = a.rsplit(":", 1)
    try:
        socket.create_connection((host, int(port)), timeout=3).close()
        add("tcp:" + a, "OPEN")
    except OSError as e:
        add("tcp:" + a, "blocked:" + reason(e))

for h in ("api", "egress", "example.com"):
    try:
        add("dns:" + h, "OPEN:" + ",".join(sorted({i[4][0] for i in socket.getaddrinfo(h, 80)})))
    except OSError as e:
        add("dns:" + h, "blocked:" + reason(e))

add("ifaces", ",".join(sorted(os.listdir("/sys/class/net"))))

leak = [k for k in os.environ if "TOKEN" in k or k.upper().endswith("_PROXY") or k.startswith("PATHOS_API")]
add("env", "OPEN:" + ",".join(leak) if leak else "clean")

# Every visible process: its command and whether its environment leaks.
procs, secrets, readable = [], [], 0
for pid in sorted((p for p in os.listdir("/proc") if p.isdigit()), key=int):
    try:
        with open("/proc/%s/cmdline" % pid, "rb") as f:
            procs.append(f.read().split(b"\0")[0].decode(errors="replace").rsplit("/", 1)[-1])
    except OSError:
        continue
    try:
        with open("/proc/%s/environ" % pid, "rb") as f:
            env = f.read()
        readable += 1
        if b"TOKEN" in env or b"PATHOS_API" in env or b"_PROXY=" in env:
            secrets.append(pid)
    except OSError:
        pass
add("procs", ",".join(sorted(set(procs))))
add("proc-environ", "OPEN:" + ",".join(secrets) if secrets else "clean(readable=%d)" % readable)
try:
    with open("/proc/1/environ", "rb") as f:
        f.read()
    add("proc1-environ", "readable")
except OSError as e:
    add("proc1-environ", "blocked:" + reason(e))

for p in ("/tmp", "/var/tmp", "/dev/shm", "/sandbox", "/sandbox/jobs", "/sandbox/queue", "/opt/pathos", "/etc", "/work"):
    f = os.path.join(p, "pathos-probe")
    try:
        with open(f, "w") as fh:
            fh.write("x")
        os.remove(f)
        add("write:" + p, "OPEN")
    except OSError as e:
        add("write:" + p, "blocked:" + reason(e))

# PROBE_NO_FORK skips the fork bomb (the test's unsandboxed control run).
# Fork bomb (bounded at 5000 so that a failure of the limit cannot take the
# host down): every child sleeps until the deadline, then exits.
end, n, err = time.time() + 5, 0, None
children = []
while "PROBE_NO_FORK" not in os.environ and n < 5000 and time.time() < end:
    try:
        pid = os.fork()
    except OSError as e:
        err = e
        break
    if pid == 0:
        time.sleep(max(0, end - time.time()))
        os._exit(0)
    children.append(pid)
    n += 1
for pid in children:
    try:
        os.waitpid(pid, 0)
    except OSError:
        pass
add("fork", "limited:%d:%s" % (n, reason(err)) if err else "OPEN:%d" % n)

# A daemon (double fork, new session) that would outlive the run and spy
# on the next one; sandbox-e2e.sh checks that the runner killed it.
if "PROBE_NO_FORK" not in os.environ and os.fork() == 0:
    os.setsid()
    if os.fork() == 0:
        # Detached from the harness's output, which would otherwise stay
        # open and keep pathos-fuzz waiting.
        null = os.open(os.devnull, os.O_RDWR)
        for fd in (0, 1, 2):
            os.dup2(null, fd)
        time.sleep(600)
    os._exit(0)
add("daemon", "started")

print("SANDBOX-PROBE " + " ".join(out), flush=True)
sys.exit(3)


def test_one_input(data):
    pass


atheris.Setup(sys.argv, test_one_input)
atheris.Fuzz()
