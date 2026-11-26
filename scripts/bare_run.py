#!/usr/bin/env python3
"""Runs the package as built for `aarch64-none-elf`, and logs in to it with OpenSSH's client.

    CANCHO=/path/to/cancho python3 scripts/bare_run.py

`tests/probes/bare.cho` is a host shaped like a kernel's (no heap, the connection in a region, four foreign functions
for the drivers). It is built with `--target aarch64-none-elf --emit obj`, linked with `tests/probes/board.c`, which
makes the four functions out of a socket, and run under `qemu-aarch64`. What runs is the code a kernel links: the bare
runtime, the regions out of the link's heap, strict alignment, and AArch64.

Needs `aarch64-linux-gnu-gcc` and `qemu-aarch64`; where either is missing it says so and exits 0, having checked
nothing (`scripts/gate.sh` reports that as a skip).
"""
import base64
import os
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sshd_fixture import cancho, free_port  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
failed = []


def check(name, ok, detail=""):
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else "\n     " + detail.replace("\n", "\n     ")))
    if not ok:
        failed.append(name)


def bare_sources():
    src = sorted(os.path.join(ROOT, "src", f) for f in os.listdir(os.path.join(ROOT, "src")) if f.endswith(".cho"))
    return [os.path.join(ROOT, "tests", "probes", "bare.cho"), os.path.join(ROOT, "examples", "sshd", "shell.cho")] + src


def main():
    gcc = shutil.which("aarch64-linux-gnu-gcc")
    qemu = shutil.which("qemu-aarch64")
    if not gcc or not qemu:
        print("skip bare_run: needs aarch64-linux-gnu-gcc and qemu-aarch64")
        return 0
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    work = tempfile.mkdtemp(prefix="cancho-ssh-bare-")
    try:
        obj = os.path.join(work, "bare.o")
        exe = os.path.join(work, "bare")
        subprocess.run([cancho(), "build", *bare_sources(), "--std", "--target", "aarch64-none-elf", "--emit", "obj", "-o", obj], check=True)
        subprocess.run([gcc, "-static", "-O1", "-o", exe, os.path.join(ROOT, "tests", "probes", "board.c"), obj], check=True)

        identity = os.path.join(work, "id")
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "test", "-f", identity], check=True)
        with open(identity + ".pub") as f:
            allowed = base64.b64decode(f.read().split()[1])[19:]
        seed = os.urandom(32)
        public = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        keys = os.path.join(work, "keys")
        with open(keys, "wb") as f:
            f.write(seed + public + allowed)
        blob = b"\0\0\0\x0bssh-ed25519\0\0\0 " + public

        def session(name, args, stdin, want_status, want_out):
            port = free_port()
            known = os.path.join(work, "known_hosts")
            with open(known, "w") as f:
                f.write("[127.0.0.1]:%d ssh-ed25519 %s\n" % (port, base64.b64encode(blob).decode()))
            log = open(os.path.join(work, "board.log"), "wb")
            board = subprocess.Popen([qemu, exe], env=dict(os.environ, BOARD_PORT=str(port), BOARD_KEYS=keys), stdout=log, stderr=subprocess.STDOUT)
            try:
                deadline = time.time() + 20
                while b"listening" not in open(os.path.join(work, "board.log"), "rb").read():
                    if board.poll() is not None or time.time() > deadline:
                        check(name, False, "the board did not start")
                        return
                    time.sleep(0.02)
                r = subprocess.run(["ssh", "-F", "none", "-p", str(port), "-i", identity, "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
                                    "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + known,
                                    "-o", "GlobalKnownHostsFile=/dev/null", *args], input=stdin, capture_output=True, timeout=120)
                try:
                    status = board.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    status = "still running"
                check(name, r.returncode == want_status and r.stdout == want_out and status == 0,
                      repr((r.returncode, r.stdout, r.stderr[-400:], status)))
            finally:
                if board.poll() is None:
                    board.kill()
                board.wait()
                log.close()

        session("the bare object, on AArch64, runs a command for OpenSSH", ["root@127.0.0.1", "echo", "from the bare target"], b"", 0, b"from the bare target\n")
        session("it runs a shell and passes its exit status", ["-T", "root@127.0.0.1"], b"whoami\nexit 9\n", 9, b"root\n")
        lines = b"".join(b"echo line %05d\n" % i for i in range(3000))
        session("it survives re-keying", ["-T", "-o", "RekeyLimit=16K", "root@127.0.0.1"], lines, 0, b"".join(b"line %05d\n" % i for i in range(3000)))
    finally:
        shutil.rmtree(work, ignore_errors=True)
    print("%d failed" % len(failed) if failed else "all passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
