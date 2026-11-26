"""What the scripts that run `examples/sshd` share: build it, start it on a free port, and stop it.

    with Server(root) as server:
        server.port, server.dir, server.known_hosts, server.identity

`CANCHO` names the compiler (default: `cancho` on the path). The server's output is `server.log()`.
"""
import os
import shutil
import socket
import subprocess
import tempfile
import time


def cancho():
    return os.environ.get("CANCHO", "cancho")


def sources(root):
    src = sorted(os.path.join(root, "src", f) for f in os.listdir(os.path.join(root, "src")) if f.endswith(".cho"))
    ex = os.path.join(root, "examples", "sshd")
    return sorted(os.path.join(ex, f) for f in os.listdir(ex) if f.endswith(".cho")) + src


def build(root):
    out = os.path.join(root, "build", "sshd")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    subprocess.run([cancho(), "build", *sources(root), "--std", "-o", out], check=True)
    return out


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Server:
    def __init__(self, root, binary=None):
        self.root = root
        self.binary = binary or build(root)

    def __enter__(self):
        self.dir = tempfile.mkdtemp(prefix="cancho-ssh-")
        self.host_key = os.path.join(self.dir, "host_key")
        with open(self.host_key, "wb") as f:
            f.write(os.urandom(32))
        self.identity = os.path.join(self.dir, "id")
        self.stranger = os.path.join(self.dir, "stranger")
        for path in (self.identity, self.stranger):
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "test", "-f", path], check=True)
        self.authorized = os.path.join(self.dir, "authorized_keys")
        shutil.copy(self.identity + ".pub", self.authorized)
        self.port = free_port()
        self.out = open(os.path.join(self.dir, "sshd.log"), "wb")
        self.process = subprocess.Popen([self.binary, str(self.port), self.host_key, self.authorized], stdout=self.out, stderr=subprocess.STDOUT)
        deadline = time.time() + 10
        while b"listening" not in self.log_bytes():
            if self.process.poll() is not None or time.time() > deadline:
                raise RuntimeError("sshd did not start: " + self.log())
            time.sleep(0.02)
        self.host_line = [l for l in self.log().splitlines() if l.startswith("host key ")][0][len("host key "):]
        self.known_hosts = os.path.join(self.dir, "known_hosts")
        with open(self.known_hosts, "w") as f:
            f.write("[127.0.0.1]:%d %s\n" % (self.port, self.host_line))
        return self

    def log_bytes(self):
        with open(os.path.join(self.dir, "sshd.log"), "rb") as f:
            return f.read()

    def log(self):
        return self.log_bytes().decode("utf-8", "replace")

    def alive(self):
        return self.process.poll() is None

    def ended(self, count, timeout=10):
        """The reasons the first `count` connections ended with, once that many have."""
        deadline = time.time() + timeout
        while True:
            lines = [l.split(" ended: ", 1)[1] for l in self.log().splitlines() if " ended: " in l]
            if len(lines) >= count or time.time() > deadline or not self.alive():
                return lines
            time.sleep(0.02)

    def __exit__(self, *exc):
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait()
        self.out.close()
        shutil.rmtree(self.dir, ignore_errors=True)
