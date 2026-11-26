#!/usr/bin/env python3
"""Interoperation: OpenSSH's client, and asyncssh, Dropbear's client and paramiko where they are installed, against
`examples/sshd`.

    CANCHO=/path/to/cancho python3 scripts/interop.py [--first-failure]

Each check logs in the way a person would and compares what came back. Exit status 0 if every check passed.
"""
import os
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sshd_fixture import Server  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
failed = []


def check(name, ok, detail=""):
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else "\n     " + detail.replace("\n", "\n     ")))
    if not ok:
        failed.append(name)
        if "--first-failure" in sys.argv:
            # For `scripts/mutants.py`, which only asks whether anything fails. The server is stopped on the way out.
            sys.exit(1)


def ssh(server, *args, identity=None, known_hosts=None, stdin=b"", options=(), verbose="-v", timeout=60):
    cmd = ["ssh", verbose, "-F", "none", "-p", str(server.port), "-i", identity or server.identity,
           "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-o", "BatchMode=yes",
           "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + (known_hosts or server.known_hosts),
           "-o", "GlobalKnownHostsFile=/dev/null"]
    for o in options:
        cmd += ["-o", o]
    cmd += ["alice@127.0.0.1", *args]
    return subprocess.run(cmd, input=stdin, capture_output=True, timeout=timeout)


def main():
    with Server(ROOT) as server:
        r = ssh(server, "echo", "hello from cancho")
        check("a command runs and its output comes back", r.returncode == 0 and r.stdout == b"hello from cancho\n", repr((r.returncode, r.stdout, r.stderr[-400:])))
        log = r.stderr.decode("utf-8", "replace")
        check("the algorithms are the four offered",
              "kex: algorithm: curve25519-sha256" in log and "host key algorithm: ssh-ed25519" in log
              and log.count("cipher: chacha20-poly1305@openssh.com") == 2, log[-1500:])

        r = ssh(server, "exit", "7")
        check("the exit status of a command is the client's", r.returncode == 7, repr((r.returncode, r.stderr[-300:])))

        r = ssh(server, "nonesuch")
        check("an unknown command is 127", r.returncode == 127 and r.stdout == b"unknown command: nonesuch\n", repr((r.returncode, r.stdout)))

        r = ssh(server, "whoami")
        check("the user name reaches the host", r.stdout == b"alice\n", repr(r.stdout))

        r = ssh(server, "-T", stdin=b"echo one\nwhoami\n# nothing\necho three\n")
        check("a shell without a terminal reads lines and ends at end of input",
              r.returncode == 0 and r.stdout == b"one\nalice\nthree\n", repr((r.returncode, r.stdout, r.stderr[-300:])))

        r = ssh(server, "-tt", stdin=b"echo hi\rsize\rexit 3\r")
        out = r.stdout.replace(b"\r\n", b"\n")
        check("a shell with a terminal echoes, prompts and exits with a status",
              r.returncode == 3 and b"cancho> echo hi\nhi\n" in out and b"cancho> exit 3\n" in out and b"x" in out,
              repr((r.returncode, r.stdout)))

        r = ssh(server, "echo", "no", identity=server.stranger)
        check("a key that is not authorized is refused", r.returncode == 255 and b"Permission denied" in r.stderr and r.stdout == b"", repr((r.returncode, r.stderr[-300:])))

        other = os.path.join(server.dir, "other_hosts")
        with open(other, "w") as f:
            with open(server.stranger + ".pub") as k:
                f.write("[127.0.0.1]:%d %s" % (server.port, k.read()))
        r = ssh(server, "echo", "no", known_hosts=other)
        check("a client that expects another host key refuses this server", r.returncode == 255 and b"HOST IDENTIFICATION HAS CHANGED" in r.stderr and r.stdout == b"", repr((r.returncode, r.stderr[-300:])))

        r = ssh(server, "echo", "strict", verbose="-vvv")
        check("strict key exchange is agreed", b"will use strict KEX ordering" in r.stderr and r.stdout == b"strict\n", repr(r.stderr[-600:]))

        # Re-keying: 6,000 lines out under a limit of 32 KiB each way, so the client re-keys many times, in the
        # middle of the session's output.
        lines = b"".join(b"echo line %06d of the re-key check, padded to be long enough to count\n" % i for i in range(6000))
        expected = b"".join(b"line %06d of the re-key check, padded to be long enough to count\n" % i for i in range(6000))
        r = ssh(server, "-T", stdin=lines, options=["RekeyLimit=32K"], verbose="-vv", timeout=180)
        rekeys = r.stderr.count(b"SSH2_MSG_NEWKEYS sent") - 1
        check("output survives %d re-keys" % rekeys, r.returncode == 0 and r.stdout == expected and rekeys >= 5,
              repr((r.returncode, len(r.stdout), len(expected), rekeys, r.stderr[-400:])))

        r = ssh(server, "echo", "gcm", options=["Ciphers=aes256-gcm@openssh.com"])
        check("OpenSSH with AES-256-GCM runs a command", r.returncode == 0 and r.stdout == b"gcm\n"
              and r.stderr.count(b"cipher: aes256-gcm@openssh.com") == 2, repr((r.returncode, r.stdout, r.stderr[-400:])))
        # Both ciphers offered, this server's second one first: the client's order decides (RFC 4253 section 7.1).
        r = ssh(server, "echo", "order", options=["Ciphers=aes256-gcm@openssh.com,chacha20-poly1305@openssh.com"])
        check("a client that lists AES-GCM first gets it", r.returncode == 0 and r.stdout == b"order\n"
              and r.stderr.count(b"cipher: aes256-gcm@openssh.com") == 2, repr((r.returncode, r.stdout, r.stderr[-400:])))
        r = ssh(server, "-T", stdin=lines, options=["RekeyLimit=32K", "Ciphers=aes256-gcm@openssh.com"], verbose="-vv", timeout=180)
        rekeys = r.stderr.count(b"SSH2_MSG_NEWKEYS sent") - 1
        check("with AES-256-GCM, output survives %d re-keys" % rekeys, r.returncode == 0 and r.stdout == expected and rekeys >= 5,
              repr((r.returncode, len(r.stdout), len(expected), rekeys, r.stderr[-400:])))

        # The window: 3 MiB in, three times what the window is, so it must be raised for the input to arrive.
        big = b"# " + b"x" * 125 + b"\n"
        r = ssh(server, "-T", stdin=big * (3 * 1024 * 1024 // len(big)) + b"echo done\n", timeout=180)
        check("3 MiB of input passes the 1 MiB window", r.returncode == 0 and r.stdout == b"done\n", repr((r.returncode, r.stdout[-100:], r.stderr[-400:])))

        # Three other implementations. Each is skipped, and said to be, where it is not installed.
        try:
            import asyncssh
        except ImportError:
            asyncssh = None
        if asyncssh is None:
            print("skip asyncssh is not installed")
        else:
            import asyncio

            async def with_asyncssh():
                async with asyncssh.connect("127.0.0.1", port=server.port, username="carol", client_keys=[server.identity],
                                            known_hosts=server.known_hosts, agent_path=None, config=None) as conn:
                    done = await conn.run("whoami")
                    return done.stdout, done.exit_status, conn.get_extra_info("send_cipher")
            try:
                got = asyncio.run(asyncio.wait_for(with_asyncssh(), 30))
                check("asyncssh %s logs in and runs a command" % asyncssh.__version__, got[0] == "carol\n" and got[1] == 0, repr(got))
            except Exception as e:  # noqa: BLE001
                check("asyncssh %s logs in and runs a command" % asyncssh.__version__, False, repr(e))

        if shutil.which("dbclient") is None or shutil.which("dropbearconvert") is None:
            print("skip dropbear's client is not installed")
        else:
            home = os.path.join(server.dir, "home")
            os.makedirs(os.path.join(home, ".ssh"))
            # Dropbear looks a host up by its name alone, without OpenSSH's `[host]:port`.
            with open(os.path.join(home, ".ssh", "known_hosts"), "w") as f:
                f.write("127.0.0.1 %s\n" % server.host_line)
            key = os.path.join(server.dir, "id.dropbear")
            subprocess.run(["dropbearconvert", "openssh", "dropbear", server.identity, key], check=True, capture_output=True)
            r = subprocess.run(["dbclient", "-p", str(server.port), "-i", key, "dave@127.0.0.1", "whoami"],
                               env=dict(os.environ, HOME=home), input=b"", capture_output=True, timeout=30)
            check("dropbear's client logs in and runs a command", r.returncode == 0 and r.stdout == b"dave\n", repr((r.returncode, r.stdout, r.stderr[-300:])))

        # paramiko has no ChaCha20 cipher: it is the client that needs AES-GCM (`docs/design.md` section 3).
        try:
            import paramiko
        except ImportError:
            paramiko = None
        if paramiko is None:
            print("skip paramiko is not installed")
        else:
            import logging
            logging.getLogger("paramiko").setLevel(logging.CRITICAL)
            client = paramiko.SSHClient()
            client.load_host_keys(server.known_hosts)
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
            try:
                client.connect("127.0.0.1", port=server.port, username="bob", key_filename=server.identity, allow_agent=False, look_for_keys=False, timeout=20)
                _, stdout, _ = client.exec_command("whoami")
                out = stdout.read()
                status = stdout.channel.recv_exit_status()
                cipher = client.get_transport().remote_cipher
                check("paramiko %s logs in over AES-256-GCM and runs a command" % paramiko.__version__,
                      out == b"bob\n" and status == 0 and cipher == "aes256-gcm@openssh.com", repr((out, status, cipher)))
            except Exception as e:  # noqa: BLE001
                check("paramiko %s logs in over AES-256-GCM and runs a command" % paramiko.__version__, False, repr(e))
            finally:
                client.close()

        check("the server is still running", server.alive(), server.log()[-600:])
        reasons = server.ended(1)
        check("every connection ended by the client's disconnect or a refusal with a tag",
              all(r.startswith("ssh-") or r == "socket closed" for r in reasons), repr(reasons))
    print("%d failed" % len(failed) if failed else "all passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
