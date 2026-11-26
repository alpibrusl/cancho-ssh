# cancho-ssh

An SSH server written in [cancho](https://github.com/alpibrusl/cancho) that owns no socket, no clock, no file and
no heap: it is given bytes and gives bytes back. The same eight files serve a login on Linux and macOS, and build for
a machine with nothing under them (`--target aarch64-none-elf`), which is what
[cancho-os](https://github.com/alpibrusl/cancho-os) needs to put its shell on the network.

```
$ cancho build                      # builds examples/sshd into build/sshd
$ head -c 32 /dev/urandom > host_key
$ build/sshd 2222 host_key ~/.ssh/authorized_keys
host key ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA+yWAXV...
authorized keys 1
listening 127.0.0.1 port 2222

$ ssh -p 2222 you@127.0.0.1
cancho-ssh demonstration shell; `help` lists the commands
cancho> whoami
you
```

**Status: it works against real clients, and nobody but its author has read it.** OpenSSH 9.6, asyncssh 2.24 and
Dropbear 2022.83 log in, run commands, get exit statuses and survive re-keying; the object built for the bare
target does the same when run on AArch64 under qemu. It has not been reviewed, has not been run on a Raspberry Pi
or on macOS (the gate was run on Linux x86-64), and should not guard anything yet. [`docs/design.md`](docs/design.md) says what was decided, what was measured and
what is not done.

## What it speaks

One algorithm of each kind, all of them already in cancho's standard library:

| | |
|---|---|
| key exchange | `curve25519-sha256` |
| host key | `ssh-ed25519` |
| cipher | `chacha20-poly1305@openssh.com` |
| user authentication | `publickey`, with `ssh-ed25519` keys |
| channels | one `session` at a time: a shell or a command, with or without a terminal |

with OpenSSH's strict key exchange (the Terrapin countermeasure) and re-keying when the client asks. No passwords,
no forwarding, no SFTP. A client that shares no algorithm is refused and told why; paramiko, which has no ChaCha20
cipher, is one.

## Using it

```
import ssh_server as ssh;

ssh.start(ints, bytes, host_seed, host_public, entropy);       // once a connection
// then, in a loop:
ssh.sent(ints, bytes, send(ssh.pending(ints, bytes)));         // what goes to the client
ssh.feed(ints, bytes, received);                               // what came from it
// ssh.wants(ints) says what the host must do next:
//   want_auth     may this key log in as this user?   ssh.auth_decide(ints, bytes, accept)
//   want_data     the client typed something          ssh.received(ints, bytes), ssh.consume(ints, bytes, n)
//   want_nothing  the connection is over              ssh.failure(ints), ssh.refusal_tag(code)
// and ssh.write(ints, bytes, output) / ssh.exit_session(ints, bytes, status) speak for the session.
```

The state is two slices the host provides and sizes. Who may log in, and what a session runs, are the host's
decisions. Three hosts are in this repository:

- [`examples/sshd`](examples/sshd/sshd.cho): Linux and macOS, over cancho's sockets, with a small shell.
- [`tests/probes/bare.cho`](tests/probes/bare.cho): the shape of a kernel's, with four foreign functions for its
  drivers and the connection in a region.
- [`docs/cancho-os.md`](docs/cancho-os.md): what cancho-os has to provide, and the loop.

As a dependency of another project (`cancho.toml`), pinned to a commit:

```
cancho add ssh https://github.com/alpibrusl/cancho-ssh --path .cancho-vcs/ssh_server
```

## The gate

```
scripts/gate.sh --cancho /path/to/cancho
```

Stages `fmt`, `files`, `check`, `bare`, `store`, `tests`, `interop`, `hostile`, `run`; [`docs/design.md`](docs/design.md)
section 8 says what each is. `interop` and `hostile` need Python 3 with `cryptography` and OpenSSH's client; `run`
needs `aarch64-linux-gnu-gcc` and `qemu-aarch64` and says so when it skips. `scripts/mutants.py` takes checks out of
the package one at a time and expects a test to fail each time.

## Licence

EUPL-1.2, copyright Alpibru S.L. ([`LICENSE`](LICENSE)), as cancho's own packages.
