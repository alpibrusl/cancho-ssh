# An SSH server with no system under it

> **Status: built** (sections 2 to 8), with what was measured in section 9 and what is not done in section 10.
> Not reviewed by anyone but its author.
> The asker is [cancho-os](https://github.com/alpibrusl/cancho-os), a kernel for the Raspberry Pi written in cancho:
> it has a shell on the UART and wants the same shell over the network. The same package must also serve on Linux and
> macOS, where it can be tested against a real client. Claims are marked **[measured]** (run, with the command),
> **[read]** (from a source) or **[choice]** (a decision).

---

## 1. What was in the way

An SSH server is usually a program: it owns a socket, a clock, a file of keys, a random device and a child process
with a terminal. A kernel has none of these as an operating system gives them, and cancho's bare target
(`--target aarch64-none-elf`, `docs/freestanding.md` of cancho) refuses every builtin that needs a system.

Measured on the compiler at `e9cbde8`, with one probe program that calls each primitive SSH needs and is built with
`cancho build probe.cho --std --target aarch64-none-elf --emit obj`:

| primitive | module | bare target |
|---|---|---|
| X25519 | `std.x25519` | builds **[measured]** |
| Ed25519 sign and verify | `std.ed25519` | builds **[measured]** |
| SHA-512 (inside Ed25519) | `std.crypto` | builds **[measured]** |
| ChaCha20 block and XOR, Poly1305 | `std.chacha20` | builds **[measured]** |
| SHA-256 | `std.crypto` | **refused**, `unsupported-on-target` at `crypto.cho:268` **[measured]** |

The object without the SHA-256 call has three undefined symbols: the two heap bounds of the link script and the
probe's own foreign function. SHA-256 is refused because `std.crypto` asks `hw_sha256()` (the CPU's SHA instructions)
before choosing a path, and that builtin is one of those whose support is not written for the bare target.

So three things are decided here:

1. **The package owns no socket, clock, file or heap** (section 2). It is given bytes and gives bytes back.
2. **The package carries its own SHA-256** (`src/sha256.cho`), the software path of `std.crypto` with nothing else.
   When `std.crypto.sha256` builds for the bare target this file goes away **[choice]**.
3. **One algorithm of each kind** (section 3), chosen so that everything else is already in `std`.

## 2. The shape: bytes in, bytes out

```
import ssh_server as ssh;

ssh.start(ints, bytes, host_seed, host_public, entropy);     // once a connection
let took = ssh.feed(ints, bytes, from_network);              // as bytes arrive
let out = ssh.pending(ints, bytes);                          // what to send; then ssh.sent(ints, n)
```

- **The state is two slices the host provides**, `ints: [int]` and `bytes: [byte]`, as `packages/tls` of cancho does.
  Nothing is allocated by the package except short work areas in a region of its own, so the same code runs where
  there is no heap. On Linux the host takes them from the heap (`box_slice`); in the kernel, from a region.
- **The host chooses the size.** `bytes` is a fixed part (keys, names, the hash) and two buffers of equal size, input
  and output. `ssh.bytes_len(packet)` says how long `bytes` must be for packets of at most `packet` bytes. A region is
  one 64 KiB chunk (`docs/region-limit.md` of cancho), so a kernel that keeps a connection in a region asks for a
  packet of 8,192 or so; a host with a heap asks for 35,000, the size RFC 4253 section 6.1 says an implementation
  must accept. A packet longer than the host's choice is a refusal (`ssh-packet-too-large`), not a trap.
- **No function is passed.** cancho-os writes no function type, so nothing here calls back. Where the host must
  decide something, `feed` stops and a question waits: `ssh.wants(ints)` says which.

| `wants` | the host | then |
|---|---|---|
| `want_input` | reads the network, calls `feed` | |
| `want_auth` | reads `auth_user` and `auth_key`, decides | `auth_decide(ints, bytes, accept)` |
| `want_data` | reads `received`, the bytes the client typed | `consume(ints, bytes, n)` |
| `want_nothing` | the connection is over: flush `pending`, close | `forget(ints, bytes)` |

The rest is level state the host reads when it likes: `session(ints)` (none, a shell or a command, with `command`),
`session_count` (so a host notices that one session ended and another began between two looks), `terminal`,
`terminal_columns`/`terminal_rows`, `peer_eof`. The host writes to the client with `write(ints, bytes, data)`, which
answers how many bytes it took (the client's window, the packet size and the output buffer all limit it), and ends a
session with `exit_session(ints, bytes, status)`.

**Back-pressure is the buffers.** `feed` takes what fits in the input buffer and says how much. While a question
waits no further packet is opened, so a client cannot make the server hold more than one buffer of its input. No
packet is opened either while the output buffer has less than 1,024 bytes free, so every reply has somewhere to go.

**Two rules for a host's loop**, both found by breaking them in `tests/probes/bare.cho` (section 9): the network is
read only when nothing else moved, and what `feed` did not take is kept and given again. [`cancho-os.md`](cancho-os.md)
section 3 has the loop.

**Randomness is the host's, once.** `start` takes 32 bytes of entropy; the package draws the KEXINIT cookie and each
ephemeral key from ChaCha20 under it, replacing the key after every draw (fast key erasure), so a later compromise
of the state does not give earlier ephemeral keys. On Linux the host reads `/dev/urandom`; a kernel reads its
hardware generator. **A host that passes a constant has no security at all**, and nothing here can detect that.

## 3. The protocol, and what is not offered

| | offered | not offered |
|---|---|---|
| key exchange | `curve25519-sha256`, `curve25519-sha256@libssh.org` (the same thing) | everything else |
| host key | `ssh-ed25519` | RSA, ECDSA |
| cipher | `chacha20-poly1305@openssh.com` | AES-GCM, AES-CTR with a MAC |
| compression | `none` | zlib |
| user authentication | `publickey` with `ssh-ed25519` | passwords, keyboard-interactive, host-based |
| channels | one `session` at a time: `pty-req`, `shell`, `exec`, `window-change` | forwarding, agents, subsystems (SFTP), X11 |

**[choice]** One of each. OpenSSH has offered all four since 6.5 (2014), and a second algorithm is a second thing
to get wrong. A client that shares none is refused with `ssh-no-common-algorithm`; paramiko 5.1 is one (it has no
ChaCha20 cipher), and the interoperation test checks that it is refused that way **[measured]**. A MAC name
(`hmac-sha2-256`) is in KEXINIT and is never used: the one cipher carries its own tag.

**Strict key exchange** (`kex-strict-s-v00@openssh.com`) is offered and, when the client offers its half, enforced:
the first packet must be KEXINIT, nothing but key exchange messages may arrive before NEWKEYS, and both sequence
numbers return to 0 at NEWKEYS. This is the countermeasure to the prefix truncation attack (Terrapin,
CVE-2023-48795), which is against exactly this cipher.

**Re-keying**: a KEXINIT from the client at any time after the first exchange is answered. The server does not start
one itself; it refuses to let a sequence number wrap instead (`ssh-sequence-exhausted`), which a client that re-keys
on its own schedule (OpenSSH: every 1 GiB by default for this cipher) never reaches.

**The cipher on `std.chacha20`.** OpenSSH's construction is not RFC 8439's AEAD: two keys, the length encrypted
under the second with the sequence number as nonce, the tag over the encrypted length and payload, no padding of the
tag's input. `std.chacha20` exposes `block`, `xor` and `poly1305`, which is enough: the 64-bit counter and 64-bit
nonce of the original ChaCha are the 32-bit counter and 96-bit nonce of RFC 8439 with four zero bytes in front of
the sequence number.

## 4. Who may log in is the host's

The package checks the signature (that the client holds the private key) and asks the host whether that key may log
in as that user. The host answers from wherever it keeps that: a file on Linux, a static table in a kernel.
`ssh.key_listed(list, key)` is a helper for the usual case, a list of 32-byte keys.

A query (`publickey` without a signature) asks the host the same question and answers `PK_OK`; the request with the
signature asks again, so a host that changes its mind in between is obeyed. The host is asked before the signature
is checked: a key that may not log in costs no verification. The sixth failed request ends the connection with
`ssh-auth-tries`, as OpenSSH's `MaxAuthTries` does. A user name is the bytes the client sent, at most 64, and is not
otherwise looked at. **How long a client may take to log in is the host's** (it has the clock): `examples/sshd`
allows 30 seconds.

## 5. What a session is, is the host's too

The package delivers bytes typed and takes bytes to show. It does not start a process, and it has no terminal
discipline: a client that asked for a terminal sends a carriage return for Enter and echoes nothing itself, so the
host echoes and edits the line, as a UART shell already does. `examples/sshd` is a small shell of this kind on
Linux and macOS, and it is what the interoperation test logs in to.

## 6. Refusals

Every failure is a negative code with a stable tag (`ssh.refusal_tag(code)`), and after one the connection is over:
`feed` answers the code, `wants` answers `want_nothing`, and where the protocol has a message for it (DISCONNECT)
that message is in `pending`. No input reaches a trap: every length is checked against what has arrived before
anything is indexed, and `scripts/hostile.py` (section 9) is the check.

## 7. Layout

| file | module | |
|---|---|---|
| `src/sha256.cho` | `ssh_sha256` | SHA-256, software, streaming, state in the caller's `[int]` |
| `src/wire.cho` | `ssh_wire` | the refusal codes; `uint32`, `string`, name-lists, `mpint`, read and written |
| `src/cipher.cho` | `ssh_cipher` | `chacha20-poly1305@openssh.com`: seal and open one packet in place; the generator |
| `src/slot.cho` | `ssh_slot` | where everything lives in `ints` and `bytes`; the queues; packets in and out |
| `src/kex.cho` | `ssh_kex` | KEXINIT, the exchange, the exchange hash, the keys |
| `src/auth.cho` | `ssh_auth` | the service request and `publickey` |
| `src/channel.cho` | `ssh_channel` | the one session channel |
| `src/server.cho` | `ssh_server` | `start`, `feed`, the questions, and what the host calls |
| `examples/sshd/` | | a host for Linux and macOS: `sshd.cho` (the socket and the loop), `shell.cho` (a shell with no capability), `keys.cho` (OpenSSH's key lines) |
| `tests/probes/bare.cho` | | a host shaped like a kernel's; `board.c` beside it stands for the drivers when the object is run |
| `.cancho-vcs/` | | the package as `cancho vcs publish --dir src` writes it, for a dependent to pin |

2,816 lines of cancho in `src/`; no file is over 609.

## 8. The gate

`scripts/gate.sh`, stages in order, stopping at the first that fails:

| stage | |
|---|---|
| `fmt` | `cancho fmt --check src examples tests` |
| `files` | no source file over 2,000 lines |
| `check` | the package type-checks with the example, and with the bare probe |
| `bare` | the probe builds for `aarch64-none-elf`; its module calls and does not define exactly its four drivers; the object is an ELF |
| `store` | the committed `.cancho-vcs` is what publishing `src` writes |
| `tests` | `cancho test` over the four files of `tests/`, each with the number of tests it must pass (34 in all) |
| `interop` | `scripts/interop.py`: OpenSSH's client, asyncssh, Dropbear's client and paramiko against `examples/sshd` |
| `hostile` | `scripts/hostile.py`: 28 connections from a client that misbehaves, each refused with the tag expected |
| `run` | `scripts/bare_run.py`: the bare object, linked with `board.c`, run under `qemu-aarch64` and logged in to |

`scripts/mutants.py` is not a stage: it removes one check at a time and runs the stage that must then fail.

## 9. Measured

On Linux x86-64 (Xeon 2.1 GHz, 4 cores, clang 18.1.3), cancho at `e9cbde8`, at the commit that adds this section.

**It interoperates.** `scripts/interop.py`, 17 checks, all pass:

- OpenSSH 9.6p1: a command and its output; exit statuses 7 and 127; a shell without a terminal, ended by end of
  input; a shell with a terminal (echo, prompt, `exit 3`); the user name; a key that is not authorized is refused
  (`Permission denied`); a client expecting another host key refuses the server; the client's own log says
  `will use strict KEX ordering`; 6,000 lines of output arrive intact across **13 re-keys** (`RekeyLimit=32K`);
  3 MiB of input pass the 1 MiB window.
- asyncssh 2.24.1 and Dropbear 2022.83 each log in and run a command.
- paramiko 5.1.0 is refused at the negotiation, and the server's reason is `ssh-no-common-algorithm`.

**It refuses.** `scripts/hostile.py`, 28 connections from `scripts/minissh.py`, a client written from the RFCs with
Python's `cryptography` and not from this code: a changed bit in a sealed packet and a changed tag
(`ssh-bad-mac`); a replayed packet; a client that does not reset its sequence number; a forged signature, a
signature over another session's identifier, a stranger's key, a changed signature byte (each a failure, and the
honest request after them still logs in); the sixth failure (`ssh-auth-tries`); a key query, which is answered and
is not a login; a password; channels before a login; data for a channel that is not open; forwarding, a second
session, SFTP and an unknown message (each declined, and the session still works); a command longer than the host
keeps; data in the middle of a re-key; three re-keys by the client with the session used between them. The server
process is running after all of them.

**No input reached a trap.** Besides the above, `tests/server_test.cho` feeds 4,000 connections of generated bytes
after a good identification line, half of them shaped as a packet: 3,000 or more are refused with a tag and none
traps. *(This is not a fuzzer with coverage; it is 4,000 inputs.)*

**The bare target.** `cancho build tests/probes/bare.cho examples/sshd/shell.cho src/*.cho --std --target
aarch64-none-elf --emit obj`: an ELF object of 145,714 bytes of text whose undefined symbols are
`__cancho_heap_start`, `__cancho_heap_end` and the probe's four `board_` functions (`llvm-nm -u`). Linked with
`tests/probes/board.c` by `aarch64-linux-gnu-gcc -static` and run under `qemu-aarch64` 8.2, OpenSSH logs in to it:
a command, a shell with an exit status, and 3,000 lines across re-keys (`RekeyLimit=16K`). This runs the bare
runtime, regions out of the link's heap, `-mstrict-align` and AArch64 code generation. It is **not** a kernel, an
MMU-off boot or a real network: those are cancho-os's.

**Two bugs this found, both in the probe host and neither in the package**: the host read the network before
writing what it had, and waited for ever on a client that was waiting for it; and it dropped what `feed` did not
take when the input buffer was full, after which the connection hung on a packet whose tail was gone. They are the
two rules of section 2.

**What the package can reach.** `cancho authority` on a program that calls `ssh.start` and nothing else of its own
says `performs nothing`, and `never touches` the console, the filesystem, the network, the heap, the command line,
signals, other programs and foreign code. The package holds no capability; a host lends it none. `examples/sshd`
reports what a server would: `net_in("")`, `conn_accept`, `conn_read`, `conn_write`, `poll`, `clock`,
`fs_read("")`, `heap`, `args`, and no foreign code (it is `UNBOUNDED` only in that it does not name its port in a
literal, since the port is an argument).

**A dependent can pin it.** A scratch project, `cancho add ssh <a git repository of this tree> --rev <commit> --path
.cancho-vcs/ssh_server`: 8 files installed, and a program that imports `ssh_server` built and ran. The repository
was a local one (`file://`).

**Cost**, `examples/sshd` on the machine above, from `/proc/<pid>/stat`: 50 logins that each run one command cost
380 ms of the server's CPU, **7.6 ms a login** (a key pair, a shared secret, a signature and a verification). 10.6 MB
in and 10.1 MB out through a shell without a terminal cost 190 ms: about **100 MB/s** of ChaCha20-Poly1305, in place.
Not measured on a Raspberry Pi.

**The tests fail when the code is wrong.** `scripts/mutants.py`, 20 mutants, each the package with one check taken
out, and for each the stage that must then fail: **all 20 were caught.** By `hostile`, 9: the tag is not compared;
a packet with a bad tag is decrypted anyway; any signature logs in; failed logins are not counted; a key query
logs in; a re-key replaces the session identifier; channel data is taken during a re-key; a second session is
opened over the first; the connection protocol is open before a login. By `interop`, 5: the signature is not over
the session identifier; the host's refusal is not obeyed; the sequence number is not reset at NEWKEYS; the window
is never raised; the exchange hash leaves out this server's KEXINIT. By `tests`, 6: strict key exchange does not
look at the first packet; it lets IGNORE through; a zero shared secret is accepted; the padding of a packet is not
checked; a packet may be longer than the buffer; SHA-256 rotates by one bit too few. *(Corrected: this paragraph
was committed first as a description, before the run had finished.)* Twenty mutants are the checks its author
thought of; a check nobody thought to remove is not covered by this.

## 10. What this does not do

- **No client.** Only the server side is written.
- **One cipher.** A client without `chacha20-poly1305@openssh.com` cannot connect (paramiko). `std.aes` and
  `std.gcm` have software paths, and `aes256-gcm@openssh.com` is the algorithm to add if this matters; whether those
  paths build for the bare target was not tried.
- **No server-initiated re-key**, no passwords, no second channel, no SFTP, no forwarding, no banner, no extension
  negotiation (`ext-info`) (section 3).
- **Not reviewed.** Nobody but its author has read this code, and it has not been run on a Raspberry Pi: the bare
  object is run under qemu as a process, not booted, because the network of cancho-os is not there yet.
- **Not run on macOS.** Nothing here is specific to Linux (`examples/sshd` uses cancho's own sockets, poller and
  clock, and `/dev/urandom`), and cancho builds for Apple silicon, but the gate was run on Linux x86-64 only.
- **Not constant time by measurement.** The secret-dependent work is in `std.x25519`, `std.ed25519` and
  `std.chacha20`, whose own documents say what was measured; the code here that touches secrets (the tag comparison,
  the key derivation) is written without secret-dependent branches, and that was not measured.
- **Padding is zeros**, not random bytes (RFC 4253 section 6 says "should"): under an authenticated cipher the
  padding is encrypted and its content is not observable.
- **`examples/sshd` serves one connection at a time**, on the loopback address, and runs a shell of five commands.
  It is a test host. A server for people needs processes and terminals, which is another program.
- **`cancho add` against the repository on GitHub was not run**: it was run against a local copy (section 9),
  because the repository had no commit when this was written.
