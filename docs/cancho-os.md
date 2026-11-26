# On cancho-os: where this fits, and what is in the way

> **Status: not in the kernel.** Nothing here has been run on cancho-os. This document was first written
> without the kernel's sources and said so; it is now written from them, at
> [`1c82b62`](https://github.com/alpibrusl/cancho-os/commit/1c82b626474d0f0b108b29f0fbddce682681f387) of
> cancho-os (`main`), and every statement about the kernel is marked **[read]** (from that source) or is a
> proposal. What was run is the package itself: it builds for `aarch64-none-elf`, and that object, linked with a
> stand-in for the drivers, runs on AArch64 under qemu and is logged in to by OpenSSH's client
> ([`design.md`](design.md) section 9).
>
> *(Corrected: the first version listed "a TCP byte stream" and "a hardware generator" as things the kernel
> would have to write. It has both, sections 1 and 2. What it lacks is narrower, section 3.)*

---

## 1. What the kernel already has **[read]**

| what this package needs | what the kernel has |
|---|---|
| a byte stream | `src/inet.cho`: TCP whose state is the caller's. `tcp_read(tcp, inbox, c, into, most)` takes what arrived, `tcp_write(tcp, bufs, c, data, at, n)` answers how much it had room for, `tcp_flush` makes the segment, `tcp_close` ends, `tcp_state` is 2 while open and 3 once the other end has finished |
| a timer | `tcp_quiet(tcp, c, now)`: how long a connection has been silent. The shell on port 23 hangs up after 300,000 ms |
| entropy | a pool of sixteen 32-bit words at `k[4136..]`, `k[37]` of them ready, filled by `rng_fill` from virtio-rng (QEMU `virt`) or the BCM2835 generator (Pi 3). `docs/random.md` |
| a shell with one way out | every command's output goes through `putc`, which fills a queue (`k[40..]`, 4,096 bytes) while a line from the network runs |
| the place | `session` in `src/network.cho`: it moves bytes between one connection and two things, the line being typed (`rline`) and that queue. It touches no hardware. **SSH goes exactly there**, between `tcp_read`/`tcp_write` and those two |

The kernel's own documents ask for this: `docs/network.md` section 8 says port 23 "is here to be replaced by SSH,
and it must be gone, or behind SSH, before the kernel can move a servo", and section 11 lists "SSH, as its own
package" next.

## 2. How it would go in (a proposal)

`session` today: read a byte from the connection, build a line, return 1 when it is whole; write the queue to the
connection as it has room. With SSH between, the same function becomes the loop of `tests/probes/bare.cho`:

```
    tcp_read into a small buffer        ->  ssh.feed            (keep what it did not take)
    ssh.pending                         ->  tcp_write, ssh.sent (only what tcp_write took)
    ssh.wants == want_auth              ->  ssh.auth_decide(ssh.key_listed(allowed, ssh.auth_key))
    ssh.wants == want_data              ->  ssh.received into rline, a line at a time; ssh.consume
    the output queue k[40..]            ->  ssh.write           (drop from the queue only what it took)
    `exit`, or tcp_quiet past the limit ->  ssh.exit_session / ssh.disconnect, then tcp_close
    tcp_state not 2 or 3                ->  ssh.forget
```

- **The files.** `build.sh` names the kernel's sources one by one; the eight files of `src/` here are added to that
  line, and to the three `cancho test` lines only if a test wants them. (`cancho add`, [`design.md`](design.md)
  section 9, is the other way, and needs the kernel to have a `cancho.toml`, which it does not **[read]**.)
- **Memory.** The shell's region holds its buffers already, about 12 KB **[read]**. A connection is
  `ssh.ints_len()` words (386, so 3,088 bytes) and `ssh.bytes_len(4096)` bytes (9,296), or 17,488 for packets of 8,192. A
  region is one 64 KiB chunk, so both fit beside what is there; if they come not to, a second region inside the
  first is the way.
- **Authority.** The package holds no capability and `session` holds none **[read]**, so `./authority.sh` should
  still say "as recorded". That is the kernel's check to run, and a difference is a finding.
- **The window is 256 bytes.** A connection's inbox is `tcp_inbox()` = 256 bytes and its window is the room in it
  **[read]**. A client's KEXINIT is about 1,500 bytes, so the handshake arrives in six or more segments. That is
  slow, not wrong: `feed` takes whatever it is given.
- **Echo.** The shell does not echo ("Not a terminal", `docs/network.md` section 8) **[read]**. An SSH client that
  asked for a terminal echoes nothing itself, so either the glue echoes when `ssh.terminal(ints)` is true, or
  people use `ssh -T`. `examples/sshd/shell.cho` is the first choice written out.
- **The test.** `MACHINE=virt` already forwards a host port to the kernel's port 23 for `nc` **[read]**; the same
  line with port 22 lets OpenSSH's client log in to the kernel in QEMU, in the kernel's own CI.

## 3. What is in the way

1. **The Pi 4 has no random numbers.** `docs/random.md`: the RNG200 at `0xfe104000` is not driven, QEMU's Pi 4
   does not have it, and the kernel "falls back to the counter" **[read]**. A counter is fine for nothing here:
   with predictable entropy the ephemeral keys are predictable and every session can be decrypted afterwards.
   **SSH must refuse to start when the pool is not from a generator** (`k[34] == 0`), and so on a Pi 4 there is no
   SSH until that driver exists and has been tried on the board. On QEMU's `virt` and the Pi 3 there is one.
2. **Thirty-two bytes a connection, from a pool of sixteen words.** `ssh.start` wants 32 bytes: eight words of
   the pool, used once and never printed (the kernel's own rule) **[read]**. `docs/random.md` also says the
   hardware is believed as it comes, with no health test.
3. **A host key with nowhere to live.** The kernel has no storage driver **[read]**. A seed compiled into the
   image is the same on every board and public if the image is. A seed drawn at every boot makes every client's
   `known_hosts` wrong after every restart, which teaches people to ignore the warning. A seed drawn at first
   boot needs an SD card driver. This is the kernel's decision; the package takes whatever 32 bytes it is given.
   For QEMU and CI, drawing one at boot and printing its public key on the serial console is enough.
4. **Who may log in.** There is no file to read, so the allowed keys are a table in the image: 32 bytes each,
   end to end, for `ssh.key_listed`.
5. **`std.crypto.sha256` on the bare target.** It does not build there, which is why this package carries
   `src/sha256.cho` ([`design.md`](design.md) section 1). Nothing for the kernel to do; if cancho changes, the file
   goes.

## 4. The two rules of the loop

Both were found by getting them wrong in `tests/probes/bare.cho`, and `session` is built so that the first is
natural and the second is easy to miss:

1. **Read the network only when nothing else moved.** `session` already writes before it reads **[read]**; keep
   that order.
2. **Keep what `feed` did not take, and what `tcp_write` did not take.** `feed` answers how many bytes it took.
   `session` today reads one byte at a time and so never has a remainder; with SSH it should read into a buffer,
   and the bytes `feed` leaves must be given again on the next turn. Dropping them desynchronises the stream, and
   the connection then waits for ever for a packet whose tail is gone. The same holds outwards: call `ssh.sent`
   with what `tcp_write` took, not with what was offered.

## 5. What the kernel does not need

No heap, no threads, no interrupts (the loop polls, as the kernel does), no file system, no clock of the day, no
floating point, and no new capability.
