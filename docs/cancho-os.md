# On cancho-os: what the kernel provides, and the loop

> **Status: not run on the kernel.** cancho-os has no network yet (it is being written), and this document is
> written without its sources. What is claimed is what was run: the package builds for `aarch64-none-elf`, and that
> object, linked with a stand-in for the drivers, runs on AArch64 under qemu and is logged in to by OpenSSH's client
> (`scripts/bare_run.py`, [`design.md`](design.md) section 9). Everything about the kernel itself below is what it
> will have to do, not something observed. Correct this document when the kernel says otherwise.

---

## 1. What the kernel provides

| | what | what goes wrong without it |
|---|---|---|
| a byte stream | one TCP connection: bytes that arrived, bytes to send, and whether the peer has gone | nothing works |
| 32 bytes of entropy a connection | from the SoC's hardware generator, read after it has warmed up | **the ephemeral keys are predictable and every session can be decrypted**; nothing in the package can detect a weak source |
| a host key | a 32-byte Ed25519 seed and its public key (`std.ed25519.public_key_from_seed`, once at boot) | clients cannot tell this machine from an impostor |
| who may log in | a list of 32-byte Ed25519 public keys | nobody can log in, or everybody |
| a timer | to disconnect a client that does not log in, or goes silent | a client holds the one connection for ever |
| a shell | what the UART shell already is: it echoes and edits the line itself | a session has nothing to run |

**The host key is the hard one.** A seed compiled into the image is the same on every board that boots the image
and is public if the image is. A seed made on first boot needs somewhere to be kept (the SD card) and entropy at
first boot. A seed made at every boot makes every client's `known_hosts` wrong after every restart, which trains
people to ignore the warning. This is the kernel's decision; the package takes whatever 32 bytes it is given.

## 2. Memory

All of it is the two slices given to `ssh.start`:

- `ints`: `ssh.ints_len()` words, 1,024 bytes.
- `bytes`: `ssh.bytes_len(packet)` bytes. For `packet` = 8,192 that is 17,480; the smallest, 4,096, is 9,288.

A region is one 64 KiB chunk, so a connection fits in a region with room for the kernel's own buffers
(`tests/probes/bare.cho` has the connection, a shell and an input buffer in one). The package's own functions open
short regions for their work areas; the largest is the signed part of an authentication request, at most the
packet size plus 36 bytes.

## 3. The loop

`tests/probes/bare.cho` is this loop, built by the gate; read it there. Its two rules were both found by getting
them wrong:

1. **Read the network only when nothing else moved.** A loop that reads first blocks on a client that is itself
   waiting, for output the loop had not written yet.
2. **Keep what `feed` did not take.** `feed` takes what its buffer has room for and says how much. The rest must be
   given again later; dropping it desynchronises the stream, and the connection then hangs waiting for a packet
   whose tail never arrives.

```
loop:
    give feed() what was received and not yet taken
    send pending() to the client; sent()
    want_auth  -> auth_decide(key_listed(allowed, auth_key()))
    a session began (session_count() changed) -> start the shell for it
    shell output -> write()
    want_data  -> the shell takes received(); consume()
    peer_eof() -> the shell's input has ended
    the shell exited and its output is written -> exit_session(status)
    want_nothing and nothing pending -> close; forget()
    nothing moved -> wait for the network (or the timer)
```

With no terminal requested (`ssh host command`, or `ssh -T`), lines end with a line feed and nothing is echoed. With
one (`ssh host`), the client sends a carriage return for Enter and echoes nothing, so the shell echoes and ends its
lines with CR LF, as it does on a UART. `ssh.terminal(ints)` says which.

## 4. What the kernel does not need

No heap, no threads, no interrupts (the loop polls), no file system, no clock of the day (SSH carries no dates), no
floating point.

## 5. Open, on the cancho side

`std.crypto.sha256` does not build for the bare target (it asks for the CPU's SHA instructions through a builtin
that is refused there), which is why this package carries `src/sha256.cho`. If cancho makes that builtin answer
"no" on the bare target, or uses the instructions there, the file can go and the kernel gets hardware SHA-256.
