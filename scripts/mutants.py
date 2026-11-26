#!/usr/bin/env python3
"""Mutants: the package with one check taken out, and the test that must then fail.

    CANCHO=/path/to/cancho python3 scripts/mutants.py

A test that passes on a mutant is a test that does not check what it says. Each mutant is one textual change in a copy
of the repository; the named check is run there and must fail. Not a stage of the gate (it runs the slow checks a
dozen times); run it when a check of the protocol is added or moved. Exit status 0 if every mutant was caught.
"""
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
from sshd_fixture import cancho  # noqa: E402

UNIT = "unit"
MUTANTS = [
    ("the tag of a packet is not compared", "src/cipher.cho", "    if diff != 0 {\n        return wire.bad_mac();\n    }\n    return 0;\n}\n\n// ---- The generator", "    return 0;\n}\n\n// ---- The generator", "hostile.py"),
    ("a packet with a bad tag is decrypted all the same", "src/cipher.cho", "        if diff == 0 {\n            chacha20.xor(key[0..32], 1, nonce, buf[4..body], buf[4..body]);\n        }", "        chacha20.xor(key[0..32], 1, nonce, buf[4..body], buf[4..body]);\n        diff = 0;", "hostile.py"),
    ("any signature logs in", "src/auth.cho", "bytes[at + sig + 23..at + sig + 87]) == 1;", "bytes[at + sig + 23..at + sig + 87]) >= 0;", "hostile.py"),
    ("the signature is not over the session identifier", "src/auth.cho", "let p = wire.put_string(signed, 0, bytes[slot.b_session_id()..slot.b_session_id() + 32]);", "let p = wire.put_string(signed, 0, bytes[slot.b_cookie()..slot.b_cookie() + 32]);", "interop.py"),
    ("failed logins are not counted", "src/auth.cho", "        if ints[slot.i_tries()] >= tries_max() {", "        if ints[slot.i_tries()] >= 1000 {", "hostile.py"),
    ("a key query logs in", "src/auth.cho", "    } else if !slot.has(ints, slot.f_auth_signed()) {\n        region r {", "    } else if !slot.has(ints, slot.f_auth_signed()) {\n        ints[slot.i_phase()] = slot.phase_open();\n        region r {", "hostile.py"),
    ("the host's refusal is not obeyed", "src/auth.cho", "    if !accept {\n        result = failure(ints, bytes, true);\n    } else if", "    if !accept && sig < 0 {\n        result = failure(ints, bytes, true);\n    } else if", "interop.py"),
    ("strict key exchange does not look at the first packet", "src/kex.cho", "        if ints[slot.i_packet_seq()] != 0 {", "        if ints[slot.i_packet_seq()] < 0 {", UNIT),
    ("strict key exchange lets IGNORE through", "src/server.cho", "    if kind == wire.msg_ignore() || kind == wire.msg_debug() || kind == wire.msg_unimplemented() {\n        if strict_first {", "    if kind == wire.msg_ignore() || kind == wire.msg_debug() || kind == wire.msg_unimplemented() {\n        if strict_first && kind == 99 {", UNIT),
    ("the sequence number is not reset at NEWKEYS", "src/kex.cho", "    if slot.has(ints, slot.f_strict()) {\n        ints[slot.i_read_seq()] = 0;\n    }", "", "interop.py"),
    ("a re-key replaces the session identifier", "src/kex.cho", "            if !slot.has(ints, slot.f_first_kex_done()) {\n                copy_into(bytes[slot.b_session_id()..slot.b_session_id() + 32], h);\n            }", "            copy_into(bytes[slot.b_session_id()..slot.b_session_id() + 32], h);", "hostile.py"),
    ("a zero shared secret is accepted", "src/kex.cho", "        if x25519.scalarmult(secret, bytes[at + 5..at + 37], k) != 0 {", "        if x25519.scalarmult(secret, bytes[at + 5..at + 37], k) > 0 {", UNIT),
    ("the padding of a packet is not checked", "src/slot.cho", "    if pad < 4 || pad + 2 > n {", "    if pad + 2 > n {", UNIT),
    ("a packet may be longer than the buffer", "src/slot.cho", "    if n > cap(ints) - 20 {\n        return wire.packet_too_large();\n    }", "", UNIT),
    ("channel data is taken during a re-key", "src/server.cho", "    if in_kex {\n        if strict_first {\n            return wire.strict_kex();\n        }\n        return wire.unexpected_message();\n    }", "    if in_kex && phase == slot.phase_kex() {\n        if strict_first {\n            return wire.strict_kex();\n        }\n        return wire.unexpected_message();\n    }", "hostile.py"),
    ("a second session is opened over the first", "src/channel.cho", "    } else if slot.has(ints, slot.f_channel_open()) {\n        // SSH_OPEN_RESOURCE_SHORTAGE\n        reason = 4;\n    }", "    }", "hostile.py"),
    ("the connection protocol is open before a login", "src/server.cho", "    if kind >= 80 && kind <= 100 && phase != slot.phase_open() {", "    if kind >= 80 && kind <= 100 && phase == slot.phase_ended() {", "hostile.py"),
    ("the window is never raised", "src/channel.cho", "    if owed < window() / 2 || !open_to_send(ints) || slot.out_free(ints) < 64 {", "    if owed >= 0 {", "interop.py"),
    ("the exchange hash leaves out this server's KEXINIT", "src/kex.cho", "        let m = our_kexinit(bytes, mine);\n        hash_string(st, mine[0..m]);", "        let m = our_kexinit(bytes, mine);\n        hash_string(st, mine[0..m - 1]);", "interop.py"),
    ("SHA-256 rotates by one bit too few", "src/sha256.cho", "let s1 = rotr32(we, 6) ^ rotr32(we, 11) ^ rotr32(we, 25);", "let s1 = rotr32(we, 6) ^ rotr32(we, 11) ^ rotr32(we, 24);", UNIT),
]


def run_check(copy, check):
    env = dict(os.environ, CANCHO=cancho())
    if check == UNIT:
        return subprocess.run(["sh", "scripts/gate.sh", "--cancho", cancho(), "--only", "tests"], cwd=copy, env=env, capture_output=True, timeout=900)
    return subprocess.run([sys.executable, os.path.join("scripts", check), "--first-failure"], cwd=copy, env=env, capture_output=True, timeout=900)


def main():
    survived = []
    only = sys.argv[1:]
    for name, path, old, new, check in MUTANTS:
        if only and not any(o in name for o in only):
            continue
        copy = tempfile.mkdtemp(prefix="cancho-ssh-mutant-")
        try:
            for d in ("src", "examples", "tests", "scripts"):
                shutil.copytree(os.path.join(ROOT, d), os.path.join(copy, d))
            target = os.path.join(copy, path)
            with open(target) as f:
                text = f.read()
            if text.count(old) != 1:
                print("STALE    %s: the text to change is in %s %d times" % (name, path, text.count(old)))
                survived.append(name)
                continue
            with open(target, "w") as f:
                f.write(text.replace(old, new))
            r = run_check(copy, check)
            if r.returncode == 0:
                print("SURVIVED %s (%s passed)" % (name, check), flush=True)
                survived.append(name)
            else:
                print("caught   %s (%s)" % (name, check), flush=True)
        finally:
            shutil.rmtree(copy, ignore_errors=True)
    print("%d survived" % len(survived) if survived else "every mutant was caught")
    return 1 if survived else 0


if __name__ == "__main__":
    sys.exit(main())
