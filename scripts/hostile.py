#!/usr/bin/env python3
"""Hostile clients against `examples/sshd`: every one must be refused with the tag named here, and the server must
still be running afterwards (a trap would end it).

    CANCHO=/path/to/cancho python3 scripts/hostile.py [--first-failure]

Each case is one connection. `refused(tag)` waits for the server's line for that connection and compares the reason
it ended with. The cases after the key exchange are the ones no honest client can make: they need a client that
holds the keys and misuses them (`scripts/minissh.py`).
"""
import os
import socket
import sys

from cryptography.exceptions import InvalidTag

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from minissh import GCM, Client, Closed, Reader, load_key, new_key, string, u32  # noqa: E402
from sshd_fixture import Server  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
failed = []
count = 0


def check(name, ok, detail=""):
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else "\n     " + str(detail).replace("\n", "\n     ")))
    if not ok:
        failed.append(name)
        if "--first-failure" in sys.argv:
            # For `scripts/mutants.py`, which only asks whether anything fails. The server is stopped on the way out.
            sys.exit(1)


def main():
    global count
    with Server(ROOT) as server:
        good = load_key(server.identity)

        def case(name, tag, act, logged_in=False, strict=True, cipher=None):
            """Runs `act(client)` on a fresh connection and checks that the server ended it with `tag`."""
            global count
            count += 1
            problem = ""
            try:
                c = Client(server.port, strict=strict, **({"cipher": cipher} if cipher else {}))
                c.hello()
                if logged_in:
                    c.exchange()
                    c.login(good)
                act(c)
                c.closed()
                c.sock.close()
            except (Closed, ConnectionError, socket.timeout, InvalidTag):
                pass
            except Exception as e:  # noqa: BLE001
                problem = repr(e)
            reasons = server.ended(count)
            got = reasons[count - 1] if len(reasons) >= count else "no line (alive=%s)" % server.alive()
            wanted = tag if isinstance(tag, tuple) else (tag,)
            check(name, got in wanted and server.alive() and not problem, "ended with %r, wanted %r %s" % (got, tag, problem))

        # ---- before any key ----
        # A packet opened under the wrong key or sequence number has a length that is noise: it is refused as too
        # large or malformed when the noise says so, and by its tag otherwise.
        noise = ("ssh-bad-mac", "ssh-packet-too-large", "ssh-packet-malformed")
        case("random bytes where a packet is due", "ssh-packet-too-large", lambda c: c.raw(b"\xff" * 64))
        case("a packet that is all padding", "ssh-packet-malformed", lambda c: c.raw(u32(12) + bytes([11]) + bytes(11)))
        case("a key share of 33 bytes", "ssh-bad-key-share", lambda c: (c.send(c.kexinit()), c.send(bytes([30]) + string(bytes(33)))))
        case("the connection protocol before any key", "ssh-strict-kex", lambda c: (c.send(c.kexinit()), c.send(bytes([90]) + string(b"session") + u32(0) * 3)))
        case("the same, from a client that is not strict", "ssh-unexpected-message", lambda c: (c.send(c.kexinit()), c.send(bytes([90]) + string(b"session") + u32(0) * 3)), strict=False)
        case("a client that only connects and leaves", "socket closed", lambda c: c.sock.shutdown(socket.SHUT_RDWR))

        # ---- with keys: the cipher ----
        def flipped(c):
            c.exchange()
            sealed = bytearray(c.seal(bytes([5]) + string(b"ssh-userauth")))
            sealed[9] ^= 0x10
            c.raw(bytes(sealed))
        case("a sealed packet with one bit changed", "ssh-bad-mac", flipped)

        def flipped_tag(c):
            c.exchange()
            sealed = bytearray(c.seal(bytes([5]) + string(b"ssh-userauth")))
            sealed[-1] ^= 1
            c.raw(bytes(sealed))
        case("a sealed packet with its tag changed", "ssh-bad-mac", flipped_tag)

        def replayed(c):
            c.exchange()
            sealed = c.seal(bytes([2]) + string(b"ignore me"))
            c.raw(sealed)
            c.raw(sealed)
        case("a sealed packet sent twice", noise, replayed)

        def wrong_sequence(c):
            # A client that did not return its sequence number to 0 at NEWKEYS, as strict key exchange requires.
            c.exchange()
            c.send(bytes([5]) + string(b"ssh-userauth"), seq=3)
        case("a client that does not reset its sequence number", noise, wrong_sequence)

        def huge_claim(c):
            c.exchange()
            k1 = c.send_key[32:]
            from minissh import chacha
            c.raw(chacha(k1, 0, c.send_seq, u32(0x7ffffff8)) + bytes(64))
        case("a sealed length of two gigabytes", "ssh-packet-too-large", huge_claim)

        # ---- with keys: the other cipher ----
        def gcm_flipped(c):
            c.exchange()
            sealed = bytearray(c.seal(bytes([5]) + string(b"ssh-userauth")))
            sealed[9] ^= 0x10
            c.raw(bytes(sealed))
        case("AES-GCM: a sealed packet with one bit changed", "ssh-bad-mac", gcm_flipped, cipher=GCM)

        def gcm_length(c):
            # The length is in the clear and is authenticated: a packet claiming to be one block shorter.
            c.exchange()
            sealed = bytearray(c.seal(bytes([2]) + string(b"x" * 40)))
            sealed[3] -= 16
            c.raw(bytes(sealed))
        case("AES-GCM: a changed length", "ssh-bad-mac", gcm_length, cipher=GCM)

        def gcm_replayed(c):
            c.exchange()
            sealed = c.seal(bytes([2]) + string(b"ignore me"))
            c.raw(sealed)
            c.raw(sealed)
        case("AES-GCM: a sealed packet sent twice", "ssh-bad-mac", gcm_replayed, cipher=GCM)

        def gcm_stuck_nonce(c):
            # A client that seals two packets under one nonce, which is what GCM must never see.
            c.exchange()
            c.raw(c.seal(bytes([2]) + string(b"first"), step=False))
            c.raw(c.seal(bytes([2]) + string(b"second")))
        case("AES-GCM: a nonce used twice", "ssh-bad-mac", gcm_stuck_nonce, cipher=GCM)

        def gcm_session(c):
            c.open_session()
            c.request(b"shell")
            c.expect(99)
            for i in range(3):
                c.exchange()
                c.data(b"echo gcm after re-key %d\n" % i)
                assert c.read_data(b"\n") == b"gcm after re-key %d\n" % i
            c.send(bytes([1]) + u32(11) + string(b"") + string(b""))
        case("AES-GCM: a login, a shell and three re-keys", "ssh-peer-disconnected", gcm_session, logged_in=True, cipher=GCM)

        # ---- with keys: authentication ----
        case("a service that does not exist", "ssh-unknown-service", lambda c: (c.exchange(), c.send(bytes([5]) + string(b"ssh-connection"))))
        case("a channel before logging in", "ssh-unexpected-message", lambda c: (c.exchange(), c.service(), c.send(bytes([90]) + string(b"session") + u32(0) * 3)))
        case("an authentication request before the service", "ssh-unexpected-message", lambda c: (c.exchange(), c.send(c.auth_request(good))))

        def outcome_of(c, request):
            c.send(request)
            return c.expect(51)[0]

        def forged(c):
            # The authorized key is named, and the signature is by a key the client does hold.
            c.exchange()
            c.service()
            assert outcome_of(c, c.auth_request(good, sign_with=new_key())) == 51
            # A good signature over another session's identifier: a replay from another connection.
            assert outcome_of(c, c.auth_request(good, session_id=os.urandom(32))) == 51
            # A stranger's key, properly signed.
            assert outcome_of(c, c.auth_request(new_key())) == 51
            # A signature whose last byte is changed.
            bad = bytearray(c.auth_request(good))
            bad[-1] ^= 1
            assert outcome_of(c, bytes(bad)) == 51
            # After four failures the right request still logs in: a failure costs a try and nothing else.
            c.send(c.auth_request(good))
            c.expect(52)
            c.send(bytes([1]) + u32(11) + string(b"") + string(b""))
        case("four forged logins fail, and the fifth, honest, succeeds", "ssh-peer-disconnected", forged)

        def many_tries(c):
            c.exchange()
            c.service()
            for _ in range(5):
                c.send(c.auth_request(new_key()))
                c.expect(51)
            c.send(c.auth_request(new_key()))
            assert c.expect(1)[0] == 1
        case("the sixth failed login ends the connection", "ssh-auth-tries", many_tries)

        def truncated_auth(c):
            c.exchange()
            c.service()
            c.send(c.auth_request(good)[:-10])
        case("an authentication request cut short", "ssh-decode", truncated_auth)

        def query_then_nothing(c):
            c.exchange()
            c.service()
            c.send(c.auth_request(good, signed=False))
            ok = Reader(c.expect(60))
            ok.byte()
            assert ok.string() == b"ssh-ed25519"
            # A query is not a login: the connection protocol is still refused.
            c.send(bytes([90]) + string(b"session") + u32(0) * 3)
        case("a key query is answered and is not a login", "ssh-unexpected-message", query_then_nothing)

        def password(c):
            c.exchange()
            c.service()
            c.send(bytes([50]) + string(b"root") + string(b"ssh-connection") + string(b"password") + b"\0" + string(b"toor"))
            r = Reader(c.expect(51))
            r.byte()
            assert r.string() == b"publickey"
            c.send(bytes([50]) + string(b"root") + string(b"ssh-connection") + string(b"none"))
            c.expect(51)
            c.send(bytes([1]) + u32(11) + string(b"") + string(b""))
        case("a password is not a method", "ssh-peer-disconnected", password)

        # ---- logged in: channels ----
        def no_channel(c):
            c.send(bytes([94]) + u32(0) + string(b"data for nobody"))
        case("data for a channel that was never opened", "ssh-channel-violation", no_channel, logged_in=True)

        def wrong_channel(c):
            c.open_session()
            c.send(bytes([94]) + u32(5) + string(b"data for another"))
        case("data for a channel number that is not the open one", "ssh-channel-violation", wrong_channel, logged_in=True)

        def odd_channels(c):
            c.send(bytes([90]) + string(b"direct-tcpip") + u32(1) + u32(1000) + u32(1000) + string(b"example.org") + u32(22) + string(b"1.2.3.4") + u32(1))
            r = Reader(c.expect(92))
            r.byte()
            assert (r.u32(), r.u32()) == (1, 3)
            c.open_session()
            c.send(bytes([90]) + string(b"session") + u32(8) + u32(1000) + u32(1000))
            r = Reader(c.expect(92))
            r.byte()
            assert (r.u32(), r.u32()) == (8, 4)
            c.request(b"subsystem", string(b"sftp"))
            c.expect(100)
            c.request(b"env", string(b"LANG") + string(b"C"))
            c.expect(100)
            c.send(bytes([80]) + string(b"tcpip-forward") + b"\1" + string(b"0.0.0.0") + u32(2222))
            c.expect(82)
            c.send(bytes([192]) + b"what is this")
            r = Reader(c.expect(3))
            r.byte()
            assert r.u32() == c.send_seq - 1
            c.request(b"exec", string(b"echo still here"))
            c.expect(99)
            assert c.read_data(b"\n") == b"still here\n"
            c.send(bytes([1]) + u32(11) + string(b"") + string(b""))
        case("forwarding, a second session, SFTP and an unknown message are each declined, and the session still works", "ssh-peer-disconnected", odd_channels, logged_in=True)

        def long_command(c):
            c.open_session()
            c.request(b"exec", string(b"echo " + b"y" * 300))
            c.expect(100)
            c.request(b"exec", string(b"echo fits"))
            c.expect(99)
            assert c.read_data(b"\n") == b"fits\n"
            c.send(bytes([1]) + u32(11) + string(b"") + string(b""))
        case("a command longer than the host keeps is declined, not cut", "ssh-peer-disconnected", long_command, logged_in=True)

        def cut_request(c):
            c.open_session()
            c.send(bytes([98]) + u32(c.channel) + string(b"pty-req") + b"\1" + string(b"xterm") + u32(80))
        case("a terminal request cut short", "ssh-decode", cut_request, logged_in=True)

        def rekey_then_data_in_the_middle(c):
            c.open_session()
            c.request(b"shell")
            c.expect(99)
            c.send(c.kexinit())
            c.data(b"echo not now\n")
        case("channel data in the middle of a re-key", "ssh-unexpected-message", rekey_then_data_in_the_middle, logged_in=True)

        def rekey_properly(c):
            c.open_session()
            c.request(b"shell")
            c.expect(99)
            for i in range(3):
                c.exchange()
                c.data(b"echo after re-key %d\n" % i)
                assert c.read_data(b"\n") == b"after re-key %d\n" % i
            c.send(bytes([1]) + u32(11) + string(b"") + string(b""))
        case("three re-keys by this client, with the session used between them", "ssh-peer-disconnected", rekey_properly, logged_in=True)

        def loose(c):
            # Without strict key exchange the sequence numbers run on, and IGNORE may come at any time.
            c.send(bytes([2]) + string(b"before kexinit"))
            c.exchange()
            c.send(bytes([2]) + string(b"after"))
            c.login(good)
            c.open_session()
            c.request(b"exec", string(b"whoami"))
            c.expect(99)
            assert c.read_data(b"\n") == b"mallory\n"
            c.send(bytes([1]) + u32(11) + string(b"") + string(b""))
        case("a client without strict key exchange is served", "ssh-peer-disconnected", loose, strict=False)

        # ---- noise ----
        case("random bytes after logging in", noise, lambda c: c.raw(os.urandom(5000)), logged_in=True)

        check("the server is still running after %d hostile connections" % count, server.alive(), server.log()[-800:])
    print("%d failed" % len(failed) if failed else "all passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
