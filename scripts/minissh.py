"""A small SSH client that can misbehave: the tool of `scripts/hostile.py`.

It speaks what `examples/sshd` speaks (curve25519-sha256, ssh-ed25519, chacha20-poly1305@openssh.com) with Python's
`cryptography`, and every step can be done wrongly on purpose: a packet can be sent with a changed bit, a signature
made with another key, a message sent where it may not be. It is written from the RFCs and OpenSSH's PROTOCOL files,
independently of the cancho code, so the two agreeing is evidence about both.
"""
import hashlib
import os
import socket
import struct

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.poly1305 import Poly1305

RAW = (serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def u32(n):
    return struct.pack(">I", n)


def string(b):
    return u32(len(b)) + b


def mpint(b):
    b = b.lstrip(b"\0")
    if b and b[0] & 0x80:
        b = b"\0" + b
    return string(b)


class Reader:
    def __init__(self, data):
        self.data, self.at = data, 0

    def byte(self):
        self.at += 1
        return self.data[self.at - 1]

    def u32(self):
        self.at += 4
        return struct.unpack(">I", self.data[self.at - 4:self.at])[0]

    def string(self):
        n = self.u32()
        self.at += n
        return self.data[self.at - n:self.at]


def chacha(key, counter, seq, data):
    nonce = struct.pack("<Q", counter) + struct.pack(">Q", seq)
    return Cipher(algorithms.ChaCha20(key, nonce), None).encryptor().update(data)


class Closed(Exception):
    pass


class Client:
    def __init__(self, port, strict=True, kex="curve25519-sha256", timeout=10):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        self.strict = strict
        self.kex = kex
        self.send_seq = self.recv_seq = 0
        self.send_key = self.recv_key = None
        self.session_id = None
        self.buffer = b""
        self.banner = b"SSH-2.0-minissh"

    # ---- bytes ----

    def raw(self, data):
        self.sock.sendall(data)

    def need(self, n):
        while len(self.buffer) < n:
            got = self.sock.recv(65536)
            if not got:
                raise Closed()
            self.buffer += got
        out, self.buffer = self.buffer[:n], self.buffer[n:]
        return out

    def closed(self):
        """True if the server ends the connection without sending more than it already has."""
        try:
            while True:
                if not self.sock.recv(65536):
                    return True
        except (ConnectionError, socket.timeout):
            return True

    # ---- packets ----

    def seal(self, payload, seq=None, pad_extra=0):
        seq = self.send_seq if seq is None else seq
        if self.send_key is None:
            pad = 8 - (5 + len(payload)) % 8
            pad += 8 if pad < 4 else 0
            pad += pad_extra
            return u32(1 + len(payload) + pad) + bytes([pad]) + payload + bytes(pad)
        pad = 8 - (1 + len(payload)) % 8
        pad += 8 if pad < 4 else 0
        pad += pad_extra
        body = bytes([pad]) + payload + bytes(pad)
        k2, k1 = self.send_key[:32], self.send_key[32:]
        length = chacha(k1, 0, seq, u32(len(body)))
        text = chacha(k2, 1, seq, body)
        mac = Poly1305(chacha(k2, 0, seq, bytes(32)))
        mac.update(length + text)
        return length + text + mac.finalize()

    def send(self, payload, **how):
        self.raw(self.seal(payload, **how))
        self.send_seq = (self.send_seq + 1) & 0xffffffff

    def receive(self):
        if self.recv_key is None:
            n = struct.unpack(">I", self.need(4))[0]
            body = self.need(n)
        else:
            k2, k1 = self.recv_key[:32], self.recv_key[32:]
            length = self.need(4)
            n = struct.unpack(">I", chacha(k1, 0, self.recv_seq, length))[0]
            text, tag = self.need(n), self.need(16)
            mac = Poly1305(chacha(k2, 0, self.recv_seq, bytes(32)))
            mac.update(length + text)
            mac.verify(tag)
            body = chacha(k2, 1, self.recv_seq, text)
        self.recv_seq = (self.recv_seq + 1) & 0xffffffff
        return body[1:len(body) - body[0]]

    def expect(self, kind):
        """The next packet that is not IGNORE or DEBUG; it must be of `kind`."""
        while True:
            p = self.receive()
            if p[0] not in (2, 4):
                break
        if p[0] != kind:
            raise AssertionError("expected message %d, got %d: %r" % (kind, p[0], p[:60]))
        return p

    # ---- the protocol, done properly ----

    def hello(self):
        self.raw(self.banner + b"\r\n")
        line = b""
        while not line.endswith(b"\n"):
            line += self.need(1)
        self.server_banner = line.rstrip(b"\r\n")

    def kexinit(self):
        names = self.kex + (",kex-strict-c-v00@openssh.com" if self.strict else "")
        lists = [names, "ssh-ed25519", "chacha20-poly1305@openssh.com", "chacha20-poly1305@openssh.com",
                 "hmac-sha2-256", "hmac-sha2-256", "none", "none", "", ""]
        return bytes([20]) + os.urandom(16) + b"".join(string(l.encode()) for l in lists) + b"\0" + u32(0)

    def exchange(self, mine=None, first=True):
        """KEXINIT both ways, the key share, the reply checked, NEWKEYS both ways."""
        mine = mine or self.kexinit()
        self.send(mine)
        theirs = self.expect(20)
        self.server_kexinit = theirs
        secret = X25519PrivateKey.generate()
        share = secret.public_key().public_bytes(*RAW)
        self.send(bytes([30]) + string(share))
        reply = Reader(self.expect(31))
        reply.byte()
        host_blob, server_share, signature = reply.string(), reply.string(), reply.string()
        k = secret.exchange(X25519PublicKey.from_public_bytes(server_share))
        h = hashlib.sha256(string(self.banner) + string(self.server_banner) + string(mine) + string(theirs)
                           + string(host_blob) + string(share) + string(server_share) + mpint(k)).digest()
        blob = Reader(host_blob)
        assert blob.string() == b"ssh-ed25519"
        self.host_key = blob.string()
        sig = Reader(signature)
        assert sig.string() == b"ssh-ed25519"
        Ed25519PublicKey.from_public_bytes(self.host_key).verify(sig.string(), h)
        if self.session_id is None:
            self.session_id = h

        def key(letter):
            k1 = hashlib.sha256(mpint(k) + h + letter + self.session_id).digest()
            return k1 + hashlib.sha256(mpint(k) + h + k1).digest()
        self.expect(21)
        self.recv_key = key(b"D")
        self.send(bytes([21]))
        self.send_key = key(b"C")
        if self.strict:
            self.send_seq = self.recv_seq = 0

    def service(self):
        self.send(bytes([5]) + string(b"ssh-userauth"))
        self.expect(6)

    def auth_request(self, key, user=b"mallory", sign_with=None, signed=True, session_id=None):
        public = key.public_key().public_bytes(*RAW)
        blob = string(b"ssh-ed25519") + string(public)
        body = bytes([50]) + string(user) + string(b"ssh-connection") + string(b"publickey") + bytes([1 if signed else 0]) + string(b"ssh-ed25519") + string(blob)
        if not signed:
            return body
        sig = (sign_with or key).sign(string(self.session_id if session_id is None else session_id) + body)
        return body + string(string(b"ssh-ed25519") + string(sig))

    def login(self, key, user=b"mallory"):
        self.service()
        self.send(self.auth_request(key, user))
        self.expect(52)

    def open_session(self, window=1 << 21, packet=32768):
        self.send(bytes([90]) + string(b"session") + u32(7) + u32(window) + u32(packet))
        r = Reader(self.expect(91))
        r.byte()
        assert r.u32() == 7
        self.channel = r.u32()
        self.window, self.max_packet = r.u32(), r.u32()

    def request(self, kind, extra=b"", reply=True):
        self.send(bytes([98]) + u32(self.channel) + string(kind) + bytes([1 if reply else 0]) + extra)

    def data(self, text):
        self.send(bytes([94]) + u32(self.channel) + string(text))

    def read_data(self, until):
        """Channel data, collected until it contains `until` or the channel is closed."""
        got = b""
        while until not in got:
            p = self.receive()
            if p[0] == 94:
                r = Reader(p)
                r.byte()
                r.u32()
                got += r.string()
            elif p[0] == 97:
                break
        return got


def load_key(path):
    with open(path, "rb") as f:
        return serialization.load_ssh_private_key(f.read(), None)


def new_key():
    return Ed25519PrivateKey.generate()
