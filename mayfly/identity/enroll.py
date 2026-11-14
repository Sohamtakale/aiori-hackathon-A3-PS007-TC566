"""Enrollment handshake (FR-S1): ephemeral X25519 + HKDF, authenticated by a
one-time tenant token via HMAC over the transcript.

    device  -> monitor  HELLO    tenant_id, token_id, dev_pub, n_d,
                                 HMAC(token, 'hello'    || T_h)
    monitor -> device   RESPONSE token_id, mon_pub, n_m,
                                 HMAC(token, 'response' || T_r)
    device  -> monitor  CONFIRM  token_id, HMAC(K_c, 'confirm' || T_r)

    T_h = 'mayfly/v1/enroll' || len(tenant_id) || tenant_id || token_id || dev_pub || n_d
    T_r = T_h || mon_pub || n_m
    S   = HKDF(X25519(dev, mon), salt=tenant_id, info='mayfly/v1/session' || SHA256(T_r))
    K_0 = HKDF(S, 'epoch0'),  K_c = HKDF(S, 'mayfly/v1/confirm');  S is zeroized.

The token proves to each side that the other was given the token out of band.
CONFIRM gives the monitor key confirmation before it marks the session ACTIVE.
The token itself never crosses the wire, only its id.
"""

from __future__ import annotations

import hmac
import struct
from dataclasses import dataclass
from hashlib import sha256
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from mayfly.identity.keys import RandFn, default_rand, hkdf, zeroize
from mayfly.params import INFO_CONFIRM, INFO_EPOCH0, INFO_SESSION

VERSION = 1
TOKEN_ID_LEN = 8
TOKEN_LEN = 32
PUB_LEN = 32
NONCE_LEN = 16
MAC_LEN = 32
TRANSCRIPT_DOMAIN = b"mayfly/v1/enroll"


class EnrollmentError(Exception):
    """Handshake failed. Messages are deliberately vague to avoid oracles."""


@dataclass(frozen=True)
class EnrollmentToken:
    """Handed to a device out of band by the tenant admin. Single use."""

    tenant_id: bytes
    token_id: bytes
    secret: bytes

    def __post_init__(self) -> None:
        if not 1 <= len(self.tenant_id) <= 255:
            raise ValueError("tenant_id must be 1..255 bytes")
        if len(self.token_id) != TOKEN_ID_LEN or len(self.secret) != TOKEN_LEN:
            raise ValueError("bad token sizes")


# --------------------------------------------------------------------------- wire

@dataclass(frozen=True)
class Hello:
    tenant_id: bytes
    token_id: bytes
    device_pub: bytes
    nonce: bytes
    mac: bytes

    def to_bytes(self) -> bytes:
        return (struct.pack("!BB", VERSION, len(self.tenant_id)) + self.tenant_id
                + self.token_id + self.device_pub + self.nonce + self.mac)

    @classmethod
    def from_bytes(cls, data: bytes) -> "Hello":
        if len(data) < 2 or data[0] != VERSION:
            raise EnrollmentError("bad hello")
        tlen = data[1]
        body = data[2:]
        if tlen == 0 or len(body) != tlen + TOKEN_ID_LEN + PUB_LEN + NONCE_LEN + MAC_LEN:
            raise EnrollmentError("bad hello")
        tid, body = body[:tlen], body[tlen:]
        tok, body = body[:TOKEN_ID_LEN], body[TOKEN_ID_LEN:]
        pub, body = body[:PUB_LEN], body[PUB_LEN:]
        nonce, mac = body[:NONCE_LEN], body[NONCE_LEN:]
        return cls(tid, tok, pub, nonce, mac)


@dataclass(frozen=True)
class Response:
    token_id: bytes
    monitor_pub: bytes
    nonce: bytes
    mac: bytes

    def to_bytes(self) -> bytes:
        return bytes([VERSION]) + self.token_id + self.monitor_pub + self.nonce + self.mac

    @classmethod
    def from_bytes(cls, data: bytes) -> "Response":
        if len(data) != 1 + TOKEN_ID_LEN + PUB_LEN + NONCE_LEN + MAC_LEN or data[0] != VERSION:
            raise EnrollmentError("bad response")
        o = 1
        tok = data[o:o + TOKEN_ID_LEN]; o += TOKEN_ID_LEN
        pub = data[o:o + PUB_LEN]; o += PUB_LEN
        nonce = data[o:o + NONCE_LEN]; o += NONCE_LEN
        return cls(tok, pub, nonce, data[o:])


@dataclass(frozen=True)
class Confirm:
    token_id: bytes
    mac: bytes

    def to_bytes(self) -> bytes:
        return bytes([VERSION]) + self.token_id + self.mac

    @classmethod
    def from_bytes(cls, data: bytes) -> "Confirm":
        if len(data) != 1 + TOKEN_ID_LEN + MAC_LEN or data[0] != VERSION:
            raise EnrollmentError("bad confirm")
        return cls(data[1:1 + TOKEN_ID_LEN], data[1 + TOKEN_ID_LEN:])


# --------------------------------------------------------------------------- helpers

def _hello_transcript(tenant_id: bytes, token_id: bytes, dev_pub: bytes, n_d: bytes) -> bytes:
    return TRANSCRIPT_DOMAIN + bytes([len(tenant_id)]) + tenant_id + token_id + dev_pub + n_d


def _mac(key: bytes | bytearray, label: bytes, transcript: bytes) -> bytes:
    return hmac.new(bytes(key), label + transcript, sha256).digest()


def _pub_bytes(priv: X25519PrivateKey) -> bytes:
    return priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _new_private(rand: RandFn) -> X25519PrivateKey:
    return X25519PrivateKey.from_private_bytes(rand(32))


def _derive(priv: X25519PrivateKey, peer_pub: bytes, tenant_id: bytes,
            transcript: bytes) -> Tuple[bytearray, bytearray]:
    try:
        shared = bytearray(priv.exchange(X25519PublicKey.from_public_bytes(peer_pub)))
    except ValueError as exc:  # low-order point -> all-zero shared secret
        raise EnrollmentError("key exchange failed") from exc
    s = hkdf(shared, INFO_SESSION + sha256(transcript).digest(), salt=tenant_id)
    zeroize(shared)
    k0 = hkdf(s, INFO_EPOCH0)
    kc = hkdf(s, INFO_CONFIRM)
    zeroize(s)
    return k0, kc


# --------------------------------------------------------------------------- device side

class DeviceEnrollment:
    """Device half of the handshake. Use once: hello() then finish()."""

    def __init__(self, token: EnrollmentToken, rand: RandFn = default_rand) -> None:
        self._token = token
        self._priv = _new_private(rand)
        self._nonce = rand(NONCE_LEN)
        self._t_h = _hello_transcript(token.tenant_id, token.token_id, _pub_bytes(self._priv), self._nonce)
        self._done = False

    def hello(self) -> Hello:
        mac = _mac(self._token.secret, b"hello", self._t_h)
        return Hello(self._token.tenant_id, self._token.token_id, _pub_bytes(self._priv), self._nonce, mac)

    def finish(self, resp: Response) -> Tuple[Confirm, bytearray]:
        """Verify the monitor and return (CONFIRM to send, K_0)."""
        if self._done:
            raise EnrollmentError("handshake already finished")
        self._done = True
        if resp.token_id != self._token.token_id:
            raise EnrollmentError("monitor authentication failed")
        t_r = self._t_h + resp.monitor_pub + resp.nonce
        if not hmac.compare_digest(_mac(self._token.secret, b"response", t_r), resp.mac):
            raise EnrollmentError("monitor authentication failed")
        k0, kc = _derive(self._priv, resp.monitor_pub, self._token.tenant_id, t_r)
        confirm = Confirm(self._token.token_id, _mac(kc, b"confirm", t_r))
        zeroize(kc)
        del self._priv
        return confirm, k0


# --------------------------------------------------------------------------- monitor side

class MonitorEnrollment:
    """Monitor half for one HELLO. Created by the tenant key store after it has
    looked up the token by id; holds K_0 until CONFIRM verifies."""

    def __init__(self, token: EnrollmentToken, hello: Hello, rand: RandFn = default_rand) -> None:
        if hello.tenant_id != token.tenant_id or hello.token_id != token.token_id:
            raise EnrollmentError("device authentication failed")
        t_h = _hello_transcript(hello.tenant_id, hello.token_id, hello.device_pub, hello.nonce)
        if not hmac.compare_digest(_mac(token.secret, b"hello", t_h), hello.mac):
            raise EnrollmentError("device authentication failed")
        priv = _new_private(rand)
        mon_pub = _pub_bytes(priv)
        nonce = rand(NONCE_LEN)
        self._t_r = t_h + mon_pub + nonce
        self._k0, self._kc = _derive(priv, hello.device_pub, token.tenant_id, self._t_r)
        self.response = Response(token.token_id, mon_pub, nonce, _mac(token.secret, b"response", self._t_r))

    def confirm(self, msg: Confirm) -> bytearray:
        """Verify key confirmation and hand over K_0 (ownership moves to caller)."""
        if self._k0 is None:
            raise EnrollmentError("handshake already finished")
        ok = hmac.compare_digest(_mac(self._kc, b"confirm", self._t_r), msg.mac)
        if not ok:
            raise EnrollmentError("key confirmation failed")
        zeroize(self._kc)
        k0, self._k0 = self._k0, None
        return k0

    def abort(self) -> None:
        zeroize(self._k0)
        zeroize(self._kc)
        self._k0 = None
