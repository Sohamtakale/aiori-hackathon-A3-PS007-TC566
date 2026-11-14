"""Enrollment endpoint: carries the FR-S1 handshake between the lab's devices
and the monitor over a local UNIX socket.

Frames: 4-byte big-endian length, 1-byte type, payload.

    T  {"tenant": "A"}            -> K  token + protocol parameters (JSON)
    H  Hello bytes                -> R  Response bytes
    C  Confirm bytes              -> L  label (ASCII)
    any error                     -> E  message

'T' stands in for the tenant admin handing a one-time token to a device out
of band. The socket is created mode 0600 (root only) for that reason.
The label is returned to the enrolling party so the emulator can record ground
truth; the label is the monitor's pseudonym, not key material.
"""

from __future__ import annotations

import json
import os
import socket
import struct
from typing import Callable, Dict, Tuple

from mayfly.identity.enroll import (Confirm, EnrollmentError, EnrollmentToken, Hello, Response)
from mayfly.keystore import TenantKeyStore
from mayfly.params import Params

MAX_FRAME = 4096
IO_TIMEOUT = 2.0


class ProtocolError(Exception):
    pass


def send_frame(sock: socket.socket, ftype: bytes, payload: bytes) -> None:
    sock.sendall(struct.pack("!I", len(payload) + 1) + ftype + payload)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError()
        buf += chunk
    return buf


def recv_frame(sock: socket.socket) -> Tuple[bytes, bytes]:
    (n,) = struct.unpack("!I", _recv_exact(sock, 4))
    if not 1 <= n <= MAX_FRAME:
        raise ProtocolError("bad frame length %d" % n)
    data = _recv_exact(sock, n)
    return data[:1], data[1:]


# --------------------------------------------------------------------------- server side

class EnrollmentService:
    """Protocol handler bound to the monitor's per-tenant key stores."""

    def __init__(self, stores: Dict[str, TenantKeyStore], clock: Callable[[], float]) -> None:
        self.stores = stores
        self.by_id = {s.tenant_id: s for s in stores.values()}
        self.clock = clock
        self.enrolled = 0

    def handle(self, ftype: bytes, payload: bytes) -> Tuple[bytes, bytes]:
        try:
            if ftype == b"T":
                req = json.loads(payload)
                store = self.stores.get(req.get("tenant"))
                if store is None:
                    raise EnrollmentError("unknown tenant")
                tok = store.issue_token()
                p = store.params
                return b"K", json.dumps({
                    "tenant_id": tok.tenant_id.hex(), "token_id": tok.token_id.hex(),
                    "secret": tok.secret.hex(), "epoch": p.epoch_seconds,
                    "ttl": p.session_ttl_seconds, "grace": p.grace_epochs}).encode()
            if ftype == b"H":
                hello = Hello.from_bytes(payload)
                store = self.by_id.get(hello.tenant_id)
                if store is None:
                    raise EnrollmentError("device authentication failed")
                return b"R", store.handle_hello(hello, self.clock()).to_bytes()
            if ftype == b"C":
                confirm = Confirm.from_bytes(payload)
                for store in self.stores.values():
                    if store.has_pending(confirm.token_id):
                        label = store.handle_confirm(confirm, self.clock())
                        self.enrolled += 1
                        return b"L", label.encode()
                raise EnrollmentError("no handshake in progress")
            raise EnrollmentError("unknown request")
        except (EnrollmentError, ValueError) as exc:
            return b"E", str(exc).encode()

    def serve_connection(self, conn: socket.socket) -> None:
        conn.settimeout(IO_TIMEOUT)
        try:
            while True:
                ftype, payload = recv_frame(conn)
                rtype, reply = self.handle(ftype, payload)
                send_frame(conn, rtype, reply)
        except (EOFError, socket.timeout, ProtocolError, OSError):
            pass
        finally:
            conn.close()


def listen(path: str) -> socket.socket:
    if os.path.exists(path):
        os.unlink(path)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    old = os.umask(0o177)
    try:
        srv.bind(path)
    finally:
        os.umask(old)
    os.chmod(path, 0o600)
    srv.listen(8)
    srv.setblocking(False)
    return srv


# --------------------------------------------------------------------------- client side

class EnrollClient:
    def __init__(self, path: str) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(IO_TIMEOUT)
        self.sock.connect(path)

    def _call(self, ftype: bytes, payload: bytes, want: bytes) -> bytes:
        send_frame(self.sock, ftype, payload)
        rtype, reply = recv_frame(self.sock)
        if rtype == b"E":
            raise EnrollmentError(reply.decode(errors="replace"))
        if rtype != want:
            raise ProtocolError("expected %r, got %r" % (want, rtype))
        return reply

    def issue_token(self, tenant: str) -> Tuple[EnrollmentToken, Params]:
        d = json.loads(self._call(b"T", json.dumps({"tenant": tenant}).encode(), b"K"))
        tok = EnrollmentToken(bytes.fromhex(d["tenant_id"]), bytes.fromhex(d["token_id"]),
                              bytes.fromhex(d["secret"]))
        return tok, Params(epoch_seconds=d["epoch"], session_ttl_seconds=d["ttl"], grace_epochs=d["grace"])

    def hello(self, hello: Hello) -> Response:
        return Response.from_bytes(self._call(b"H", hello.to_bytes(), b"R"))

    def confirm(self, confirm: Confirm) -> str:
        return self._call(b"C", confirm.to_bytes(), b"L").decode()

    def close(self) -> None:
        self.sock.close()

    def __enter__(self) -> "EnrollClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
