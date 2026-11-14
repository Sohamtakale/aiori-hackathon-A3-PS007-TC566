"""Per-tenant key store (FR-R2): tokens, pending handshakes and live sessions.

Each tenant gets its own ``TenantKeyStore``; stores never share state, so one
tenant's resolver has no key that could resolve another tenant's devices (PT-2).
"""

from __future__ import annotations

from typing import Dict, Iterator, List, Optional, Tuple

from mayfly.identity.enroll import (TOKEN_ID_LEN, TOKEN_LEN, Confirm, EnrollmentError,
                                    EnrollmentToken, Hello, MonitorEnrollment, Response)
from mayfly.identity.keys import RandFn, default_rand
from mayfly.identity.session import MonitorSession, SessionState, new_label
from mayfly.params import DEFAULT_PARAMS, Params


class TenantKeyStore:
    def __init__(self, tenant_id: bytes, params: Params = DEFAULT_PARAMS,
                 rand: RandFn = default_rand) -> None:
        self.tenant_id = bytes(tenant_id)
        self.params = params
        self._rand = rand
        self._tokens: Dict[bytes, EnrollmentToken] = {}
        self._pending: Dict[bytes, Tuple[MonitorEnrollment, MonitorSession]] = {}
        self._sessions: Dict[str, MonitorSession] = {}

    # ------------------------------------------------------------- enrollment
    def issue_token(self) -> EnrollmentToken:
        tok = EnrollmentToken(self.tenant_id, self._rand(TOKEN_ID_LEN), self._rand(TOKEN_LEN))
        self._tokens[tok.token_id] = tok
        return tok

    def handle_hello(self, hello: Hello, now: float) -> Response:
        token = self._tokens.get(hello.token_id)
        if token is None or hello.tenant_id != self.tenant_id:
            raise EnrollmentError("device authentication failed")
        enr = MonitorEnrollment(token, hello, self._rand)
        old = self._pending.pop(hello.token_id, None)
        if old is not None:
            old[0].abort()
            old[1].expire()
        self._pending[hello.token_id] = (enr, MonitorSession(self._fresh_label(), now, self.params))
        return enr.response

    def handle_confirm(self, confirm: Confirm, now: float) -> str:
        """Finish enrollment; returns the new pseudonym label."""
        entry = self._pending.pop(confirm.token_id, None)
        if entry is None:
            raise EnrollmentError("no handshake in progress")
        enr, session = entry
        try:
            k0 = enr.confirm(confirm)
        except EnrollmentError:
            enr.abort()
            session.expire()
            raise
        del self._tokens[confirm.token_id]          # one-time token is now spent
        session.activate(k0, now)
        assert session.label is not None
        self._sessions[session.label] = session
        return session.label

    def _fresh_label(self) -> str:
        while True:
            label = new_label(self._rand)
            if label not in self._sessions:
                return label

    # ------------------------------------------------------------- lifecycle
    def tick(self, now: float) -> List[str]:
        """Advance all sessions; returns labels that expired on this tick."""
        for tid, (enr, s) in list(self._pending.items()):
            if s.tick(now) is SessionState.EXPIRED:
                enr.abort()
                del self._pending[tid]
        gone = []
        for label, s in list(self._sessions.items()):
            if s.tick(now) is SessionState.EXPIRED:
                del self._sessions[label]
                gone.append(label)
        return gone

    def expire(self, label: str) -> bool:
        s = self._sessions.pop(label, None)
        if s is None:
            return False
        s.expire()
        return True

    def expire_all(self) -> None:
        for label in list(self._sessions):
            self.expire(label)

    # ------------------------------------------------------------- queries
    def has_pending(self, token_id: bytes) -> bool:
        return token_id in self._pending

    def get(self, label: str) -> Optional[MonitorSession]:
        return self._sessions.get(label)

    def labels(self) -> List[str]:
        return list(self._sessions)

    def live_keys(self) -> Iterator[Tuple[str, int, bytearray]]:
        for label, s in self._sessions.items():
            for epoch, key in s.live_keys():
                yield label, epoch, key

    def __len__(self) -> int:
        return len(self._sessions)

    def _buffers(self) -> List[bytearray]:
        out: List[bytearray] = []
        for s in self._sessions.values():
            out.extend(s._buffers())
        return out
