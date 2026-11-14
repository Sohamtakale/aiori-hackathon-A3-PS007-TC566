"""Session lifecycle (FR-S2, FR-S3, FR-S4).

Monitor side: ``MonitorSession`` moves ENROLLING -> ACTIVE -> GRACE -> EXPIRED.
Epoch e is derived from time since enrollment. At EXPIRED the key material and
the label are deleted, so nothing remains that can resolve old addresses.

Device side: ``DeviceIdentity`` keeps only K_e and mints resolvable IIDs.
"""

from __future__ import annotations

import enum
from typing import List, Optional, Tuple

from mayfly.identity.iid import make_iid
from mayfly.identity.keys import RandFn, default_rand
from mayfly.identity.ratchet import EpochRatchet, ResyncRequired
from mayfly.params import DEFAULT_PARAMS, LABEL_LEN, Params


class SessionState(enum.Enum):
    ENROLLING = "ENROLLING"
    ACTIVE = "ACTIVE"
    GRACE = "GRACE"
    EXPIRED = "EXPIRED"


class SessionExpired(Exception):
    pass


def new_label(rand: RandFn = default_rand) -> str:
    """Random 48-bit pseudonym, independent of any key material (FR-S2)."""
    return rand(LABEL_LEN).hex()


def epoch_at(enrolled_at: float, now: float, params: Params) -> int:
    if now < enrolled_at:
        return 0
    return int((now - enrolled_at) // params.epoch_seconds)


class MonitorSession:
    def __init__(self, label: str, enrolled_at: float, params: Params = DEFAULT_PARAMS) -> None:
        self.label: Optional[str] = label
        self.enrolled_at = enrolled_at
        self.params = params
        self.state = SessionState.ENROLLING
        self._ratchet: Optional[EpochRatchet] = None

    def activate(self, k0: bytearray, now: float) -> None:
        if self.state is not SessionState.ENROLLING:
            raise ValueError("session is %s, not ENROLLING" % self.state.value)
        self._ratchet = EpochRatchet(k0, keep_previous=True)
        self.state = SessionState.ACTIVE
        self.tick(now)

    @property
    def epoch(self) -> Optional[int]:
        return None if self._ratchet is None or self._ratchet.erased else self._ratchet.epoch

    def tick(self, now: float) -> SessionState:
        """Advance the ratchet and the state machine to time ``now``."""
        if self.state is SessionState.EXPIRED:
            return self.state
        elapsed = now - self.enrolled_at
        p = self.params
        if self.state is SessionState.ENROLLING:
            if elapsed >= p.enroll_timeout_seconds:
                self.expire()
            return self.state
        assert self._ratchet is not None
        if elapsed >= p.session_ttl_seconds + p.grace_seconds:
            self.expire()
        elif elapsed >= p.session_ttl_seconds:
            # No new epochs after the TTL; keep e_last and e_last-1 for one grace period.
            self._ratchet.advance_to(max(self._ratchet.epoch, p.last_epoch))
            self.state = SessionState.GRACE
        else:
            self._ratchet.advance_to(epoch_at(self.enrolled_at, now, p))
        return self.state

    def live_keys(self) -> List[Tuple[int, bytearray]]:
        """(epoch, key) for epochs e and e-1 while ACTIVE or GRACE; else empty."""
        if self.state not in (SessionState.ACTIVE, SessionState.GRACE) or self._ratchet is None:
            return []
        return self._ratchet.live_keys()

    def expire(self) -> None:
        if self._ratchet is not None:
            self._ratchet.erase()
            self._ratchet = None
        self.label = None
        self.state = SessionState.EXPIRED

    def _buffers(self) -> List[bytearray]:
        return [] if self._ratchet is None else self._ratchet._buffers()


class DeviceIdentity:
    """Device-side key holder. Call ``tick`` at least every epoch; if it falls
    more than ``max_resync_epochs`` behind it must re-enroll (FR-S4)."""

    def __init__(self, k0: bytearray, enrolled_at: float, params: Params = DEFAULT_PARAMS,
                 rand: RandFn = default_rand) -> None:
        self._ratchet: Optional[EpochRatchet] = EpochRatchet(k0, keep_previous=False)
        self.enrolled_at = enrolled_at
        self.params = params
        self._rand = rand

    @property
    def expired(self) -> bool:
        return self._ratchet is None

    @property
    def epoch(self) -> int:
        if self._ratchet is None:
            raise SessionExpired()
        return self._ratchet.epoch

    def tick(self, now: float) -> int:
        if self._ratchet is None:
            raise SessionExpired()
        if now - self.enrolled_at >= self.params.session_ttl_seconds:
            self.erase()
            raise SessionExpired()
        try:
            self._ratchet.advance_to(epoch_at(self.enrolled_at, now, self.params),
                                     max_steps=self.params.max_resync_epochs)
        except ResyncRequired:
            self.erase()
            raise
        return self._ratchet.epoch

    def new_iid(self, prefix: bytes, now: float) -> bytes:
        """Fresh resolvable IID for ``prefix`` in the epoch containing ``now``."""
        self.tick(now)
        assert self._ratchet is not None
        _, key = self._ratchet.current()
        return make_iid(key, prefix, self._rand)

    def erase(self) -> None:
        if self._ratchet is not None:
            self._ratchet.erase()
            self._ratchet = None
