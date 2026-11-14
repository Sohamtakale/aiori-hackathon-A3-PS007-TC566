"""Epoch key ratchet (FR-K1).

    K_{e+1} = HKDF(K_e, 'mayfly/v1/ratchet')

The old key is overwritten as soon as the next one is derived. The monitor side
keeps exactly one previous key (epoch e-1) so it can resolve addresses created
just before an epoch boundary (FR-R1); the device side keeps none.
"""

from __future__ import annotations

from typing import List, Optional, Tuple

from mayfly.identity.keys import hkdf, zeroize
from mayfly.params import INFO_RATCHET, KEY_LEN


class ResyncRequired(Exception):
    """The ratchet fell further behind than allowed and must re-enroll (FR-S4)."""


class KeyErased(Exception):
    """The ratchet has been erased; no key material remains."""


def ratchet_step(key: bytes | bytearray) -> bytearray:
    return hkdf(key, INFO_RATCHET)


class EpochRatchet:
    def __init__(self, k0: bytearray, keep_previous: bool) -> None:
        if not isinstance(k0, bytearray) or len(k0) != KEY_LEN:
            raise ValueError("k0 must be a %d-byte bytearray" % KEY_LEN)
        # Take ownership of the caller's buffer so there is only one copy to erase.
        self._current: Optional[bytearray] = k0
        self._previous: Optional[bytearray] = None
        self._keep_previous = keep_previous
        self._epoch = 0

    @property
    def epoch(self) -> int:
        return self._epoch

    @property
    def erased(self) -> bool:
        return self._current is None

    def advance(self) -> None:
        if self._current is None:
            raise KeyErased()
        nxt = ratchet_step(self._current)
        zeroize(self._previous)
        if self._keep_previous:
            self._previous = self._current
        else:
            zeroize(self._current)
            self._previous = None
        self._current = nxt
        self._epoch += 1

    def advance_to(self, epoch: int, max_steps: Optional[int] = None) -> None:
        if epoch < self._epoch:
            raise ValueError("ratchet cannot move backwards (at %d, asked %d)" % (self._epoch, epoch))
        steps = epoch - self._epoch
        if max_steps is not None and steps > max_steps:
            raise ResyncRequired("%d epochs behind, limit %d" % (steps, max_steps))
        for _ in range(steps):
            self.advance()

    def current(self) -> Tuple[int, bytearray]:
        if self._current is None:
            raise KeyErased()
        return self._epoch, self._current

    def live_keys(self) -> List[Tuple[int, bytearray]]:
        """Keys for epochs e and (monitor only) e-1, newest first."""
        if self._current is None:
            return []
        keys = [(self._epoch, self._current)]
        if self._previous is not None:
            keys.append((self._epoch - 1, self._previous))
        return keys

    def erase(self) -> None:
        zeroize(self._current)
        zeroize(self._previous)
        self._current = None
        self._previous = None

    def _buffers(self) -> List[bytearray]:
        """For tests: the buffers currently held."""
        return [b for b in (self._current, self._previous) if b is not None]
