"""Protocol parameters (PRD section 8)."""

from __future__ import annotations

from dataclasses import dataclass

KEY_LEN = 32          # bytes, HKDF-SHA256 output / epoch key size
PRAND_LEN = 4         # bytes (32 bit) random part of the IID
TAG_LEN = 4           # bytes (32 bit) keyed tag part of the IID
IID_LEN = PRAND_LEN + TAG_LEN
PREFIX_LEN = 8        # bytes, a /64 prefix
LABEL_LEN = 6         # bytes, 48-bit pseudonym label

# HKDF info strings. 'epoch0', 'mayfly/v1/ratchet' and 'iid' are taken verbatim
# from the PRD; the others are needed by the handshake and are namespaced.
INFO_RATCHET = b"mayfly/v1/ratchet"
INFO_EPOCH0 = b"epoch0"
INFO_SESSION = b"mayfly/v1/session"
INFO_CONFIRM = b"mayfly/v1/confirm"
TAG_DOMAIN = b"iid"


@dataclass(frozen=True)
class Params:
    """Tunable timing parameters. Defaults are the demo values from section 8."""

    epoch_seconds: float = 60.0
    session_ttl_seconds: float = 30 * 60.0
    grace_epochs: int = 1
    max_resync_epochs: int = 3       # FR-S4
    enroll_timeout_seconds: float = 30.0

    def __post_init__(self) -> None:
        if self.epoch_seconds <= 0:
            raise ValueError("epoch_seconds must be positive")
        if self.session_ttl_seconds < self.epoch_seconds:
            raise ValueError("session TTL must cover at least one epoch")
        if self.grace_epochs < 0 or self.max_resync_epochs < 0:
            raise ValueError("epoch counts must be non-negative")

    @property
    def last_epoch(self) -> int:
        """Index of the last epoch that starts before the TTL ends."""
        n = int(self.session_ttl_seconds // self.epoch_seconds)
        if n * self.epoch_seconds == self.session_ttl_seconds:
            n -= 1
        return n

    @property
    def grace_seconds(self) -> float:
        return self.grace_epochs * self.epoch_seconds


DEFAULT_PARAMS = Params()
