"""Key helpers: HKDF wrapper and best-effort zeroization.

Keys are kept in ``bytearray`` so they can be overwritten in place. Python and
the cryptography library make temporary immutable copies we cannot reach, so
erasure is best-effort (PRD section 12, "Known limits").
"""

from __future__ import annotations

import secrets
from typing import Callable, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from mayfly.params import KEY_LEN

RandFn = Callable[[int], bytes]


def default_rand(n: int) -> bytes:
    return secrets.token_bytes(n)


def hkdf(ikm: bytes | bytearray, info: bytes, salt: Optional[bytes] = None,
         length: int = KEY_LEN) -> bytearray:
    """HKDF-SHA256. Returns a mutable buffer the caller is responsible for zeroizing."""
    out = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(bytes(ikm))
    return bytearray(out)


def zeroize(buf: Optional[bytearray]) -> None:
    """Overwrite a key buffer with zeros in place."""
    if buf is None:
        return
    for i in range(len(buf)):
        buf[i] = 0


def is_zero(buf: bytes | bytearray) -> bool:
    return not any(buf)
