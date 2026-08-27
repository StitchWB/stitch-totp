"""Dependency-free TOTP (RFC 6238) helpers for the plugin process.

Stdlib-only (hmac/hashlib/struct/base64) so the plugin does not depend
on pyotp.  Supports SHA1/SHA256/SHA512, configurable digits/period —
the same parameter space as the core ``totp_keys`` rows.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import struct
import time

_ALGOS = {
    "SHA1": hashlib.sha1,
    "SHA256": hashlib.sha256,
    "SHA512": hashlib.sha512,
}


def generate_secret() -> str:
    """Generate a new base32 TOTP secret (160-bit, like pyotp default)."""
    return base64.b32encode(os.urandom(20)).decode("ascii")


def _decode_secret(secret: str) -> bytes:
    """Decode a base32 secret, tolerating missing padding / lowercase."""
    cleaned = secret.strip().upper()
    padding = (-len(cleaned)) % 8
    return base64.b32decode(cleaned + "=" * padding)


def _hotp(key: bytes, counter: int, digits: int, algorithm: str) -> str:
    algo = _ALGOS.get(algorithm.upper(), hashlib.sha1)
    digest = hmac.new(key, struct.pack(">Q", counter), algo).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % (10**digits)).zfill(digits)


def generate_code(
    secret: str,
    digits: int = 6,
    period: int = 30,
    algorithm: str = "SHA1",
    timestamp: float | None = None,
) -> str:
    """Current TOTP code for *secret* (or at *timestamp* seconds)."""
    ts = time.time() if timestamp is None else float(timestamp)
    counter = int(ts // max(1, int(period)))
    return _hotp(_decode_secret(secret), counter, digits, algorithm)


def verify_code(
    secret: str,
    code: str,
    digits: int = 6,
    period: int = 30,
    algorithm: str = "SHA1",
    window: int = 1,
) -> bool:
    """Verify *code* against *secret* with ±*window* time-step drift."""
    try:
        key = _decode_secret(secret)
    except (binascii.Error, ValueError):
        return False
    counter = int(time.time() // max(1, int(period)))
    candidate = str(code).strip()
    return any(
        hmac.compare_digest(
            _hotp(key, counter + delta, digits, algorithm), candidate
        )
        for delta in range(-window, window + 1)
    )
