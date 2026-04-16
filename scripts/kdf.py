from __future__ import annotations
import logging

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

logger = logging.getLogger(__name__)

_VALID_PROTOCOLS = frozenset({"laid", "hybrid"})
_NONCE_LEN = 16
_KEY_LEN = 32


def derive_keys(
    shared_secret: bytes,
    n_c: bytes,
    n_s: bytes,
    protocol: str,
) -> tuple[bytes, bytes]:
    if len(n_c) != _NONCE_LEN:
        raise ValueError(f"n_c must be {_NONCE_LEN} bytes, got {len(n_c)}")
    if len(n_s) != _NONCE_LEN:
        raise ValueError(f"n_s must be {_NONCE_LEN} bytes, got {len(n_s)}")
    if protocol not in _VALID_PROTOCOLS:
        raise ValueError(
            f"protocol must be one of {sorted(_VALID_PROTOCOLS)!r}, got {protocol!r}"
        )

    salt = n_c + n_s

    def _derive(info_label: str) -> bytes:
        # split key purposes
        return HKDF(
            algorithm=hashes.SHA256(),
            length=_KEY_LEN,
            salt=salt,
            info=info_label.encode(),
        ).derive(shared_secret)

    return _derive(f"{protocol}-enc-v1"), _derive(f"{protocol}-mac-v1")
