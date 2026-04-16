from __future__ import annotations
import logging
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)

NONCE_LEN: int = 12
TAG_LEN: int = 16
_KEY_LEN: int = 32


class AEAD:
    def __init__(self, key: bytes) -> None:
        if len(key) != _KEY_LEN:
            raise ValueError(f"AES-256 key must be {_KEY_LEN} bytes, got {len(key)}")
        self._aesgcm = AESGCM(key)

    def encrypt(self, plaintext: bytes, associated_data: bytes = b"") -> bytes:
        # fresh nonce always
        nonce = os.urandom(NONCE_LEN)
        ct_tag = self._aesgcm.encrypt(nonce, plaintext, associated_data or None)
        return nonce + ct_tag

    def decrypt(
        self,
        ciphertext_with_nonce_and_tag: bytes,
        associated_data: bytes = b"",
    ) -> bytes:
        min_len = NONCE_LEN + TAG_LEN
        if len(ciphertext_with_nonce_and_tag) < min_len:
            raise ValueError(
                f"Input too short: need >= {min_len} bytes, "
                f"got {len(ciphertext_with_nonce_and_tag)}"
            )
        nonce = ciphertext_with_nonce_and_tag[:NONCE_LEN]
        ct_tag = ciphertext_with_nonce_and_tag[NONCE_LEN:]
        return self._aesgcm.decrypt(nonce, ct_tag, associated_data or None)
