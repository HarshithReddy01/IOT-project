from __future__ import annotations
import logging

logger = logging.getLogger(__name__)

LCG_A: int = 1_664_525
LCG_C: int = 1_013_904_223
LCG_M: int = 2**32


class LCG:
    def __init__(self, seed: bytes) -> None:
        if len(seed) != 8:
            raise ValueError(f"LCG seed must be 8 bytes, got {len(seed)}")
        self._state: int = int.from_bytes(seed, "big") % LCG_M

    def next_uint32(self) -> int:
        self._state = (LCG_A * self._state + LCG_C) % LCG_M
        return self._state

    def next_bytes(self, n: int) -> bytes:
        words = (n + 3) // 4
        raw = b"".join(self.next_uint32().to_bytes(4, "big") for _ in range(words))
        return raw[:n]
