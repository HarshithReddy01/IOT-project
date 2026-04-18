from __future__ import annotations
import logging
import socket
import struct
from types import TracebackType
from typing import Optional, Type

logger = logging.getLogger(__name__)

MAX_FRAME: int = 64 * 1024


class ByteCountingSocket:
    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock
        self.bytes_tx: int = 0
        self.bytes_rx: int = 0

    def sendall(self, data: bytes) -> None:
        self._sock.sendall(data)
        self.bytes_tx += len(data)

    def send(self, data: bytes) -> int:
        n = self._sock.send(data)
        self.bytes_tx += n
        return n

    def recv(self, bufsize: int) -> bytes:
        data = self._sock.recv(bufsize)
        self.bytes_rx += len(data)
        return data

    def close(self) -> None:
        self._sock.close()

    def __enter__(self) -> "ByteCountingSocket":
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        self._sock.close()

    def __getattr__(self, name: str) -> object:
        return getattr(self._sock, name)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(f"EOF after {len(buf)}/{n} bytes")
        buf.extend(chunk)
    return bytes(buf)


def send_framed(sock: socket.socket, data: bytes) -> None:
    sock.sendall(struct.pack(">I", len(data)) + data)


def recv_framed(sock: socket.socket) -> bytes:
    raw_len = _recv_exact(sock, 4)
    (length,) = struct.unpack(">I", raw_len)
    if length > MAX_FRAME:
        raise ValueError(f"Frame length {length} exceeds MAX_FRAME ({MAX_FRAME})")
    return _recv_exact(sock, length)
