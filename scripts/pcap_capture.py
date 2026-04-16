from __future__ import annotations
import logging
import subprocess
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

TSHARK_PATH_CANDIDATES: list[str] = [
    r"C:\Program Files\Wireshark\tshark.exe",
    "tshark",
]

try:
    from scapy.all import rdpcap, TCP
    _SCAPY_AVAILABLE = True
except ImportError:
    _SCAPY_AVAILABLE = False

if not _SCAPY_AVAILABLE:
    logger.warning(
        "scapy not installed. Install with: pip install scapy. "
        "pcap byte counting will return (0, 0) for all trials."
    )


def _find_tshark() -> Optional[str]:
    for candidate in TSHARK_PATH_CANDIDATES:
        try:
            r = subprocess.run(
                [candidate, "--version"],
                capture_output=True,
                timeout=5,
            )
            if r.returncode == 0:
                return candidate
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            continue
    return None


def detect_loopback_interface() -> Optional[str]:
    tshark = _find_tshark()
    if tshark is None:
        logger.warning("tshark not found; pcap capture disabled for this run")
        return None

    try:
        result = subprocess.run(
            [tshark, "-D"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
        )
    except subprocess.TimeoutExpired:
        logger.warning("tshark -D timed out")
        return None

    for line in result.stdout.splitlines():
        if "loopback" in line.lower():
            parts = line.strip().split(".", 1)
            if parts[0].strip().isdigit():
                iface = parts[0].strip()
                logger.info("Selected loopback interface number %s (line: %s)", iface, line.strip())
                return iface

    # try safe fallback
    fallback = r"\Device\NPF_Loopback"
    logger.warning(
        "No loopback line found in tshark -D output; "
        "falling back to %s", fallback
    )
    logger.info("Selected loopback interface fallback: %s", fallback)
    return fallback


class CaptureSession:
    def __init__(
        self, interface: str, capture_filter: str, output_path: Path
    ) -> None:
        self._interface = interface
        self._filter = capture_filter
        self._output_path = output_path
        self._proc: Optional[subprocess.Popen] = None
        self._tshark = _find_tshark()

    def __enter__(self) -> "CaptureSession":
        if self._tshark is None:
            logger.warning("tshark unavailable; skipping pcap capture for this session")
            return self
        cmd = [
            self._tshark,
            "-i", self._interface,
            "-f", self._filter,
            "-w", str(self._output_path),
        ]
        self._proc = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline:
            if self._output_path.exists() and self._output_path.stat().st_size > 0:
                break
            time.sleep(0.05)
        return self

    def __exit__(self, *_args) -> None:
        if self._proc is None:
            return
        self._proc.terminate()
        try:
            self._proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self._proc.kill()
            self._proc.wait()


def count_pcap_bytes(
    pcap_path: Path,
    local_port_set: set[int],
) -> tuple[int, int]:
    if not _SCAPY_AVAILABLE:
        logger.warning("scapy not installed; count_pcap_bytes returns (0, 0)")
        return 0, 0

    if not pcap_path.exists() or pcap_path.stat().st_size == 0:
        logger.warning("pcap missing or empty: %s", pcap_path)
        return 0, 0

    try:
        packets = rdpcap(str(pcap_path))
    except Exception as exc:
        logger.warning("Failed to parse pcap %s: %s", pcap_path, exc)
        return 0, 0

    tx = rx = 0
    for pkt in packets:
        if TCP not in pkt:
            continue
        size = len(pkt)
        if pkt[TCP].dport in local_port_set:
            tx += size
        elif pkt[TCP].sport in local_port_set:
            rx += size
    return tx, rx
