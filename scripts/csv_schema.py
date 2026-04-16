from __future__ import annotations
import csv
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Union

import pandas as pd

logger = logging.getLogger(__name__)

NOT_MEASURED: str = "NOT MEASURED"

COLUMNS: list[str] = [
    "trial_id",
    "protocol",
    "payload_size_bytes",
    "timestamp_iso",
    "hardware_tag",
    "t_handshake_start_ns",
    "t_handshake_end_ns",
    "t_mqtt_connect_start_ns",
    "t_connected_ns",
    "t_publish_start_ns",
    "t_publish_done_ns",
    "cpu_time_start_ns",
    "cpu_time_end_ns",
    "bytes_tx_pcap",
    "bytes_rx_pcap",
    "bytes_tx_socket",
    "bytes_rx_socket",
    "tls_cipher_suite",
    "success",
    "error_msg",
    "pcap_path",
]

_PURE_INT_COLS: list[str] = [
    "trial_id",
    "payload_size_bytes",
    "t_handshake_start_ns",
    "t_handshake_end_ns",
    "t_mqtt_connect_start_ns",
    "t_connected_ns",
    "t_publish_start_ns",
    "t_publish_done_ns",
    "cpu_time_start_ns",
    "cpu_time_end_ns",
]

_NULLABLE_INT_COLS: list[str] = [
    "bytes_tx_pcap",
    "bytes_rx_pcap",
    "bytes_tx_socket",
    "bytes_rx_socket",
]


@dataclass
class TrialResult:
    trial_id: int
    protocol: str
    payload_size_bytes: int
    timestamp_iso: str
    hardware_tag: str
    t_handshake_start_ns: int
    t_handshake_end_ns: int
    t_mqtt_connect_start_ns: int
    t_connected_ns: int
    t_publish_start_ns: int
    t_publish_done_ns: int
    cpu_time_start_ns: int
    cpu_time_end_ns: int

    bytes_tx_pcap: Union[int, str] = NOT_MEASURED
    bytes_rx_pcap: Union[int, str] = NOT_MEASURED
    bytes_tx_socket: Union[int, str] = NOT_MEASURED
    bytes_rx_socket: Union[int, str] = NOT_MEASURED
    tls_cipher_suite: str = "N/A"
    success: bool = True
    error_msg: str = ""
    pcap_path: str = NOT_MEASURED


def write_row(csv_path: Path, result: TrialResult) -> None:
    write_header = not csv_path.exists()
    row = {col: getattr(result, col) for col in COLUMNS}
    with csv_path.open("a", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=COLUMNS)
        if write_header:
            writer.writeheader()
        writer.writerow(row)


def read_results(csv_path: Path) -> pd.DataFrame:
    df = pd.read_csv(csv_path, dtype=str)

    for col in _PURE_INT_COLS:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce").astype("Int64")

    for col in _NULLABLE_INT_COLS:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce").astype("Int64")

    if "success" in df.columns:
        df["success"] = df["success"].map(
            {"True": True, "False": False, "true": True, "false": False}
        )

    return df
