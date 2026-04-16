from __future__ import annotations
import os
import socket
import struct
from pathlib import Path

import pandas as pd
import pytest

from scripts.aead_wrapper import AEAD, InvalidTag, NONCE_LEN, TAG_LEN
from scripts.csv_schema import (
    COLUMNS,
    NOT_MEASURED,
    TrialResult,
    read_results,
    write_row,
)
from scripts.kdf import derive_keys
from scripts.lcg import LCG
from scripts.pcap_capture import detect_loopback_interface
from scripts.socket_utils import (
    MAX_FRAME,
    ByteCountingSocket,
    recv_framed,
    send_framed,
)


def test_lcg_determinism():
    seed = os.urandom(8)
    assert LCG(seed).next_bytes(32) == LCG(seed).next_bytes(32)


def test_lcg_different_seeds():
    a = LCG(b"\x00" * 8).next_bytes(32)
    b = LCG(b"\x01" * 8).next_bytes(32)
    assert a != b


def test_lcg_seed_validation():
    with pytest.raises(ValueError):
        LCG(b"\x00" * 7)
    with pytest.raises(ValueError):
        LCG(b"\x00" * 9)


def test_aead_roundtrip():
    key = os.urandom(32)
    plaintext = b"sensor:temp=23.5,hum=60"
    aead = AEAD(key)
    assert aead.decrypt(aead.encrypt(plaintext)) == plaintext


def test_aead_tamper_detection():
    key = os.urandom(32)
    aead = AEAD(key)
    ct = bytearray(aead.encrypt(b"data"))
    ct[NONCE_LEN] ^= 0xFF
    with pytest.raises(InvalidTag):
        aead.decrypt(bytes(ct))


def test_aead_key_validation():
    with pytest.raises(ValueError):
        AEAD(b"\x00" * 31)
    with pytest.raises(ValueError):
        AEAD(b"\x00" * 33)


def test_kdf_two_keys_differ():
    k_enc, k_mac = derive_keys(b"s" * 32, b"c" * 16, b"v" * 16, "laid")
    assert len(k_enc) == 32
    assert len(k_mac) == 32
    assert k_enc != k_mac


def test_kdf_protocol_isolation():
    args = (b"s" * 32, b"c" * 16, b"v" * 16)
    k_laid, _ = derive_keys(*args, "laid")
    k_hybrid, _ = derive_keys(*args, "hybrid")
    assert k_laid != k_hybrid


def test_kdf_nonce_validation():
    with pytest.raises(ValueError):
        derive_keys(b"s" * 32, b"c" * 15, b"v" * 16, "laid")


def test_socket_framing():
    for payload in (os.urandom(10), os.urandom(10 * 1024)):
        s1, s2 = socket.socketpair()
        try:
            send_framed(s1, payload)
            assert recv_framed(s2) == payload
        finally:
            s1.close()
            s2.close()


def test_socket_counter():
    s1, s2 = socket.socketpair()
    data = b"hello world"
    bcs = ByteCountingSocket(s1)
    bcs.sendall(data)
    assert bcs.bytes_tx == len(data)
    bcs.close()
    s2.close()


def test_socket_counter_rx():
    s1, s2 = socket.socketpair()
    data = b"hello world receive side"
    try:
        bcs_tx = ByteCountingSocket(s1)
        bcs_rx = ByteCountingSocket(s2)
        bcs_tx.sendall(data)
        received = bcs_rx.recv(len(data))
        assert bcs_tx.bytes_tx == len(data)
        assert bcs_rx.bytes_rx == len(data)
        assert received == data
    finally:
        s1.close()
        s2.close()


def test_socket_max_frame():
    s1, s2 = socket.socketpair()
    s1.sendall(struct.pack(">I", MAX_FRAME + 1))
    with pytest.raises(ValueError):
        recv_framed(s2)
    s1.close()
    s2.close()


def test_csv_schema_roundtrip(tmp_path: Path):
    result = TrialResult(
        trial_id=42,
        protocol="hybrid",
        payload_size_bytes=256,
        timestamp_iso="2026-04-16T12:00:00+00:00",
        hardware_tag="win11-loopback-py312",
        t_handshake_start_ns=1_000_000_000,
        t_handshake_end_ns=1_005_000_000,
        t_mqtt_connect_start_ns=1_005_100_000,
        t_connected_ns=1_006_000_000,
        t_publish_start_ns=1_006_100_000,
        t_publish_done_ns=1_007_000_000,
        cpu_time_start_ns=500_000,
        cpu_time_end_ns=600_000,
        bytes_tx_pcap=NOT_MEASURED,
        bytes_rx_pcap=NOT_MEASURED,
        bytes_tx_socket=12345,
        bytes_rx_socket=6789,
        tls_cipher_suite="N/A",
        success=True,
        error_msg="",
        pcap_path=NOT_MEASURED,
    )

    csv_file = tmp_path / "results.csv"
    write_row(csv_file, result)

    df = read_results(csv_file)
    assert len(df) == 1
    row = df.iloc[0]

    assert row["trial_id"] == 42
    assert row["protocol"] == "hybrid"
    assert row["payload_size_bytes"] == 256
    assert pd.isna(row["bytes_tx_pcap"])
    assert pd.isna(row["bytes_rx_pcap"])
    assert row["bytes_tx_socket"] == 12345
    assert row["bytes_rx_socket"] == 6789
    assert row["success"]
    assert list(df.columns) == COLUMNS


def test_pcap_capture_optional():
    result = detect_loopback_interface()
    if result is None:
        pytest.skip(
            "tshark not available or loopback interface not detected "
            "(expected on some Windows setups)"
        )
    assert isinstance(result, str)
    assert len(result) > 0
