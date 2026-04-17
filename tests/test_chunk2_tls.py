import pytest
from pathlib import Path

from baseline_tls.tls_client import run_tls_trial


def test_tls_trial_basic():
    cert_dir = Path("certs")
    if not (cert_dir / "ca.crt").exists():
        pytest.skip("TLS certs not available")
    result = run_tls_trial(
        trial_id=0,
        payload_size_bytes=30,
        hardware_tag="test",
        ca_cert=cert_dir / "ca.crt",
        client_cert=cert_dir / "client.crt",
        client_key=cert_dir / "client.key",
    )
    assert result.success is True
    assert result.protocol == "tls"
    assert result.payload_size_bytes == 30
    assert result.t_handshake_start_ns < result.t_handshake_end_ns
    assert result.t_handshake_end_ns <= result.t_connected_ns
    assert result.t_publish_start_ns < result.t_publish_done_ns
    assert result.cpu_time_end_ns >= result.cpu_time_start_ns
    assert result.tls_cipher_suite not in ("", "N/A", "UNKNOWN")


def test_tls_trial_wrong_port():
    cert_dir = Path("certs")
    if not (cert_dir / "ca.crt").exists():
        pytest.skip("TLS certs not available")
    with pytest.raises((TimeoutError, ConnectionRefusedError, OSError)):
        run_tls_trial(
            trial_id=99,
            payload_size_bytes=30,
            hardware_tag="test-fail",
            ca_cert=cert_dir / "ca.crt",
            client_cert=cert_dir / "client.crt",
            client_key=cert_dir / "client.key",
            broker_port=9999,
        )


def test_tls_payload_sizes():
    cert_dir = Path("certs")
    if not (cert_dir / "ca.crt").exists():
        pytest.skip("TLS certs not available")
    for size in (30, 256, 1024):
        result = run_tls_trial(
            trial_id=size,
            payload_size_bytes=size,
            hardware_tag="test",
            ca_cert=cert_dir / "ca.crt",
            client_cert=cert_dir / "client.crt",
            client_key=cert_dir / "client.key",
        )
        assert result.success is True
        assert result.payload_size_bytes == size
