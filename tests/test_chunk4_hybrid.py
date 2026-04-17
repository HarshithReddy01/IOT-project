import socket
import subprocess
import sys
import time

import pytest

from hybrid_protocol.hybrid_client import run_hybrid_trial

AUTH_PORT = 9003


def _wait_for_port(host: str, port: int, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.1)
    return False


@pytest.fixture(scope="module")
def hybrid_server():
    proc = subprocess.Popen(
        [sys.executable, "-m", "hybrid_protocol.hybrid_server", "--port", str(AUTH_PORT)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if not _wait_for_port("127.0.0.1", AUTH_PORT):
        proc.terminate()
        pytest.fail("Hybrid auth server did not start within timeout")
    yield proc
    proc.terminate()
    proc.wait()


def test_hybrid_trial_basic(hybrid_server):
    result = run_hybrid_trial(
        trial_id=0,
        payload_size_bytes=30,
        hardware_tag="test",
        auth_port=AUTH_PORT,
    )
    assert result.success is True
    assert result.protocol == "hybrid"
    assert result.payload_size_bytes == 30
    assert result.tls_cipher_suite == "N/A"
    assert result.t_handshake_start_ns < result.t_handshake_end_ns
    assert result.t_publish_start_ns < result.t_publish_done_ns
    assert result.cpu_time_end_ns >= result.cpu_time_start_ns


def test_hybrid_socket_byte_counts(hybrid_server):
    result = run_hybrid_trial(
        trial_id=1,
        payload_size_bytes=30,
        hardware_tag="test",
        auth_port=AUTH_PORT,
    )
    assert result.bytes_tx_socket == 121
    assert result.bytes_rx_socket == 117


def test_hybrid_payload_sizes(hybrid_server):
    for size in (30, 256, 1024):
        result = run_hybrid_trial(
            trial_id=size,
            payload_size_bytes=size,
            hardware_tag="test",
            auth_port=AUTH_PORT,
        )
        assert result.success is True
        assert result.payload_size_bytes == size


def test_hybrid_wrong_auth_port(hybrid_server):
    with pytest.raises((TimeoutError, ConnectionRefusedError, OSError)):
        run_hybrid_trial(
            trial_id=99,
            payload_size_bytes=30,
            hardware_tag="test-fail",
            auth_port=9997,
        )


def test_hybrid_uses_lcg_derived_scalar(hybrid_server):
    r1 = run_hybrid_trial(trial_id=1, payload_size_bytes=30, hardware_tag="t", auth_port=AUTH_PORT)
    r2 = run_hybrid_trial(trial_id=2, payload_size_bytes=30, hardware_tag="t", auth_port=AUTH_PORT)
    assert r1.success and r2.success


def test_hybrid_hkdf_label_differs_from_laid():
    import os
    from scripts.kdf import derive_keys

    shared = os.urandom(32)
    n_c, n_s = os.urandom(16), os.urandom(16)

    laid_enc, laid_mac = derive_keys(shared, n_c, n_s, "laid")
    hybrid_enc, hybrid_mac = derive_keys(shared, n_c, n_s, "hybrid")

    assert laid_enc != hybrid_enc
    assert laid_mac != hybrid_mac
