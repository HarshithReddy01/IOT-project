import socket
import subprocess
import sys
import time

import pytest

from baseline_ecc.ecc_client import run_ecc_trial

AUTH_PORT = 9002


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
def ecc_server():
    proc = subprocess.Popen(
        [sys.executable, "-m", "baseline_ecc.ecc_server", "--port", str(AUTH_PORT)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if not _wait_for_port("127.0.0.1", AUTH_PORT):
        proc.terminate()
        pytest.fail("ECC auth server did not start within timeout")
    yield proc
    proc.terminate()
    proc.wait()


def test_ecc_trial_basic(ecc_server):
    result = run_ecc_trial(
        trial_id=0,
        payload_size_bytes=30,
        hardware_tag="test",
        auth_port=AUTH_PORT,
    )
    assert result.success is True
    assert result.protocol == "laid"
    assert result.payload_size_bytes == 30
    assert result.tls_cipher_suite == "N/A"
    assert result.t_handshake_start_ns < result.t_handshake_end_ns
    assert result.t_publish_start_ns < result.t_publish_done_ns
    assert result.cpu_time_end_ns >= result.cpu_time_start_ns


def test_ecc_socket_byte_counts(ecc_server):
    result = run_ecc_trial(
        trial_id=1,
        payload_size_bytes=30,
        hardware_tag="test",
        auth_port=AUTH_PORT,
    )
    assert result.bytes_tx_socket >= 121
    assert result.bytes_rx_socket >= 117


def test_ecc_payload_sizes(ecc_server):
    for size in (30, 256, 1024):
        result = run_ecc_trial(
            trial_id=size,
            payload_size_bytes=size,
            hardware_tag="test",
            auth_port=AUTH_PORT,
        )
        assert result.success is True
        assert result.payload_size_bytes == size


def test_ecc_wrong_auth_port(ecc_server):
    with pytest.raises((TimeoutError, ConnectionRefusedError, OSError)):
        run_ecc_trial(
            trial_id=99,
            payload_size_bytes=30,
            hardware_tag="test-fail",
            auth_port=9998,
        )


def test_ecc_mac_binds_full_transcript(ecc_server):
    import hmac as _hmac
    import os
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.ec import ECDH, SECP256R1
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from scripts.kdf import derive_keys

    c_priv = ec.generate_private_key(SECP256R1())
    s_priv = ec.generate_private_key(SECP256R1())
    q_c = c_priv.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    q_s = s_priv.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    n_c, n_s = os.urandom(16), os.urandom(16)
    shared = c_priv.exchange(ECDH(), s_priv.public_key())
    _, k_mac = derive_keys(shared, n_c, n_s, "laid")

    expected_mac_s = _hmac.new(k_mac, q_c + n_c + q_s + n_s, "sha256").digest()
    expected_mac_c = _hmac.new(k_mac, q_s + n_s + q_c + n_c, "sha256").digest()

    assert expected_mac_s != expected_mac_c
    assert len(expected_mac_s) == 32
    assert len(expected_mac_c) == 32
