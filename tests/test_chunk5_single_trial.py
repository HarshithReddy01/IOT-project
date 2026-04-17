import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from scripts.csv_schema import read_results

AUTH_PORT_LAID = 9004
AUTH_PORT_HYBRID = 9005


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
def laid_server():
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "baseline_ecc.ecc_server",
            "--port",
            str(AUTH_PORT_LAID),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if not _wait_for_port("127.0.0.1", AUTH_PORT_LAID):
        proc.terminate()
        pytest.fail("ECC auth server did not start within timeout")
    yield proc
    proc.terminate()
    proc.wait()


@pytest.fixture(scope="module")
def hybrid_server():
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "hybrid_protocol.hybrid_server",
            "--port",
            str(AUTH_PORT_HYBRID),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if not _wait_for_port("127.0.0.1", AUTH_PORT_HYBRID):
        proc.terminate()
        pytest.fail("Hybrid auth server did not start within timeout")
    yield proc
    proc.terminate()
    proc.wait()


def test_single_trial_tls_writes_csv_row(tmp_path):
    cert_dir = Path("certs")
    if not (cert_dir / "ca.crt").exists():
        pytest.skip("TLS certs not available")
    csv_path = tmp_path / "test.csv"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "benchmarks.single_trial",
            "--protocol",
            "tls",
            "--trial-id",
            "0",
            "--payload-size",
            "30",
            "--output",
            str(csv_path),
            "--hardware-tag",
            "test",
        ],
        cwd=str(Path.cwd()),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, f"stderr: {result.stderr}"
    assert csv_path.exists()
    df = read_results(csv_path)
    assert len(df) == 1
    assert df.iloc[0]["protocol"] == "tls"
    assert df.iloc[0]["success"] == True


def test_single_trial_laid_writes_csv_row(laid_server, tmp_path):
    csv_path = tmp_path / "test.csv"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "benchmarks.single_trial",
            "--protocol",
            "laid",
            "--trial-id",
            "0",
            "--payload-size",
            "30",
            "--output",
            str(csv_path),
            "--hardware-tag",
            "test",
            "--auth-port",
            str(AUTH_PORT_LAID),
        ],
        cwd=str(Path.cwd()),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, f"stderr: {result.stderr}"
    assert csv_path.exists()
    df = read_results(csv_path)
    assert len(df) == 1
    assert df.iloc[0]["protocol"] == "laid"
    assert df.iloc[0]["success"] == True


def test_single_trial_hybrid_writes_csv_row(hybrid_server, tmp_path):
    csv_path = tmp_path / "test.csv"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "benchmarks.single_trial",
            "--protocol",
            "hybrid",
            "--trial-id",
            "0",
            "--payload-size",
            "30",
            "--output",
            str(csv_path),
            "--hardware-tag",
            "test",
            "--auth-port",
            str(AUTH_PORT_HYBRID),
        ],
        cwd=str(Path.cwd()),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, f"stderr: {result.stderr}"
    assert csv_path.exists()
    df = read_results(csv_path)
    assert len(df) == 1
    assert df.iloc[0]["protocol"] == "hybrid"
    assert df.iloc[0]["success"] == True
