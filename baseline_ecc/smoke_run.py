import socket
import subprocess
import sys
import time

from baseline_ecc.ecc_client import run_ecc_trial

AUTH_PORT = 9001
POLL_TIMEOUT = 5.0


def _wait_for_port(host: str, port: int, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.1)
    return False


server = subprocess.Popen(
    [sys.executable, "-m", "baseline_ecc.ecc_server", "--port", str(AUTH_PORT)],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)

try:
    if not _wait_for_port("127.0.0.1", AUTH_PORT, POLL_TIMEOUT):
        print("ERROR: ECC auth server did not start within timeout")
        server.terminate()
        sys.exit(1)

    result = run_ecc_trial(
        trial_id=0,
        payload_size_bytes=30,
        hardware_tag="win11-smoke-test",
    )

    handshake_ms = (result.t_handshake_end_ns - result.t_handshake_start_ns) / 1_000_000
    publish_ms   = (result.t_publish_done_ns  - result.t_publish_start_ns)   / 1_000_000
    total_ms     = (result.t_publish_done_ns  - result.t_handshake_start_ns) / 1_000_000
    cpu_ms       = (result.cpu_time_end_ns    - result.cpu_time_start_ns)    / 1_000_000

    print("=== ECC (LAID) Smoke Test ===")
    print(f"Trial ID:           {result.trial_id}")
    print(f"Payload size:       {result.payload_size_bytes} bytes")
    print(f"Protocol:           {result.protocol}")
    print(f"Handshake:          {handshake_ms:.2f} ms")
    print(f"Publish:            {publish_ms:.2f} ms")
    print(f"Total:              {total_ms:.2f} ms")
    print(f"CPU time:           {cpu_ms:.2f} ms")
    print(f"Bytes TX (socket):  {result.bytes_tx_socket}")
    print(f"Bytes RX (socket):  {result.bytes_rx_socket}")
    print(f"Bytes TX (pcap):    {result.bytes_tx_pcap}")
    print(f"Bytes RX (pcap):    {result.bytes_rx_pcap}")
    print(f"Success:            {result.success}")
    print("=============================")

finally:
    server.terminate()
    server.wait()

sys.exit(0 if result.success else 1)
