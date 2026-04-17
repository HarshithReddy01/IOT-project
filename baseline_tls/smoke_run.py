import sys
from pathlib import Path

from baseline_tls.tls_client import run_tls_trial

cert_dir = Path("certs")

result = run_tls_trial(
    trial_id=0,
    payload_size_bytes=30,
    hardware_tag="win11-smoke-test",
    ca_cert=cert_dir / "ca.crt",
    client_cert=cert_dir / "client.crt",
    client_key=cert_dir / "client.key",
)

# display metrics only
handshake_ms = (result.t_handshake_end_ns - result.t_handshake_start_ns) / 1_000_000
publish_ms   = (result.t_publish_done_ns  - result.t_publish_start_ns)   / 1_000_000
total_ms     = (result.t_publish_done_ns  - result.t_handshake_start_ns) / 1_000_000
cpu_ms       = (result.cpu_time_end_ns    - result.cpu_time_start_ns)    / 1_000_000

print("=== TLS Smoke Test ===")
print(f"Trial ID:         {result.trial_id}")
print(f"Payload size:     {result.payload_size_bytes} bytes")
print(f"TLS cipher:       {result.tls_cipher_suite}")
print(f"Handshake:        {handshake_ms:.2f} ms")
print(f"Publish:          {publish_ms:.2f} ms")
print(f"Total:            {total_ms:.2f} ms")
print(f"CPU time:         {cpu_ms:.2f} ms")
print(f"Bytes TX (pcap):  {result.bytes_tx_pcap}")
print(f"Bytes RX (pcap):  {result.bytes_rx_pcap}")
print(f"Success:          {result.success}")
print("===================")

sys.exit(0 if result.success else 1)
