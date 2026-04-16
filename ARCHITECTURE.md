# ARCHITECTURE.md
## Performance Analysis of a Hybrid ECC-LCG Lightweight Authentication Protocol for MQTT-Based IoT Networks

**Author:** Harshith Reddy Nalla (Student ID: 101139582)  
**Course:** Internet of Things, Spring 2026  
**Deadline:** April 28, 2026

---

## 1. Scope

### Measured Metrics

| Metric | Collection Method | Unit in CSV |
|--------|-------------------|-------------|
| Handshake latency | `time.perf_counter_ns()` at phase boundaries | raw ns integer |
| First-publish latency | `time.perf_counter_ns()` at publish start/done | raw ns integer |
| Total session latency | `time.perf_counter_ns()` trial start to session teardown | raw ns integer |
| CPU time per trial | `time.process_time_ns()` start and end | raw ns integer |
| Bytes transmitted (pcap) | tshark pcap capture parsed per trial | integer bytes or `NOT MEASURED` |
| Bytes received (pcap) | tshark pcap capture parsed per trial | integer bytes or `NOT MEASURED` |
| Bytes transmitted (socket) | ByteCountingSocket wrapper on custom protocols | integer bytes or `NOT MEASURED` |
| Bytes received (socket) | ByteCountingSocket wrapper on custom protocols | integer bytes or `NOT MEASURED` |
| Payload size | Fixed per benchmark pass; recorded per row | integer bytes |
| Estimated energy (ESP32 proxy) | Derived in analysis script from CPU time only | mJ (float) |

### Trial Count and Benchmark Passes

The benchmark is structured as a nested loop over **3 protocols × 3 payload sizes = 9 (protocol, payload_size) combinations**. Each combination runs **500 trials** (trial_id 0–499). The first 10 trials (trial_id 0–9) are warmup and are discarded in analysis via a `trial_id >= 10` filter, leaving **490 analysis trials per combination** (4,410 total rows in the raw CSV after warmup filtering).

Payload sizes:
- **Small:** 30 bytes — representative of a compact sensor reading (e.g., `temperature:23.5,humidity:60`)
- **Medium:** 256 bytes — realistic IoT JSON sensor report
- **Large:** 1024 bytes — JSON with extended metadata fields

The plaintext payload for each size is **fixed random bytes**, generated once from a seeded PRNG at benchmark startup and reused across all 500 trials for that size. This ensures byte counts and encryption overhead are reproducible across runs. The seed is stored as a constant in `benchmarks/run_benchmark.py` and recorded in `logs/errors.log` at startup. Different payload sizes use different random byte blocks (derived from the same seed but at different offsets), so medium and large payloads are not prefixes of each other.

Derived metrics (handshake_ms, publish_ms, total_ms, estimated_energy_mj_esp32_proxy) are computed **only** in `analysis/analyze_results.py` after all trials are complete. Raw CSV contains only timestamps, byte counts, and payload size.

### Out-of-Scope Items

- Real-device energy measurement (no physical hardware in this study)
- Formal security proofs (ProVerif, AVISPA, Tamarin)
- Radio-layer simulation (Cooja, NS-3) — noted as future work
- Multi-hop or dense IoT topologies
- Side-channel analysis
- Physical attack models

### Honest Limitations

This study runs entirely on a loopback interface on a single Windows 11 machine. Python's GIL and interpreter overhead inflate absolute latency values relative to embedded C implementations. Relative comparisons among the three protocols are preserved because all three run under identical conditions. Energy values are a proxy computed from CPU time and an ESP32 datasheet model; they do not represent actual power draw. No formal security proof is provided; the security argument (Section 12) is informal and cites the constituent papers.

---

## 2. Three Protocols Under Test

### Baseline A — MQTT over TLS 1.2/1.3

The client connects to Mosquitto on port 8883 using paho-mqtt with a mutual-TLS context (ca.crt, client.crt, client.key). The TLS record layer provides confidentiality and integrity natively. This baseline represents the industry-standard approach and is expected to exhibit the highest handshake latency, highest byte overhead (due to the TLS certificate exchange and record-layer framing), and highest CPU cost. It serves as the upper-bound reference against which the lightweight protocols are compared. TLS session tickets are disabled via `ssl.OP_NO_TICKET` to enforce cold-start semantics per trial.

### Baseline B — Standalone LAID (ECC-only, No LCG)

The client and a custom TCP authentication server (`ecc_server.py`, port 9001) execute a 3-message ECC mutual-authentication handshake derived from the LAID protocol (Khalique et al. 2025). Private keys are generated using `ec.generate_private_key(ec.SECP256R1())` — the standard cryptographic method, with no LCG involvement. After the handshake completes, the authentication server closes its connection. The client then derives session keys K_enc and K_mac via HKDF-SHA256 over the ECDH shared secret, connects directly to Mosquitto on port 1883, and publishes the AES-256-GCM-wrapped payload itself. The authentication server's sole role is the handshake; it does not relay MQTT traffic. This baseline isolates the cost of ECC mutual-auth without the LCG acceleration layer and is expected to have lower overhead than TLS but higher computation than the hybrid (due to `generate_private_key` being a full CSPRNG draw).

### Proposed — Hybrid ECC-LCG Protocol

The client and a custom TCP authentication server (`hybrid_server.py`, port 9002) execute the same 3-message LAID-style mutual-authentication handshake, but the ECC private scalar is derived from LCG output seeded by `os.urandom(8)` rather than from `ec.generate_private_key()`. Each party seeds its own LCG locally from its own `os.urandom(8)`; the seed is never transmitted. The LCG (Numerical Recipes constants) rapidly expands 8 bytes of cryptographic entropy into 32 bytes for the ECC scalar and 16 bytes for the anti-replay nonce. After the handshake completes, the authentication server closes its connection. The client derives K_enc and K_mac via HKDF-SHA256 over the ECDH shared secret, connects directly to Mosquitto on port 1883, and publishes the AES-256-GCM-wrapped payload itself. The hypothesis is that LCG-based scalar derivation reduces per-trial CPU time (and thus estimated energy) compared to Baseline B while preserving mutual-authentication security, because the security root remains `os.urandom` and ECDH, not the LCG. The wire message format is byte-for-byte identical to LAID; the advantage is pure CPU time savings.

---

## 3. Cryptographic Primitives

### Elliptic Curve

- **Curve:** SECP256R1 (NIST P-256)
- **Rationale:** NIST-standard curve used in the LAID paper (Khalique et al. 2025) and Alghamdi (2025). Supported natively by the Python `cryptography` library. 256-bit security sufficient for IoT authentication contexts per NIST SP 800-57.
- **Library:** `cryptography.hazmat.primitives.asymmetric.ec`

### Key Derivation Function — Two Separate Keys

Two independent HKDF-SHA256 invocations are performed after the ECDH exchange, one for each key. The `shared_secret` is the raw ECDH output bytes.

```
K_enc = HKDF-SHA256(
    ikm   = shared_secret,
    salt  = n_c || n_s,
    info  = b"<protocol>-enc-v1",
    length = 32
)

K_mac = HKDF-SHA256(
    ikm   = shared_secret,
    salt  = n_c || n_s,
    info  = b"<protocol>-mac-v1",
    length = 32
)
```

Where `<protocol>` is `laid` or `hybrid` depending on the protocol in use (e.g., `b"laid-enc-v1"`, `b"hybrid-mac-v1"`).

- **K_enc** (32 bytes): used as the AES-256-GCM key to encrypt/decrypt the MQTT application payload.
- **K_mac** (32 bytes): used as the HMAC-SHA256 key in handshake messages 2 and 3 for mutual authentication.
- **Library:** `cryptography.hazmat.primitives.kdf.hkdf.HKDF`

### Authenticated Encryption

- **Algorithm:** AES-256-GCM
- **Key:** K_enc (32 bytes, from HKDF above)
- **Nonce:** 12 bytes, randomly generated per message via `os.urandom(12)`
- **Tag:** 16 bytes (GCM authentication tag)
- **Wire format:** `nonce(12) || ciphertext(variable) || tag(16)`
- **Purpose:** Wraps MQTT application payload after handshake for Baseline B and Hybrid; client applies this before publishing to Mosquitto port 1883
- **Library:** `cryptography.hazmat.primitives.ciphers.aead.AESGCM`

### Message Authentication Code

- **Algorithm:** HMAC-SHA256
- **Key:** K_mac (32 bytes, from HKDF above)
- **Output:** 32 bytes
- **Input for MAC_s (server in Msg2):** `HMAC(K_mac, Q_c || n_c || Q_s || n_s)`
- **Input for MAC_c (client in Msg3):** `HMAC(K_mac, Q_s || n_s || Q_c || n_c)` (roles reversed)
- **Library:** `cryptography.hazmat.primitives.hmac.HMAC`

### Nonces

- **Handshake nonces:** 16 bytes everywhere in handshake messages
- **Generation:** `os.urandom(16)` for LAID; `lcg.next_bytes(16)` (after scalar derivation) for Hybrid
- **AES-GCM nonces:** 12 bytes, `os.urandom(12)` per payload encryption call (separate from handshake nonces)

---

## 4. LCG Specification (Hybrid Protocol Only)

### Constants

| Parameter | Value | Source |
|-----------|-------|--------|
| Multiplier `a` | 1,664,525 | Numerical Recipes in C, 2nd ed., §7.1 |
| Increment `c` | 1,013,904,223 | Numerical Recipes in C, 2nd ed., §7.1 |
| Modulus `m` | 2³² (4,294,967,296) | Numerical Recipes in C, 2nd ed., §7.1 |

### Seed

- **Size:** 8 bytes, sourced from `os.urandom(8)` locally on each party
- **Interpretation:** `seed = int.from_bytes(os.urandom(8), 'big') % m`
- **Security root:** `os.urandom` is the cryptographically secure entropy source. The LCG is a fast deterministic expansion of this entropy; it is not the security primitive.
- **Transmission:** The seed is **never transmitted**. Each party (client and server) independently generates its own local seed. The peer receives only the derived public key Q, from which recovering the LCG scalar requires solving the Elliptic Curve Discrete Logarithm Problem (ECDLP), which is computationally infeasible.

### Output Derivation

The LCG is iterated to produce a byte stream. Each call to `next_bytes(n)` concatenates enough 4-byte LCG outputs (big-endian) to fill `n` bytes:

1. **ECC scalar `s`:** `int.from_bytes(lcg.next_bytes(32), 'big') % curve_order`
   - Applied as: `priv_key = ec.derive_private_key(private_value, ec.SECP256R1())`
   - `Q = s · P` (public key, uncompressed, 65 bytes)
2. **Anti-replay nonce `n`:** `lcg.next_bytes(16)` (next 16 bytes from the same LCG stream, after scalar derivation)

### Security Statement

The LCG serves as a fast pseudo-random expansion layer, consistent with the design intent of the DLKS-MQTT paper (Kaganurmath et al. 2025), which uses LCG for lightweight key material generation in resource-constrained devices. The LCG does **not** replace the security primitives: ECDH over SECP256R1 provides the key agreement security, `os.urandom` provides the entropy root, and HMAC-SHA256 provides mutual authentication. Prediction of the ECC scalar by an adversary who does not know the 8-byte seed requires breaking `os.urandom` (2^64 seed space), not breaking the LCG. This design matches the threat model of DLKS-MQTT and is documented as a design choice, not a security claim about LCG alone.

---

## 5. Protocol Message Formats (Byte-Exact Application Layer)

All sizes below are application-layer payload bytes. Real wire bytes (including TCP/IP headers, Ethernet framing) are measured per-trial via tshark pcap capture and recorded in `bytes_tx_pcap` / `bytes_rx_pcap`. The `+4 framing` refers to a 4-byte big-endian length prefix prepended by the custom TCP server/client to delimit messages on the stream.

### Baseline B — LAID (ECC-only)

```
Msg1  C → S:  Q_c(65) || n_c(16)                              = 81 bytes app  [+4 framing = 85]
Msg2  S → C:  Q_s(65) || n_s(16) || MAC_s(32)                 = 113 bytes app [+4 framing = 117]
Msg3  C → S:  MAC_c(32)                                        = 32 bytes app  [+4 framing = 36]
```

Total application bytes (handshake only): 81 + 113 + 32 = **226 bytes**  
Total with framing: 85 + 117 + 36 = **238 bytes**

- `Q_c`, `Q_s`: Uncompressed EC public key, 65 bytes (0x04 prefix + 32-byte x + 32-byte y)
- `n_c`, `n_s`: 16-byte random nonces (`os.urandom(16)`)
- `MAC_s`, `MAC_c`: 32-byte HMAC-SHA256 using K_mac

### Proposed — Hybrid ECC-LCG

```
Msg1  C → S:  Q_c(65) || n_c(16)                              = 81 bytes app  [+4 framing = 85]
Msg2  S → C:  Q_s(65) || n_s(16) || MAC_s(32)                 = 113 bytes app [+4 framing = 117]
Msg3  C → S:  MAC_c(32)                                        = 32 bytes app  [+4 framing = 36]
```

Total application bytes (handshake only): 81 + 113 + 32 = **226 bytes**  
Total with framing: 85 + 117 + 36 = **238 bytes**

- `Q_c`, `Q_s`: Uncompressed EC public key derived from LCG scalar `s = lcg.next_bytes(32) % curve_order`, 65 bytes
- `n_c`, `n_s`: 16-byte nonces derived from LCG output (`lcg.next_bytes(16)`) after scalar derivation
- `MAC_s`, `MAC_c`: 32-byte HMAC-SHA256 using K_mac
- LCG seeds are local to each party and are **never transmitted**

> **Key observation:** The Hybrid has **identical wire bytes to LAID** (238 bytes with framing). The hybrid's advantage is pure CPU time savings from LCG-based scalar derivation versus a full CSPRNG-based `generate_private_key()` call, with zero byte cost penalty. Any difference in the measured `bytes_tx_pcap` / `bytes_rx_pcap` between LAID and Hybrid should be zero at the application layer; discrepancies indicate measurement noise in TCP framing and are noted as such in the analysis.

### Baseline A — MQTT over TLS

No custom message format. TLS handshake bytes and MQTT payload bytes are measured via tshark on port 8883. Application-layer byte count is NOT MEASURED separately from TLS record overhead — total wire bytes on port 8883 are the reported metric. TODO: confirm tshark can capture on Npcap loopback for 127.0.0.1:8883.

### Baseline A — MQTT over TLS (Post-Handshake Payload)

For TLS trials, the client publishes the **raw plaintext** payload directly to Mosquitto on port 8883. TLS record-layer encryption is applied transparently. There is no additional AES-GCM wrapping. The plaintext sizes (30, 256, 1024 bytes) match those used by LAID and Hybrid exactly, ensuring the application-layer payload is identical across all three protocols for a given payload size pass.

### Post-Handshake MQTT Payload (Baseline B and Hybrid)

After the authentication handshake, the client publishes to Mosquitto port 1883. The on-wire payload is:

```
AES-GCM payload:  nonce_gcm(12) || ciphertext(N) || tag(16)
```

where N is the plaintext size (30, 256, or 1024 bytes). Total MQTT application payload sizes on the wire:

| Payload pass | Plaintext (N) | AES-GCM overhead | Wire payload |
|-------------|--------------|-----------------|-------------|
| Small       | 30 bytes     | 12 + 16 = 28    | 58 bytes    |
| Medium      | 256 bytes    | 12 + 16 = 28    | 284 bytes   |
| Large       | 1024 bytes   | 12 + 16 = 28    | 1052 bytes  |

The plaintext for each size is **fixed random bytes** generated once at benchmark startup from a seeded PRNG (`PAYLOAD_SEED = 0xDEADBEEFCAFE1234` in `run_benchmark.py`). The same bytes are reused across all 500 trials for a given size, so AES-GCM ciphertext length and MQTT PUBLISH packet size are deterministic. A fresh 12-byte GCM nonce (`os.urandom(12)`) is drawn per trial, so ciphertext content varies but length does not.

Wire bytes for the MQTT publish on port 1883 are captured by tshark (when available) and included in `bytes_tx_pcap`. ByteCountingSocket counters on the custom-TCP handshake portion (ports 9001/9002) are separate from the MQTT publish bytes; both are summed by tshark into the total `bytes_tx_pcap` for LAID and Hybrid trials.

---

## 6. Transport Architecture

### Baseline A — TLS

```
paho-mqtt client
      │
      │ TLS 1.2/1.3 (port 8883)
      ▼
Mosquitto broker (Windows service, mosquitto_tls.conf)
```

- Client authenticates with `client.crt` / `client.key`; broker with `server.crt`
- `ssl_context.options |= ssl.OP_NO_TICKET` (cold-start enforcement)
- Mosquitto started manually as Administrator with `mosquitto_tls.conf` before TLS trials

### Baseline B — LAID

```
ecc_client.py ──── Custom TCP (port 9001) ────► ecc_server.py
                   [3-message ECC handshake]     [auth only; closes after Msg3]
      │
      │ (client derives K_enc, K_mac from ECDH shared secret)
      │
      │ paho-mqtt (port 1883, anonymous)
      │ payload = nonce_gcm(12) || AES-GCM(K_enc, plaintext) || tag(16)
      ▼
Mosquitto broker (Windows service, port 1883)
```

- `ecc_server.py` launched by benchmark runner via `subprocess.Popen`
- Benchmark runner polls port 9001 with `socket.connect_ex` until bind confirmed
- After Msg3 is sent and verified, `ecc_server.py` closes its socket and the client proceeds independently to MQTT
- The authentication server does not relay or publish MQTT traffic

### Proposed — Hybrid ECC-LCG

```
hybrid_client.py ── Custom TCP (port 9002) ──► hybrid_server.py
                    [3-message Hybrid handshake] [auth only; closes after Msg3]
      │
      │ (client derives K_enc, K_mac from ECDH shared secret)
      │
      │ paho-mqtt (port 1883, anonymous)
      │ payload = nonce_gcm(12) || AES-GCM(K_enc, plaintext) || tag(16)
      ▼
Mosquitto broker (Windows service, port 1883)
```

- `hybrid_server.py` launched by benchmark runner via `subprocess.Popen`
- Same port-poll readiness check as LAID
- After Msg3 is sent and verified, `hybrid_server.py` closes its socket and the client proceeds independently to MQTT
- The authentication server does not relay or publish MQTT traffic

### Process Model

All server processes are separate OS processes (not threads). The benchmark runner (`benchmarks/run_benchmark.py`) is the sole orchestrator. It never imports server code directly. Servers are started with `subprocess.Popen`, waited on for readiness, and terminated with `.terminate()` + `.wait()` after all trials for that protocol complete.

---

## 7. Timing Methodology

### Wall-Clock Timing

`time.perf_counter_ns()` is called at every phase boundary on the **client** process:

| Timestamp column | Capture point |
|-----------------|---------------|
| `t_handshake_start_ns` | Immediately before Msg1 is sent (socket.sendall) |
| `t_handshake_end_ns` | Immediately after Msg3 ACK is received (for custom) or after `client.connect()` returns (TLS) |
| `t_mqtt_connect_start_ns` | Immediately before `client.connect()` call to Mosquitto |
| `t_connected_ns` | Inside `on_connect` callback, captured via `threading.Event` |
| `t_publish_start_ns` | Immediately before `client.publish()` call |
| `t_publish_done_ns` | Inside `on_publish` callback, captured via `threading.Event` |

All timestamps are stored as raw `int` values (nanoseconds). No arithmetic is performed during trials.

### CPU Time

`time.process_time_ns()` is called once at trial start (`cpu_time_start_ns`) and once at trial end (`cpu_time_end_ns`) on the client process. CPU time for the server process is NOT captured (would require IPC); this is noted as a limitation.

### Derived Metrics (Analysis Script Only)

```
handshake_ms      = (t_handshake_end_ns   - t_handshake_start_ns)  / 1_000_000
publish_ms        = (t_publish_done_ns    - t_publish_start_ns)    / 1_000_000
total_ms          = (t_publish_done_ns    - t_handshake_start_ns)  / 1_000_000
cpu_time_s        = (cpu_time_end_ns      - cpu_time_start_ns)     / 1_000_000_000
```

These are computed only in `analysis/analyze_results.py`.

### Timestamp for CSV Metadata

Trial wall-clock timestamps are recorded using `datetime.now(timezone.utc).isoformat()` (not `datetime.utcnow()`, which is deprecated in Python 3.12).

---

## 8. Byte Measurement Methodology

### Primary Method — tshark pcap Capture

For each trial, `scripts/pcap_capture.py` starts a tshark subprocess to capture on the loopback interface, filtered to the relevant port(s), writing to a per-trial `.pcap` file in `results/pcaps/`. After the trial completes, tshark is terminated and the pcap is parsed to sum `frame.len` for outbound and inbound frames separately.

**Interface detection:**

```
tshark -D
```

Output is parsed to find the loopback interface name (typically `\Device\NPF_Loopback` on Windows with Npcap, or `lo` index). If Npcap loopback capture fails, the benchmark will log `bytes_tx_pcap = "NOT MEASURED"` and `bytes_rx_pcap = "NOT MEASURED"` and continue. This is a known Windows limitation.

**Capture filter examples:**

- LAID: `tcp port 9001 or tcp port 1883`
- Hybrid: `tcp port 9002 or tcp port 1883`
- TLS: `tcp port 8883`

**Pcap path** is recorded in the `pcap_path` CSV column for reproducibility.

### Secondary Method — ByteCountingSocket

For the two custom-TCP protocols (LAID, Hybrid), `scripts/socket_utils.py` wraps the raw socket in a `ByteCountingSocket` class that increments `bytes_sent` and `bytes_received` counters on every `send`/`recv` call. These counters are recorded in `bytes_tx_socket` and `bytes_rx_socket`. They capture application-layer bytes only (no TCP/IP headers).

### Sanity Check

After each protocol's full trial set, `analysis/analyze_results.py` computes the mean difference between `bytes_tx_pcap` and `bytes_tx_socket` (the delta should approximate TCP/IP header overhead × number of segments). Large unexplained discrepancies are flagged as warnings in the analysis output.

---

## 9. Energy Proxy Methodology (Honest)

### Formula

```
cpu_time_s                      = (cpu_time_end_ns - cpu_time_start_ns) / 1_000_000_000
estimated_energy_mj_esp32_proxy = cpu_time_s × 3.3 × 0.040 × 1000
```

Where:
- `3.3` V = ESP32 operating voltage
- `0.040` A = ESP32 active-mode current at 240 MHz (typical)
- `× 1000` = Joules to millijoules conversion

**Source:** Espressif Systems, *ESP32 Technical Reference Manual* and *ESP32 Datasheet*, active-mode current specification at 240 MHz CPU clock. [Espressif ESP32 Datasheet, Rev. 4.1, Table 12, Idd (active) typical = 40 mA at 240 MHz]

### Assumptions and Limitations

This formula applies CPU time measured on the Windows Python client process to an ESP32 power model. This is a **proxy**, not a measurement. The assumptions are:

1. The same logical operations would run on an ESP32 at proportional CPU time (order-preserving assumption)
2. The ESP32 draws constant 40 mA during active computation (datasheet typical, not min or max)
3. Python overhead and OS scheduling on Windows do not invert the relative ranking among protocols

This metric is always labeled **"estimated (ESP32 model)"** in all tables, figures, and text. It is used only for order-of-magnitude comparison and directional insight.

### Column

CSV column name: `estimated_energy_mj_esp32_proxy` (computed only in `analysis/analyze_results.py`, never written during trials)

---

## 10. Cold-Start Enforcement

Each trial enforces a fully cold start with no state reuse:

| Mechanism | Implementation |
|-----------|---------------|
| Fresh server process | `subprocess.Popen` per trial (for custom protocols) OR server restarts between trials |
| Fresh TCP connection | New `socket.socket()` per trial; no connection pooling |
| Fresh ephemeral keys | `ec.generate_private_key()` (LAID) or `ec.derive_private_key(lcg_scalar)` (Hybrid) called per trial inside client code |
| Fresh nonces | `os.urandom(16)` or `lcg.next_bytes(16)` called per trial |
| Fresh LCG seed | New `os.urandom(8)` drawn per trial for Hybrid; LCG object created fresh per trial |
| TLS session tickets disabled | `ssl_context.options \|= ssl.OP_NO_TICKET` on client SSLContext |
| Fresh SSLContext per trial | New `ssl.SSLContext` object created per trial to prevent session resumption |
| Warmup trials | trial_id in [0, 9] inclusive (first 10 trials per combination); discarded in analysis via `trial_id >= 10` filter; 490 analysis trials per (protocol, payload_size) combination remain |
| Trial count | 500 trials per (protocol, payload_size) combination (trial_id 0–499); 9 combinations total |
| Inter-trial sleep | `time.sleep(0.100)` (100 ms) between consecutive trials within the same (protocol, payload_size) combination |
| Inter-protocol sleep | `time.sleep(5.000)` (5000 ms) between protocol transitions (i.e., between combinations) to allow Windows TIME_WAIT states to clear and server ports to be fully released |
| Payload bytes | Fixed random bytes per payload size, generated once at startup from `PAYLOAD_SEED`; reused across all 500 trials for that size; fresh `os.urandom(12)` GCM nonce drawn per trial |

For the custom-TCP protocols, the benchmark runner starts the server process before trial 0 of each combination and terminates it after all 500 trials for that combination complete. The server accepts one connection per trial and closes it after Msg3, enforcing fresh TCP state per trial.

---

## 11. CSV Schema (Exact Columns, One Row Per Trial, Raw Values Only)

File: `results/benchmark_results.csv`

| Column | Type | Description |
|--------|------|-------------|
| `trial_id` | int | Zero-indexed trial number within (protocol, payload_size) combination (0–499); 0–9 = warmup |
| `protocol` | str | One of: `tls`, `laid`, `hybrid` |
| `payload_size_bytes` | int | Plaintext payload size for this trial: one of `30`, `256`, `1024` |
| `timestamp_iso` | str | ISO 8601 UTC timestamp at trial start (`datetime.now(timezone.utc).isoformat()`) |
| `hardware_tag` | str | Static string identifying the test machine (e.g., `win11-loopback-py312`) |
| `t_handshake_start_ns` | int | `perf_counter_ns()` before first handshake message sent |
| `t_handshake_end_ns` | int | `perf_counter_ns()` after handshake complete |
| `t_mqtt_connect_start_ns` | int | `perf_counter_ns()` before MQTT connect call to Mosquitto |
| `t_connected_ns` | int | `perf_counter_ns()` inside `on_connect` callback |
| `t_publish_start_ns` | int | `perf_counter_ns()` before publish call |
| `t_publish_done_ns` | int | `perf_counter_ns()` inside `on_publish` callback |
| `cpu_time_start_ns` | int | `process_time_ns()` at trial start |
| `cpu_time_end_ns` | int | `process_time_ns()` at trial end |
| `bytes_tx_pcap` | int or `NOT MEASURED` | Total outbound bytes from pcap (frame.len sum); `NOT MEASURED` if tshark unavailable |
| `bytes_rx_pcap` | int or `NOT MEASURED` | Total inbound bytes from pcap (frame.len sum); `NOT MEASURED` if tshark unavailable |
| `bytes_tx_socket` | int or `NOT MEASURED` | Outbound bytes from ByteCountingSocket (LAID/Hybrid only; `NOT MEASURED` for TLS) |
| `bytes_rx_socket` | int or `NOT MEASURED` | Inbound bytes from ByteCountingSocket (LAID/Hybrid only; `NOT MEASURED` for TLS) |
| `tls_cipher_suite` | str or `N/A` | TLS cipher suite string for TLS trials; `N/A` for LAID and Hybrid |
| `success` | bool | `True` if trial completed without error |
| `error_msg` | str or empty | Exception message if `success == False`; empty string otherwise |
| `pcap_path` | str or `NOT MEASURED` | Relative path to per-trial pcap file, e.g., `results/pcaps/tls_30_trial_0042.pcap`; `NOT MEASURED` if tshark unavailable |

**Column ordering in the CSV header is fixed** as shown above. The `payload_size_bytes` column is the third column (after `trial_id` and `protocol`), allowing downstream tools to group by `(protocol, payload_size_bytes)` without post-hoc joins.

**Invariant:** No arithmetic or derived metrics are written during trials. Analysis script reads this CSV, filters `trial_id >= 10`, groups by `(protocol, payload_size_bytes)`, and produces a separate `results/analysis_results.csv` with derived columns.

---

## 12. Security Argument Plan (Informal, for Paper Section)

This section outlines the informal security argument to be developed in the paper. No formal proof is in scope.

### Attacks Enumerated and Defenses

| Attack | Defense in LAID Baseline | Defense in Hybrid | Citation |
|--------|--------------------------|-------------------|----------|
| **MITM (Man-in-the-Middle)** | ECDH: shared secret not derivable without private key; MAC_s and MAC_c bind the full transcript (both public keys and nonces) | Same; LCG scalar still yields a valid ECDH keypair; attacker cannot forge the MAC without knowing the shared secret | Khalique et al. 2025, §IV; Alghamdi 2025, §III |
| **Replay** | 16-byte fresh nonce (`n_c`, `n_s`) per session; both nonces are bound into the MAC over the full transcript | Same nonces in MAC; nonces are LCG-derived, changing every session with a new `os.urandom(8)` seed | Kaganurmath et al. 2025, §III; Khalique et al. 2025, §IV-B |
| **Impersonation** | Mutual MAC verification: client verifies MAC_s before sending MAC_c; server verifies MAC_c; both MACs depend on the ECDH-derived K_mac | Same mutual MAC structure with K_mac derived from ECDH over LCG-based scalar | Khalique et al. 2025, §IV-C |
| **Desynchronization** | Stateless handshake: no persistent session counter or state carried across sessions; fresh keys and nonces per session | Same stateless design | Khalique et al. 2025, §IV-D |
| **LCG scalar prediction** | N/A (LAID uses `generate_private_key`) | Requires predicting `os.urandom(8)` seed (2^64 space); the LCG itself does not need to be cryptographically secure because its seed is | Kaganurmath et al. 2025, LCG security discussion |
| **Forward secrecy** | Fresh ECDH key pair generated per session via `generate_private_key()`; compromise of one session key does not expose others | Identical forward secrecy property: fresh ECDH key pair generated per session from a new `os.urandom(8)` seed; both LAID and Hybrid provide equivalent per-session forward secrecy | Khalique et al. 2025, §IV; Kaganurmath et al. 2025 |

### Out of Scope for Security Section

- Formal verification (ProVerif, AVISPA, Tamarin Prover)
- Physical attacks (fault injection, power analysis)
- Side-channel attacks on the LCG or ECC implementation
- Quantum adversary models (SECP256R1 is not post-quantum)

---

## 13. Directory Layout

All files relative to project root: `D:\Spring 2026\Internet of Things\IOT class Project\`

```
ARCHITECTURE.md                  ← This document
README.md                        ← Setup and run instructions (to be written)

certs/                           ← TLS certificates (already populated)
    ca.crt
    server.crt
    server.key
    client.crt
    client.key

baseline_tls/
    tls_client.py                ← paho-mqtt TLS client; runs one trial, writes one CSV row to stdout

baseline_ecc/
    ecc_server.py                ← Custom TCP auth server on port 9001; LAID 3-message handshake;
                                    closes connection after Msg3; does NOT publish to MQTT
    ecc_client.py                ← LAID client; connects to ecc_server.py for handshake; derives K_enc
                                    and K_mac; then independently publishes AES-GCM payload to Mosquitto
                                    port 1883; records timestamps; writes one CSV row to stdout

hybrid_protocol/
    hybrid_server.py             ← Custom TCP auth server on port 9002; Hybrid LCG+ECC handshake;
                                    closes connection after Msg3; does NOT publish to MQTT
    hybrid_client.py             ← Hybrid client; LCG scalar derivation; connects to hybrid_server.py
                                    for handshake; derives K_enc and K_mac; then independently publishes
                                    AES-GCM payload to Mosquitto port 1883; records timestamps; writes
                                    one CSV row to stdout

scripts/
    csv_schema.py                ← Defines CSV column names as a constant list; imported by all trial scripts
    socket_utils.py              ← ByteCountingSocket wrapper class; length-prefixed send/recv helpers
    pcap_capture.py              ← tshark subprocess manager; interface detection; pcap parse to byte sums
    aead_wrapper.py              ← AES-256-GCM encrypt/decrypt helpers; wire format: nonce(12)||ct||tag(16)
    lcg.py                       ← LCG class with Numerical Recipes constants; next_bytes(n) method
    kdf.py                       ← HKDF-SHA256 wrapper; two-key derivation (K_enc, K_mac) with
                                    protocol-specific info labels

benchmarks/
    single_trial.py              ← Runs exactly one trial for one protocol; accepts protocol name +
                                    trial_id as argv; prints one CSV row to stdout
    run_benchmark.py             ← Orchestrator; launches server subprocesses; loops trials; sleeps 100ms
                                    between trials; sleeps 5000ms between protocols; writes
                                    results/benchmark_results.csv

analysis/
    analyze_results.py           ← Reads benchmark_results.csv; filters trial_id >= 10; computes derived
                                    metrics; outputs analysis_results.csv and figures

results/                         ← Created at runtime; gitignored for large pcaps
    benchmark_results.csv        ← Raw trial data (one row per trial, all protocols)
    analysis_results.csv         ← Derived metrics (one row per trial, warmup excluded)
    pcaps/                       ← Per-trial pcap files (named: {protocol}_trial_{trial_id:04d}.pcap)
    figures/                     ← PNG plots generated by analyze_results.py

logs/
    errors.log                   ← Errors from all processes; format: ISO timestamp | protocol |
                                    trial_id | error message
```

### Files Explicitly Not in Scope

- No `conftest.py` or pytest fixtures (unit tests may be added later but are not in scope for this phase)
- No Docker, virtual env, or requirements.txt management (environment already set up per project spec)
- No Cooja/NS-3 scripts (future work)
- No ProVerif models (out of scope)

---

## 14. Known Limitations

1. **Loopback only.** All measurements are on a single Windows 11 machine using the loopback interface (127.0.0.1). Network propagation delay, packet loss, and radio-layer overhead are not present. Results represent computation cost, not end-to-end IoT network cost.

2. **Single machine.** Server and client run on the same physical machine, sharing CPU, cache, and memory. On a real IoT deployment, client and server are separate devices with different hardware constraints.

3. **Python interpreter overhead.** Python 3.12 with GIL, interpreter dispatch, and garbage collection adds latency not present in embedded C/Rust implementations. Absolute latency values are not representative of production IoT devices. Relative comparisons among the three protocols are meaningful only if Python overhead is assumed to affect all three equally.

4. **Energy is estimated, not measured.** The `estimated_energy_mj_esp32_proxy` column applies CPU time from a Windows Python process to an ESP32 power model. This is a directional proxy only. Real embedded device power measurement requires physical hardware and a current monitor.

5. **Client CPU time only.** `time.process_time_ns()` captures client-side CPU time. Server-side CPU time is not captured and is excluded from energy estimates. This underestimates total system energy and is consistent across all three protocols (the MQTT broker CPU cost is also excluded).

6. **No formal security proof.** The security argument in Section 12 is informal. No model checker was used. Claims about attack resistance are based on structural properties of the protocols and citations to the constituent papers.

7. **Windows Npcap loopback capture and tshark fallback.** tshark loopback capture on Windows requires Npcap with loopback adapter support. At benchmark startup, `scripts/pcap_capture.py` runs `tshark -D` to detect the loopback interface. If tshark is missing from PATH or no Npcap loopback adapter is found, a **single warning is logged** to `logs/errors.log` and to stderr at startup. The benchmark then continues without pcap capture for the entire run — it does **not** retry tshark on a per-trial basis. Affected trials will have `bytes_tx_pcap = NOT MEASURED`, `bytes_rx_pcap = NOT MEASURED`, and `pcap_path = NOT MEASURED`. For LAID and Hybrid, ByteCountingSocket counters (`bytes_tx_socket`, `bytes_rx_socket`) continue to function regardless of tshark status and provide application-layer byte counts for the custom-TCP handshake. For TLS, if tshark is unavailable, **no byte measurement is available at all** for that protocol; this limitation is disclosed in the paper's methodology section.

8. **LCG is not a CSPRNG.** The LCG scalar derivation is fast but statistically weaker than `os.urandom`. This is a design choice documented in Section 4 and is not treated as a security claim about the LCG output alone.

9. **No radio-layer simulation.** Cooja or NS-3 simulation of multi-hop IoT networks is noted as future work and is not in scope for this study.

10. **Single MQTT message per trial.** Each trial publishes exactly one fixed-size payload. Throughput and behavior under multiple messages or subscriptions are not studied.

---

## 15. Fairness Arguments (Preemptive)

### TLS Payload Encryption vs. LAID/Hybrid

TLS provides confidentiality and integrity via its record layer automatically. To ensure all three protocols offer equivalent security guarantees for the MQTT application payload, LAID and Hybrid both encrypt the payload with AES-256-GCM under K_enc before the client publishes to Mosquitto on port 1883. The wire format is `nonce_gcm(12) || ciphertext || tag(16)`. All three protocols therefore provide authenticated encryption of the application payload. TLS gets its AEAD from the TLS record layer; LAID and Hybrid get it from explicit AES-GCM wrapping with a handshake-derived key. The comparison is fair in terms of security functionality.

### Python vs. C/Embedded

All three protocols are implemented in Python 3.12 on the same machine using the same interpreter. Python's overhead (GIL, dynamic dispatch, garbage collection) is constant across all three protocols in this study. Absolute latency values are higher than they would be on an embedded C implementation, but the relative ordering among protocols is preserved, because the same interpreter overhead applies to each. The paper explicitly acknowledges this limitation (Section 14, item 3) and frames results as relative comparisons, not absolute performance claims for IoT devices.

### Loopback vs. Radio-Layer Network

All trials use the loopback interface (127.0.0.1). Loopback eliminates propagation delay, packet loss, and radio-layer overhead, which are the dominant costs in real IoT deployments. This study intentionally isolates **computation cost** (handshake crypto, key derivation, AES-GCM) from network cost. Loopback measurements can be combined with radio-layer simulation results (Cooja, NS-3) in future work to produce end-to-end estimates. This choice is a scope limitation, not a methodological flaw, and is disclosed upfront.

### LCG Not a CSPRNG

The hybrid protocol uses an LCG to derive the ECC scalar, which is faster but statistically weaker than `os.urandom`. This is documented in Section 4 with explicit citation to the DLKS-MQTT paper's design rationale. The paper's claim is not that "LCG is secure in isolation" but that "LCG as a fast expansion layer seeded by `os.urandom`, combined with ECDH mutual authentication, provides equivalent authentication security at lower computational cost." The security root is `os.urandom` + ECDH, not the LCG. The LCG seed (8 bytes, `os.urandom`) occupies a 2^64 space; the seed is never transmitted; recovering the scalar from the transmitted public key Q requires solving ECDLP.

---

*End of ARCHITECTURE.md*
