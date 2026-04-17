from __future__ import annotations
import hmac as _hmac
import logging
import os
import socket
import time
import threading
from contextlib import nullcontext
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import ECDH, SECP256R1
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from scripts.aead_wrapper import AEAD
from scripts.csv_schema import NOT_MEASURED, TrialResult
from scripts.kdf import derive_keys
from scripts.pcap_capture import CaptureSession, count_pcap_bytes
from scripts.socket_utils import ByteCountingSocket, send_framed, recv_framed

logger = logging.getLogger(__name__)

_WAIT_TIMEOUT: float = 10.0
_Q_LEN = 65
_NONCE_LEN = 16
_MAC_LEN = 32


def _cpu_time_ns() -> int:
    try:
        return time.thread_time_ns()
    except (AttributeError, OSError):
        try:
            return time.process_time_ns()
        except (AttributeError, OSError):
            return 0


def run_ecc_trial(
    trial_id: int,
    payload_size_bytes: int,
    hardware_tag: str,
    auth_host: str = "127.0.0.1",
    auth_port: int = 9001,
    broker_host: str = "127.0.0.1",
    broker_port: int = 1883,
    topic: str = "iot/sensor/data",
    payload_bytes: Optional[bytes] = None,
    pcap_path: Optional[Path] = None,
    loopback_interface: Optional[str] = None,
) -> TrialResult:
    timestamp_iso = datetime.now(timezone.utc).isoformat()

    t_hs_start = t_hs_end = t_connected = 0
    t_pub_start = t_pub_done = cpu_start = cpu_end = 0

    if payload_bytes is None:
        payload_bytes = os.urandom(payload_size_bytes)

    connected_event = threading.Event()
    publish_event = threading.Event()

    capture_ctx = (
        CaptureSession(
            loopback_interface,
            f"tcp port {auth_port} or tcp port {broker_port}",
            pcap_path,
        )
        if (pcap_path is not None and loopback_interface is not None)
        else nullcontext()
    )

    try:
        cpu_start = _cpu_time_ns()
        t_hs_start = time.perf_counter_ns()

        with capture_ctx:
            raw_sock = socket.create_connection((auth_host, auth_port), timeout=_WAIT_TIMEOUT)
            bcs = ByteCountingSocket(raw_sock)

            client_key = ec.generate_private_key(SECP256R1())
            client_pub = client_key.public_key()
            q_c_bytes = client_pub.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
            n_c = os.urandom(_NONCE_LEN)

            send_framed(bcs, q_c_bytes + n_c)

            msg2 = recv_framed(bcs)
            if len(msg2) != _Q_LEN + _NONCE_LEN + _MAC_LEN:
                raise ValueError(f"Msg2 wrong length: {len(msg2)}")

            q_s_bytes = msg2[:_Q_LEN]
            n_s = msg2[_Q_LEN: _Q_LEN + _NONCE_LEN]
            mac_s_recv = msg2[_Q_LEN + _NONCE_LEN:]

            server_pub = ec.EllipticCurvePublicKey.from_encoded_point(SECP256R1(), q_s_bytes)
            shared_secret = client_key.exchange(ECDH(), server_pub)
            k_enc, k_mac = derive_keys(shared_secret, n_c, n_s, "laid")

            mac_s_expected = _hmac.new(k_mac, q_c_bytes + n_c + q_s_bytes + n_s, "sha256").digest()
            if not _hmac.compare_digest(mac_s_recv, mac_s_expected):
                raise ValueError("Server MAC verification failed")

            mac_c = _hmac.new(k_mac, q_s_bytes + n_s + q_c_bytes + n_c, "sha256").digest()
            send_framed(bcs, mac_c)

            t_hs_end = time.perf_counter_ns()

            bytes_tx_socket: int | str = bcs.bytes_tx
            bytes_rx_socket: int | str = bcs.bytes_rx
            bcs.close()

            aead = AEAD(k_enc)
            encrypted_payload = aead.encrypt(payload_bytes)

            mqtt_connected = threading.Event()
            mqtt_published = threading.Event()
            t_pub_done_holder: list[int] = [0]

            def on_connect(client, userdata, connect_flags, reason_code, properties):
                nonlocal t_connected
                t_connected = time.perf_counter_ns()
                mqtt_connected.set()

            def on_publish(client, userdata, mid, reason_code, properties):
                t_pub_done_holder[0] = time.perf_counter_ns()
                mqtt_published.set()

            client_id = f"ecc-trial-{trial_id}-{os.urandom(4).hex()}"
            c = mqtt.Client(
                callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
                client_id=client_id,
                clean_session=True,
            )
            c.on_connect = on_connect
            c.on_publish = on_publish

            t_mqtt_start = time.perf_counter_ns()
            c.connect(broker_host, broker_port, keepalive=60)
            c.loop_start()

            if not mqtt_connected.wait(timeout=_WAIT_TIMEOUT):
                raise TimeoutError(
                    f"MQTT CONNACK not received within {_WAIT_TIMEOUT}s "
                    f"(broker={broker_host}:{broker_port})"
                )

            t_pub_start = time.perf_counter_ns()
            c.publish(topic, encrypted_payload, qos=1)

            if not mqtt_published.wait(timeout=_WAIT_TIMEOUT):
                raise TimeoutError(f"MQTT PUBACK not received within {_WAIT_TIMEOUT}s")

            t_pub_done = t_pub_done_holder[0]

        cpu_end = _cpu_time_ns()

        if pcap_path is not None:
            bytes_tx_pcap, bytes_rx_pcap = count_pcap_bytes(
                pcap_path, {auth_port, broker_port}
            )
        else:
            bytes_tx_pcap: int | str = NOT_MEASURED
            bytes_rx_pcap: int | str = NOT_MEASURED

        return TrialResult(
            trial_id=trial_id,
            protocol="laid",
            payload_size_bytes=payload_size_bytes,
            timestamp_iso=timestamp_iso,
            hardware_tag=hardware_tag,
            t_handshake_start_ns=t_hs_start,
            t_handshake_end_ns=t_hs_end,
            t_mqtt_connect_start_ns=t_mqtt_start,
            t_connected_ns=t_connected,
            t_publish_start_ns=t_pub_start,
            t_publish_done_ns=t_pub_done,
            cpu_time_start_ns=cpu_start,
            cpu_time_end_ns=cpu_end,
            bytes_tx_pcap=bytes_tx_pcap,
            bytes_rx_pcap=bytes_rx_pcap,
            bytes_tx_socket=bytes_tx_socket,
            bytes_rx_socket=bytes_rx_socket,
            tls_cipher_suite="N/A",
            success=True,
            error_msg="",
            pcap_path=str(pcap_path) if pcap_path is not None else NOT_MEASURED,
        )

    except Exception as exc:
        cpu_end = _cpu_time_ns()
        logger.error("ECC trial %d failed — %s: %s", trial_id, type(exc).__name__, exc)
        raise

    finally:
        try:
            c.loop_stop()
        except Exception:
            pass
        try:
            c.disconnect()
        except Exception:
            pass
