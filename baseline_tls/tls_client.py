from __future__ import annotations
import logging
import os
import ssl
import sys
import time
import threading
from contextlib import nullcontext
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import paho.mqtt.client as mqtt

from scripts.csv_schema import NOT_MEASURED, TrialResult
from scripts.pcap_capture import CaptureSession, count_pcap_bytes

logger = logging.getLogger(__name__)

_WAIT_TIMEOUT: float = 10.0


def _cpu_time_ns() -> int:
    try:
        return time.thread_time_ns()
    except (AttributeError, OSError):
        try:
            return _cpu_time_ns()
        except (AttributeError, OSError):
            return 0


def run_tls_trial(
    trial_id: int,
    payload_size_bytes: int,
    hardware_tag: str,
    ca_cert: Path,
    client_cert: Path,
    client_key: Path,
    broker_host: str = "127.0.0.1",
    broker_port: int = 8883,
    topic: str = "iot/sensor/data",
    payload_bytes: Optional[bytes] = None,
    pcap_path: Optional[Path] = None,
    loopback_interface: Optional[str] = None,
) -> TrialResult:
    timestamp_iso = datetime.now(timezone.utc).isoformat()

    t_hs_start = t_hs_end = t_mqtt_start = t_connected = 0
    t_pub_start = t_pub_done = cpu_start = cpu_end = 0
    cipher_suite = "UNKNOWN"

    connected_event = threading.Event()
    publish_event = threading.Event()

    if payload_bytes is None:
        payload_bytes = os.urandom(payload_size_bytes)

    # prevent ticket reuse
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.options |= ssl.OP_NO_TICKET
    ctx.load_verify_locations(str(ca_cert))
    ctx.load_cert_chain(str(client_cert), str(client_key))
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED

    client_id = f"tls-trial-{trial_id}-{os.urandom(4).hex()}"
    c = mqtt.Client(
        callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
        client_id=client_id,
        clean_session=True,
    )
    c.tls_set_context(ctx)

    def on_connect(client, userdata, connect_flags, reason_code, properties):
        nonlocal t_connected, cipher_suite
        t_connected = time.perf_counter_ns()
        try:
            sock = client.socket()
            if sock is not None and hasattr(sock, "cipher"):
                info = sock.cipher()
                if info:
                    cipher_suite = info[0]
        except (AttributeError, TypeError):
            pass
        connected_event.set()

    def on_publish(client, userdata, mid, reason_code, properties):
        nonlocal t_pub_done
        t_pub_done = time.perf_counter_ns()
        publish_event.set()

    c.on_connect = on_connect
    c.on_publish = on_publish

    capture_ctx = (
        CaptureSession(loopback_interface, f"tcp port {broker_port}", pcap_path)
        if (pcap_path is not None and loopback_interface is not None)
        else nullcontext()
    )

    try:
        cpu_start = _cpu_time_ns()
        t_hs_start = time.perf_counter_ns()
        t_mqtt_start = t_hs_start

        with capture_ctx:
            c.connect(broker_host, broker_port, keepalive=60)
            c.loop_start()

            if not connected_event.wait(timeout=_WAIT_TIMEOUT):
                raise TimeoutError(
                    f"MQTT CONNACK not received within {_WAIT_TIMEOUT}s "
                    f"(broker={broker_host}:{broker_port})"
                )
            t_hs_end = t_connected

            t_pub_start = time.perf_counter_ns()
            c.publish(topic, payload_bytes, qos=1)

            if not publish_event.wait(timeout=_WAIT_TIMEOUT):
                raise TimeoutError(f"MQTT PUBACK not received within {_WAIT_TIMEOUT}s")

        cpu_end = _cpu_time_ns()

        if pcap_path is not None:
            bytes_tx_pcap, bytes_rx_pcap = count_pcap_bytes(pcap_path, {broker_port})
        else:
            bytes_tx_pcap: int | str = NOT_MEASURED
            bytes_rx_pcap: int | str = NOT_MEASURED

        return TrialResult(
            trial_id=trial_id,
            protocol="tls",
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
            bytes_tx_socket=NOT_MEASURED,
            bytes_rx_socket=NOT_MEASURED,
            tls_cipher_suite=cipher_suite,
            success=True,
            error_msg="",
            pcap_path=str(pcap_path) if pcap_path is not None else NOT_MEASURED,
        )

    except Exception as exc:
        cpu_end = _cpu_time_ns()
        logger.error("TLS trial %d failed — %s: %s", trial_id, type(exc).__name__, exc)
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
