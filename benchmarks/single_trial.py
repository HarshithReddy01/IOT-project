from __future__ import annotations
import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from baseline_ecc.ecc_client import run_ecc_trial
from baseline_tls.tls_client import run_tls_trial
from hybrid_protocol.hybrid_client import run_hybrid_trial
from scripts.csv_schema import NOT_MEASURED, TrialResult, write_row


def _failed_result(
    trial_id: int,
    protocol: str,
    payload_size_bytes: int,
    hardware_tag: str,
    exc: BaseException,
) -> TrialResult:
    ts = datetime.now(timezone.utc).isoformat()
    return TrialResult(
        trial_id=trial_id,
        protocol=protocol,
        payload_size_bytes=payload_size_bytes,
        timestamp_iso=ts,
        hardware_tag=hardware_tag,
        t_handshake_start_ns=0,
        t_handshake_end_ns=0,
        t_mqtt_connect_start_ns=0,
        t_connected_ns=0,
        t_publish_start_ns=0,
        t_publish_done_ns=0,
        cpu_time_start_ns=0,
        cpu_time_end_ns=0,
        bytes_tx_pcap=NOT_MEASURED,
        bytes_rx_pcap=NOT_MEASURED,
        bytes_tx_socket=NOT_MEASURED,
        bytes_rx_socket=NOT_MEASURED,
        tls_cipher_suite="N/A",
        success=False,
        error_msg=str(exc),
        pcap_path=NOT_MEASURED,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--protocol",
        required=True,
        choices=("tls", "laid", "hybrid"),
    )
    parser.add_argument("--trial-id", type=int, required=True)
    parser.add_argument("--payload-size", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--hardware-tag", type=str, required=True)
    parser.add_argument("--pcap-path", type=str, default=None)
    parser.add_argument("--loopback-interface", type=str, default=None)
    parser.add_argument("--auth-port", type=int, default=None)
    parser.add_argument("--broker-host", type=str, default="127.0.0.1")
    parser.add_argument("--broker-port", type=int, default=None)
    args = parser.parse_args()

    csv_path = args.output
    csv_path.parent.mkdir(parents=True, exist_ok=True)

    pcap_path = Path(args.pcap_path) if args.pcap_path else None
    loopback = args.loopback_interface
    default_broker = 8883 if args.protocol == "tls" else 1883
    broker_port = (
        args.broker_port if args.broker_port is not None else default_broker
    )

    try:
        if args.protocol == "tls":
            result = run_tls_trial(
                trial_id=args.trial_id,
                payload_size_bytes=args.payload_size,
                hardware_tag=args.hardware_tag,
                ca_cert=Path("certs/ca.crt"),
                client_cert=Path("certs/client.crt"),
                client_key=Path("certs/client.key"),
                broker_host=args.broker_host,
                broker_port=broker_port,
                pcap_path=pcap_path,
                loopback_interface=loopback,
            )
        elif args.protocol == "laid":
            auth_port = (
                args.auth_port if args.auth_port is not None else 9001
            )
            result = run_ecc_trial(
                trial_id=args.trial_id,
                payload_size_bytes=args.payload_size,
                hardware_tag=args.hardware_tag,
                auth_port=auth_port,
                broker_host=args.broker_host,
                broker_port=broker_port,
                pcap_path=pcap_path,
                loopback_interface=loopback,
            )
        else:
            auth_port = (
                args.auth_port if args.auth_port is not None else 9002
            )
            result = run_hybrid_trial(
                trial_id=args.trial_id,
                payload_size_bytes=args.payload_size,
                hardware_tag=args.hardware_tag,
                auth_port=auth_port,
                broker_host=args.broker_host,
                broker_port=broker_port,
                pcap_path=pcap_path,
                loopback_interface=loopback,
            )
        write_row(csv_path, result)
        print(
            f"[trial_id={result.trial_id} protocol={result.protocol}] OK"
        )
        sys.exit(0)
    except Exception as exc:
        fr = _failed_result(
            args.trial_id,
            args.protocol,
            args.payload_size,
            args.hardware_tag,
            exc,
        )
        if pcap_path is not None:
            fr.pcap_path = str(pcap_path)
        write_row(csv_path, fr)
        print(str(exc), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
