from __future__ import annotations
import argparse
import logging
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

from scripts.csv_schema import read_results

logger = logging.getLogger(__name__)

INTER_TRIAL_SLEEP = 0.100
INTER_PROTOCOL_SLEEP = 5.000
WARMUP_TRIALS = 10

LAID_AUTH_PORT = 9001
HYBRID_AUTH_PORT = 9002
LAID_SERVER_MODULE = "baseline_ecc.ecc_server"
HYBRID_SERVER_MODULE = "hybrid_protocol.hybrid_server"


def _wait_for_port(host: str, port: int, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def _start_server(module: str, port: int) -> subprocess.Popen:
    proc = subprocess.Popen(
        [sys.executable, "-m", module, "--port", str(port)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if not _wait_for_port("127.0.0.1", port, timeout=5.0):
        proc.terminate()
        raise RuntimeError(f"Server {module} did not start within 5s on port {port}")
    logger.info("Started %s on port %d (pid=%d)", module, port, proc.pid)
    return proc


def _stop_server(proc: Optional[subprocess.Popen]) -> None:
    if proc is None:
        return
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
    except Exception:
        pass


def _check_mosquitto_alive(port: int) -> bool:
    return _wait_for_port("127.0.0.1", port, timeout=2.0)


def _completed_tuples(csv_path: Path) -> set:
    if not csv_path.exists():
        return set()
    try:
        df = read_results(csv_path)
        return set(
            (row["protocol"], int(row["payload_size_bytes"]), int(row["trial_id"]))
            for _, row in df.iterrows()
        )
    except Exception as e:
        logger.warning("Could not read existing CSV for resume: %s", e)
        return set()


def _run_single_trial_subprocess(
    protocol: str,
    trial_id: int,
    payload_size: int,
    hardware_tag: str,
    output_csv: Path,
    auth_port: Optional[int] = None,
    pcap_path: Optional[Path] = None,
    loopback_interface: Optional[str] = None,
) -> tuple[int, str]:
    cmd = [
        sys.executable, "-m", "benchmarks.single_trial",
        "--protocol", protocol,
        "--trial-id", str(trial_id),
        "--payload-size", str(payload_size),
        "--output", str(output_csv),
        "--hardware-tag", hardware_tag,
    ]
    if auth_port is not None:
        cmd += ["--auth-port", str(auth_port)]
    if pcap_path is not None:
        cmd += ["--pcap-path", str(pcap_path)]
    if loopback_interface is not None:
        cmd += ["--loopback-interface", str(loopback_interface)]

    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return r.returncode, r.stderr
    except subprocess.TimeoutExpired:
        return 1, "subprocess timeout"


def main() -> None:
    parser = argparse.ArgumentParser(description="IoT protocol benchmark orchestrator")
    parser.add_argument("--trials", type=int, default=500)
    parser.add_argument("--payload-sizes", type=str, default="30,256,1024")
    parser.add_argument("--protocols", type=str, default="tls,laid,hybrid")
    parser.add_argument("--hardware-tag", type=str,
                        default=f"{socket.gethostname()}-py312")
    parser.add_argument("--output", type=Path,
                        default=Path("results/benchmark_results.csv"))
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--pcap", action="store_true")
    parser.add_argument("--loopback-interface", type=str, default=None)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    Path("logs").mkdir(exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[
            logging.FileHandler("logs/errors.log"),
            logging.StreamHandler(sys.stdout),
        ],
    )

    payload_sizes = [int(s) for s in args.payload_sizes.split(",")]
    protocols = args.protocols.split(",")

    args.output.parent.mkdir(parents=True, exist_ok=True)

    if "laid" in protocols or "hybrid" in protocols:
        if not _check_mosquitto_alive(1883):
            logger.error("Mosquitto not reachable on 127.0.0.1:1883. Start broker first.")
            sys.exit(2)
    if "tls" in protocols:
        if not _check_mosquitto_alive(8883):
            logger.error("Mosquitto TLS not reachable on 127.0.0.1:8883. Start broker first.")
            sys.exit(2)

    total_trials = len(protocols) * len(payload_sizes) * args.trials
    logger.info(
        "Plan: %d protocols × %d payload sizes × %d trials = %d total",
        len(protocols), len(payload_sizes), args.trials, total_trials,
    )

    if args.dry_run:
        for p in protocols:
            for s in payload_sizes:
                logger.info("  %s payload=%d: trials 0..%d", p, s, args.trials - 1)
        logger.info("Dry run complete; no trials executed.")
        sys.exit(0)

    completed = _completed_tuples(args.output) if args.resume else set()
    if args.resume and completed:
        logger.info("Resume: %d trials already in output CSV", len(completed))

    pcap_dir = Path("results/pcaps")
    if args.pcap:
        pcap_dir.mkdir(parents=True, exist_ok=True)
        if args.loopback_interface is None:
            logger.error("--pcap requires --loopback-interface")
            sys.exit(2)

    laid_proc: Optional[subprocess.Popen] = None
    hybrid_proc: Optional[subprocess.Popen] = None

    start_time = time.monotonic()
    trials_run = 0
    trials_failed = 0

    try:
        for proto_idx, protocol in enumerate(protocols):
            if protocol == "laid" and laid_proc is None:
                laid_proc = _start_server(LAID_SERVER_MODULE, LAID_AUTH_PORT)
            elif protocol == "hybrid" and hybrid_proc is None:
                hybrid_proc = _start_server(HYBRID_SERVER_MODULE, HYBRID_AUTH_PORT)

            for payload_size in payload_sizes:
                logger.info(
                    "=== Running %s payload=%d (%d trials) ===",
                    protocol, payload_size, args.trials,
                )
                combo_start = time.monotonic()
                combo_trials = 0
                combo_failed = 0

                for trial_id in range(args.trials):
                    key = (protocol, payload_size, trial_id)
                    if key in completed:
                        continue

                    pcap_path = None
                    if args.pcap:
                        pcap_path = (
                            pcap_dir
                            / f"{protocol}_{payload_size}_trial_{trial_id:04d}.pcap"
                        )

                    auth_port = None
                    if protocol == "laid":
                        auth_port = LAID_AUTH_PORT
                    elif protocol == "hybrid":
                        auth_port = HYBRID_AUTH_PORT

                    rc, stderr = _run_single_trial_subprocess(
                        protocol=protocol,
                        trial_id=trial_id,
                        payload_size=payload_size,
                        hardware_tag=args.hardware_tag,
                        output_csv=args.output,
                        auth_port=auth_port,
                        pcap_path=pcap_path,
                        loopback_interface=args.loopback_interface,
                    )

                    trials_run += 1
                    combo_trials += 1
                    if rc != 0:
                        trials_failed += 1
                        combo_failed += 1
                        logger.warning(
                            "FAIL %s payload=%d trial=%d: %s",
                            protocol, payload_size, trial_id,
                            stderr.strip()[:200],
                        )

                    if combo_trials % 50 == 0:
                        elapsed = time.monotonic() - combo_start
                        rate = combo_trials / elapsed if elapsed > 0 else 0
                        logger.info(
                            "  [%s p=%d] %d/%d done, %d failed, %.1f trials/sec",
                            protocol, payload_size, combo_trials,
                            args.trials, combo_failed, rate,
                        )

                    time.sleep(INTER_TRIAL_SLEEP)

                combo_elapsed = time.monotonic() - combo_start
                logger.info(
                    ">>> %s payload=%d: %d trials in %.1fs, %d failed",
                    protocol, payload_size, combo_trials, combo_elapsed, combo_failed,
                )

            if proto_idx < len(protocols) - 1:
                logger.info(
                    "Sleeping %.1fs before next protocol (TIME_WAIT clear)",
                    INTER_PROTOCOL_SLEEP,
                )
                time.sleep(INTER_PROTOCOL_SLEEP)

        elapsed_total = time.monotonic() - start_time
        logger.info(
            "BENCHMARK COMPLETE: %d trials in %.1fs (%.2f min), %d failures",
            trials_run, elapsed_total, elapsed_total / 60, trials_failed,
        )

    except KeyboardInterrupt:
        logger.warning("Interrupted by user — shutting down gracefully")
    finally:
        _stop_server(laid_proc)
        _stop_server(hybrid_proc)
        logger.info("All servers stopped. CSV flushed: %s", args.output)


if __name__ == "__main__":
    main()
