import subprocess
import sys
from pathlib import Path

import pandas as pd
import pytest

from scripts.csv_schema import COLUMNS, NOT_MEASURED


def _make_synthetic_csv(path, n_per_combo=15):
    import random
    random.seed(42)
    rows = []
    for protocol in ["tls", "laid", "hybrid"]:
        for payload in [30, 256]:
            for trial_id in range(n_per_combo):
                base = trial_id * 1_000_000_000
                row = {col: "" for col in COLUMNS}
                row.update({
                    "trial_id": trial_id,
                    "protocol": protocol,
                    "payload_size_bytes": payload,
                    "timestamp_iso": "2026-01-01T00:00:00+00:00",
                    "hardware_tag": "test",
                    "t_handshake_start_ns": base + 100,
                    "t_handshake_end_ns": base + 5_000_000 + random.randint(0, 1_000_000),
                    "t_mqtt_connect_start_ns": base + 5_100_000,
                    "t_connected_ns": base + 30_000_000,
                    "t_publish_start_ns": base + 30_100_000,
                    "t_publish_done_ns": base + 31_000_000,
                    "cpu_time_start_ns": 0,
                    "cpu_time_end_ns": 15_625_000 if trial_id % 2 == 0 else 0,
                    "bytes_tx_pcap": NOT_MEASURED,
                    "bytes_rx_pcap": NOT_MEASURED,
                    "bytes_tx_socket": 121 if protocol != "tls" else NOT_MEASURED,
                    "bytes_rx_socket": 117 if protocol != "tls" else NOT_MEASURED,
                    "tls_cipher_suite": "TLS_AES_256_GCM_SHA384" if protocol == "tls" else "N/A",
                    "success": "True",
                    "error_msg": "",
                    "pcap_path": NOT_MEASURED,
                })
                rows.append(row)
    df = pd.DataFrame(rows, columns=COLUMNS)
    df.to_csv(path, index=False)


def test_analysis_produces_outputs(tmp_path):
    csv_in = tmp_path / "fake.csv"
    out_dir = tmp_path / "out"
    _make_synthetic_csv(csv_in)
    r = subprocess.run(
        [
            sys.executable, "-m", "analysis.analyze_results",
            "--input", str(csv_in),
            "--output-dir", str(out_dir),
            "--warmup", "10",
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert r.returncode == 0, f"stderr: {r.stderr}"
    assert (out_dir / "analysis_results.csv").exists()
    assert (out_dir / "summary_table.csv").exists()
    assert (out_dir / "summary_table.md").exists()
    assert (out_dir / "statistical_tests.csv").exists()
    assert (out_dir / "figures" / "handshake_latency_bar.png").exists()
    assert (out_dir / "figures" / "bytes_on_wire_bar.png").exists()
    assert (out_dir / "figures" / "latency_box_plot.png").exists()
    assert (out_dir / "figures" / "cpu_time_distribution.png").exists()


def test_warmup_filter(tmp_path):
    csv_in = tmp_path / "fake.csv"
    out_dir = tmp_path / "out"
    _make_synthetic_csv(csv_in, n_per_combo=20)
    subprocess.run(
        [
            sys.executable, "-m", "analysis.analyze_results",
            "--input", str(csv_in),
            "--output-dir", str(out_dir),
            "--warmup", "10",
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )
    df = pd.read_csv(out_dir / "analysis_results.csv")
    assert len(df) == 60


def test_statistical_tests_run(tmp_path):
    csv_in = tmp_path / "fake.csv"
    out_dir = tmp_path / "out"
    _make_synthetic_csv(csv_in)
    subprocess.run(
        [
            sys.executable, "-m", "analysis.analyze_results",
            "--input", str(csv_in),
            "--output-dir", str(out_dir),
            "--warmup", "10",
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )
    stats = pd.read_csv(out_dir / "statistical_tests.csv")
    assert "p_value" in stats.columns
    assert "cohens_d" in stats.columns
    assert "comparison" in stats.columns
    assert len(stats) == 2 * 2
