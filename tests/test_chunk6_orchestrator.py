import subprocess
import sys

import pytest

from scripts.csv_schema import read_results


def test_orchestrator_dry_run():
    r = subprocess.run(
        [
            sys.executable, "-m", "benchmarks.run_benchmark",
            "--trials", "5",
            "--payload-sizes", "30",
            "--protocols", "tls",
            "--dry-run",
            "--output", "tests/dummy.csv",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert r.returncode == 0
    combined = r.stdout + r.stderr
    assert "Dry run complete" in combined


def test_orchestrator_small_tls_run(tmp_path):
    csv = tmp_path / "small.csv"
    r = subprocess.run(
        [
            sys.executable, "-m", "benchmarks.run_benchmark",
            "--trials", "5",
            "--payload-sizes", "30",
            "--protocols", "tls",
            "--output", str(csv),
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert r.returncode == 0, f"stderr: {r.stderr}"
    assert csv.exists()
    df = read_results(csv)
    assert len(df) == 5
    assert all(df["protocol"] == "tls")


def test_orchestrator_resume(tmp_path):
    csv = tmp_path / "resume.csv"
    subprocess.run(
        [
            sys.executable, "-m", "benchmarks.run_benchmark",
            "--trials", "3",
            "--payload-sizes", "30",
            "--protocols", "tls",
            "--output", str(csv),
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    )
    assert len(read_results(csv)) == 3

    subprocess.run(
        [
            sys.executable, "-m", "benchmarks.run_benchmark",
            "--trials", "5",
            "--payload-sizes", "30",
            "--protocols", "tls",
            "--resume",
            "--output", str(csv),
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    )
    assert len(read_results(csv)) == 5
