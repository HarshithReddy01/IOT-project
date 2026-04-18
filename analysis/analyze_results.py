from __future__ import annotations
import argparse
import logging
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from scipy.stats import wilcoxon

from scripts.csv_schema import read_results

ESP32_VOLTAGE = 3.3
ESP32_CURRENT = 0.040

COLORS = {"tls": "#888888", "laid": "#1f77b4", "hybrid": "#ff7f0e"}


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=str, default="results/benchmark_results.csv")
    parser.add_argument("--output-dir", type=str, default="results/analysis")
    parser.add_argument("--warmup", type=int, default=10)
    return parser.parse_args()


def build_summary_table(df: pd.DataFrame) -> pd.DataFrame:
    def agg(g):
        tx_socket = pd.to_numeric(g["bytes_tx_socket"], errors="coerce")
        rx_socket = pd.to_numeric(g["bytes_rx_socket"], errors="coerce")
        tx_pcap = pd.to_numeric(g["bytes_tx_pcap"], errors="coerce")
        rx_pcap = pd.to_numeric(g["bytes_rx_pcap"], errors="coerce")
        return pd.Series({
            "n_trials": len(g),
            "handshake_mean_ms": g["handshake_ms"].mean(),
            "handshake_median_ms": g["handshake_ms"].median(),
            "handshake_p95_ms": g["handshake_ms"].quantile(0.95),
            "handshake_std_ms": g["handshake_ms"].std(),
            "mqtt_connect_mean_ms": g["mqtt_connect_ms"].mean(),
            "publish_mean_ms": g["publish_ms"].mean(),
            "total_mean_ms": g["total_ms"].mean(),
            "cpu_mean_ms": g["cpu_ms"].mean(),
            "cpu_coverage_pct": 100.0 * (g["cpu_delta_ns"] > 0).mean(),
            "energy_mean_mj_esp32": g["estimated_energy_mj_esp32"].mean(),
            "bytes_tx_socket_mean": tx_socket.mean() if tx_socket.notna().any() else float("nan"),
            "bytes_rx_socket_mean": rx_socket.mean() if rx_socket.notna().any() else float("nan"),
            "bytes_tx_pcap_mean": tx_pcap.mean() if tx_pcap.notna().any() else float("nan"),
            "bytes_rx_pcap_mean": rx_pcap.mean() if rx_pcap.notna().any() else float("nan"),
        })
    return df.groupby(["protocol", "payload_size_bytes"]).apply(agg)


def save_markdown_summary(summary: pd.DataFrame, path: Path) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write("# Benchmark Summary\n\n")
        f.write(
            "Mean values per (protocol, payload_size). N=490 per group "
            "after warmup filter.\n\n"
        )
        f.write(
            "> **Energy column**: estimated (ESP32 model) — "
            "cpu_time_s × 3.3 V × 0.040 A × 1000. "
            "Not measured on real hardware.\n\n"
        )
        f.write(summary.round(3).to_markdown())
        f.write("\n")


def plot_handshake_bar(df: pd.DataFrame, path: Path) -> None:
    protocols = ["tls", "laid", "hybrid"]
    payloads = sorted(df["payload_size_bytes"].unique())

    fig, ax = plt.subplots(figsize=(7, 4.5))
    width = 0.25
    x = np.arange(len(payloads))

    for i, proto in enumerate(protocols):
        means, ci95 = [], []
        for p in payloads:
            data = df[(df["protocol"] == proto) & (df["payload_size_bytes"] == p)]["handshake_ms"]
            means.append(data.mean())
            ci95.append(1.96 * data.sem())
        label = proto.upper() if proto == "tls" else proto.capitalize()
        ax.bar(
            x + (i - 1) * width, means, width, yerr=ci95,
            label=label, color=COLORS[proto], capsize=4,
            edgecolor="black", linewidth=0.5,
        )

    ax.set_xticks(x)
    ax.set_xticklabels([f"{p} B" for p in payloads])
    ax.set_xlabel("Payload size")
    ax.set_ylabel("Handshake latency (ms)")
    ax.set_title("Mean handshake latency with 95% CI (n=490)")
    ax.legend()
    ax.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    plt.savefig(path, dpi=300, bbox_inches="tight")
    plt.close()


def plot_bytes_bar(df: pd.DataFrame, path: Path) -> None:
    protocols = ["laid", "hybrid"]
    payloads = sorted(df["payload_size_bytes"].unique())

    fig, ax = plt.subplots(figsize=(7, 4.5))
    width = 0.35
    x = np.arange(len(payloads))

    for i, proto in enumerate(protocols):
        means_tx = []
        for p in payloads:
            data = pd.to_numeric(
                df[(df["protocol"] == proto) & (df["payload_size_bytes"] == p)]["bytes_tx_socket"],
                errors="coerce",
            )
            means_tx.append(data.mean() if data.notna().any() else 0)
        ax.bar(
            x + (i - 0.5) * width, means_tx, width,
            label=proto.capitalize(), color=COLORS[proto],
            edgecolor="black", linewidth=0.5,
        )

    ax.set_xticks(x)
    ax.set_xticklabels([f"{p} B" for p in payloads])
    ax.set_xlabel("Payload size")
    ax.set_ylabel("Application-layer bytes transmitted (handshake)")
    ax.set_title("LAID vs Hybrid handshake byte cost\n(TLS bytes not measured — paho owns socket)")
    ax.legend()
    ax.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    plt.savefig(path, dpi=300, bbox_inches="tight")
    plt.close()


def plot_latency_box(df: pd.DataFrame, path: Path) -> None:
    fig, ax = plt.subplots(figsize=(9, 5))

    labels = []
    data = []
    for payload in sorted(df["payload_size_bytes"].unique()):
        for proto in ["tls", "laid", "hybrid"]:
            vals = df[
                (df["protocol"] == proto) & (df["payload_size_bytes"] == payload)
            ]["handshake_ms"]
            data.append(vals.values)
            labels.append(f"{proto}\n{payload}B")

    bp = ax.boxplot(data, labels=labels, patch_artist=True, showfliers=True)

    for i, patch in enumerate(bp["boxes"]):
        proto = ["tls", "laid", "hybrid"][i % 3]
        patch.set_facecolor(COLORS[proto])
        patch.set_alpha(0.7)

    ax.set_ylabel("Handshake latency (ms)")
    ax.set_title("Handshake latency distribution by protocol and payload")
    ax.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    plt.savefig(path, dpi=300, bbox_inches="tight")
    plt.close()


def plot_cpu_dist(df: pd.DataFrame, path: Path) -> None:
    fig, axes = plt.subplots(1, 3, figsize=(12, 4), sharey=True)

    for ax, proto in zip(axes, ["tls", "laid", "hybrid"]):
        vals_ms = df[df["protocol"] == proto]["cpu_ms"].values
        ax.hist(vals_ms, bins=30, color=COLORS[proto], edgecolor="black", linewidth=0.5)
        ax.set_title(proto.upper() if proto == "tls" else proto.capitalize())
        ax.set_xlabel("CPU time per trial (ms)")
        ax.grid(axis="y", alpha=0.3)

    axes[0].set_ylabel("Number of trials")
    fig.suptitle("CPU time distribution (Windows scheduler tick visible at ~15.6ms)")
    plt.tight_layout()
    plt.savefig(path, dpi=300, bbox_inches="tight")
    plt.close()


def run_stats(df: pd.DataFrame) -> pd.DataFrame:
    rows = []
    payloads = sorted(df["payload_size_bytes"].unique())

    for payload in payloads:
        for target in ["tls", "laid"]:
            hyb = (
                df[(df["protocol"] == "hybrid") & (df["payload_size_bytes"] == payload)]
                .sort_values("trial_id")["handshake_ms"]
                .values
            )
            oth = (
                df[(df["protocol"] == target) & (df["payload_size_bytes"] == payload)]
                .sort_values("trial_id")["handshake_ms"]
                .values
            )
            n = min(len(hyb), len(oth))
            h, o = hyb[:n], oth[:n]

            try:
                w, p = wilcoxon(h, o)
            except ValueError:
                w, p = float("nan"), float("nan")

            pooled_var = (h.var() + o.var()) / 2
            pooled_std = np.sqrt(pooled_var) if pooled_var > 0 else float("nan")
            d = (h.mean() - o.mean()) / pooled_std if not np.isnan(pooled_std) else float("nan")

            rows.append({
                "payload_size_bytes": payload,
                "comparison": f"hybrid_vs_{target}",
                "n": n,
                "hybrid_mean_ms": h.mean(),
                "other_mean_ms": o.mean(),
                "difference_ms": h.mean() - o.mean(),
                "wilcoxon_W": w,
                "p_value": p,
                "cohens_d": d,
                "significant_at_0.05": bool(p < 0.05) if not np.isnan(p) else False,
            })

    return pd.DataFrame(rows)


def print_findings(summary: pd.DataFrame, stats: pd.DataFrame) -> None:
    print()
    print("=" * 70)
    print("KEY FINDINGS")
    print("=" * 70)

    payloads = sorted(set(summary.index.get_level_values("payload_size_bytes")))
    for payload in payloads:
        print(f"\nPayload = {payload} bytes:")
        for proto in ["tls", "laid", "hybrid"]:
            try:
                row = summary.loc[(proto, payload)]
                print(
                    f"  {proto:6s}: handshake={row['handshake_mean_ms']:6.2f} ms "
                    f"(±{row['handshake_std_ms']:5.2f}), "
                    f"cpu={row['cpu_mean_ms']:5.2f} ms "
                    f"(coverage={row['cpu_coverage_pct']:.1f}%), "
                    f"energy={row['energy_mean_mj_esp32']:6.4f} mJ [estimated ESP32]"
                )
            except KeyError:
                pass

    print()
    print("=" * 70)
    print("STATISTICAL SIGNIFICANCE (Wilcoxon signed-rank, paired by trial_id)")
    print("=" * 70)
    for _, row in stats.iterrows():
        if np.isnan(row["p_value"]):
            sig = "n/a"
        elif row["p_value"] < 0.001:
            sig = "***"
        elif row["p_value"] < 0.01:
            sig = "**"
        elif row["p_value"] < 0.05:
            sig = "*"
        else:
            sig = "n.s."
        print(
            f"  payload={int(row['payload_size_bytes']):4d}B  "
            f"{row['comparison']:20s}  "
            f"diff={row['difference_ms']:+7.2f}ms  "
            f"p={row['p_value']:.4g}  d={row['cohens_d']:+.3f}  {sig}"
        )


def main() -> None:
    args = parse_args()
    out = Path(args.output_dir)
    (out / "figures").mkdir(parents=True, exist_ok=True)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    logger = logging.getLogger(__name__)

    df = read_results(Path(args.input))
    logger.info("Raw rows: %d", len(df))
    n_failures = (~df["success"].astype(bool)).sum()
    logger.info("Failures: %d", n_failures)

    df = df[df["success"].astype(bool) & (df["trial_id"] >= args.warmup)].copy()
    logger.info(
        "Analysis rows after filter (warmup=%d, success=True): %d",
        args.warmup, len(df),
    )

    df["handshake_ms"] = (df["t_handshake_end_ns"] - df["t_handshake_start_ns"]) / 1e6
    df["publish_ms"] = (df["t_publish_done_ns"] - df["t_publish_start_ns"]) / 1e6
    df["total_ms"] = (df["t_publish_done_ns"] - df["t_handshake_start_ns"]) / 1e6
    df["mqtt_connect_ms"] = (df["t_connected_ns"] - df["t_mqtt_connect_start_ns"]) / 1e6
    df["cpu_delta_ns"] = df["cpu_time_end_ns"] - df["cpu_time_start_ns"]
    df["cpu_ms"] = df["cpu_delta_ns"] / 1e6
    df["estimated_energy_mj_esp32"] = (
        df["cpu_delta_ns"] * 1e-9 * ESP32_VOLTAGE * ESP32_CURRENT * 1000
    )

    df.to_csv(out / "analysis_results.csv", index=False)
    logger.info("Wrote analysis_results.csv")

    summary = build_summary_table(df)
    summary.to_csv(out / "summary_table.csv")
    logger.info("Wrote summary_table.csv")

    save_markdown_summary(summary, out / "summary_table.md")
    logger.info("Wrote summary_table.md")

    plot_handshake_bar(df, out / "figures" / "handshake_latency_bar.png")
    logger.info("Wrote handshake_latency_bar.png")

    plot_bytes_bar(df, out / "figures" / "bytes_on_wire_bar.png")
    logger.info("Wrote bytes_on_wire_bar.png")

    plot_latency_box(df, out / "figures" / "latency_box_plot.png")
    logger.info("Wrote latency_box_plot.png")

    plot_cpu_dist(df, out / "figures" / "cpu_time_distribution.png")
    logger.info("Wrote cpu_time_distribution.png")

    stats = run_stats(df)
    stats.to_csv(out / "statistical_tests.csv", index=False)
    logger.info("Wrote statistical_tests.csv")

    print_findings(summary, stats)


if __name__ == "__main__":
    main()
