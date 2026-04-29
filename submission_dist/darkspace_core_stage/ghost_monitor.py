"""
ghost_monitor.py — Encrypted-traffic fingerprinting (passive, read-only).

Analyses packet TIMING and LENGTH distributions from a pcap file or
psutil network-counter snapshots to surface token-streaming behaviour.
No payload decryption, no traffic modification, no TCP resets.

Usage:
    python ghost_monitor.py               # live counter sampling (no root needed)
    python ghost_monitor.py --pcap FILE   # analyse an existing .pcap file
"""

import argparse
import json
import math
import sqlite3
import time
from collections import deque
from datetime import datetime

import psutil

import config


# ── DB ────────────────────────────────────────────────────────────────────────

def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _init_db():
    conn = _get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS ghost_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP,
            iface       TEXT,
            metric      TEXT,
            value       REAL,
            flag        TEXT
        );
    """)
    conn.commit()
    conn.close()


def _log_event(iface: str, metric: str, value: float, flag: str = "normal"):
    conn = _get_conn()
    conn.execute(
        "INSERT INTO ghost_log (iface, metric, value, flag) VALUES (?, ?, ?, ?)",
        (iface, metric, value, flag),
    )
    conn.commit()
    conn.close()


# ── Statistical helpers ───────────────────────────────────────────────────────

def _mean(xs: list[float]) -> float:
    return sum(xs) / len(xs) if xs else 0.0


def _stddev(xs: list[float]) -> float:
    if len(xs) < 2:
        return 0.0
    m = _mean(xs)
    variance = sum((x - m) ** 2 for x in xs) / (len(xs) - 1)
    return math.sqrt(variance)


def _coefficient_of_variation(xs: list[float]) -> float:
    m = _mean(xs)
    return _stddev(xs) / m if m > 0 else 0.0


# ── Token-stream fingerprint heuristics ──────────────────────────────────────
# LLM token-streaming produces many small (~20-200 byte) bursts at
# regular short intervals (~50-300 ms). We flag windows where:
#   • mean inter-arrival time (IAT) < 400 ms
#   • coefficient of variation of IAT < 0.6  (regularity)
#   • mean packet-size is small (< 512 bytes)

_IAT_THRESHOLD_MS = 400.0
_SIZE_THRESHOLD_BYTES = 512.0
_CV_THRESHOLD = 0.60


def _is_streaming_pattern(
    iats_ms: list[float], sizes: list[float]
) -> tuple[bool, str]:
    if len(iats_ms) < 4:
        return False, "insufficient samples"
    mean_iat = _mean(iats_ms)
    cv_iat = _coefficient_of_variation(iats_ms)
    mean_size = _mean(sizes)
    if mean_iat < _IAT_THRESHOLD_MS and cv_iat < _CV_THRESHOLD and mean_size < _SIZE_THRESHOLD_BYTES:
        return True, (
            f"mean_iat={mean_iat:.1f}ms  cv={cv_iat:.3f}  "
            f"mean_size={mean_size:.0f}B"
        )
    return False, (
        f"mean_iat={mean_iat:.1f}ms  cv={cv_iat:.3f}  mean_size={mean_size:.0f}B"
    )


# ── Live counter mode (uses psutil, no root required) ─────────────────────────

def _live_sample(iface: str | None, window: int, interval_s: float):
    """
    Sample psutil net_io_counters every `interval_s` seconds.
    Build a rolling window of byte-delta sizes and pseudo-IATs.
    """
    _init_db()
    print(f"[GHOST] Live sampling  iface={iface or 'all'}  "
          f"interval={interval_s}s  window={window} samples")
    print("[GHOST] Passive mode — no traffic is modified.\n")

    history: deque[tuple[float, float]] = deque(maxlen=window)  # (timestamp, bytes_sent)
    try:
        while True:
            counters = psutil.net_io_counters(pernic=bool(iface))
            if iface:
                stats = counters.get(iface)
                if stats is None:
                    print(f"[GHOST] Interface '{iface}' not found. Available: "
                          f"{list(counters.keys())}")
                    time.sleep(interval_s)
                    continue
                sent = float(stats.bytes_sent)
            else:
                stats = psutil.net_io_counters()
                sent = float(stats.bytes_sent)

            now = time.monotonic()
            history.append((now, sent))

            if len(history) >= 4:
                times = [h[0] for h in history]
                iats_ms = [(times[i] - times[i - 1]) * 1000.0 for i in range(1, len(times))]
                sizes = [abs(history[i][1] - history[i - 1][1]) for i in range(1, len(history))]
                suspicious, detail = _is_streaming_pattern(iats_ms, sizes)
                flag = "streaming_suspect" if suspicious else "normal"
                _log_event(iface or "all", "live_sample", _mean(sizes), flag)
                ts = datetime.utcnow().strftime("%H:%M:%S")
                marker = " ⚠ STREAMING PATTERN" if suspicious else ""
                print(f"  [{ts}] {detail}{marker}")
                if suspicious:
                    print(f"    [GHOST] ALERT logged to ghost_log table.")

            time.sleep(interval_s)

    except KeyboardInterrupt:
        print("\n[GHOST] Stopped.")


# ── PCAP mode ─────────────────────────────────────────────────────────────────

def _analyse_pcap(pcap_path: str):
    """Analyse a pcap using scapy if available; otherwise print a warning."""
    try:
        from scapy.all import rdpcap, IP, TCP  # optional dependency
    except ImportError:
        print("[GHOST] scapy not installed. Install it with: pip install scapy")
        print("[GHOST] Falling back to live sampling mode instead.")
        _live_sample(None, window=30, interval_s=1.0)
        return

    _init_db()
    print(f"[GHOST] Reading pcap: {pcap_path}")
    try:
        pkts = rdpcap(pcap_path)
    except FileNotFoundError:
        print(f"[GHOST] File not found: {pcap_path}")
        return

    records: list[tuple[float, int]] = []  # (timestamp, pkt_len)
    for pkt in pkts:
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            records.append((float(pkt.time), len(pkt)))

    if len(records) < 4:
        print(f"[GHOST] Only {len(records)} TCP packets — not enough to analyse.")
        return

    records.sort(key=lambda r: r[0])
    iats_ms = [(records[i][0] - records[i - 1][0]) * 1000 for i in range(1, len(records))]
    sizes = [float(r[1]) for r in records[1:]]

    suspicious, detail = _is_streaming_pattern(iats_ms, sizes)
    flag = "streaming_suspect" if suspicious else "normal"
    _log_event(pcap_path, "pcap_analysis", _mean(sizes), flag)

    print(f"  Packets  : {len(records)}")
    print(f"  Analysis : {detail}")
    print(f"  Verdict  : {'STREAMING PATTERN DETECTED' if suspicious else 'Normal'}")


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="DARKSPACE Ghost Monitor — passive traffic fingerprinting"
    )
    parser.add_argument("--pcap", metavar="FILE",
                        help="Analyse a .pcap file instead of live sampling")
    parser.add_argument("--iface", metavar="NAME",
                        help="Network interface for live mode (default: all)")
    parser.add_argument("--interval", type=float, default=1.0,
                        help="Sampling interval in seconds (default: 1.0)")
    parser.add_argument("--window", type=int, default=30,
                        help="Rolling window size in samples (default: 30)")
    args = parser.parse_args()

    if args.pcap:
        _analyse_pcap(args.pcap)
    else:
        _live_sample(args.iface, window=args.window, interval_s=args.interval)
