"""
enforcer.py — Passive MCP/tool-call signature monitor and rate-based detector.

Reads from stdin (piped log lines) or a named log file and flags:
  - MCP / tool-call shaped payloads
  - Credential/sensitive-keyword patterns
  - Bursts of >ENFORCER_RATE_THRESHOLD events within ENFORCER_RATE_WINDOW_SECONDS

All detections are written to the shared SQLite audit database.
No TCP resets, no blocking, no active probing.
"""

import argparse
import hashlib
import hmac
import json
import re
import sqlite3
import sys
import time
from collections import deque
from datetime import datetime

import config


# ── DB helpers ────────────────────────────────────────────────────────────────

def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = _get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS threat_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP,
            source_ip   TEXT,
            threat_type TEXT,
            description TEXT,
            risk_score  REAL DEFAULT 0,
            hmac_sig    TEXT
        );
    """)
    conn.commit()
    conn.close()


def _hmac_sign(data: str) -> str:
    return hmac.new(config.HMAC_SECRET, data.encode(), hashlib.sha256).hexdigest()


def log_detection(source_ip: str, threat_type: str,
                  description: str, risk_score: float = 5.0):
    payload = json.dumps({
        "source_ip": source_ip,
        "threat_type": threat_type,
        "description": description,
        "risk_score": risk_score,
        "ts": datetime.utcnow().isoformat(),
    })
    sig = _hmac_sign(payload)
    conn = _get_conn()
    conn.execute(
        "INSERT INTO threat_log (source_ip, threat_type, description, risk_score, hmac_sig) "
        "VALUES (?, ?, ?, ?, ?)",
        (source_ip, threat_type, description[:1000], risk_score, sig),
    )
    conn.commit()
    conn.close()
    print(f"[ENFORCER][{datetime.utcnow().isoformat()}] {threat_type} | {source_ip} | score={risk_score:.1f}")


# ── Pattern matching ──────────────────────────────────────────────────────────

_mcp_re = [re.compile(p, re.IGNORECASE) for p in config.MCP_SIGNATURES]
_sus_re = [re.compile(p, re.IGNORECASE) for p in config.SUSPICIOUS_SIGNATURES]


def check_line(line: str, source: str = "stdin") -> list[dict]:
    """Return list of detection dicts for a given text line."""
    detections: list[dict] = []

    for pat in _mcp_re:
        if pat.search(line):
            detections.append({
                "source": source,
                "threat_type": "MCP_TOOL_CALL",
                "description": f"Tool-call signature matched: {pat.pattern[:60]}",
                "risk_score": 6.0,
            })
            break

    for pat in _sus_re:
        if pat.search(line):
            detections.append({
                "source": source,
                "threat_type": "SUSPICIOUS_PATTERN",
                "description": f"Suspicious pattern matched: {pat.pattern[:60]}",
                "risk_score": 7.5,
            })
            break

    return detections


# ── Rate limiter ──────────────────────────────────────────────────────────────

class RateTracker:
    """Sliding-window event counter per source."""

    def __init__(self, window: int = config.ENFORCER_RATE_WINDOW_SECONDS,
                 threshold: int = config.ENFORCER_RATE_THRESHOLD):
        self.window = window
        self.threshold = threshold
        self._buckets: dict[str, deque] = {}

    def record(self, source: str) -> bool:
        """Record an event; return True if rate limit exceeded."""
        now = time.monotonic()
        if source not in self._buckets:
            self._buckets[source] = deque()
        bucket = self._buckets[source]
        bucket.append(now)
        cutoff = now - self.window
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        return len(bucket) > self.threshold


# ── Main loop ─────────────────────────────────────────────────────────────────

def run(source_file=None, verbose: bool = False):
    init_db()
    tracker = RateTracker()

    if source_file:
        stream = open(source_file, "r", encoding="utf-8", errors="ignore")
        print(f"[ENFORCER] Monitoring file: {source_file}")
    else:
        stream = sys.stdin
        print("[ENFORCER] Reading from stdin. Pipe log output here, or press Ctrl+C to stop.")

    print(f"[ENFORCER] Rate threshold: >{config.ENFORCER_RATE_THRESHOLD} events "
          f"in {config.ENFORCER_RATE_WINDOW_SECONDS}s per source")
    print("[ENFORCER] Passive mode — observation and logging only.\n")

    try:
        for raw_line in stream:
            line = raw_line.rstrip("\n")
            if not line:
                continue

            if verbose:
                print(f"  [line] {line[:120]}")

            source = "stdin"
            parts = line.split("|", 1)
            if len(parts) == 2 and re.match(r"[\d.]+", parts[0].strip()):
                source = parts[0].strip()
                line = parts[1]

            detections = check_line(line, source)

            for det in detections:
                log_detection(det["source"], det["threat_type"],
                              det["description"], det["risk_score"])

            if detections and tracker.record(source):
                log_detection(
                    source,
                    "RATE_ALERT",
                    f"More than {config.ENFORCER_RATE_THRESHOLD} flagged events "
                    f"within {config.ENFORCER_RATE_WINDOW_SECONDS}s from {source}",
                    risk_score=9.0,
                )

    except KeyboardInterrupt:
        print("\n[ENFORCER] Shutting down gracefully.")
    except FileNotFoundError:
        print(f"[ENFORCER] ERROR: File not found: {source_file}", file=sys.stderr)
        sys.exit(1)
    finally:
        if source_file and not stream.closed:
            stream.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="DARKSPACE Enforcer — passive MCP/tool-call and signature monitor"
    )
    parser.add_argument("--file", "-f", help="Log file to monitor (default: stdin)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Print every line as it is read")
    args = parser.parse_args()
    run(source_file=args.file, verbose=args.verbose)
