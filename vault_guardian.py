# DISABLED_FOR_GRAY_SWAN_CONTEST
"""
vault_guardian.py — Alert-driven mock credential-rotation workflow.

Monitors the threat_log table in audit_log.db for high-risk detections
and triggers a mock key-rotation workflow when the threshold is exceeded.

No real credentials are touched. Rotation is simulated via log entries
and printed workflow steps — a safe hook for integration with real vaults
(HashiCorp Vault, AWS Secrets Manager, etc.).

Usage:  python vault_guardian.py
"""

import argparse
import hashlib
import json
import os
import sqlite3
import time
from datetime import datetime

import config


# ── DB ────────────────────────────────────────────────────────────────────────

def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _init_db():
    conn = _get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS vault_events (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       DATETIME DEFAULT CURRENT_TIMESTAMP,
            trigger_alert   INTEGER,
            action          TEXT,
            mock_key_id     TEXT,
            result          TEXT
        );
    """)
    conn.commit()
    conn.close()


# ── Mock rotation ─────────────────────────────────────────────────────────────

def _mock_rotate_key(trigger_alert_id: int, reason: str) -> str:
    """
    Simulate a credential-rotation workflow.
    In production replace this with a real vault API call.
    Returns a mock new-key identifier.
    """
    new_key_id = "mk-" + hashlib.sha256(
        f"{trigger_alert_id}{time.time()}".encode()
    ).hexdigest()[:16]

    steps = [
        "1. Audit current key usage — MOCK",
        "2. Generate new ephemeral key material — MOCK",
        "3. Propagate to dependent services — MOCK",
        "4. Revoke old key material — MOCK",
        "5. Verify rotation complete — MOCK",
    ]
    ts = datetime.utcnow().strftime("%H:%M:%S UTC")
    print(f"\n[VAULT] ⚡ ROTATION TRIGGERED at {ts}")
    print(f"[VAULT] Reason : {reason}")
    print(f"[VAULT] Mock new key ID: {new_key_id}")
    for step in steps:
        print(f"[VAULT]   {step}")

    conn = _get_conn()
    conn.execute(
        "INSERT INTO vault_events (trigger_alert, action, mock_key_id, result) "
        "VALUES (?, ?, ?, ?)",
        (trigger_alert_id, "mock_rotate", new_key_id, "success"),
    )
    conn.commit()
    conn.close()
    return new_key_id


# ── Monitor loop ──────────────────────────────────────────────────────────────

def _already_rotated(alert_id: int) -> bool:
    conn = _get_conn()
    row = conn.execute(
        "SELECT id FROM vault_events WHERE trigger_alert = ?", (alert_id,)
    ).fetchone()
    conn.close()
    return row is not None


def run_once():
    _init_db()
    conn = _get_conn()
    rows = conn.execute(
        "SELECT id, source_ip, threat_type, risk_score FROM threat_log "
        "WHERE risk_score >= ? ORDER BY timestamp DESC LIMIT 20",
        (config.VAULT_CRITICAL_SCORE_THRESHOLD,),
    ).fetchall()
    conn.close()

    for row in rows:
        if not _already_rotated(row["id"]):
            reason = (
                f"High-risk alert #{row['id']} — "
                f"{row['threat_type']} from {row['source_ip']} "
                f"(score={row['risk_score']})"
            )
            _mock_rotate_key(row["id"], reason)


def run_loop(interval: int = config.VAULT_CHECK_INTERVAL_SECONDS):
    print(f"[VAULT] Monitoring threat_log for alerts with risk_score >= "
          f"{config.VAULT_CRITICAL_SCORE_THRESHOLD}")
    print(f"[VAULT] Check interval: {interval}s  |  Passive mock-only mode.\n")
    while True:
        try:
            run_once()
        except Exception as e:
            print(f"[VAULT] Error: {e}")
        time.sleep(interval)


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    pass
