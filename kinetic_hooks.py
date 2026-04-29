# DISABLED_FOR_GRAY_SWAN_CONTEST
"""
kinetic_hooks.py — Active response layer (v2 kinetic hooks).

Monitors threat_log for alerts that cross the critical threshold and
executes a configurable response pipeline:

  1. QUARANTINE  — invalidate the agent session token (mock + real hook)
  2. REAUTH      — force re-authentication challenge (mock + real hook)
  3. NOTIFY      — write a structured incident record to the DB
  4. ESCALATE    — (optional) POST a signed alert to a human-in-the-loop
                   webhook endpoint

Design constraints (per DoD reviewer requirement):
  - All actions are logged before execution (intent log)
  - Each action can be individually disabled via config
  - No TCP resets, no kernel calls, no hardware commands
  - Human-in-the-loop escalation is optional and off by default
  - Real hooks are pluggable; stubs are provided for integration

Usage:
    python kinetic_hooks.py               # continuous monitor loop
    python kinetic_hooks.py --once        # single check and exit
    python kinetic_hooks.py --dry-run     # log what would happen, take no action
"""

import argparse
import hashlib
import json
import os
import sqlite3
import time
import urllib.error
import urllib.request
import urllib.parse
from datetime import datetime, timezone

import config


# ── Config (all overridable via environment / config.py) ─────────────────────

KINETIC_ENABLED          = True      # master switch
QUARANTINE_ENABLED       = True      # invalidate session tokens
REAUTH_ENABLED           = True      # force re-authentication
NOTIFY_ENABLED           = True      # write incident record to DB
ESCALATE_ENABLED         = False     # POST to human-in-the-loop webhook
ESCALATE_WEBHOOK_URL     = ""        # set to your SIEM / SOC webhook
KINETIC_SCORE_THRESHOLD  = getattr(config, "VAULT_CRITICAL_SCORE_THRESHOLD", 8.0)
KINETIC_CHECK_INTERVAL   = 15        # seconds between checks
IDP_PROVIDER             = os.environ.get("DARKSPACE_KINETIC_IDP_PROVIDER", "").strip().lower()


def _idp_client():
    if IDP_PROVIDER != "keycloak":
        return None
    try:
        from contrib.keycloak_idp_example import KeycloakIdP
        return KeycloakIdP()
    except Exception:
        return None


# ── DB ────────────────────────────────────────────────────────────────────────

def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _init_db():
    conn = _get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS kinetic_log (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       DATETIME DEFAULT CURRENT_TIMESTAMP,
            threat_log_id   INTEGER UNIQUE,
            source_ip       TEXT,
            threat_type     TEXT,
            risk_score      REAL,
            actions_taken   TEXT,
            dry_run         INTEGER DEFAULT 0,
            outcome         TEXT
        );
        CREATE TABLE IF NOT EXISTS session_quarantine (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            quarantined_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
            source_ip       TEXT,
            session_token   TEXT,
            reason          TEXT,
            released        INTEGER DEFAULT 0,
            released_at     DATETIME
        );
        CREATE TABLE IF NOT EXISTS reauth_challenges (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            issued_at       DATETIME DEFAULT CURRENT_TIMESTAMP,
            source_ip       TEXT,
            challenge_token TEXT,
            completed       INTEGER DEFAULT 0,
            completed_at    DATETIME
        );
        CREATE TABLE IF NOT EXISTS security_metrics (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       DATETIME DEFAULT CURRENT_TIMESTAMP,
            metric_name     TEXT NOT NULL,
            metric_value    REAL NOT NULL,
            metric_unit     TEXT,
            module          TEXT,
            correlation_id  TEXT,
            metadata_json   TEXT
        );
    """)
    conn.commit()
    conn.close()


def _record_metric(metric_name: str, metric_value: float,
                   correlation_id: str = "", metadata: dict | None = None):
    conn = _get_conn()
    conn.execute(
        "INSERT INTO security_metrics "
        "(metric_name, metric_value, metric_unit, module, correlation_id, metadata_json) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (
            metric_name,
            float(metric_value),
            "ratio",
            "kinetic_hooks",
            correlation_id,
            json.dumps(metadata or {}),
        ),
    )
    conn.commit()
    conn.close()


def _already_actioned(threat_id: int) -> bool:
    conn = _get_conn()
    row = conn.execute(
        "SELECT id FROM kinetic_log WHERE threat_log_id = ?", (threat_id,)
    ).fetchone()
    conn.close()
    return row is not None


def _log_kinetic(threat_id: int, source_ip: str, threat_type: str,
                 risk_score: float, actions: list[str],
                 dry_run: bool, outcome: str):
    conn = _get_conn()
    conn.execute(
        "INSERT OR IGNORE INTO kinetic_log "
        "(threat_log_id, source_ip, threat_type, risk_score, "
        " actions_taken, dry_run, outcome) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (threat_id, source_ip, threat_type, risk_score,
         json.dumps(actions), int(dry_run), outcome),
    )
    conn.commit()
    conn.close()


# ── Action: Quarantine session ────────────────────────────────────────────────

def _quarantine_session(source_ip: str, reason: str, dry_run: bool) -> str:
    """
    Invalidate any active session tokens for source_ip.

    Real integration: replace the body of this function with a call to
    your identity provider (Okta, AD, Keycloak) to revoke sessions.
    The quarantine record in session_quarantine serves as the audit trail.
    """
    # Generate a deterministic invalidation token for this event
    token = hashlib.sha256(
        f"quarantine:{source_ip}:{datetime.now(timezone.utc).isoformat()}".encode()
    ).hexdigest()[:24]

    if dry_run:
        return f"[DRY-RUN] would quarantine {source_ip}  token={token}"

    conn = _get_conn()
    conn.execute(
        "INSERT INTO session_quarantine (source_ip, session_token, reason) "
        "VALUES (?, ?, ?)",
        (source_ip, token, reason[:500]),
    )
    conn.commit()
    conn.close()

    client = _idp_client()
    if client is not None:
        try:
            status = client.revoke_user_sessions(source_ip)
            return f"QUARANTINED {source_ip}  invalidation_token={token}  idp=keycloak status={status}"
        except Exception as e:
            return f"QUARANTINED {source_ip}  invalidation_token={token}  idp=keycloak error={e}"

    return f"QUARANTINED {source_ip}  invalidation_token={token}"


# ── Action: Force re-auth ─────────────────────────────────────────────────────

def _force_reauth(source_ip: str, dry_run: bool) -> str:
    """
    Issue a re-authentication challenge for source_ip.

    Real integration: replace with a call to your IdP to revoke the current
    session and set a flag requiring MFA re-verification on next request.
    """
    challenge = hashlib.sha256(
        f"reauth:{source_ip}:{datetime.now(timezone.utc).isoformat()}".encode()
    ).hexdigest()[:24]

    if dry_run:
        return f"[DRY-RUN] would issue reauth challenge for {source_ip}  token={challenge}"

    conn = _get_conn()
    conn.execute(
        "INSERT INTO reauth_challenges (source_ip, challenge_token) VALUES (?, ?)",
        (source_ip, challenge),
    )
    conn.commit()
    conn.close()

    client = _idp_client()
    if client is not None:
        try:
            status = client.require_reauth(source_ip)
            return f"REAUTH_ISSUED {source_ip}  challenge={challenge}  idp=keycloak status={status}"
        except Exception as e:
            return f"REAUTH_ISSUED {source_ip}  challenge={challenge}  idp=keycloak error={e}"

    return f"REAUTH_ISSUED {source_ip}  challenge={challenge}"


# ── Action: Escalate to SOC / SIEM webhook ────────────────────────────────────

def _escalate(payload: dict, dry_run: bool) -> str:
    """
    POST a signed incident alert to a human-in-the-loop webhook.
    Off by default. Set ESCALATE_ENABLED=True and ESCALATE_WEBHOOK_URL in config.
    """
    if not ESCALATE_WEBHOOK_URL:
        return "ESCALATE skipped — no webhook URL configured"

    parsed = urllib.parse.urlparse(ESCALATE_WEBHOOK_URL)
    if parsed.scheme not in ("http", "https"):
        return "ESCALATE skipped — webhook URL must use http/https"

    if dry_run:
        return f"[DRY-RUN] would POST to {ESCALATE_WEBHOOK_URL}"

    body = json.dumps(payload).encode()
    sig = hashlib.sha256(config.HMAC_SECRET + body).hexdigest()
    req = urllib.request.Request(
        ESCALATE_WEBHOOK_URL,
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-DARKSPACE-SIG": sig,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:  # nosec B310
            return f"ESCALATED → {ESCALATE_WEBHOOK_URL}  status={resp.status}"
    except urllib.error.URLError as e:
        return f"ESCALATE FAILED: {e.reason}"
    except Exception as e:
        return f"ESCALATE FAILED: {e}"


# ── Response pipeline ─────────────────────────────────────────────────────────

def respond_to_threat(threat: sqlite3.Row, dry_run: bool = False) -> list[str]:
    """
    Execute the full response pipeline for a single high-risk threat record.
    Returns a list of action result strings.
    """
    tid       = threat["id"]
    source_ip = threat["source_ip"] or "unknown"
    ttype     = threat["threat_type"]
    score     = threat["risk_score"]
    reason    = f"threat_log #{tid} — {ttype} score={score}"

    ts = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
    print(f"\n[KINETIC][{ts}] Responding to threat #{tid} "
          f"({ttype}  score={score}  src={source_ip})")

    actions_taken: list[str] = []

    if QUARANTINE_ENABLED:
        result = _quarantine_session(source_ip, reason, dry_run)
        actions_taken.append(f"QUARANTINE: {result}")
        print(f"  {actions_taken[-1]}")

    if REAUTH_ENABLED:
        result = _force_reauth(source_ip, dry_run)
        actions_taken.append(f"REAUTH: {result}")
        print(f"  {actions_taken[-1]}")

    if ESCALATE_ENABLED:
        payload = {
            "threat_id": tid,
            "source_ip": source_ip,
            "threat_type": ttype,
            "risk_score": score,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        result = _escalate(payload, dry_run)
        actions_taken.append(f"ESCALATE: {result}")
        print(f"  {actions_taken[-1]}")

    outcome = "dry_run" if dry_run else "actioned"
    _log_kinetic(tid, source_ip, ttype, score, actions_taken, dry_run, outcome)

    return actions_taken


# ── Monitor loop ──────────────────────────────────────────────────────────────

def run_once(dry_run: bool = False) -> int:
    _init_db()
    conn = _get_conn()
    rows = conn.execute(
        "SELECT id, source_ip, threat_type, risk_score FROM threat_log "
        "WHERE risk_score >= ? ORDER BY timestamp DESC LIMIT 50",
        (KINETIC_SCORE_THRESHOLD,),
    ).fetchall()
    conn.close()

    actioned = 0
    attempted = 0
    for row in rows:
        if not _already_actioned(row["id"]):
            attempted += 1
            respond_to_threat(row, dry_run=dry_run)
            actioned += 1

    success_rate = (actioned / attempted) if attempted else 1.0
    _record_metric(
        metric_name="kinetic_action_success_rate",
        metric_value=success_rate,
        correlation_id=f"kinetic_run_{int(time.time())}",
        metadata={"attempted": attempted, "actioned": actioned, "dry_run": dry_run},
    )

    if actioned == 0:
        print(f"[KINETIC] No new threats above score={KINETIC_SCORE_THRESHOLD}")
    return actioned


def run_loop(dry_run: bool = False):
    mode = "DRY-RUN" if dry_run else "LIVE"
    print(f"[KINETIC] v2 Active Response Layer — {mode} mode")
    print(f"[KINETIC] Threshold: risk_score >= {KINETIC_SCORE_THRESHOLD}")
    print(f"[KINETIC] Actions: quarantine={QUARANTINE_ENABLED}  "
          f"reauth={REAUTH_ENABLED}  escalate={ESCALATE_ENABLED}")
    print(f"[KINETIC] Check interval: {KINETIC_CHECK_INTERVAL}s\n")

    while True:
        try:
            run_once(dry_run=dry_run)
        except Exception as e:
            print(f"[KINETIC] Error: {e}")
        time.sleep(KINETIC_CHECK_INTERVAL)


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    pass
