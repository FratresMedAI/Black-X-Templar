# DISABLED_FOR_GRAY_SWAN_CONTEST
"""
osint_expert.py — OSINT vulnerability-feed correlator.

Pulls recent CVEs from the NVD 2.0 REST API (no key required),
stores them in audit_log.db, and cross-references with recent
threat_log entries to surface relevant defensive context.

Safe to run standalone:  python osint_expert.py
"""

import argparse
import json
import sqlite3
import time
from datetime import datetime, timedelta, timezone

import requests

import config


# ── DB ────────────────────────────────────────────────────────────────────────

def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = _get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS vuln_log (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id          TEXT UNIQUE,
            description     TEXT,
            severity        TEXT,
            cvss_score      REAL,
            published_at    TEXT,
            last_seen       DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS vuln_correlation (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       DATETIME DEFAULT CURRENT_TIMESTAMP,
            cve_id          TEXT,
            threat_log_id   INTEGER,
            note            TEXT
        );
    """)
    conn.commit()
    conn.close()


# ── NVD fetch ─────────────────────────────────────────────────────────────────

def fetch_recent_cves(days_back: int = 1, max_results: int = 50,
                     offline_only: bool = False) -> list[dict]:
    """Return recent CVEs from the NVD 2.0 API."""
    if offline_only:
        print("[OSINT] Offline-only mode active — skipping NVD network fetch.")
        return []

    now = datetime.now(timezone.utc)
    start = now - timedelta(days=days_back)

    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": max_results,
        "startIndex": 0,
    }
    try:
        resp = requests.get(config.NVD_FEEDS_URL, params=params, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        return data.get("vulnerabilities", [])
    except requests.exceptions.ConnectionError:
        print("[OSINT] Network error: cannot reach NVD API.")
    except requests.exceptions.Timeout:
        print("[OSINT] NVD API request timed out.")
    except requests.exceptions.HTTPError as e:
        print(f"[OSINT] NVD HTTP error: {e}")
    except Exception as e:
        print(f"[OSINT] Unexpected error: {e}")
    return []


def _parse_cve(vuln: dict) -> dict | None:
    try:
        cve = vuln["cve"]
        cve_id = cve["id"]
        published = cve.get("published", "")

        descs = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in descs if d.get("lang") == "en"), ""
        )

        metrics = cve.get("metrics", {})
        cvss_score: float = 0.0
        severity: str = "UNKNOWN"

        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                m = metrics[key][0]
                cvss_data = m.get("cvssData", {})
                cvss_score = float(cvss_data.get("baseScore", 0))
                severity = cvss_data.get("baseSeverity",
                                         m.get("baseSeverity", "UNKNOWN"))
                break

        return {
            "cve_id": cve_id,
            "description": description[:800],
            "severity": severity,
            "cvss_score": cvss_score,
            "published_at": published,
        }
    except Exception as e:
        print(f"[OSINT] Parse error: {e}")
        return None


# ── Storage & correlation ──────────────────────────────────────────────────────

def upsert_cve(record: dict):
    conn = _get_conn()
    conn.execute("""
        INSERT INTO vuln_log (cve_id, description, severity, cvss_score, published_at)
        VALUES (:cve_id, :description, :severity, :cvss_score, :published_at)
        ON CONFLICT(cve_id) DO UPDATE SET
            last_seen = CURRENT_TIMESTAMP,
            severity  = excluded.severity,
            cvss_score = excluded.cvss_score
    """, record)
    conn.commit()
    conn.close()


def correlate_with_threats(cve_id: str, description: str):
    """Cross-reference CVE keywords with recent threat_log entries."""
    keywords = [w for w in description.lower().split() if len(w) > 5][:10]
    if not keywords:
        return

    conn = _get_conn()
    for kw in keywords:
        rows = conn.execute(
            "SELECT id FROM threat_log WHERE lower(description) LIKE ? "
            "ORDER BY timestamp DESC LIMIT 5",
            (f"%{kw}%",),
        ).fetchall()
        for row in rows:
            conn.execute(
                "INSERT OR IGNORE INTO vuln_correlation (cve_id, threat_log_id, note) "
                "VALUES (?, ?, ?)",
                (cve_id, row["id"], f"keyword match: {kw}"),
            )
    conn.commit()
    conn.close()


# ── Main loop ─────────────────────────────────────────────────────────────────

def run_once(days_back: int = 1, verbose: bool = False,
             offline_only: bool = False) -> int:
    init_db()
    vulns = fetch_recent_cves(days_back=days_back, offline_only=offline_only)
    if not vulns:
        print("[OSINT] No CVEs fetched (API unavailable or no recent entries).")
        return 0

    saved = 0
    for v in vulns:
        record = _parse_cve(v)
        if record:
            upsert_cve(record)
            correlate_with_threats(record["cve_id"], record["description"])
            saved += 1
            if verbose:
                print(f"  [{record['severity']:8}] {record['cve_id']}  cvss={record['cvss_score']}  {record['description'][:60]}")

    print(f"[OSINT] Stored/updated {saved} CVEs. Correlations written to vuln_correlation table.")
    return saved


def run_loop(interval_seconds: int = 1800, days_back: int = 1,
             offline_only: bool = False):
    print(f"[OSINT] Starting continuous loop — refresh every {interval_seconds}s.")
    while True:
        run_once(days_back=days_back, offline_only=offline_only)
        time.sleep(interval_seconds)


if __name__ == "__main__":
    pass
