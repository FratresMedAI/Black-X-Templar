import sqlite3
import sys
import os
from pathlib import Path

sys.path.insert(0, ".")
os.environ.setdefault("DARKSPACE_HMAC_SECRET", "0123456789abcdef0123456789abcdef")

# ── Gap 1: Kinetic Hooks ────────────────────────────────────────────────────
from kinetic_hooks import _init_db, run_once, _quarantine_session, _force_reauth
_init_db()
q = _quarantine_session('10.0.0.1', 'test reason', dry_run=True)
assert 'DRY-RUN' in q, f"quarantine dry-run failed: {q}"
r = _force_reauth('10.0.0.1', dry_run=True)
assert 'DRY-RUN' in r, f"reauth dry-run failed: {r}"

import config
ok, errors = config.validate_security_baseline()
assert ok, f"security baseline validation failed: {errors}"
print("security_baseline : OK")

conn = sqlite3.connect(config.DB_PATH)
conn.execute("""CREATE TABLE IF NOT EXISTS threat_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    source_ip TEXT, threat_type TEXT, description TEXT,
    risk_score REAL DEFAULT 0, hmac_sig TEXT)""")
conn.execute(
    "INSERT INTO threat_log (source_ip, threat_type, description, risk_score) "
    "VALUES ('1.2.3.4','TEST','kinetic smoke test',9.5)"
)
conn.commit()
conn.close()
count = run_once(dry_run=True)
assert count >= 1, f"kinetic run_once returned {count}"
print(f"kinetic_hooks     : OK  ({count} threat(s) dry-run actioned)")

# Ensure dry-run does not mutate quarantine / reauth tables.
conn = sqlite3.connect(config.DB_PATH)
q_count = conn.execute("SELECT COUNT(*) FROM session_quarantine").fetchone()[0]
r_count = conn.execute("SELECT COUNT(*) FROM reauth_challenges").fetchone()[0]
conn.close()
assert q_count == 0, f"dry-run should not quarantine sessions, got {q_count} rows"
assert r_count == 0, f"dry-run should not issue reauth challenges, got {r_count} rows"
print("kinetic_dry_run   : OK")

# ── Gap 2: P2P attestation ──────────────────────────────────────────────────
from p2p_mesh import _sign, _verify, _attest_claim, _verify_attest, _node_id
claim = _attest_claim(nonce='smoke-nonce')
assert _verify_attest(dict(claim)), "attestation verify failed"
node_id = _node_id()
assert node_id.startswith('spiffe://darkspace/node/'), f"bad node_id: {node_id}"
print(f"p2p_mesh attest   : OK  node={node_id}")

# ── Gap 3: Calibrate ────────────────────────────────────────────────────────
from calibrate import run as calibrate_run, _BUILTIN_CORPUS
result = calibrate_run(_BUILTIN_CORPUS, apply=False, verbose=False)
assert 'entropy' in result and 'drift' in result
assert 0 < result['entropy']['threshold'] < 6.0, f"bad entropy threshold: {result['entropy']}"
assert 0 < result['drift']['threshold'] < 1.0, f"bad drift threshold: {result['drift']}"
print(f"calibrate         : OK  entropy={result['entropy']['threshold']}  drift={result['drift']['threshold']}")

# ── Gap 4: Offline IOC cache ────────────────────────────────────────────────
conn = sqlite3.connect(config.DB_PATH)
conn.execute(
    """
    CREATE TABLE IF NOT EXISTS ioc_cache (
        id                INTEGER PRIMARY KEY AUTOINCREMENT,
        cached_at         DATETIME DEFAULT CURRENT_TIMESTAMP,
        ioc               TEXT,
        ioc_type          TEXT,
        threat_type       TEXT,
        malware_printable TEXT,
        confidence_level  INTEGER,
        reporter          TEXT,
        raw_json          TEXT
    )
    """
)
conn.execute("DELETE FROM ioc_cache")
conn.execute(
    "INSERT INTO ioc_cache "
    "(ioc, ioc_type, threat_type, malware_printable, confidence_level, reporter, raw_json) "
    "VALUES (?, ?, ?, ?, ?, ?, ?)",
    ("evil.example.com", "domain", "botnet_cc", "Emotet", 90, "smoke_test", "{}"),
)
ioc_row = conn.execute("SELECT ioc, cached_at FROM ioc_cache ORDER BY cached_at DESC LIMIT 1").fetchone()
assert ioc_row is not None, "cache read returned empty"
assert ioc_row[0] == "evil.example.com", f"wrong ioc: {ioc_row[0]}"
print(f"ioc_cache         : OK  cached_at={ioc_row[1]}")

conn.execute(
    """
    CREATE TABLE IF NOT EXISTS security_metrics (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp       DATETIME DEFAULT CURRENT_TIMESTAMP,
        metric_name     TEXT NOT NULL,
        metric_value    REAL NOT NULL,
        metric_unit     TEXT,
        module          TEXT,
        correlation_id  TEXT,
        metadata_json   TEXT
    )
    """
)
conn.execute(
    "INSERT INTO security_metrics "
    "(metric_name, metric_value, metric_unit, module, correlation_id, metadata_json) "
    "VALUES (?, ?, ?, ?, ?, ?)",
    ("smoke_detection_latency", 12.5, "ms", "smoke", "smoke-ci", "{}"),
)
metric_count = conn.execute("SELECT COUNT(*) FROM security_metrics").fetchone()[0]
conn.commit()
conn.close()
assert metric_count >= 1, "security_metrics should contain at least one record"
print("security_metrics  : OK")

# ── Gap 5: Neural Mirror expanded corpus ───────────────────────────────────
from whisper_detector import _init_db as _init_whisper_db
_init_whisper_db()
from neural_mirror import _SAMPLES, run_simulation
cats = {s['category'] for s in _SAMPLES}
required_cats = {
    'jailbreak_advanced', 'prompt_injection_indirect',
    'exfiltration_covert', 'supply_chain', 'mcp_abuse', 'adversarial_reasoning',
}
missing = required_cats - cats
assert not missing, f"missing categories: {missing}"
assert len(_SAMPLES) >= 40, f"corpus too small: {len(_SAMPLES)}"
results = run_simulation(limit=len(_SAMPLES))
correct = sum(1 for r in results if r['correct'])
pct = 100 * correct // len(results)
missed = [r for r in results if not r['correct']]
print(f"neural_mirror     : OK  {len(_SAMPLES)} samples  {correct}/{len(results)} correct ({pct}%)")
if missed:
    for r in missed:
        print(f"  MISSED [{r['id']}] {r['category']}  expected={r['expected']}  got={r['verdict']}")

# ── Compliance checks (STIG-like lightweight gates) ──────────────────────────
root = Path(__file__).resolve().parent
python_files = [p for p in root.glob("*.py") if p.is_file() and p.name != "_smoke_v2.py"]

secret_markers = [
    "AKIA",
    "BEGIN RSA PRIVATE KEY",
    "BEGIN PRIVATE KEY",
    "xoxb-",
]
bad_hits: list[str] = []

for py in python_files:
    text = py.read_text(encoding="utf-8", errors="ignore")
    for marker in secret_markers:
        if marker in text:
            bad_hits.append(f"{py.name}: marker={marker}")

assert not bad_hits, f"hardcoded secret markers detected: {bad_hits}"
print("secret_scan       : OK")

enforcer_text = (root / "enforcer.py").read_text(encoding="utf-8", errors="ignore")
kinetic_text = (root / "kinetic_hooks.py").read_text(encoding="utf-8", errors="ignore")
assert "hmac.new(config.HMAC_SECRET" in enforcer_text, "enforcer missing HMAC signing path"
assert "config.HMAC_SECRET + body" in kinetic_text, "kinetic escalation missing HMAC signature"
print("hmac_usage        : OK")

print()
print("=== DARKSPACE regression + compliance smoke suite passed ===")
