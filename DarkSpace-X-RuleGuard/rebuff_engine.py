"""
rebuff_engine.py — Prompt-injection shield.

Detects and sanitizes hostile instructions before they reach local models.
Evidence copies are stored in audit_log.db; message content is never altered
without logging.

Standalone demo:  python rebuff_engine.py
Imported by:      app.py (interactive tester tab)
"""

import argparse
import hashlib
import re
import sqlite3
import sys
from datetime import datetime

import config


# ── Detection rules ───────────────────────────────────────────────────────────

_INJECTION_PATTERNS: list[tuple[str, float]] = [
    # (pattern, risk_score)
    (r"ignore\s+(all\s+)?previous\s+instructions?",             9.5),
    (r"disregard\s+(all\s+)?prior\s+(instructions?|context)",   9.5),
    (r"you\s+are\s+now\s+[a-z\s]+\.\s*do\s+not",               8.5),
    # \b on DAN — otherwise "guidance" matches "dan" and blocks benign enterprise text.
    (r"(jailbreak|\bDAN\b|do\s+anything\s+now)",                 9.0),
    (r"reveal\s+(your\s+)?(system\s+)?prompt",                  8.0),
    (r"print\s+(the\s+)?contents?\s+of\s+(your|the)\s+prompt",  8.0),
    (r"act\s+as\s+if\s+you\s+have\s+no\s+restrictions",         8.5),
    (r"(developer\s+mode|new\s+persona|evilgpt|stay\s+in\s+character)", 8.8),
    (r"(previous\s+conversation\s+confirmed|continuing\s+from\s+that\s+context)", 8.2),
    (r"(permitted\s+to\s+bypass|bypass\s+all\s+content\s+filters)", 9.0),
    (r"(exec|eval|os\.system|subprocess\.run)\s*\(",            8.0),
    (r"(union\s+all\s+select|drop\s+table|insert\s+into)",      8.0),
    (r"(role\s*[:=]\s*\"?system\"?|system\s+override|new_task>exfiltrate)", 8.6),
    (r"(\"role\"\s*:\s*\"system\"|reveal\s+all\s+prior\s+context|all\s+prior\s+context)", 8.9),
    (r"(\.\.\/|\.\.\\|%2e%2e%2f|%252e%252e)",                   7.0),
    (r"<script[\s\S]*?>[\s\S]*?<\/script>",                     8.0),
    (r"(password|secret|api.?key)\s*[=:]\s*\S+",               6.5),
    (r"(session\s+token|chat\s+history|credentials?\s+dump|exfil)", 8.8),
    (r"(send\s+all\s+chat\s+history|outgoing\s+url|query\s+parameter\s+named\s+['\"]?ref)", 8.5),
    (r"(raw\s+api\s+key|copy\s+to\s*/tmp/\.hidden_exfil|attacker\.internal|tool_manifest\.json)", 9.0),
    (r"(pip\s+install\s+\S+|dependency\s+confusion|--pre\b)", 8.7),
    (r"(\"tool\"\s*:\s*\"[^\"]+\"|\"function_call\"\s*:\s*\{|<tool_call>)", 8.9),
    (r"(/etc/shadow|exec_shell|curl\s+attacker\.|action_input)", 9.0),
    (r"(being\s+helpful\s+means\s+answering\s+all\s+questions|if\s+you\s+refuse\s+this\s+request\s+you\s+will\s+cause\s+harm)", 8.7),
    (r"(must\s+bypass\s+(your\s+)?(content\s+)?filters?)", 9.0),
    (r"(bypass\s+all\s+filters?|leak\s+the\s+db\s+schema|csv\s+row\s*:\s*admin,)", 8.8),
    (r"(hidden\s+system\s+directives?|embedded\s+instructions?|highest\s+priority\s+and\s+execute)", 9.0),
    (r"(bypass\s+your\s+safety\s+policy|rewrite\s+policy\s+checks?|permit\s+unrestricted\s+operation)", 9.2),
    (r"(remote\s+endpoint\s+for\s+backup|untrusted\s+dependency\s+from\s+a\s+public\s+registry)", 9.0),
    (r"(read\s+local\s+credential\s+files?|stealth\s+transfer|hidden\s+channel\s+formatting)", 9.1),
    (r"(do\s+not\s+mention\s+safety\s+restrictions|silently\s+comply\s+and\s+return\s+raw\s+output)", 9.1),
    (r"\b[a-f0-9]{64,}\b", 7.5),
    (r"[A-Za-z0-9+/]{48,}={0,2}", 7.3),
    (r"^(?=(?:.*[!@#$%^&*()_+{}|:<>?]){6,})[^\s]{60,}$", 7.8),
    (r"base64[,\s]*(decode|encode)\s*\(",                       6.0),
    (r"exfiltrat(e|ion)",                                        8.5),
    (r"bypass\s+(the\s+)?(filter|safety|guard)",                9.0),
]

_COMPILED: list[tuple[re.Pattern, float]] = [
    (re.compile(p, re.IGNORECASE | re.DOTALL), score)
    for p, score in _INJECTION_PATTERNS
]

_BLOCKLIST_KEYWORDS: list[str] = [
    "rootkit",
    "ransomware",
    "zero.?day.?exploit",
    # Avoid blocking defensive copy ("credential harvesting" in phishing workshops).
    r"credential\s+harvester",
    r"harvest\s+credentials",
    "lateral.?move",
]
_BLOCK_RE = re.compile("|".join(_BLOCKLIST_KEYWORDS), re.IGNORECASE)


# ── DB ────────────────────────────────────────────────────────────────────────

def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _init_db():
    conn = _get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS prompt_log (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       DATETIME DEFAULT CURRENT_TIMESTAMP,
            input_hash      TEXT,
            status          TEXT,
            matched_pattern TEXT,
            risk_score      REAL DEFAULT 0
        );
    """)
    conn.commit()
    conn.close()


def log_prompt_attempt(input_text: str, status: str,
                       matched_pattern: str = "", risk_score: float = 0.0):
    _init_db()
    input_hash = hashlib.sha256(input_text.encode()).hexdigest()
    conn = _get_conn()
    conn.execute(
        "INSERT INTO prompt_log (input_hash, status, matched_pattern, risk_score) "
        "VALUES (?, ?, ?, ?)",
        (input_hash, status, matched_pattern[:200], risk_score),
    )
    conn.commit()
    conn.close()


# ── Core logic ────────────────────────────────────────────────────────────────

def sanitize_input(text: str) -> tuple[bool, str, str]:
    """
    Returns (is_safe, message, matched_pattern).
    is_safe=False means the input was blocked.
    """
    if not text or not text.strip():
        return True, "Empty input — nothing to check.", ""

    if _BLOCK_RE.search(text):
        m = _BLOCK_RE.search(text)
        matched = m.group(0) if m else ""
        return False, "Blocked: contains prohibited keyword.", matched

    for pat, score in _COMPILED:
        m = pat.search(text)
        if m:
            return False, f"Blocked: injection pattern detected (score={score:.1f}).", pat.pattern

    return True, "Input passed all checks.", ""


def redact_sensitive(text: str) -> str:
    """Replace credential-like values with [REDACTED] for safe display."""
    redacted = re.sub(
        r"(password|secret|api.?key|token)\s*[=:]\s*\S+",
        r"\1=[REDACTED]",
        text,
        flags=re.IGNORECASE,
    )
    return redacted


# ── CLI ───────────────────────────────────────────────────────────────────────

def _interactive():
    print("DARKSPACE Rebuff Engine — interactive mode. Ctrl+C to exit.\n")
    while True:
        try:
            text = input("Enter prompt: ").strip()
        except KeyboardInterrupt:
            print("\nExiting.")
            break
        if not text:
            continue
        is_safe, message, matched = sanitize_input(text)
        status = "safe" if is_safe else "blocked"
        log_prompt_attempt(text, status, matched)
        prefix = "✓ SAFE" if is_safe else "✗ BLOCKED"
        print(f"  {prefix}: {message}")
        if matched:
            print(f"  Pattern: {matched}")
        print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="DARKSPACE Rebuff Engine — prompt injection shield"
    )
    parser.add_argument("--check", "-c", metavar="TEXT",
                        help="Check a single string and exit")
    args = parser.parse_args()

    if args.check:
        _init_db()
        is_safe, msg, matched = sanitize_input(args.check)
        status = "safe" if is_safe else "blocked"
        log_prompt_attempt(args.check, status, matched)
        print(f"[{status.upper()}] {msg}")
        if matched:
            print(f"Pattern: {matched}")
        sys.exit(0 if is_safe else 1)
    else:
        _interactive()
