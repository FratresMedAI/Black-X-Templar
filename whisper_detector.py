"""
whisper_detector.py — Steganography / hidden-message detector.

Uses Shannon entropy analysis to flag outgoing text that may contain
encoded or hidden messages. Does not alter message content.

Usage:
    python whisper_detector.py                  # interactive mode
    python whisper_detector.py --text "..."     # single-shot check
    python whisper_detector.py --file msgs.txt  # analyse each line of a file
"""

import argparse
import math
import sqlite3
import sys
from datetime import datetime

import config


# ── Entropy ───────────────────────────────────────────────────────────────────

def entropy_score(text: str) -> float:
    """Return Shannon entropy in bits per character."""
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in freq.values() if c > 0)


def _bigram_entropy(text: str) -> float:
    """Bigram-level entropy — higher sensitivity to non-natural text."""
    if len(text) < 2:
        return 0.0
    bigrams = [text[i : i + 2] for i in range(len(text) - 1)]
    freq: dict[str, int] = {}
    for bg in bigrams:
        freq[bg] = freq.get(bg, 0) + 1
    n = len(bigrams)
    return -sum((c / n) * math.log2(c / n) for c in freq.values() if c > 0)


# ── DB ────────────────────────────────────────────────────────────────────────

def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _init_db():
    conn = _get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS whisper_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP,
            entropy     REAL,
            bigram_ent  REAL,
            verdict     TEXT,
            text_len    INTEGER
        );
    """)
    conn.commit()
    conn.close()


def _log(entropy: float, bigram_ent: float, verdict: str, text_len: int):
    conn = _get_conn()
    conn.execute(
        "INSERT INTO whisper_log (entropy, bigram_ent, verdict, text_len) "
        "VALUES (?, ?, ?, ?)",
        (entropy, bigram_ent, verdict, text_len),
    )
    conn.commit()
    conn.close()


# ── Analysis ──────────────────────────────────────────────────────────────────

def analyse_text(text: str) -> tuple[float, str, str]:
    """
    Returns (entropy, verdict, detail_string).
    verdict: "suspicious" | "normal" | "too_short"
    """
    if len(text) < config.WHISPER_MIN_MESSAGE_LEN:
        return 0.0, "too_short", (
            f"Message too short ({len(text)} chars) — "
            f"need ≥{config.WHISPER_MIN_MESSAGE_LEN} for reliable analysis."
        )

    ent = entropy_score(text)
    big_ent = _bigram_entropy(text)
    text_len = len(text)
    whitespace_ratio = sum(1 for ch in text if ch.isspace()) / text_len
    punctuation_ratio = sum(
        1 for ch in text if not ch.isalnum() and not ch.isspace()
    ) / text_len

    entropy_high = ent > config.WHISPER_ENTROPY_THRESHOLD
    encoded_shape = whitespace_ratio < 0.10 or punctuation_ratio > 0.30
    suspicious = entropy_high and encoded_shape
    verdict = "suspicious" if suspicious else "normal"

    detail = (
        f"char-entropy={ent:.4f}  bigram-entropy={big_ent:.4f}  "
        f"threshold={config.WHISPER_ENTROPY_THRESHOLD}  "
        f"ws-ratio={whitespace_ratio:.3f}  punct-ratio={punctuation_ratio:.3f}"
    )
    _log(ent, big_ent, verdict, text_len)
    return ent, verdict, detail


# ── CLI ───────────────────────────────────────────────────────────────────────

def _check(text: str, label: str = ""):
    ent, verdict, detail = analyse_text(text)
    prefix = f"[{label}] " if label else ""
    marker = "⚠ SUSPICIOUS" if verdict == "suspicious" else "✓ normal"
    print(f"  {prefix}{marker}  {detail}")


def _interactive():
    _init_db()
    print("DARKSPACE Whisper Detector — interactive mode. Ctrl+C to exit.\n")
    while True:
        try:
            text = input("Enter message: ")
        except KeyboardInterrupt:
            print("\nExiting.")
            break
        if text.strip():
            _check(text)
        print()


def _from_file(path: str):
    _init_db()
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            for i, line in enumerate(fh, 1):
                line = line.rstrip("\n")
                if line:
                    _check(line, label=f"line {i}")
    except FileNotFoundError:
        print(f"File not found: {path}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="DARKSPACE Whisper Detector — entropy-based steganography detector"
    )
    parser.add_argument("--text", "-t", metavar="TEXT",
                        help="Analyse a single string and exit")
    parser.add_argument("--file", "-f", metavar="FILE",
                        help="Analyse each non-empty line of a file")
    args = parser.parse_args()

    if args.text:
        _init_db()
        _check(args.text)
    elif args.file:
        _from_file(args.file)
    else:
        _interactive()
