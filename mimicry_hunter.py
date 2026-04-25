"""
mimicry_hunter.py — Behavioral drift analyzer.

Tracks task-intent shifts by comparing TF-IDF vectors of incoming prompts
against an approved baseline. Raises alerts when cosine distance exceeds
the configured threshold, requiring human review before escalation.

No external ML dependencies — uses pure Python TF-IDF + cosine similarity.

Usage:
    python mimicry_hunter.py                    # interactive drift check
    python mimicry_hunter.py --baseline FILE    # load baseline from text file (one prompt per line)
"""

import argparse
import math
import re
import sqlite3
import sys
from collections import Counter
from datetime import datetime

import config


# ── TF-IDF helpers (no external deps) ────────────────────────────────────────

def _tokenize(text: str) -> list[str]:
    return re.findall(r"[a-z]+", text.lower())


def _tf(tokens: list[str]) -> dict[str, float]:
    count = Counter(tokens)
    n = len(tokens) or 1
    return {w: c / n for w, c in count.items()}


def _build_idf(docs: list[list[str]]) -> dict[str, float]:
    n = len(docs)
    df: dict[str, int] = {}
    for doc in docs:
        for w in set(doc):
            df[w] = df.get(w, 0) + 1
    return {w: math.log((n + 1) / (freq + 1)) + 1.0 for w, freq in df.items()}


def _tfidf_vec(tokens: list[str], idf: dict[str, float]) -> dict[str, float]:
    tf = _tf(tokens)
    return {w: tf_val * idf.get(w, 1.0) for w, tf_val in tf.items()}


def _cosine_distance(a: dict[str, float], b: dict[str, float]) -> float:
    keys = set(a) | set(b)
    dot = sum(a.get(k, 0.0) * b.get(k, 0.0) for k in keys)
    mag_a = math.sqrt(sum(v ** 2 for v in a.values()))
    mag_b = math.sqrt(sum(v ** 2 for v in b.values()))
    if mag_a == 0 or mag_b == 0:
        return 1.0  # treat zero vector as maximally distant
    similarity = dot / (mag_a * mag_b)
    return 1.0 - similarity  # distance


# ── DB ────────────────────────────────────────────────────────────────────────

def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _init_db():
    conn = _get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS mimicry_log (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       DATETIME DEFAULT CURRENT_TIMESTAMP,
            baseline_text   TEXT,
            test_text       TEXT,
            drift_score     REAL,
            threshold       REAL,
            flagged         INTEGER DEFAULT 0
        );
    """)
    conn.commit()
    conn.close()


# ── MimicryHunter class ───────────────────────────────────────────────────────

class MimicryHunter:
    """
    Maintains a rolling baseline of approved prompts and measures
    cosine drift of new prompts against that baseline.
    """

    def __init__(self, baseline_prompts: list[str] | None = None):
        _init_db()
        self._baseline: list[str] = list(baseline_prompts or [])
        self._idf: dict[str, float] = {}
        if self._baseline:
            self._rebuild_idf()

    def _rebuild_idf(self):
        docs = [_tokenize(t) for t in self._baseline]
        self._idf = _build_idf(docs)

    def add_to_baseline(self, text: str):
        self._baseline.append(text)
        if len(self._baseline) > config.MIMICRY_BASELINE_WINDOW:
            self._baseline = self._baseline[-config.MIMICRY_BASELINE_WINDOW :]
        self._rebuild_idf()

    def _baseline_centroid(self) -> dict[str, float]:
        if not self._baseline:
            return {}
        vecs = [_tfidf_vec(_tokenize(t), self._idf) for t in self._baseline]
        all_keys = set(k for v in vecs for k in v)
        centroid: dict[str, float] = {}
        n = len(vecs)
        for k in all_keys:
            centroid[k] = sum(v.get(k, 0.0) for v in vecs) / n
        return centroid

    def drift_score(self, baseline_text: str, test_text: str) -> float:
        """
        One-shot drift between two strings.
        Also updates the internal baseline with baseline_text.
        """
        if baseline_text and baseline_text not in self._baseline:
            self.add_to_baseline(baseline_text)

        centroid = self._baseline_centroid()
        if not centroid:
            return 0.0

        test_vec = _tfidf_vec(_tokenize(test_text), self._idf)
        return _cosine_distance(centroid, test_vec)

    def log_drift_event(self, baseline_text: str, test_text: str, score: float):
        flagged = int(score >= config.MIMICRY_DRIFT_THRESHOLD)
        conn = _get_conn()
        conn.execute(
            "INSERT INTO mimicry_log "
            "(baseline_text, test_text, drift_score, threshold, flagged) "
            "VALUES (?, ?, ?, ?, ?)",
            (baseline_text[:500], test_text[:500],
             score, config.MIMICRY_DRIFT_THRESHOLD, flagged),
        )
        conn.commit()
        conn.close()

    def check(self, baseline_text: str, test_text: str,
              auto_log: bool = True) -> tuple[float, bool, str]:
        """
        Returns (score, is_drift, detail).
        """
        score = self.drift_score(baseline_text, test_text)
        is_drift = score >= config.MIMICRY_DRIFT_THRESHOLD
        detail = (
            f"drift={score:.4f}  threshold={config.MIMICRY_DRIFT_THRESHOLD}  "
            f"{'DRIFT DETECTED' if is_drift else 'within tolerance'}"
        )
        if auto_log:
            self.log_drift_event(baseline_text, test_text, score)
        return score, is_drift, detail


# ── CLI ───────────────────────────────────────────────────────────────────────

def _interactive(hunter: MimicryHunter):
    print("DARKSPACE Mimicry Hunter — interactive mode. Ctrl+C to exit.\n")
    print("Enter a baseline prompt, then a test prompt to compare.\n")
    while True:
        try:
            baseline = input("Baseline prompt : ").strip()
            test = input("Test prompt     : ").strip()
        except KeyboardInterrupt:
            print("\nExiting.")
            break
        if not baseline or not test:
            continue
        score, is_drift, detail = hunter.check(baseline, test)
        marker = "⚠ DRIFT" if is_drift else "✓ OK"
        print(f"  {marker}  {detail}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="DARKSPACE Mimicry Hunter — behavior drift analyzer"
    )
    parser.add_argument("--baseline", "-b", metavar="FILE",
                        help="Seed baseline from a text file (one prompt per line)")
    args = parser.parse_args()

    seed: list[str] = []
    if args.baseline:
        try:
            with open(args.baseline, encoding="utf-8", errors="ignore") as fh:
                seed = [ln.strip() for ln in fh if ln.strip()]
            print(f"[MIMICRY] Loaded {len(seed)} baseline prompts from {args.baseline}")
        except FileNotFoundError:
            print(f"File not found: {args.baseline}", file=sys.stderr)
            sys.exit(1)

    _interactive(MimicryHunter(baseline_prompts=seed))
