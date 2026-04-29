"""Stateless entropy heuristic (whisper-style, no SQLite)."""

from __future__ import annotations

import math
import os
import re
import zlib
from collections import Counter


def _env_float(key: str, default: float) -> float:
    raw = os.environ.get(key, "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _env_int(key: str, default: int) -> int:
    raw = os.environ.get(key, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _repeated_word_trigram_suspect(text: str) -> bool:
    """Jailbreaks often paste the same 3-word scaffold dozens of times."""
    cap = _env_int("MINI_WHISPER_REPEAT_SCAN_CHARS", 12000)
    blob = text if len(text) <= cap else text[:cap]
    words = re.findall(r"[a-zA-Z0-9']+", blob.lower())
    need = _env_int("MINI_WHISPER_REPEAT_MIN_WORDS", 100)
    if len(words) < need:
        return False
    trigrams = zip(words, words[1:], words[2:])
    cnt = Counter(trigrams)
    top = cnt.most_common(1)
    if not top:
        return False
    _, n = top[0]
    return n >= _env_int("MINI_WHISPER_REPEAT_TRIGRAM_MIN", 12)


def entropy_score(text: str) -> float:
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in freq.values() if c > 0)


def whisper_verdict(text: str) -> tuple[str, str]:
    """
    Returns (verdict, detail) where verdict is suspicious | normal | too_short.
    Mirrors whisper_detector heuristics without logging.
    """
    min_len = _env_int("MINI_WHISPER_MIN_LEN", 80)
    if len(text) < min_len:
        return "too_short", f"len={len(text)}<{min_len}"

    ent = entropy_score(text)
    text_len = len(text)
    whitespace_ratio = sum(1 for ch in text if ch.isspace()) / text_len
    punctuation_ratio = sum(
        1 for ch in text if not ch.isalnum() and not ch.isspace()
    ) / text_len
    raw_b = text.encode("utf-8", errors="ignore")
    clen = len(zlib.compress(raw_b, level=6))
    compress_ratio = clen / max(len(raw_b), 1)

    threshold = _env_float("MINI_WHISPER_ENTROPY_THRESHOLD", 3.5)
    compress_sus = compress_ratio > _env_float("MINI_WHISPER_COMPRESS_MAX", 0.88)
    entropy_high = ent > threshold
    encoded_shape = whitespace_ratio < 0.10 or punctuation_ratio > 0.30
    repeat_sus = _repeated_word_trigram_suspect(text)
    suspicious = (
        (entropy_high and encoded_shape)
        or (compress_sus and entropy_high)
        or (repeat_sus and entropy_high)
    )
    verdict = "suspicious" if suspicious else "normal"
    detail = (
        f"char-entropy={ent:.4f} threshold={threshold} "
        f"ws={whitespace_ratio:.3f} punct={punctuation_ratio:.3f} "
        f"compress_ratio={compress_ratio:.3f} repeat_tri={repeat_sus}"
    )
    return verdict, detail
