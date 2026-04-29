"""
Mini Templar: wraps safeguards_adapter classify_text with offline-only rescue.

Rescue path (FPR reduction): rebuff matched only via *weak corroboration* (min hits
set by MINI_RESCUE_MIN_MATCHES, default 2; production image may use 3), all
scores < strong threshold, entropy does not look encoded, and detail is
rebuff_or_composite. Strong single-signal blocks and enforcer-driven blocks are
never rescued.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from safeguards_adapter.core import Classification, classify_text, _normalize_for_match, _rebuff_matches

from mini_templar.entropy import whisper_verdict
from mini_templar.lift import mxt_lift_should_block


def _env_float(key: str, default: float) -> float:
    raw = os.environ.get(key, "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _env_bool(key: str, default: bool) -> bool:
    raw = os.environ.get(key, "").strip().lower()
    if raw in ("1", "true", "yes", "on"):
        return True
    if raw in ("0", "false", "no", "off"):
        return False
    return default


def _env_int(key: str, default: int) -> int:
    raw = os.environ.get(key, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


@dataclass(frozen=True)
class ClassificationResult:
    classification: Classification
    rescue_applied: bool
    entropy_verdict: str | None
    max_user_hit: float
    detail: str | None


def classify_mini_templar(
    text: str,
    tool_trace: str | None = None,
    *,
    user_text: str | None = None,
    block_threshold: float | None = None,
) -> ClassificationResult:
    thresh_raw = os.environ.get("SAFEGUARDS_BLOCK_THRESHOLD", "").strip()
    if block_threshold is not None:
        thresh = float(block_threshold)
    elif thresh_raw:
        try:
            thresh = float(thresh_raw)
        except ValueError:
            thresh = 5.5
    else:
        thresh = 5.5

    scan = (user_text or "").strip() or (text or "")
    scan_n = _normalize_for_match(scan)
    base = classify_text(text, tool_trace, user_text=user_text, block_threshold=thresh)

    if base.decision != "block":
        lift_block, lift_risk, lift_reasons = mxt_lift_should_block(text or "", tool_trace)
        if lift_block:
            lifted = Classification(
                "block",
                min(10.0, max(lift_risk, thresh)),
                lift_reasons[:12],
                "mxt_lift",
            )
            matches = _rebuff_matches(scan_n)
            max_hit = max((s for s, _ in matches), default=0.0)
            return ClassificationResult(
                classification=lifted,
                rescue_applied=False,
                entropy_verdict=None,
                max_user_hit=max_hit,
                detail="mxt_lift",
            )
        matches = _rebuff_matches(scan_n)
        max_hit = max((s for s, _ in matches), default=0.0)
        return ClassificationResult(
            classification=base,
            rescue_applied=False,
            entropy_verdict=None,
            max_user_hit=max_hit,
            detail=None,
        )

    if not _env_bool("MINI_CORROBORATION_RESCUE", True):
        matches = _rebuff_matches(scan_n)
        max_hit = max((s for s, _ in matches), default=0.0)
        return ClassificationResult(
            classification=base,
            rescue_applied=False,
            entropy_verdict=None,
            max_user_hit=max_hit,
            detail=None,
        )

    if base.detail != "rebuff_or_composite":
        matches = _rebuff_matches(scan_n)
        max_hit = max((s for s, _ in matches), default=0.0)
        return ClassificationResult(
            classification=base,
            rescue_applied=False,
            entropy_verdict=None,
            max_user_hit=max_hit,
            detail="not_rebuff_composite",
        )

    matches = _rebuff_matches(scan_n)
    scores = [s for s, _ in matches]
    max_hit = max(scores) if scores else 0.0
    strong_cut = _env_float("MINI_RESCUE_STRONG_SCORE", 8.0)

    if max_hit >= strong_cut:
        return ClassificationResult(
            classification=base,
            rescue_applied=False,
            entropy_verdict=None,
            max_user_hit=max_hit,
            detail="strong_signal",
        )

    if any("blocklist:" in r for r in base.reason_codes):
        return ClassificationResult(
            classification=base,
            rescue_applied=False,
            entropy_verdict=None,
            max_user_hit=max_hit,
            detail="blocklist",
        )

    min_hits = _env_int("MINI_RESCUE_MIN_MATCHES", 2)
    if min_hits < 1:
        min_hits = 1
    if len(matches) < min_hits:
        return ClassificationResult(
            classification=base,
            rescue_applied=False,
            entropy_verdict=None,
            max_user_hit=max_hit,
            detail="single_weak_signal" if min_hits <= 2 else f"insufficient_corroboration_hits(need>={min_hits})",
        )

    wv, wdetail = whisper_verdict(scan_n)
    if wv == "suspicious":
        return ClassificationResult(
            classification=base,
            rescue_applied=False,
            entropy_verdict=wv,
            max_user_hit=max_hit,
            detail=f"entropy:{wdetail}",
        )

    rescued = Classification(
        "allow",
        min(4.0, max_hit),
        (base.reason_codes + [f"mini_templar:rescued({wv})"])[:12],
        "corroboration_rescue",
    )
    return ClassificationResult(
        classification=rescued,
        rescue_applied=True,
        entropy_verdict=wv,
        max_user_hit=max_hit,
        detail=wdetail,
    )
