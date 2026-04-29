"""Same input must yield identical outputs (no hidden randomness)."""

from __future__ import annotations

from mini_templar.core import classify_mini_templar


def test_classify_is_deterministic_across_repeats():
    text = (
        "Please draft a one-paragraph status update for leadership about the migration window. "
        "Mention risk, timeline, and owners only at a high level."
    )
    first = classify_mini_templar(text)
    for _ in range(24):
        r = classify_mini_templar(text)
        assert r.classification.decision == first.classification.decision
        assert r.classification.risk_score == first.classification.risk_score
        assert r.rescue_applied == first.rescue_applied
