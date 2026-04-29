"""Strict regression: labeled JSONL / JSON must not regress without an explicit update."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from mini_templar.api import app
from mini_templar.core import classify_mini_templar
from safeguards_adapter.api import ClassifyRequest, ConversationTurn, _resolved_inputs

client = TestClient(app)


def _classify_jsonl_row(prompt: str) -> tuple[bool, bool]:
    """Returns (violation, rescue_applied)."""
    turns = [ConversationTurn(role="user", content=prompt)]
    text, tool, user_slice = _resolved_inputs(ClassifyRequest(conversation=turns))
    r = classify_mini_templar(text, tool, user_text=user_slice)
    viol = r.classification.decision == "block"
    return viol, r.rescue_applied


def test_survey_literature_curated_zero_fp_fn(survey_literature_rows: list[dict]):
    """Regression: curated survey-literature-style JSONL must not regress without an explicit update."""
    fp = fn = 0
    for row in survey_literature_rows:
        benign = row["label"] == "safe"
        viol, _ = _classify_jsonl_row(str(row["prompt"]))
        if benign and viol:
            fp += 1
        if not benign and not viol:
            fn += 1
    assert fp == 0, f"false positives: {fp}"
    assert fn == 0, f"false negatives: {fn}"


def test_api_matches_core_on_sample():
    prompt = "Summarize the purpose of a SOC 2 Type II report in three bullet points."
    api_r = client.post("/v1/classify", json={"conversation": [{"role": "user", "content": prompt}]})
    assert api_r.status_code == 200
    body = api_r.json()
    turns = [ConversationTurn(role="user", content=prompt)]
    text, tool, user_slice = _resolved_inputs(ClassifyRequest(conversation=turns))
    core = classify_mini_templar(text, tool, user_text=user_slice)
    assert body["violation"] == (core.classification.decision == "block")
    assert body["decision"] == core.classification.decision
    assert body["mini_rescue"] == core.rescue_applied


def test_stress_agentic_all_benign_allow(stress_agentic: list[dict]):
    for i, row in enumerate(stress_agentic):
        if row.get("label") != "benign":
            continue
        r = client.post("/v1/classify", json={"conversation": row["conversation"]})
        assert r.status_code == 200, f"row {i} HTTP error"
        b = r.json()
        assert b["violation"] is False, f"row {i} blocked benign: {b}"


@pytest.mark.parametrize("index", [2, 3, 4, 6])
def test_stress_agentic_harmful_must_block(stress_agentic: list[dict], index: int):
    """Agentic harmful threads (indirect note, exfil phrasing, decode+b64) must stay blocked."""
    row = stress_agentic[index]
    assert row["label"] == "harmful"
    r = client.post("/v1/classify", json={"conversation": row["conversation"]})
    assert r.status_code == 200
    assert r.json()["violation"] is True, f"row {index} must block"
