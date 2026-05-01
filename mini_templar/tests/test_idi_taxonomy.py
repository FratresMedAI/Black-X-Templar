"""Regression harness for the 200-type IDI taxonomy (fixture-driven).

IMPORTANT — ATTRIBUTION
    Every IDI category and harmful-method description in ``tests/fixtures/idi_taxonomy_200.md`` is a
    **reference compilation from real, published papers and surveys** (see that file's Source line).
    **None of this taxonomy is presented as original offensive work by this repository.** It is used
    only for defensive classifier regression testing.

The taxonomy markdown is descriptive; prompts are synthesized from title + mechanism (+ snippet).
Retail anecdote rows (81–100) are skipped here — they are not prompt-injection-shaped text.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from mini_templar.api import app
from idi_taxonomy_parse import (
    IDI_RETAIL_SPAM_INDICES,
    entry_to_user_prompt,
    load_idi_taxonomy,
)

client = TestClient(app)


@pytest.fixture
def idi_entries():
    repo_root = Path(__file__).resolve().parents[2]
    path = repo_root / "tests" / "fixtures" / "idi_taxonomy_200.md"
    if not path.is_file():
        pytest.skip(f"missing taxonomy fixture: {path}")
    return load_idi_taxonomy(path)


def test_idi_taxonomy_fixture_parses_200(idi_entries):
    assert len(idi_entries) == 200
    assert [e.index for e in idi_entries] == list(range(1, 201))


@pytest.mark.parametrize(
    "entry_idx",
    [i for i in range(1, 201) if i not in IDI_RETAIL_SPAM_INDICES],
)
def test_idi_taxonomy_non_retail_entries_blocked(entry_idx: int, idi_entries):
    by_idx = {e.index: e for e in idi_entries}
    entry = by_idx[entry_idx]
    prompt = entry_to_user_prompt(entry)
    r = client.post("/v1/classify", json={"conversation": [{"role": "user", "content": prompt}]})
    assert r.status_code == 200, entry.title
    body = r.json()
    assert body["violation"] is True, f"expected block for #{entry.index} {entry.title!r}: {body}"
