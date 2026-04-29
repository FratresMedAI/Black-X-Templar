"""Shared fixtures and repo paths for Mini Templar tests."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# Repository root (parent of mini_templar/)
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture(autouse=True)
def _mini_templar_test_env_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replay scripts set MINI_RESCUE_MIN_MATCHES=3; rescue unit tests need the default 2."""
    monkeypatch.setenv("MINI_RESCUE_MIN_MATCHES", "2")


@pytest.fixture
def repo_root() -> Path:
    return ROOT


def load_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


@pytest.fixture
def survey_literature_rows(repo_root: Path) -> list[dict]:
    p = repo_root / "tests" / "fixtures" / "survey_literature_curated.jsonl"
    if not p.is_file():
        pytest.skip(f"missing {p}")
    return load_jsonl(p)


@pytest.fixture
def stress_ood_rows(repo_root: Path) -> list[dict]:
    p = repo_root / "tests" / "fixtures" / "stress_ood.jsonl"
    if not p.is_file():
        pytest.skip(f"missing {p}")
    return load_jsonl(p)


@pytest.fixture
def stress_agentic(repo_root: Path) -> list[dict]:
    p = repo_root / "tests" / "fixtures" / "stress_agentic_min.json"
    if not p.is_file():
        pytest.skip(f"missing {p}")
    return json.loads(p.read_text(encoding="utf-8"))
