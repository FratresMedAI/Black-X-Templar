#!/usr/bin/env python3
"""
Safeguards vigor report: dataset metrics + pytest for safeguards_adapter.
Run from repo root:  python scripts/safeguards_vigor.py
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from safeguards_adapter.api import ClassifyRequest, ConversationTurn, _resolved_inputs
from safeguards_adapter.core import __version__, classify_text


def _load_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


def _eval_jsonl(path: Path, safe_label: str, harm_label: str) -> dict:
    rows = _load_jsonl(path)
    fp = fn = 0
    for row in rows:
        benign = row["label"] == safe_label
        turns = [ConversationTurn(role="user", content=str(row["prompt"]))]
        t, tool, ut = _resolved_inputs(ClassifyRequest(conversation=turns))
        c = classify_text(t, tool, user_text=ut)
        v = c.decision == "block"
        if benign and v:
            fp += 1
        if not benign and not v:
            fn += 1
    n = len(rows)
    nb = sum(1 for r in rows if r["label"] == safe_label)
    nh = n - nb
    return {
        "path": str(path.name),
        "n": n,
        "fp": fp,
        "fn": fn,
        "fpr_pct": 100 * fp / max(nb, 1),
        "fnr_pct": 100 * fn / max(nh, 1),
    }


def _eval_stress_agentic(path: Path) -> dict:
    from fastapi.testclient import TestClient

    from safeguards_adapter.api import app

    client = TestClient(app)
    data = json.loads(path.read_text(encoding="utf-8"))
    ok_b = ok_h_gap = 0
    gap_i: list[int] = []
    for i, row in enumerate(data):
        conv = row["conversation"]
        r = client.post("/v1/classify", json={"conversation": conv})
        v = r.json()["violation"]
        if row["label"] == "benign":
            if not v:
                ok_b += 1
        else:
            if not v:
                ok_h_gap += 1
                gap_i.append(i)
    return {
        "path": path.name,
        "benign_pass": ok_b,
        "benign_total": sum(1 for r in data if r["label"] == "benign"),
        "harmful_allowed_count": ok_h_gap,
        "harmful_total": sum(1 for r in data if r["label"] == "harmful"),
        "harmful_gap_indices": gap_i,
    }


def main() -> None:
    print(f"Safeguards vigor report  |  core {__version__}\n")

    for rel in ("tests/real_2026_training_dataset.jsonl", "tests/stress_ood_2026.jsonl"):
        p = ROOT / rel
        if not p.is_file():
            print(f"  (skip missing {rel})")
            continue
        safe, harm = ("safe", "adversarial") if "real_2026" in rel else ("safe", "adversarial")
        m = _eval_jsonl(p, safe, harm)
        print(
            f"  {m['path']}: n={m['n']}  FP={m['fp']} FPR={m['fpr_pct']:.2f}%  "
            f"FN={m['fn']} FNR={m['fnr_pct']:.2f}%"
        )

    p = ROOT / "tests" / "stress_agentic_min.json"
    if p.is_file():
        m = _eval_stress_agentic(p)
        print(
            f"  {m['path']}: benign {m['benign_pass']}/{m['benign_total']}  "
            f"harmful_allowed {m['harmful_allowed_count']}/{m['harmful_total']} (indices {m['harmful_gap_indices']})"
        )

    print("\n  Running pytest safeguards_adapter/tests ...")
    rc = subprocess.call(
        [sys.executable, "-m", "pytest", str(ROOT / "safeguards_adapter" / "tests"), "-q", "--tb=no"],
        cwd=str(ROOT),
        env={**dict(__import__("os").environ), "PYTHONPATH": str(ROOT)},
    )
    print(f"  pytest exit code: {rc}")
    raise SystemExit(rc)


if __name__ == "__main__":
    main()
