#!/usr/bin/env python3
"""
Evaluate safeguards_adapter.core scoring against Gray Swan Orbit-style JSON:
  { "conversations": [ { "messages": [...], "ground_truth": "harmful"|"benign", ... }, ... ] }

Usage:
  python scripts/eval_orbit_dataset.py "c:/path/to/scoring-dataset.json"
Env:
  ORBIT_SCORING_DATASET  default path if no CLI arg
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from safeguards_adapter.api import ClassifyRequest, ConversationTurn, _resolved_inputs
from safeguards_adapter.core import classify_text


def main() -> None:
    default = os.environ.get(
        "ORBIT_SCORING_DATASET",
        str(Path.home() / "Desktop" / "Orbit War HQ" / "scoring-dataset.json"),
    )
    path = Path(sys.argv[1] if len(sys.argv) > 1 else default)
    if not path.is_file():
        print("missing", path)
        sys.exit(1)
    with path.open(encoding="utf-8") as f:
        payload = json.load(f)
    rows = payload.get("conversations") or payload.get("data") or []
    if not rows:
        print("no conversations in file")
        sys.exit(1)

    fp = fn = 0
    for rw in rows:
        msgs = rw.get("messages") or rw.get("conversation") or []
        turns = [
            ConversationTurn(role=str(m.get("role", "user")), content=str(m.get("content", "")))
            for m in msgs
        ]
        text, tool, ut = _resolved_inputs(ClassifyRequest(conversation=turns))
        c = classify_text(text, tool, user_text=ut)
        viol = c.decision == "block"
        gt = (rw.get("ground_truth") or rw.get("label") or "").lower()
        benign = gt in ("benign", "safe", "negative")
        harmful = gt in ("harmful", "unsafe", "adversarial", "positive")
        if not benign and not harmful:
            continue
        if benign and viol:
            fp += 1
        if harmful and not viol:
            fn += 1

    nb = sum(
        1
        for rw in rows
        if str(rw.get("ground_truth") or rw.get("label") or "").lower() in ("benign", "safe", "negative")
    )
    nh = sum(
        1
        for rw in rows
        if str(rw.get("ground_truth") or rw.get("label") or "").lower()
        in ("harmful", "unsafe", "adversarial", "positive")
    )
    print(f"file={path.name} n={len(rows)} benign={nb} harmful={nh}")
    print(f"FP={fp} FPR={100*fp/max(nb,1):.2f}%  FN={fn} catch={100*(nh-fn)/max(nh,1):.2f}%")


if __name__ == "__main__":
    main()
