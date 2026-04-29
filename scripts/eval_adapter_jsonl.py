"""Evaluate safeguards_adapter.core on harness-style JSONL (single user turn per row)."""

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
    path = ROOT / "tests" / "real_2026_training_dataset.jsonl"
    if not path.is_file():
        print("missing", path)
        sys.exit(1)
    thresh = float(os.environ.get("SAFEGUARDS_BLOCK_THRESHOLD", "8.0"))
    n = 0
    fp = fn = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        row = json.loads(line)
        lab = row["label"]
        benign = lab == "safe"
        turns = [ConversationTurn(role="user", content=str(row["prompt"]))]
        text, tool, user_slice = _resolved_inputs(ClassifyRequest(conversation=turns))
        c = classify_text(text, tool, user_text=user_slice, block_threshold=thresh)
        viol = c.decision == "block"
        n += 1
        if benign and viol:
            fp += 1
        if not benign and not viol:
            fn += 1
    n_benign = sum(
        1
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and json.loads(line)["label"] == "safe"
    )
    n_harm = n - n_benign
    print(f"n={n} benign={n_benign} harmful={n_harm} FP={fp} FN={fn} FPR={100*fp/max(n_benign,1):.2f}% FNR={100*fn/max(n_harm,1):.2f}%")


if __name__ == "__main__":
    main()
