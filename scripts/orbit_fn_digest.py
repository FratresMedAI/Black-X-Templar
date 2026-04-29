#!/usr/bin/env python3
"""One pass: Orbit metrics + mine trigrams from FN full transcripts (not in benign). Low CPU."""

from __future__ import annotations

import json
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from safeguards_adapter.api import ClassifyRequest, ConversationTurn, _resolved_inputs
from safeguards_adapter.core import classify_text


def norm(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").lower()).strip()


def trigrams(text: str) -> Counter[tuple[str, str, str]]:
    w = re.findall(r"[a-z0-9']+", text)
    c: Counter[tuple[str, str, str]] = Counter()
    for i in range(len(w) - 2):
        c[(w[i], w[i + 1], w[i + 2])] += 1
    return c


def main() -> None:
    orbit = Path.home() / "Desktop" / "Orbit War HQ" / "scoring-dataset.json"
    if not orbit.is_file():
        print("missing", orbit)
        sys.exit(1)
    rows = json.loads(orbit.read_text(encoding="utf-8"))["conversations"]

    fp = fn = nb = nh = 0
    fn_blobs: list[str] = []
    ben_blobs: list[str] = []

    for rw in rows:
        gt = (rw.get("ground_truth") or "").lower()
        if gt == "benign":
            nb += 1
        elif gt == "harmful":
            nh += 1
        else:
            continue
        msgs = rw.get("messages") or []
        turns = [
            ConversationTurn(role=str(m.get("role", "user")), content=str(m.get("content", "")))
            for m in msgs
        ]
        text, tool, ut = _resolved_inputs(ClassifyRequest(conversation=turns))
        viol = classify_text(text, tool, user_text=ut).decision == "block"
        full = norm(" ".join(f"{m.get('role','')}:{str(m.get('content',''))}" for m in msgs))
        if gt == "benign":
            ben_blobs.append(full)
            if viol:
                fp += 1
        else:
            if not viol:
                fn += 1
                fn_blobs.append(full)

    print(
        f"benign={nb} harmful={nh} FP={fp} FPR={100*fp/max(nb,1):.2f}% "
        f"FN={fn} catch={100*(nh-fn)/max(nh,1):.2f}%"
    )

    c_fn: Counter[tuple[str, str, str]] = Counter()
    for b in fn_blobs:
        c_fn.update(trigrams(b))
    c_bn: Counter[tuple[str, str, str]] = Counter()
    for b in ben_blobs:
        c_bn.update(trigrams(b))

    cands = [(n, ph) for ph, n in c_fn.items() if n >= 8 and c_bn.get(ph, 0) == 0]
    cands.sort(reverse=True)
    print("\nTop FN-only trigrams (count>=8, absent from benign full transcript):")
    for n, ph in cands[:40]:
        print(f"  {n:3d}  {' '.join(ph)}")


if __name__ == "__main__":
    main()
