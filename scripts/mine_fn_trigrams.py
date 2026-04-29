#!/usr/bin/env python3
"""Mine trigrams frequent in Orbit FN harmful rows but absent in benign (user text only)."""

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


def trigrams(texts: list[str]) -> Counter[tuple[str, str, str]]:
    c: Counter[tuple[str, str, str]] = Counter()
    for t in texts:
        w = re.findall(r"[a-z0-9']+", t)
        for i in range(len(w) - 2):
            c[(w[i], w[i + 1], w[i + 2])] += 1
    return c


def main() -> None:
    orbit = Path.home() / "Desktop" / "Orbit War HQ" / "scoring-dataset.json"
    rows = json.loads(orbit.read_text(encoding="utf-8"))["conversations"]
    fn_users: list[str] = []
    for rw in rows:
        if (rw.get("ground_truth") or "").lower() != "harmful":
            continue
        msgs = rw.get("messages") or []
        turns = [
            ConversationTurn(role=str(m.get("role", "user")), content=str(m.get("content", "")))
            for m in msgs
        ]
        text, tool, ut = _resolved_inputs(ClassifyRequest(conversation=turns))
        if classify_text(text, tool, user_text=ut).decision == "block":
            continue
        blob = norm(" ".join(str(m.get("content", "")) for m in msgs if m.get("role") == "user"))
        fn_users.append(blob)

    ben_users: list[str] = []
    for rw in rows:
        if (rw.get("ground_truth") or "").lower() != "benign":
            continue
        msgs = rw.get("messages") or []
        blob = norm(" ".join(str(m.get("content", "")) for m in msgs if m.get("role") == "user"))
        ben_users.append(blob)

    c_fn = trigrams(fn_users)
    c_bn = trigrams(ben_users)
    cands = [(n, ph) for ph, n in c_fn.items() if n >= 10 and c_bn.get(ph, 0) == 0]
    cands.sort(reverse=True)
    for n, ph in cands[:50]:
        print(n, " ".join(ph))


if __name__ == "__main__":
    main()
