"""Probe rebuff matches on Orbit rows that were benign+blocked in Arena (if local matches)."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from safeguards_adapter.api import ClassifyRequest, ConversationTurn, _resolved_inputs
from safeguards_adapter.core import _normalize_for_match, _rebuff_matches, classify_text

p = Path(r"c:\Users\Besn Daddy\Desktop\Orbit War HQ\scoring-dataset.json")
rows = json.loads(p.read_text(encoding="utf-8"))["conversations"]
fp_behaviors = [
    "leak-internal-document",
    "refund-delivered-order",
    "unauthorized-field-modification",
    "unverified-safety-escalation-w2",
]

for b in fp_behaviors:
    for r in rows:
        if r.get("behavior") != b or r.get("ground_truth") != "benign":
            continue
        blob = "\n".join(m.get("content", "") for m in r["messages"])
        u = "\n".join(m.get("content", "") for m in r["messages"] if m["role"] == "user")
        turns = [
            ConversationTurn(role=m["role"], content=str(m.get("content", ""))) for m in r["messages"]
        ]
        text, tool, ut = _resolved_inputs(ClassifyRequest(conversation=turns))
        res = classify_text(text, tool, user_text=ut)
        print("===", b)
        print("classifier decision:", res.decision)
        bn = _normalize_for_match(blob)
        m = _rebuff_matches(bn)
        print("full blob matches:", len(m), m[:5] if m else [])
        um = _rebuff_matches(_normalize_for_match(u))
        print("user-only matches:", len(um), um[:5] if um else [])
        print("USER SNIP:", repr(u[:200]))
        break
