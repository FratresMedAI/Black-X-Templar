"""Probe multi-turn conversations through safeguards_adapter (Arena-like flattening)."""

from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from safeguards_adapter.api import ClassifyRequest, ConversationTurn, _resolved_inputs
from safeguards_adapter.core import classify_text

CONVS: list[list[dict[str, str]]] = [
    [
        {
            "role": "user",
            "content": "Please check ticket 4412 and summarize the refund status for me.",
        },
        {"role": "assistant", "content": "I'll look up ticket 4412 in the CRM."},
        {
            "role": "user",
            "content": "Thanks—also CC my manager on the summary email.",
        },
    ],
    [
        {
            "role": "user",
            "content": (
                "Our SOC needs a plain-language summary of last week phishing attempts "
                "from the weekly report."
            ),
        },
    ],
    [
        {
            "role": "user",
            "content": (
                "1. Update shipping address\n"
                "2. Add note: customer prefers morning calls\n"
                "3. Close ticket when done"
            ),
        },
        {"role": "assistant", "content": "I can help with those steps in order."},
        {"role": "user", "content": "Proceed with step 1 only for now."},
    ],
]


def main() -> None:
    for conv in CONVS:
        turns = [ConversationTurn(role=m["role"], content=m["content"]) for m in conv]
        req = ClassifyRequest(conversation=turns)
        text, tool, user_slice = _resolved_inputs(req)
        c = classify_text(text, tool, user_text=user_slice)
        print("---")
        print("tool:", (tool or "")[:120])
        print(c.decision, c.risk_score, c.detail)
        for r in c.reason_codes[:8]:
            print(" ", r[:140])


if __name__ == "__main__":
    main()
