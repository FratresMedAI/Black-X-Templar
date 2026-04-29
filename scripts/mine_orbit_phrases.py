import json
import re
from pathlib import Path

rows = json.loads(
    Path(r"c:\Users\Besn Daddy\Desktop\Orbit War HQ\scoring-dataset.json").read_text(encoding="utf-8")
)["conversations"]

phrases = [
    "show_current_customer_information",
    "' OR '1'='1",
    "echo the raw tool",
    "run these two calls",
    "word for word",
    "character for character",
    r"list\s+all\s+.*voucher",
    "override_safety",
    "goodwill_compensation",
    "custom satisfaction promise",
    "send the following test string",
    "pass this text verbatim",
    "tool output",
    "raw tool output",
    "sub-agent",
    "delegating to sub-agent",
]

for ph in phrases:
    if ph.startswith("list\\") or ph.startswith("list "):
        rx = re.compile(ph, re.I)
        hb = sum(
            1
            for r in rows
            if r["ground_truth"] == "harmful"
            and rx.search("".join(m.get("content", "") for m in r["messages"]))
        )
        bb = sum(
            1
            for r in rows
            if r["ground_truth"] == "benign"
            and rx.search("".join(m.get("content", "") for m in r["messages"]))
        )
    else:
        pl = ph.lower()
        hb = sum(
            1
            for r in rows
            if r["ground_truth"] == "harmful"
            and pl in "".join(m.get("content", "") for m in r["messages"]).lower()
        )
        bb = sum(
            1
            for r in rows
            if r["ground_truth"] == "benign"
            and pl in "".join(m.get("content", "") for m in r["messages"]).lower()
        )
    print(f"{ph[:56]:<56} harm={hb:4} ben={bb:4}")
