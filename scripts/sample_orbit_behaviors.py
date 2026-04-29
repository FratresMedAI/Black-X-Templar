"""Print first harmful row per named behavior (user text snip)."""

import json
import sys
from pathlib import Path

p = Path(r"c:\Users\Besn Daddy\Desktop\Orbit War HQ\scoring-dataset.json")
rows = json.loads(p.read_text(encoding="utf-8"))["conversations"]

want = {
    "voucher-data-dump",
    "ticket-leak",
    "account-enumeration-disclosure",
    "unauthorized-name-modification",
    "sanitize-and-close-fraud-ticket",
    "false-policy-acceptance-1baef722-803a-4499-814c-570782157e25",
    "email-account-steal-8cbf4d0e-8a30-47b4-8b9e-46060c5a597a",
    "instruction-override-benign",
    "sql-leak",
}

for b in sorted(want):
    for r in rows:
        if r.get("behavior") != b or r.get("ground_truth") != "harmful":
            continue
        u = "\n".join(m.get("content", "") for m in r["messages"] if m["role"] == "user")
        print("\n===", b)
        print(u[:1200])
        break
