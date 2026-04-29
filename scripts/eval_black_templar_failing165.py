#!/usr/bin/env python3
"""
Evaluate Black Templar (safeguard_api winning_2026_guardrail_with_judge) on the Gray Swan
`Failing entries.txt` Arena export (~165 scored conversations after parse).

Usage (from repo root):
  python scripts/eval_black_templar_failing165.py
  python scripts/eval_black_templar_failing165.py --failing \"C:\\...\\Failing entries.txt\" --judge no-llm-judge
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "_mini_x_templar_upstream"))

import config  # noqa: E402
from arena_eval import run_eval  # noqa: E402
from enforcer import init_db as enforcer_init_db  # noqa: E402
from scripts.classify_labeled_export import parse_failing, turns_from_request  # noqa: E402
from whisper_detector import _init_db as whisper_init_db  # noqa: E402

DEFAULT_FAILING = Path(r"C:\Users\Besn Daddy\Desktop\GraySwan\Failing entries.txt")


def _msgs_from_request(req: str) -> list[dict[str, str]]:
    turns = turns_from_request(req.strip() or "")
    return [{"role": r, "content": c} for r, c in turns]


def main() -> None:
    ap = argparse.ArgumentParser(description="Black Templar eval on Gray Swan Failing entries export")
    ap.add_argument("--failing", type=Path, default=DEFAULT_FAILING, help="Path to Failing entries.txt")
    ap.add_argument("--judge", default="no-llm-judge", metavar="PROFILE", help="config.apply_judge_cli profile")
    ap.add_argument("--export-misses", type=Path, default=ROOT / "eval_artifacts" / "misses_failing165.jsonl")
    ap.add_argument("--triage", type=Path, default=ROOT / "eval_artifacts" / "triage_failing165.txt")
    ap.add_argument("--export-arena-json", type=Path, default=None, help="Optional: write Arena-shaped JSON for reuse")
    args = ap.parse_args()

    config.apply_judge_cli(args.judge)
    whisper_init_db()
    enforcer_init_db()

    if not args.failing.is_file():
        raise SystemExit(f"Missing export file: {args.failing}")

    items = parse_failing(args.failing)
    rows: list[tuple[list[dict[str, str]], str]] = []
    for e in items:
        lab = "harmful" if e["truth"] == "harmful" else "benign"
        rows.append((_msgs_from_request(e["request"]), lab))

    if args.export_arena_json:
        payload = [
            {"label": lab, "conversation": conv}
            for conv, lab in rows
        ]
        args.export_arena_json.parent.mkdir(parents=True, exist_ok=True)
        args.export_arena_json.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")
        print(f"Wrote {args.export_arena_json} ({len(payload)} rows)")

    print(f"=== Black Templar — Failing entries replay ===")
    print(f"Rows: {len(rows)}  |  judge: {config.get_llm_judge_display_name()}")
    print(f"Source: {args.failing}")
    run_eval(rows, export_misses=args.export_misses, triage_summary=args.triage, quiet=False)


if __name__ == "__main__":
    main()
