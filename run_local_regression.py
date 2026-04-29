#!/usr/bin/env python3
"""Steps 8–9: run primary JSONL + minimal stress JSON; write eval_artifacts/regression_snapshot.txt"""
from __future__ import annotations

import argparse
from pathlib import Path

import config
from arena_eval import load_arena_json, load_prompt_jsonl, run_eval
from enforcer import init_db as enforcer_init_db
from whisper_detector import _init_db as whisper_init_db

ROOT = Path(__file__).resolve().parent
ART = ROOT / "eval_artifacts"
PRIMARY = ROOT / "tests" / "real_2026_training_dataset.jsonl"
STRESS = ROOT / "tests" / "stress_agentic_min.json"
OFFICIAL = ROOT / "data" / "gray_swan_train.json"


def main() -> None:
    ap = argparse.ArgumentParser(description="Local regression bundle for DARKSPACE")
    ap.add_argument("--judge", default=None, metavar="PROFILE", help="Same as test_harness --judge")
    args = ap.parse_args()
    config.apply_judge_cli(args.judge)

    whisper_init_db()
    enforcer_init_db()

    lines: list[str] = [
        "DARKSPACE local regression snapshot",
        f"Judge: {config.get_llm_judge_display_name()}",
        "",
    ]

    if PRIMARY.is_file():
        rows = load_prompt_jsonl(str(PRIMARY))
        r = run_eval(
            rows,
            export_misses=ART / "misses_primary.jsonl",
            triage_summary=ART / "triage_primary.txt",
            quiet=True,
        )
        lines.append(f"PRIMARY (tests/real_2026_training_dataset.jsonl): n={r['n']} acc={100*r['accuracy']:.1f}% FPR={100*r['fpr']:.1f}% FNR={100*r['fnr']:.1f}% score={r['preliminary_score']:.4f}")
    else:
        lines.append("PRIMARY: skipped (tests/real_2026_training_dataset.jsonl missing)")

    lines.append("")
    if STRESS.is_file():
        rows = load_arena_json(str(STRESS))
        r = run_eval(
            rows,
            export_misses=ART / "misses_stress.jsonl",
            triage_summary=ART / "triage_stress.txt",
            quiet=True,
        )
        lines.append(f"STRESS (tests/stress_agentic_min.json): n={r['n']} acc={100*r['accuracy']:.1f}% FPR={100*r['fpr']:.1f}% FNR={100*r['fnr']:.1f}% score={r['preliminary_score']:.4f}")
    else:
        lines.append("STRESS: skipped (tests/stress_agentic_min.json missing)")

    lines.append("")
    if OFFICIAL.is_file():
        rows = load_arena_json(str(OFFICIAL))
        r = run_eval(rows, export_misses=ART / "misses_official_train.jsonl", triage_summary=ART / "triage_official_train.txt", quiet=True)
        lines.append(f"OFFICIAL (data/gray_swan_train.json): n={r['n']} acc={100*r['accuracy']:.1f}% FPR={100*r['fpr']:.1f}% FNR={100*r['fnr']:.1f}% score={r['preliminary_score']:.4f}")
    else:
        lines.append("OFFICIAL: skipped (place Arena train JSON at data/gray_swan_train.json)")

    ART.mkdir(parents=True, exist_ok=True)
    out = ART / "regression_snapshot.txt"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(out.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
