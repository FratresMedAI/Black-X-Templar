#!/usr/bin/env python3
"""
Quick local grid search over DARKSPACE_* threshold env vars using test_harness + real_2026 JSONL.
Does not import DARKSPACE modules in-process (fresh subprocess = clean config from env).

Usage:
  python tune_local_metrics.py
  python tune_local_metrics.py --quick
  python tune_local_metrics.py --judge no-llm-judge
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from itertools import product
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DEFAULT_DATASET = ROOT / "tests" / "real_2026_training_dataset.jsonl"


def _run_harness(env: dict[str, str], judge: str, dataset: Path) -> dict | None:
    merged = os.environ.copy()
    merged.update(env)
    proc = subprocess.run(
        [sys.executable, str(ROOT / "test_harness.py"), "--judge", judge, "--dataset", str(dataset)],
        cwd=str(ROOT),
        env=merged,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    out_path = ROOT / "test_results.json"
    if proc.returncode != 0 or not out_path.is_file():
        print(f"  [fail] rc={proc.returncode}", file=sys.stderr)
        if proc.stderr:
            print(proc.stderr[-2000:], file=sys.stderr)
        return None
    return json.loads(out_path.read_text(encoding="utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser(description="Grid search thresholds via test_harness subprocess")
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--judge", default="no-llm-judge")
    parser.add_argument("--quick", action="store_true", help="smaller grid (~4 runs)")
    parser.add_argument("--offline", action="store_true", default=True, help="set DARKSPACE_OFFLINE_ONLY=true")
    args = parser.parse_args()

    base_env: dict[str, str] = {}
    if args.offline:
        base_env["DARKSPACE_OFFLINE_ONLY"] = "true"

    if args.quick:
        sem = ["0.32", "0.34"]
        sec_floor = ["0.38", "0.40"]
        safe_c = ["0.48", "0.52"]
    else:
        sem = ["0.30", "0.32", "0.34", "0.36"]
        sec_floor = ["0.36", "0.38", "0.40"]
        safe_c = ["0.46", "0.50", "0.54"]

    rows: list[tuple[dict[str, str], dict]] = []
    for s, f, c in product(sem, sec_floor, safe_c):
        env = {
            **base_env,
            "DARKSPACE_SEMANTIC_THRESHOLD": s,
            "DARKSPACE_SECONDARY_SEMANTIC_FLOOR": f,
            "DARKSPACE_SAFE_CONFIDENCE_THRESHOLD": c,
        }
        label = f"sem={s} sec_floor={f} safe={c}"
        print(f"Running {label} ...")
        payload = _run_harness(env, args.judge, args.dataset)
        if payload is None:
            continue
        summ = payload["summary"]
        rows.append((env, summ))
        print(
            f"  -> acc={summ['accuracy']}% FPR={summ['fpr']}% FNR={summ['fnr']}% "
            f"lat={summ['avg_latency_ms']}ms"
        )

    if not rows:
        print("No successful runs.", file=sys.stderr)
        sys.exit(1)

    def arena_style_score(summ: dict) -> float:
        # Soft-ish emphasis on FPR (Arena uses softplus on FPR); keep simple for local ranking
        fpr = float(summ["fpr"])
        fnr = float(summ["fnr"])
        return max(0.0, fpr - 5.0) ** 2 * 0.5 + fnr * 1.5 - float(summ["accuracy"]) * 0.1

    best = min(rows, key=lambda x: arena_style_score(x[1]))
    print("\n=== Best (lower score = better for FPR-heavy objective) ===")
    b_env, b_sum = best
    tunables = {k: v for k, v in b_env.items() if k.startswith("DARKSPACE_") and k != "DARKSPACE_OFFLINE_ONLY"}
    print("env:", tunables)
    print("metrics:", json.dumps(b_sum, indent=2))


if __name__ == "__main__":
    main()
