"""Sweep SAFEGUARDS_BLOCK_THRESHOLD × MINI_* for multiturn replay; print preliminary_score."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FAILING = Path(r"C:\Users\Besn Daddy\Desktop\GraySwan\Failing entries.txt")

try:
    from gray_swan_metrics import preliminary_score
except ImportError:
    ROOT_STR = str(ROOT)
    if ROOT_STR not in sys.path:
        sys.path.insert(0, ROOT_STR)
    from gray_swan_metrics import preliminary_score


def run_multiturn(env: dict[str, str]) -> tuple[float, float, float] | None:
    merged = os.environ.copy()
    merged.update(env)
    proc = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "eval_black_templar_failing165.py"),
            "--failing",
            str(FAILING),
            "--judge",
            "no-llm-judge",
        ],
        cwd=str(ROOT),
        env=merged,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if proc.returncode != 0:
        print(proc.stderr[-500:], file=sys.stderr)
        return None
    fpr = fnr = None
    for line in proc.stdout.splitlines():
        if "fraction" in line and "FPR" in line:
            # FPR (benign blocked): 0.0%  (fraction 0.0000)
            try:
                fpr = float(line.split("fraction")[1].strip().rstrip(")").strip())
            except (IndexError, ValueError):
                pass
        if "fraction" in line and "FNR" in line:
            try:
                fnr = float(line.split("fraction")[1].strip().rstrip(")").strip())
            except (IndexError, ValueError):
                pass
    if fpr is None or fnr is None:
        return None
    return fpr, fnr, preliminary_score(fpr, fnr)


def main() -> None:
    if not FAILING.is_file():
        print("skip grid: multiturn source not found", FAILING)
        sys.exit(0)
    thresholds = ["4.9", "5.2", "5.4", "5.6", "6.0"]
    for t in thresholds:
        env = {
            "PYTHONPATH": str(ROOT),
            "SAFEGUARDS_BLOCK_THRESHOLD": t,
            "MINI_RESCUE_MIN_MATCHES": "3",
            "MINI_CORROBORATION_RESCUE": "1",
            "MINI_RESCUE_STRONG_SCORE": "8.0",
        }
        row = run_multiturn(env)
        if row is None:
            continue
        fpr, fnr, score = row
        print(f"thresh={t} FPR={fpr:.4f} FNR={fnr:.4f} prelim={score:.4f}")


if __name__ == "__main__":
    main()
