#!/usr/bin/env python3
"""
Evaluate DARKSPACE with Gray Swan preliminary scoring.

Formats:
  --format arena   JSON array of { conversation|messages, label } (default)
  --format jsonl   JSONL with { prompt, label } label in safe|adversarial (harness style)

Usage:
  python arena_eval.py tests/real_2026_training_dataset.jsonl --format jsonl --export-misses eval_artifacts/misses.jsonl
  python arena_eval.py data/gray_swan_train.json --triage-summary eval_artifacts/triage.txt
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import config
from gray_swan_metrics import preliminary_score


def _norm_label(raw: Any) -> str | None:
    if raw is None:
        return None
    s = str(raw).strip().lower()
    if s in ("benign", "safe", "0", "false", "negative", "ok"):
        return "benign"
    if s in ("harmful", "unsafe", "adversarial", "attack", "malicious", "1", "true", "positive"):
        return "harmful"
    return None


def load_arena_json(path: str) -> list[tuple[list[dict[str, str]], str]]:
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(path)
    raw = json.loads(p.read_text(encoding="utf-8"))
    rows: list[tuple[list[dict[str, str]], str]] = []

    if isinstance(raw, dict):
        if "conversations" in raw:
            raw = raw["conversations"]
        elif "data" in raw:
            raw = raw["data"]
        else:
            raw = [raw]

    if not isinstance(raw, list):
        raise ValueError("Top-level JSON must be a list or an object containing a list")

    for i, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ValueError(f"Row {i}: expected object, got {type(item)}")
        conv = item.get("conversation") or item.get("messages")
        if conv is None:
            raise ValueError(
                f"Row {i}: need 'conversation' or 'messages' array "
                f"(keys found: {list(item.keys())[:12]})"
            )
        label = _norm_label(
            item.get("label")
            or item.get("ground_truth")
            or item.get("groundTruth")
            or item.get("is_harmful")
            or item.get("harmful")
        )
        if label is None:
            raise ValueError(f"Row {i}: could not parse benign/harmful label from record")
        msgs: list[dict[str, str]] = []
        for j, m in enumerate(conv):
            if not isinstance(m, dict):
                raise ValueError(f"Row {i} message {j}: expected object")
            role = str(m.get("role", "")).strip()
            content = str(m.get("content", ""))
            msgs.append({"role": role, "content": content})
        rows.append((msgs, label))
    if not rows:
        raise ValueError("No rows loaded")
    return rows


def load_prompt_jsonl(path: str) -> list[tuple[list[dict[str, str]], str]]:
    """Harness-style JSONL: one user turn per row (single-turn approximation)."""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(path)
    rows: list[tuple[list[dict[str, str]], str]] = []
    with p.open(encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            if "prompt" not in row:
                raise ValueError(f"Line {line_num}: missing 'prompt'")
            raw_lab = row.get("label", "")
            if raw_lab == "safe":
                lab = "benign"
            elif raw_lab == "adversarial":
                lab = "harmful"
            else:
                nl = _norm_label(raw_lab)
                if nl is None:
                    raise ValueError(f"Line {line_num}: invalid label {raw_lab!r}")
                lab = nl
            prompt = str(row["prompt"])
            rows.append(([{"role": "user", "content": prompt}], lab))
    if not rows:
        raise ValueError("No rows loaded from JSONL")
    return rows


def _rows_to_pydantic(msgs: list[dict[str, str]]):
    from safeguard_api import ArenaMessage

    return [ArenaMessage(role=m["role"], content=m["content"]) for m in msgs]


def classify_conversation(msgs: list[dict[str, str]]) -> tuple[bool, float]:
    from safeguard_api import classify_prompt, _conversation_to_prompt_history

    pyd = _rows_to_pydantic(msgs)
    prompt, hist = _conversation_to_prompt_history(pyd)
    out = classify_prompt(prompt, "arena_eval", hist)
    violation = str(out.get("verdict")) == "blocked"
    conf = float(out.get("confidence", 0.5))
    return violation, max(0.0, min(1.0, conf))


def _last_user_snippet(msgs: list[dict[str, str]], max_len: int = 220) -> str:
    for m in reversed(msgs):
        if m.get("role", "").strip().lower() == "user":
            t = (m.get("content") or "").replace("\n", " ").strip()
            return t[:max_len] + ("…" if len(t) > max_len else "")
    t = (msgs[-1].get("content") or "").replace("\n", " ").strip() if msgs else ""
    return t[:max_len] + ("…" if len(t) > max_len else "")


def write_triage_summary(misses: list[dict[str, Any]], path: Path) -> None:
    fp = [m for m in misses if m.get("error") == "false_positive"]
    fn = [m for m in misses if m.get("error") == "false_negative"]
    lines = [
        "DARKSPACE triage (automated)",
        f"False positives (benign blocked): {len(fp)}",
        f"False negatives (harmful missed): {len(fn)}",
        "",
        "--- False positives (preview) ---",
    ]
    for m in fp[:40]:
        conv = m.get("conversation") or []
        lines.append(f"  idx={m.get('index')} conf={m.get('confidence')} | {_last_user_snippet(conv)}")
    lines.extend(["", "--- False negatives (preview) ---"])
    for m in fn[:40]:
        conv = m.get("conversation") or []
        lines.append(f"  idx={m.get('index')} conf={m.get('confidence')} | {_last_user_snippet(conv)}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_eval(
    rows: list[tuple[list[dict[str, str]], str]],
    export_misses: Path | None = None,
    triage_summary: Path | None = None,
    quiet: bool = False,
) -> dict[str, Any]:
    n_benign = sum(1 for _, lab in rows if lab == "benign")
    n_harm = sum(1 for _, lab in rows if lab == "harmful")

    benign_wrong = 0
    harm_wrong = 0
    misses: list[dict[str, Any]] = []

    for i, (msgs, lab) in enumerate(rows):
        viol, conf = classify_conversation(msgs)
        expected_viol = lab == "harmful"
        ok = viol == expected_viol
        if lab == "benign":
            if not ok:
                benign_wrong += 1
                misses.append(
                    {
                        "index": i,
                        "error": "false_positive",
                        "label": lab,
                        "violation": viol,
                        "confidence": conf,
                        "conversation": msgs,
                    }
                )
        else:
            if not ok:
                harm_wrong += 1
                misses.append(
                    {
                        "index": i,
                        "error": "false_negative",
                        "label": lab,
                        "violation": viol,
                        "confidence": conf,
                        "conversation": msgs,
                    }
                )

    fpr = (benign_wrong / n_benign) if n_benign else 0.0
    fnr = (harm_wrong / n_harm) if n_harm else 0.0
    acc = (len(rows) - benign_wrong - harm_wrong) / len(rows)
    score = preliminary_score(fpr, fnr)

    if not quiet:
        print("=== ARENA-SHAPED EVAL (local) ===")
        print(f"Rows: {len(rows)}  (benign={n_benign}, harmful={n_harm})")
        print(f"Accuracy:  {100*acc:.1f}%")
        print(f"FPR (benign blocked): {100*fpr:.1f}%  (fraction {fpr:.4f})")
        print(f"FNR (harmful missed): {100*fnr:.1f}%  (fraction {fnr:.4f})")
        print(f"Preliminary score (lower better): {score:.4f}")
        print(f"Judge profile: {config.get_llm_judge_display_name()}")

    if export_misses and misses:
        export_misses.parent.mkdir(parents=True, exist_ok=True)
        with export_misses.open("w", encoding="utf-8") as f:
            for m in misses:
                f.write(json.dumps(m, ensure_ascii=True) + "\n")
        if not quiet:
            print(f"Wrote {len(misses)} misses to {export_misses}")

    if triage_summary and misses:
        write_triage_summary(misses, triage_summary)
        if not quiet:
            print(f"Wrote triage summary to {triage_summary}")

    return {
        "n": len(rows),
        "n_benign": n_benign,
        "n_harmful": n_harm,
        "accuracy": acc,
        "fpr": fpr,
        "fnr": fnr,
        "preliminary_score": score,
        "misses": len(misses),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Arena / JSONL evaluation + preliminary score")
    parser.add_argument("dataset", help="Path to JSON (arena) or JSONL (prompt per line)")
    parser.add_argument(
        "--format",
        choices=("arena", "jsonl"),
        default="arena",
        help="arena=conversation JSON; jsonl=harness prompt+label lines",
    )
    parser.add_argument("--judge", default=None, metavar="PROFILE", help="config.apply_judge_cli profile")
    parser.add_argument("--export-misses", default=None, metavar="PATH", help="JSONL of wrong predictions")
    parser.add_argument("--triage-summary", default=None, metavar="PATH", help="Human-readable miss preview")
    args = parser.parse_args()

    config.apply_judge_cli(args.judge)
    from enforcer import init_db as enforcer_init_db
    from whisper_detector import _init_db as whisper_init_db

    whisper_init_db()
    enforcer_init_db()

    if args.format == "jsonl":
        rows = load_prompt_jsonl(args.dataset)
    else:
        rows = load_arena_json(args.dataset)

    export_path = Path(args.export_misses) if args.export_misses else None
    triage_path = Path(args.triage_summary) if args.triage_summary else None
    run_eval(rows, export_misses=export_path, triage_summary=triage_path, quiet=False)


if __name__ == "__main__":
    main()
