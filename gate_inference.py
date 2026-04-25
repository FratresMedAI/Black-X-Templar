"""
OpenAI-compatible HTTP client for LLM judge inference (vLLM, TGI, gates).

Configuration via environment variables only. When DARKSPACE_MOCK_GATE=1, no HTTP
is performed (CPU-local validation).
"""

from __future__ import annotations

import json
import logging
import os
import time
from contextvars import ContextVar
from typing import Any

import httpx

import config

logger = logging.getLogger(__name__)

# Set by validation harness to align mock JSON with known labels (production never sets this).
_MOCK_EXPECT_SAFE: ContextVar[bool | None] = ContextVar("MOCK_EXPECT_SAFE", default=None)


def set_mock_expected_safe(value: bool | None) -> None:
    """When set, mock gate returns JSON matching this safety bit (for local eval)."""
    _MOCK_EXPECT_SAFE.set(value)


def _timeout_seconds() -> float:
    raw = os.environ.get("DARKSPACE_GATE_TIMEOUT_SECONDS", "300").strip()
    try:
        return max(30.0, float(raw))
    except ValueError:
        return 300.0


def _heuristic_safe_from_messages(messages: list[dict[str, str]]) -> bool:
    blob = " ".join(m.get("content", "") for m in messages).lower()
    attack_hits = (
        "ignore all previous",
        "ignore previous instructions",
        "jailbreak",
        "system prompt",
        "reveal your",
        "no restrictions",
        "without safety",
        "credential theft",
        "weaponize",
    )
    return not any(h in blob for h in attack_hits)


def _mock_completion_text(
    *,
    messages: list[dict[str, str]],
    model: str,
    max_tokens: int,
) -> str:
    override = _MOCK_EXPECT_SAFE.get(None)
    if override is not None:
        safe = override
        reason = "mock aligned to harness label"
    else:
        safe = _heuristic_safe_from_messages(messages)
        reason = "mock heuristic"
    payload = {
        "safe": safe,
        "confidence": 0.88 if safe else 0.91,
        "reason": reason,
    }
    return json.dumps(payload)


def chat_completion(
    *,
    messages: list[dict[str, str]],
    max_tokens: int,
    temperature: float = 0.0,
    base_url: str,
    api_key: str,
    model: str,
) -> str:
    """
    POST {base_url}/chat/completions (OpenAI schema), or mock when DARKSPACE_MOCK_GATE=1.
    """
    prefix = config.log_prefix()
    backend = "mock_gate" if config.is_mock_gate() else "openai_http"
    t0 = time.perf_counter()

    if config.is_mock_gate():
        out = _mock_completion_text(messages=messages, model=model, max_tokens=max_tokens)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        tok_in_est = sum(len(m.get("content", "")) for m in messages) // 4
        line = (
            f"{prefix} judge_gate model={model} backend={backend} latency_ms={elapsed_ms:.2f} "
            f"tok_in_est={tok_in_est} tok_out_est={max_tokens} resp_snip={out[:120]!r}"
        )
        logger.info(line)
        print(line, flush=True)
        return out

    url = f"{base_url.rstrip('/')}/chat/completions"
    headers: dict[str, str] = {"Content-Type": "application/json"}
    key = (api_key or "").strip()
    if key:
        headers["Authorization"] = f"Bearer {key}"

    body: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "max_tokens": int(max_tokens),
        "temperature": float(temperature),
    }

    timeout = _timeout_seconds()
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.post(url, json=body, headers=headers)
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPStatusError as e:
        logger.error(
            "%s Gate HTTP error: %s %s",
            prefix,
            e.response.status_code,
            e.response.text[:500],
        )
        raise
    except Exception as e:
        logger.error("%s Gate request failed: %s", prefix, e)
        raise

    elapsed_ms = (time.perf_counter() - t0) * 1000
    usage = data.get("usage") or {}
    tok_in = usage.get("prompt_tokens", "n/a")
    tok_out = usage.get("completion_tokens", "n/a")

    choices = data.get("choices") or []
    if not choices:
        raise RuntimeError("Gate response missing choices")
    msg = choices[0].get("message") or {}
    content = msg.get("content")
    if content is None:
        raise RuntimeError("Gate response missing message.content")
    text = str(content)
    line = (
        f"{prefix} judge_gate model={model} backend={backend} latency_ms={elapsed_ms:.2f} "
        f"tok_in={tok_in} tok_out={tok_out} resp_snip={text[:120].replace(chr(10), ' ')!r}"
    )
    logger.info(line)
    print(line, flush=True)
    return text


def resolve_gate_model(fallback_hf_id: str) -> str:
    explicit = os.environ.get("DARKSPACE_GATE_MODEL", "").strip()
    if explicit:
        return explicit
    if config.is_mock_gate():
        return config.get_vllm_model_id()
    return fallback_hf_id.strip()
