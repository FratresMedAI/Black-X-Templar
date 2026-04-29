"""
Gray Swan Arena — safeguard classifier API.

- POST /classify — legacy JSON: { "prompt", "history?" } → full guardrail dict
- POST /v1/classify — Arena contract: { "conversation": [ { "role", "content" }, ... ] }
  → { "violation": bool, "confidence": float }
"""

from __future__ import annotations

import json
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from pydantic import BaseModel, Field

import config
from advanced_guards import winning_2026_guardrail_with_judge
from enforcer import init_db as enforcer_init_db, log_detection
from whisper_detector import _init_db as whisper_init_db


@asynccontextmanager
async def _lifespan(app: FastAPI):
    whisper_init_db()
    enforcer_init_db()
    if os.environ.get("DARKSPACE_SKIP_CONTEST_BASELINE", "").lower() not in (
        "1",
        "true",
        "yes",
    ):
        config.validate_contest_baseline()
    else:
        config.enforce_security_baseline()
    yield


app = FastAPI(title="Black Templar Safeguard", lifespan=_lifespan)


class ClassifyBody(BaseModel):
    prompt: str
    history: list[str] = Field(default_factory=list)


class ArenaMessage(BaseModel):
    role: str
    content: str


class ArenaClassifyBody(BaseModel):
    conversation: list[ArenaMessage]


class ArenaClassifyResponse(BaseModel):
    violation: bool
    confidence: float = Field(ge=0.0, le=1.0)


def _conversation_to_prompt_history(
    messages: list[ArenaMessage],
) -> tuple[str, list[str] | None]:
    """Map Arena multi-turn thread to (latest user text, prior turns as role-tagged strings)."""
    if not messages:
        return "", None
    last_user: int | None = None
    for i in range(len(messages) - 1, -1, -1):
        if messages[i].role.strip().lower() == "user":
            last_user = i
            break
    idx = last_user if last_user is not None else len(messages) - 1
    prompt = (messages[idx].content or "").strip()
    hist: list[str] = []
    for m in messages[:idx]:
        hist.append(f"{m.role.strip()}: {(m.content or '').strip()}")
    return prompt, hist if hist else None


def _health_payload() -> dict:
    return {"status": "ok", "service": "black-templar", "version": "gray-swan-blue-v1"}


@app.get("/")
def root_health():
    """Gray Swan and load balancers often probe ``GET /``; bare FastAPI apps 404 without this route."""
    return _health_payload()


@app.get("/health")
def health():
    return _health_payload()


def _risk_from_confidence(verdict: str, confidence: float) -> float:
    if verdict == "safe":
        return max(0.0, min(10.0, 10.0 * (1.0 - confidence)))
    return max(5.0, min(9.9, 6.0 + 4.0 * (1.0 - confidence)))


def _audit_classify(
    source_ip: str,
    verdict: str,
    reason: str,
    confidence: float,
    metadata: dict,
) -> None:
    payload = {
        "verdict": verdict,
        "reason": reason[:500],
        "confidence": confidence,
        "stages": {k: metadata.get(k) for k in ("rebuff", "whisper", "enforcer", "mimicry")},
    }
    desc = json.dumps(payload, ensure_ascii=True)[:1000]
    log_detection(
        source_ip or "unknown",
        "SAFEGUARD_CLASSIFY",
        desc,
        risk_score=_risk_from_confidence(verdict, confidence),
    )


def classify_prompt(
    prompt: str,
    source_ip: str = "unknown",
    history: list[str] | None = None,
) -> dict:
    """Run winning 2026 guardrail with LLM-as-a-Judge and write one HMAC-signed audit row."""
    out = winning_2026_guardrail_with_judge(prompt or "", history)
    _audit_classify(
        source_ip,
        out["verdict"],
        out["reason"],
        out["confidence"],
        out["metadata"],
    )
    return out


@app.post("/classify")
def classify_endpoint(body: ClassifyBody, request: Request):
    client = request.client
    ip = client.host if client else "unknown"
    hist = body.history if body.history else None
    return classify_prompt(body.prompt, ip, hist)


@app.post("/v1/classify", response_model=ArenaClassifyResponse)
def arena_classify_endpoint(body: ArenaClassifyBody, request: Request):
    """Gray Swan Safeguards recommended schema: conversation in, violation + confidence out."""
    client = request.client
    ip = client.host if client else "unknown"
    prompt, hist = _conversation_to_prompt_history(body.conversation)
    out = classify_prompt(prompt, ip, hist)
    raw_c = float(out.get("confidence", 0.5))
    violation = str(out.get("verdict", "safe")) == "blocked"
    conf = max(0.0, min(1.0, raw_c))
    return ArenaClassifyResponse(violation=violation, confidence=round(conf, 3))


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "safeguard_api:app",
        host=config.SAFEGUARD_API_HOST,
        port=config.SAFEGUARD_API_PORT,
    )
