"""
RuleGuard production API — FastAPI app `safeguard_api:app` (port 8080 in container).

- Scoring: `classify_mini_templar` with JSON contract shared by `mini_templar/api.py`.
- Multiple POST routes (`/`, `/api/…`, catch-all) so reverse proxies and compliance probes always hit a classifier.

Local harness: `classify_prompt`, `ChatMessage`, `_conversation_to_prompt_history`.
"""

from __future__ import annotations

import json
import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator

import config
from enforcer import init_db as enforcer_init_db, log_detection
from whisper_detector import _init_db as whisper_init_db

_ROOT = Path(__file__).resolve().parent
_MXT = _ROOT / "_mini_x_templar_upstream"
if (_MXT / "mini_templar" / "core.py").is_file() and str(_MXT) not in sys.path:
    sys.path.insert(0, str(_MXT))

from safeguards_adapter.core import Classification

from mini_templar import __codename__, __version__ as _PSF_VERSION
from mini_templar.core import classify_mini_templar


def _skip_mirror_startup_smoke() -> bool:
    for key in ("DARKSPACE_SKIP_MIRROR_STARTUP", "DARKSPACE_SKIP_CONTEST_BASELINE"):
        if os.environ.get(key, "").strip().lower() in ("1", "true", "yes"):
            return True
    return False


@asynccontextmanager
async def _lifespan(app: FastAPI):
    whisper_init_db()
    enforcer_init_db()
    if not _skip_mirror_startup_smoke():
        config.validate_mirror_startup_smoke()
    else:
        config.enforce_security_baseline()
    yield


app = FastAPI(title="RuleGuard", version=_PSF_VERSION, lifespan=_lifespan)


class ChatMessage(BaseModel):
    role: str
    content: str


class ConversationTurn(BaseModel):
    model_config = ConfigDict(extra="ignore")

    role: str = ""
    content: str = ""


class ClassifyRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    conversation: list[ConversationTurn] | None = Field(default=None)
    text: str = Field(
        default="",
        validation_alias=AliasChoices("text", "message", "content", "input", "prompt", "user_message"),
    )
    tool_trace: str | None = Field(
        default=None,
        validation_alias=AliasChoices("tool_trace", "tool_calls", "tools", "trace", "tooling"),
    )
    session_id: str | None = Field(
        default=None,
        validation_alias=AliasChoices("session_id", "session", "conversation_id"),
    )

    @field_validator("tool_trace", mode="before")
    @classmethod
    def _coerce_tool_trace(cls, v: object) -> str | None:
        if v is None:
            return None
        if isinstance(v, (dict, list)):
            return json.dumps(v, separators=(",", ":"), default=str)
        return str(v)


class ClassifyResponse(BaseModel):
    violation: bool
    confidence: float = Field(..., ge=0.0, le=1.0)
    decision: str
    risk_score: float
    reason_codes: list[str] = Field(default_factory=list)
    detail: str | None = None
    version: str = _PSF_VERSION
    mini_rescue: bool = False
    mini_entropy: str | None = None


def _conversation_to_prompt_history(
    messages: list[ChatMessage],
) -> tuple[str, list[str] | None]:
    """Map multi-turn thread to (latest user text, prior turns as role-tagged strings)."""
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
    for j, m in enumerate(messages):
        if j == idx:
            continue
        hist.append(f"{m.role.strip()}: {(m.content or '').strip()}")
    return prompt, hist if hist else None


def _flatten_conversation(turns: list[ConversationTurn]) -> str:
    return "\n".join(f"{t.role}: {t.content}" for t in turns)


def _user_text_from_conversation(turns: list[ConversationTurn]) -> str:
    parts = [(t.content or "").strip() for t in turns if t.role.strip().lower() == "user"]
    return "\n".join(p for p in parts if p)


def _tool_trace_from_conversation(turns: list[ConversationTurn]) -> str | None:
    for t in reversed(turns):
        if t.role.lower() in ("assistant", "tool", "function"):
            c = (t.content or "").strip()
            if c:
                return c
    return None


def _resolved_inputs(req: ClassifyRequest) -> tuple[str, str | None, str]:
    prepend = (req.text or "").strip()
    if req.conversation:
        text = _flatten_conversation(req.conversation)
        tool = _tool_trace_from_conversation(req.conversation)
        user_slice = _user_text_from_conversation(req.conversation)
        if prepend:
            text = f"{prepend}\n{text}"
            user_slice = f"{prepend}\n{user_slice}".strip()
        return text, req.tool_trace or tool, user_slice or text
    base = req.text or ""
    return base, req.tool_trace, base


def _violation_and_confidence(c: Classification) -> tuple[bool, float]:
    if c.decision == "block":
        return True, min(1.0, max(c.risk_score / 10.0, 0.51))
    return False, min(0.5, max(0.0, c.risk_score / 10.0))


def _threshold() -> float:
    raw = os.environ.get("SAFEGUARDS_BLOCK_THRESHOLD", "5.4")
    try:
        return float(raw)
    except ValueError:
        return 5.4


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


def _mini_inputs(prompt: str, history: list[str] | None) -> tuple[str, str | None, str]:
    rows = [h.strip() for h in (history or []) if (h or "").strip()]
    user_text = (prompt or "").strip()
    user_chunks: list[str] = []
    for row in rows:
        low = row.lower()
        if low.startswith("user:"):
            part = row.split(":", 1)[1].strip()
            if part:
                user_chunks.append(part)
    if user_text:
        rows.append(f"user: {user_text}")
        user_chunks.append(user_text)
    # Match HTTP `_user_text_from_conversation`: all user-role text, not only the last turn.
    combined_user = "\n".join(user_chunks).strip()
    text = "\n".join(rows).strip() or user_text
    tool_trace: str | None = None
    for row in reversed(rows):
        low = row.lower()
        if low.startswith(("assistant:", "tool:", "function:")):
            tool_trace = row.split(":", 1)[1].strip()
            if tool_trace:
                break
    return text, tool_trace, (combined_user or user_text)


def _run_psf(
    text: str,
    tool: str | None,
    user_slice: str | None,
    source_ip: str,
) -> tuple[ClassifyResponse, dict]:
    """Single Parva scoring path; returns HTTP model + legacy audit dict."""
    result = classify_mini_templar(
        text,
        tool,
        user_text=user_slice or None,
        block_threshold=_threshold(),
    )
    c = result.classification
    viol, conf = _violation_and_confidence(c)
    resp = ClassifyResponse(
        violation=viol,
        confidence=round(conf, 3),
        decision=c.decision,
        risk_score=c.risk_score,
        reason_codes=c.reason_codes,
        detail=c.detail,
        version=_PSF_VERSION,
        mini_rescue=result.rescue_applied,
        mini_entropy=result.entropy_verdict,
    )
    verdict = "blocked" if c.decision == "block" else "safe"
    meta = {
        "technique": "ruleguard_mini_templar",
        "codename": __codename__,
        "mini_templar": {
            "decision": c.decision,
            "risk_score": c.risk_score,
            "detail": c.detail,
            "reason_codes": c.reason_codes[:12],
            "rescue_applied": result.rescue_applied,
            "entropy": result.entropy_verdict,
            "max_user_hit": result.max_user_hit,
        },
        "rebuff": c.detail,
        "whisper": result.entropy_verdict,
        "enforcer": None,
        "mimicry": None,
    }
    reason = "; ".join(c.reason_codes) or (c.detail or "mini_templar")
    _audit_classify(source_ip, verdict, reason, resp.confidence, meta)
    legacy = {
        "verdict": verdict,
        "reason": reason,
        "confidence": resp.confidence,
        "metadata": meta,
    }
    return resp, legacy


def classify_prompt(
    prompt: str,
    source_ip: str = "unknown",
    history: list[str] | None = None,
) -> dict:
    """In-process hook: same Parva path as HTTP, legacy dict shape for harnesses."""
    text, tool_trace, user_text = _mini_inputs(prompt or "", history)
    _, legacy = _run_psf(text, tool_trace, user_text, source_ip)
    return legacy


def ruleguard_stack_classify(prompt: str, history: list[str] | None = None) -> dict:
    """In-process alias: same path as HTTP classification (harness / notebooks)."""
    return classify_prompt(prompt, "harness", history)


def _http_classify(req: ClassifyRequest, request: Request) -> ClassifyResponse:
    text, tool, user_slice = _resolved_inputs(req)
    ip = request.client.host if request.client else "unknown"
    resp, _ = _run_psf(text, tool, user_slice or None, ip)
    return resp


@app.get("/health")
def health() -> dict[str, str]:
    """Health check; fields stable for load balancers and monitoring."""
    return {
        "status": "ok",
        "version": _PSF_VERSION,
        "flavor": "ruleguard",
        "service": "ruleguard",
        "codename": __codename__,
    }


@app.get("/ready")
def ready() -> dict[str, str]:
    return {"status": "ready", "version": _PSF_VERSION, "service": "ruleguard"}


@app.get("/")
def root() -> dict[str, str]:
    return {
        "service": "ruleguard",
        "codename": __codename__,
        "version": _PSF_VERSION,
        "classify_post": [
            "/v1/classify",
            "/v1/classify/",
            "/classify",
            "/classify/",
            "/api/v1/classify",
            "/api/classify",
            "/",
            "(any other path → POST catch-all)",
        ],
    }


@app.post("/v1/classify", response_model=ClassifyResponse)
def classify_v1(req: ClassifyRequest, request: Request) -> ClassifyResponse:
    return _http_classify(req, request)


@app.post("/v1/classify/", response_model=ClassifyResponse)
def classify_v1_slash(req: ClassifyRequest, request: Request) -> ClassifyResponse:
    return _http_classify(req, request)


@app.post("/classify", response_model=ClassifyResponse)
def classify_root(req: ClassifyRequest, request: Request) -> ClassifyResponse:
    return _http_classify(req, request)


@app.post("/classify/", response_model=ClassifyResponse)
def classify_root_slash(req: ClassifyRequest, request: Request) -> ClassifyResponse:
    return _http_classify(req, request)


@app.post("/api/v1/classify", response_model=ClassifyResponse)
def classify_api_v1(req: ClassifyRequest, request: Request) -> ClassifyResponse:
    return _http_classify(req, request)


@app.post("/api/classify", response_model=ClassifyResponse)
def classify_api_short(req: ClassifyRequest, request: Request) -> ClassifyResponse:
    return _http_classify(req, request)


@app.post("/", response_model=ClassifyResponse)
def classify_post_root(req: ClassifyRequest, request: Request) -> ClassifyResponse:
    """Some deployments POST the service base URL with an empty path."""
    return _http_classify(req, request)


@app.post("/{catch_all:path}", response_model=ClassifyResponse, include_in_schema=False)
def classify_post_catch_all(
    catch_all: str,
    req: ClassifyRequest,
    request: Request,
) -> ClassifyResponse:
    """Last resort: any POST path classifies (proxies / typos). Register after explicit routes."""
    return _http_classify(req, request)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "safeguard_api:app",
        host=config.SAFEGUARD_API_HOST,
        port=config.SAFEGUARD_API_PORT,
    )
