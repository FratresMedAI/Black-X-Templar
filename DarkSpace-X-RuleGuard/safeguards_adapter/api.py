"""
Lightweight HTTP adapter wrapping stateless `classify_text` (see repository `docs/API.md`).
"""

from __future__ import annotations

import json
import os

from fastapi import FastAPI
from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator

from safeguards_adapter.core import Classification, __version__, classify_text

app = FastAPI(title="RuleGuard Safeguards Adapter", version=__version__)


class ConversationTurn(BaseModel):
    """Recommended JSON body: multi-turn role/content messages."""

    model_config = ConfigDict(extra="ignore")

    role: str = ""
    content: str = ""


class ClassifyRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    conversation: list[ConversationTurn] | None = Field(
        default=None,
        description="Multi-turn messages to classify",
    )
    text: str = Field(
        default="",
        validation_alias=AliasChoices("text", "message", "content", "input", "prompt", "user_message"),
        description="User-visible message or full trace slice",
    )
    tool_trace: str | None = Field(
        default=None,
        validation_alias=AliasChoices("tool_trace", "tool_calls", "tools", "trace", "tooling"),
        description="Optional JSON/tool line for enforcer patterns",
    )
    session_id: str | None = Field(
        default=None,
        validation_alias=AliasChoices("session_id", "session", "conversation_id"),
        description="Optional session key for future rate limits",
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
    """Classifier output: violation flag + confidence plus debug fields."""

    violation: bool
    confidence: float = Field(..., ge=0.0, le=1.0)
    decision: str
    risk_score: float
    reason_codes: list[str] = Field(default_factory=list)
    detail: str | None = None
    version: str = __version__


def _flatten_conversation(turns: list[ConversationTurn]) -> str:
    return "\n".join(f"{t.role}: {t.content}" for t in turns)


def _user_text_from_conversation(turns: list[ConversationTurn]) -> str:
    parts = [(t.content or "").strip() for t in turns if t.role.strip().lower() == "user"]
    return "\n".join(p for p in parts if p)


def _tool_trace_from_conversation(turns: list[ConversationTurn]) -> str | None:
    """Use last assistant (or tool) message as structured trace for enforcer patterns."""
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
    """
    Optional confidence-only harnesses treat confidence > 0.5 as violation.
    We always set violation explicitly; for allows we cap confidence at 0.5.
    """
    if c.decision == "block":
        return True, min(1.0, max(c.risk_score / 10.0, 0.51))
    return False, min(0.5, c.risk_score / 10.0)


def _threshold() -> float:
    # Default aligns with production image; override via SAFEGUARDS_BLOCK_THRESHOLD.
    raw = os.environ.get("SAFEGUARDS_BLOCK_THRESHOLD", "5.4")
    try:
        return float(raw)
    except ValueError:
        return 5.4


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


@app.get("/ready")
def ready() -> dict[str, str]:
    return {"status": "ready", "version": __version__}


@app.get("/")
def root() -> dict[str, str]:
    return {"service": "darkspace-safeguards", "version": __version__}


def _classify_response(req: ClassifyRequest) -> ClassifyResponse:
    text, tool, user_slice = _resolved_inputs(req)
    c: Classification = classify_text(
        text,
        tool,
        user_text=user_slice,
        block_threshold=_threshold(),
    )
    viol, conf = _violation_and_confidence(c)
    return ClassifyResponse(
        violation=viol,
        confidence=conf,
        decision=c.decision,
        risk_score=c.risk_score,
        reason_codes=c.reason_codes,
        detail=c.detail,
        version=__version__,
    )


@app.post("/v1/classify", response_model=ClassifyResponse)
def classify_v1(req: ClassifyRequest) -> ClassifyResponse:
    return _classify_response(req)


@app.post("/classify", response_model=ClassifyResponse)
def classify_root(req: ClassifyRequest) -> ClassifyResponse:
    """Same handler as /v1/classify for harnesses that omit the version prefix."""
    return _classify_response(req)
