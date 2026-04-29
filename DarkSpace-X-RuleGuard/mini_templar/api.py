"""
HTTP surface: FastAPI classifier with Mini Templar scoring (`classify_mini_templar`).
"""

from __future__ import annotations

import json
import os

from fastapi import FastAPI, Request
from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator

from safeguards_adapter.core import Classification

from mini_templar import __version__
from mini_templar.core import classify_mini_templar

app = FastAPI(title="RuleGuard (Mini Templar)", version=__version__)


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
    version: str = __version__
    mini_rescue: bool = False
    mini_entropy: str | None = None


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


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__, "flavor": "ruleguard", "service": "ruleguard"}


@app.get("/ready")
def ready() -> dict[str, str]:
    return {"status": "ready", "version": __version__}


@app.get("/")
def root() -> dict[str, str | list[str]]:
    return {
        "service": "ruleguard",
        "version": __version__,
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


def _classify_response(req: ClassifyRequest) -> ClassifyResponse:
    text, tool, user_slice = _resolved_inputs(req)
    result = classify_mini_templar(
        text,
        tool,
        user_text=user_slice,
        block_threshold=_threshold(),
    )
    c = result.classification
    viol, conf = _violation_and_confidence(c)
    return ClassifyResponse(
        violation=viol,
        confidence=conf,
        decision=c.decision,
        risk_score=c.risk_score,
        reason_codes=c.reason_codes,
        detail=c.detail,
        version=__version__,
        mini_rescue=result.rescue_applied,
        mini_entropy=result.entropy_verdict,
    )


@app.post("/v1/classify", response_model=ClassifyResponse)
def classify_v1(req: ClassifyRequest, request: Request) -> ClassifyResponse:
    return _classify_response(req)


@app.post("/v1/classify/", response_model=ClassifyResponse)
def classify_v1_slash(req: ClassifyRequest, request: Request) -> ClassifyResponse:
    return _classify_response(req)


@app.post("/classify", response_model=ClassifyResponse)
def classify_root(req: ClassifyRequest, request: Request) -> ClassifyResponse:
    return _classify_response(req)


@app.post("/classify/", response_model=ClassifyResponse)
def classify_root_slash(req: ClassifyRequest, request: Request) -> ClassifyResponse:
    return _classify_response(req)


@app.post("/api/v1/classify", response_model=ClassifyResponse)
def classify_api_v1(req: ClassifyRequest, request: Request) -> ClassifyResponse:
    return _classify_response(req)


@app.post("/api/classify", response_model=ClassifyResponse)
def classify_api_short(req: ClassifyRequest, request: Request) -> ClassifyResponse:
    return _classify_response(req)


@app.post("/", response_model=ClassifyResponse)
def classify_post_root(req: ClassifyRequest, request: Request) -> ClassifyResponse:
    return _classify_response(req)


@app.post("/{catch_all:path}", response_model=ClassifyResponse, include_in_schema=False)
def classify_post_catch_all(
    catch_all: str,
    req: ClassifyRequest,
    request: Request,
) -> ClassifyResponse:
    return _classify_response(req)
