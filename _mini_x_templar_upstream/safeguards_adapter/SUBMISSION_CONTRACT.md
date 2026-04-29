# Gray Swan Safeguards — submission contract (fill from Arena)

**Purpose:** Single source of truth for integrating this adapter with the live challenge harness.  
**Public rules:** https://app.grayswan.ai/arena/challenge/safeguards/rules

## Captured from public materials (not a substitute for signed-in docs)

- **Challenge:** Safeguards — blue teams defend a multi-agent customer support stack; scoring balances **attack blocking** and **legitimate customer usability** (false positives hurt).
- **Artifact types (stated in rules):** containers, system prompt configurations, and (closed leaderboard) classifier endpoints.
- **Eligibility:** Defenses must be **fully reproducible**; prize copy references **published open** solutions for blue team — confirm exact wording at submit time.
- **Account:** One blue-team account per **organization**.

## Captured from Arena (Safeguards classifier submit UI)

| Field | Value |
|--------|--------|
| **Request (recommended)** | `{"conversation":[{"role":"string","content":"string"},...]}` |
| **Response (recommended)** | `{"violation": boolean, "confidence": number}` optional `confidence` 0.0–1.0; if `violation` absent, harness treats `confidence > 0.5` as violation |
| **Health** | `GET /health` (this repo) |
| **Classify** | `POST /v1/classify` and `POST /classify` |
| Port (container) | `8080` |

### Mini X Templar (this repository)

**Root `Dockerfile.api`** — MxT HTTP service for Arena (NOT the root `Dockerfile`, which is offline PSF only):

```bash
docker build --platform linux/amd64 --provenance=false --sbom=false \
  -f Dockerfile.api \
  -t occisorleonum/mini-x-templar-gray-swan:grayswan-2026-04-24 .
```

- **CMD:** `uvicorn mini_templar.api:app` on **8080**
- **Default env:** `SAFEGUARDS_BLOCK_THRESHOLD=5.5`, `MINI_CORROBORATION_RESCUE=1`

The **`safeguards_adapter/`** folder here is a vendored rules engine; the published HTTP API is **`mini_templar.api`**.

## HTTP API (Mini Templar)

- `GET /health` — liveness (`flavor`: **`black-x-templar`**).
- `GET /ready` — readiness.
- `POST /v1/classify` / `POST /classify` — **Gray Swan** body: `conversation` array as above.  
  Also accepts legacy: `{"text", "tool_trace", "session_id}` and common aliases (see `mini_templar/api.py`).
- **Response:** `violation`, `confidence` (per Arena), plus `decision`, `risk_score`, `reason_codes`, `detail`, `version`, `mini_rescue`, `mini_entropy` for debugging.

**Hugging Face slug / optional system prompt** in the submit form apply only if you use those submission types; this codebase is **container or URL** + HTTP classify.

## Blockers checklist

- [ ] Logged into app.grayswan.ai and copied official request/response schema
- [ ] Confirmed whether SQLite or local disk is allowed in the hot path
- [ ] Confirmed secrets policy (this service uses env vars only; no keys in image)

## Implementation status (local)

- **Todo 1 (spec template):** This document + public rules links — **still need your Arena UI paste** into the table above.
- **Todo 2 (core extract):** `safeguards_adapter/core.py` — stateless rebuff + enforcer merge, corroboration for weak pattern scores.
- **Todo 3 (HTTP adapter):** `safeguards_adapter/api.py`, `Dockerfile`, `requirements.txt`, `README.md` — provisional `POST /v1/classify`.
- **Tests:** `safeguards_adapter/tests/test_core.py` — run from repo root:  
  `PYTHONPATH=. python -m pytest safeguards_adapter/tests/test_core.py`
