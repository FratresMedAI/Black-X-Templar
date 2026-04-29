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

### Mini X Templar (MxT)

**Separate repository and Docker image** from DARKSPACE Safeguards. MxT adds lift/rescue/entropy on top of the same rules engine; do not bundle it with this `darkspace-gray-swan-blue` submission.

- **Source:** [https://github.com/FratresMedAI/Mini-X-Templar-Gray-Swan](https://github.com/FratresMedAI/Mini-X-Templar-Gray-Swan)  
- **Default Docker Hub image (per repo README):** `occisorleonum/mini-x-templar-gray-swan:grayswan-2026-04-24` (port **8080**).  
- **Relationship:** `Mini-X-Templar-Gray-Swan` vendors `safeguards_adapter/` from this Darkspace tree; sync on release. Darkspace is adapter-focused: [https://github.com/FratresMedAI/darkspace-gray-swan-blue](https://github.com/FratresMedAI/darkspace-gray-swan-blue).

## API implemented in this repo

- `GET /health` — liveness.
- `GET /ready` — readiness (same as health for now).
- `POST /v1/classify` / `POST /classify` — **Gray Swan** body: `conversation` array as above.  
  Also accepts legacy: `{"text", "tool_trace", "session_id}` and common aliases (see `api.py`).
- **Response:** `violation`, `confidence` (per Arena), plus `decision`, `risk_score`, `reason_codes`, `detail`, `version` for debugging.

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
