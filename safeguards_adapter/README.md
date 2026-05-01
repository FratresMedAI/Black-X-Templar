# Gray Swan safeguards adapter

Stateless classifier service derived from `rebuff_engine.py` and `enforcer.py` (no SQLite on the hot path). Ships as part of **Black-X-Templar**.

## Prereqs

- Python 3.11+

## Run locally

**Windows (repository root):** double-click or run:

```powershell
.\run_safeguards.ps1
```

That creates `safeguards_adapter\.venv`, installs deps, sets `PYTHONPATH`, and listens on **8080**.

Manual run:

```bash
cd safeguards_adapter
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
# From repo root so package imports resolve:
cd ..
set PYTHONPATH=%CD%
python -m uvicorn safeguards_adapter.api:app --host 0.0.0.0 --port 8080
```

Unix:

```bash
cd "$(git rev-parse --show-toplevel)"
python -m venv safeguards_adapter/.venv
source safeguards_adapter/.venv/bin/activate
pip install -r safeguards_adapter/requirements.txt
export PYTHONPATH="$PWD"
python -m uvicorn safeguards_adapter.api:app --host 0.0.0.0 --port 8080
```

## Endpoints

- `GET /` — service id + version
- `GET /health` — liveness
- `GET /ready` — readiness
- `POST /v1/classify` — Gray Swan **recommended** body:
  ```json
  { "conversation": [ { "role": "user", "content": "..." } ] }
  ```
  Response: `{"violation": false, "confidence": 0.0, ...}` — `confidence` is 0.0–1.0; allows are capped at ≤0.5 so harness fallback (`confidence > 0.5`) matches `violation`.
- Legacy body still works: `{"text":"...","tool_trace":null,"session_id":null}` (or message/content aliases).
- `POST /classify` — same handler (if the harness omits `/v1`)

Request bodies may include **extra fields** (ignored). Common aliases accepted for legacy text; `tool_calls` / objects are serialized when sent as tool trace.

Optional env: `SAFEGUARDS_BLOCK_THRESHOLD` (default `8.0`).

## Verify (tests)

From repository root:

```bash
set PYTHONPATH=%CD%
python -m pytest safeguards_adapter/tests/
```

## Container builds

Use the **repository-root** packaging workflow only (published evaluator images stay aligned with that path). This README intentionally avoids duplicating container commands here.

## Arena integration

Fill in [SUBMISSION_CONTRACT.md](SUBMISSION_CONTRACT.md) after you copy the official schema from the signed-in Gray Swan Arena UI.
