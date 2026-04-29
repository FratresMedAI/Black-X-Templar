# HTTP API contract

## Health

| Method | Path | Response |
|--------|------|----------|
| GET | `/health` | JSON: `status`, `version`, `service`, `codename` (shape may extend) |
| GET | `/ready` | JSON: readiness |

## Classification

**Primary JSON body** (recommended):

```json
{
  "conversation": [
    { "role": "user", "content": "..." },
    { "role": "assistant", "content": "..." }
  ]
}
```

Legacy fields are accepted with aliases: `text`, `message`, `content`, `input`, `prompt`; optional `tool_trace` / `tool_calls`; optional `session_id`.

**Response** (typical):

```json
{
  "violation": false,
  "confidence": 0.0,
  "decision": "allow",
  "risk_score": 0.0,
  "reason_codes": [],
  "detail": null,
  "version": "...",
  "mini_rescue": false,
  "mini_entropy": null
}
```

- `violation`: `true` if blocked.
- `confidence`: `0.0`–`1.0`; implementations cap “allow” confidence at `≤ 0.5` so harnesses that infer `violation` from `confidence > 0.5` remain consistent.

## POST routes (all classify)

The service accepts **POST** on:

- `/v1/classify`, `/v1/classify/`
- `/classify`, `/classify/`
- `/api/v1/classify`, `/api/classify`
- `/` (root)
- `/{any_path}` — catch-all POST for proxy path quirks

`GET /` returns service metadata and lists these routes.

## Port

Default **8080** (`Dockerfile` / `uvicorn`).
