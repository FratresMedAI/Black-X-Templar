# `safeguards_adapter`

Stateless classification core (`classify_text`) and an optional minimal FastAPI app (`api.py`) for HTTP tests.

Public HTTP contract for the production service is documented in the repository root [`docs/API.md`](../docs/API.md).

## Development tests

```bash
pytest safeguards_adapter/tests/ -q
```
