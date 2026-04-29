#!/usr/bin/env python3
"""Step 2: confirm FastAPI exposes GET /health and POST /v1/classify (Arena contract)."""
from __future__ import annotations

from safeguard_api import app

paths = sorted({getattr(r, "path", "") for r in app.routes if hasattr(r, "path")})
need = {"/health", "/v1/classify", "/classify"}
missing = need - set(paths)
if missing:
    raise SystemExit(f"Missing routes: {missing}; have: {paths}")
print("OK: Arena contract routes present:", ", ".join(sorted(need)))
