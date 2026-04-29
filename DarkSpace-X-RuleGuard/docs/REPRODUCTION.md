# Reproduction checklist (auditors / judges)

1. **Environment:** Docker 24+ with `linux/amd64` build support (or native Linux).
2. **Clone** this repository and `cd` into the root (same directory as `Dockerfile`).
3. **Record commit:** `git rev-parse HEAD`
4. **Build:**
   ```bash
   docker build --platform linux/amd64 --provenance=false --sbom=false -t darkspace-ruleguard:audit .
   ```
5. **Run:**
   ```bash
   docker run --rm -p 8080:8080 darkspace-ruleguard:audit
   ```
6. **Smoke test:** `GET /health` returns HTTP 200 JSON; `POST /v1/classify` with a benign prompt returns `violation: false`.
7. **Tests (optional, dev dependencies):** Install `requirements-dev.txt` with `PYTHONPATH` set to repo root; set `DARKSPACE_SKIP_MIRROR_STARTUP=1` so startup skips the extended neural-mirror smoke (not needed for unit tests). Run `pytest safeguards_adapter/tests/ mini_templar/tests/`.

Expected: image builds without extra credentials; runtime serves on **8080** with `safeguard_api:app`.
