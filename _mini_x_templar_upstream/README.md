# Parva Sed Fortis (PSF) — **Mini Templar** (MxT) + vendored `safeguards_adapter`

**Codename:** *Parva Sed Fortis* — small, offline rules stack (`CODENAME` / `__codename__` in code).  
[FratresMedAI/Parva-Sed-Fortis](https://github.com/FratresMedAI/Parva-Sed-Fortis) is the home for this line; related blue-team work may also appear on the main Gray Swan adapter repo.

## Offline-first (default for PSF / Docker)

- **Scoring** is in-process: `classify_mini_templar` → `classify_text` (no LLM, no DB, no network on the hot path).
- **Container:** the included `Dockerfile` does **not** start a web server. It runs a one-shot import/version check.  
  *Optional* HTTP for local debugging: see comments at the top of `Dockerfile` (uvicorn on 8080).

## HTTP adapter (optional — dev / legacy harnesses only)

`mini_templar.api` (FastAPI) is still in the tree for local testing or hosts that require `POST /classify`:


## Docker

**Repo root** must be this folder (the one that contains `Dockerfile`, `mini_templar/`, `safeguards_adapter/`).

**Build + run locally (PowerShell):**

```powershell
cd "C:\Users\Besn Daddy\Desktop\MINI-X-TEMPLAR"
.\scripts\docker_run_local.ps1
```

**Build + push to Docker Hub (after `docker login`):**

```powershell
cd "C:\Users\Besn Daddy\Desktop\MINI-X-TEMPLAR"
.\scripts\docker_push_gray_swan.ps1
```

Default Hub image: **`occisorleonum/mini-x-templar-gray-swan:grayswan-2026-04-27`** (v0.4.6 Arena tune) — use that URL in Gray Swan (port **8080**).  
Prior: `grayswan-2026-04-24`.

**Gray Swan / Arena (HTTP on port 8080):** build with **`Dockerfile.api`**. The root `Dockerfile` is **offline PSF only** (no web server; one-shot CMD).

Manual one-liner:

```bash
docker build --platform linux/amd64 --provenance=false --sbom=false \
  -f Dockerfile.api \
  -t occisorleonum/mini-x-templar-gray-swan:grayswan-2026-04-27 .
docker run --rm -p 8080:8080 occisorleonum/mini-x-templar-gray-swan:grayswan-2026-04-27
```

Optional env: `SAFEGUARDS_BLOCK_THRESHOLD` (default `5.5` in code; **5.4** in current Docker image), `MINI_CORROBORATION_RESCUE=1`, `MINI_RESCUE_MIN_MATCHES` (default `2`; **3** in current image for stricter corroboration rescue), and other `MINI_*` vars (see `mini_templar/core.py`).

**If FPR spikes on replay:** try `MINI_RESCUE_MIN_MATCHES=2` with `SAFEGUARDS_BLOCK_THRESHOLD=5.45` (single-axis nudge) before changing lift/entropy.

## Tests

From repo root:

```bash
set PYTHONPATH=.
python -m pytest mini_templar/tests -q
```

## Relationship to Darkspace

The **`safeguards_adapter/`** tree here is a **vendored copy** of the pattern engine used by DARKSPACE. When you cut a release, sync that folder from the Darkspace repo (or cherry-pick commits) so both stay aligned.
