# Parva Sed Fortis

**Small, offline safeguards scoring** — vendored in this tree as `darkspace` / `_mini_x_templar_upstream`.

- **Codename** `Parva Sed Fortis` (PSF): `safeguards_adapter.core.CODENAME`, `mini_templar.__codename__`
- **Hot path:** `classify_mini_templar` → pure regex/enforcer rules — no LLM, no network, no API server required for the PSF **Docker** image
- **Primary code:** `_mini_x_templar_upstream/` (`mini_templar/`, `safeguards_adapter/`, `Dockerfile`) — `safeguards_adapter/` also at repo root for pytest from DARKSPACE.

**GitHub (split repo):** [github.com/FratresMedAI/Parva-Sed-Fortis](https://github.com/FratresMedAI/Parva-Sed-Fortis)

Build PSF image (from `_mini_x_templar_upstream` with `mini_templar` + `safeguards_adapter` in place, or from this monorepo copy):

```text
cd _mini_x_templar_upstream
docker build -t parva-sed-fortis:local .
```

Default container **CMD** is a one-shot import check (no `uvicorn`). For **Gray Swan** hosted classifiers on port 8080, build with **`Dockerfile.api`** (`uvicorn mini_templar.api:app`).
