# Black X Templar (BxT)
<image-card alt="Python 3.12" src="https://img.shields.io/badge/python-3.12-%233776AB.svg" ></image-card> <image-card alt="License Apache 2.0" src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" ></image-card> <image-card alt="Docker" src="https://img.shields.io/badge/Docker-ready-blue.svg" ></image-card>
**Fratres X AI**

**Fratres X AI** — Gray Swan **Safeguards** blue-team classifier (**Black Templar**), shipped as a **single Docker image** (CPU / contest profile).

**This repo:** [`github.com/FratresMedAI/Black-X-Templar`](https://github.com/FratresMedAI/Black-X-Templar)

**Related (separate work):** **Aether Guard** will be a **different** classifier (GPT‑5.5–based) in its **own** repository when you create it — not the same product as BxT.

This repository is the **minimal source** that matches the published container: layered guardrails, MiniLM semantic checks, **no GPU LLM judge** in the default image (set `DARKSPACE_LLM_JUDGE` at runtime to change that).

Full R&D history and eval harnesses live in the umbrella project ([`darkspace-gray-swan-blue`](https://github.com/FratresMedAI/darkspace-gray-swan-blue)). **BxT tracks that stack** for admin / registry upload passes.

## API (Gray Swan)

| Method | Path | Body |
|--------|------|------|
| `GET` | `/health` | — |
| `POST` | `/v1/classify` | `{"conversation":[{"role":"user","content":"..."}]}` |
| `POST` | `/classify` | `{"prompt":"...","history":[]}` (legacy, full metadata) |

**Response (v1):** `{"violation": true|false, "confidence": 0.0–1.0}`

**Port:** `8080` inside the container.

## Build (Docker V2 — required by some registries)

Avoid BuildKit OCI/attestation-only indexes if your host rejects them:

```bash
docker build --platform linux/amd64 --provenance=false --sbom=false \
  -t black-templar-safeguard:gray-swan .
```

## Run

```bash
docker run --rm -p 8080:8080 black-templar-safeguard:gray-swan
# Optional: override the baked-in 32-byte HMAC for production
# -e HMAC_SECRET="your_secret_at_least_32_characters"
```

## Published image (update digest when you re-push)

**Example (Docker Hub):** `docker.io/occisorleonum/black-templar-safeguard:gray-swan`  

**Pin:** `sha256:3b3a159e18c8b29e3282d679064668a7465bdd14d8fcc876e1d52221070415a9` (update in this README if the image changes)

## Monday review checklist (admins)

- [ ] `docker pull` the tag above; run `/health` and one `/v1/classify` call.
- [ ] Confirm this **repo** source tree + **image digest** match what Gray Swan received.
- [ ] `DARKSPACE_HMAC_SECRET` in production: override per environment; default in image is for contest boot only.

## License

See `LICENSE`.
