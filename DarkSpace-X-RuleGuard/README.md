# DarkSpace X RuleGuard

![Python 3.12](https://img.shields.io/badge/python-3.12-%233776AB.svg) ![License Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg) ![Docker](https://img.shields.io/badge/Docker-ready-blue.svg)

**Offline-first HTTP classifier for agentic customer-support transcripts.**  
Combines deterministic rule scoring with a lightweight CPU semantic gate (sentence-transformers MiniLM). Designed for **reproducibility**: fixed dependencies, declarative Dockerfile, **no network calls on the classification hot path**.

Repository: [github.com/FratresMedAI/DarkSpace-X-RuleGuard](https://github.com/FratresMedAI/DarkSpace-X-RuleGuard)

## Methodology (summary)

- **Rule layer:** High-precision patterns for prompt-injection framing, credential phishing, tool-argument abuse, and multi-turn orchestration smuggling. Pattern families were informed by **published survey and taxonomy literature** on jailbreak and indirect injection techniques (e.g. crescendo, translation smuggling, synthetic tool traces), cross-checked against benign enterprise phrasing to control false positives.
- **Semantic layer:** Embedding similarity for fuzzy alignment; runs **fully on CPU** in the default container.
- **Mini-Templar wrapper:** Optional “rescue” path for weak multi-signal cases using corroboration and entropy heuristics (see `mini_templar/core.py`).

## Quick start (Docker)

```bash
docker build --platform linux/amd64 --provenance=false --sbom=false -t darkspace-ruleguard:local .
docker run --rm -p 8080:8080 darkspace-ruleguard:local
```

Verify:

```bash
curl -s http://127.0.0.1:8080/health
curl -s http://127.0.0.1:8080/ready
curl -s -X POST http://127.0.0.1:8080/v1/classify \
  -H 'Content-Type: application/json' \
  -d '{"conversation":[{"role":"user","content":"Please summarize Q3 earnings in two bullets."}]}'
```

## HTTP API

See [docs/API.md](docs/API.md) for request/response schema and **all supported POST routes** (compatible with common classifier probes: `/v1/classify`, `/classify`, `/api/v1/classify`, root `POST /`, and a catch-all POST).

## Local verification

```bash
python -m venv .venv && source .venv/bin/activate  # or Windows equivalent
pip install -r requirements-dev.txt
# Skip extended neural-mirror smoke during pytest (not required for rule unit tests):
export DARKSPACE_SKIP_MIRROR_STARTUP=1   # Windows: set DARKSPACE_SKIP_MIRROR_STARTUP=1
export PYTHONPATH="$PWD"                  # Windows: set PYTHONPATH=%CD%
pytest safeguards_adapter/tests/ mini_templar/tests/ -q
```

## Offline evaluation

Single-turn JSONL:

```bash
python scripts/eval_labeled_dataset.py tests/fixtures/survey_literature_curated.jsonl --format jsonl --judge no-llm-judge
```

Multi-turn labeled JSON export:

```bash
python scripts/eval_labeled_dataset.py path/to/labeled.json --format conversation --judge no-llm-judge
```

## Security & privacy

See [SECURITY.md](SECURITY.md). Classification is **stateless** with respect to remote services; SQLite audit hooks initialize locally for compatibility with legacy middleware—**treat deployments as ephemeral** or mount an empty volume for `audit_log.db` if persistence is undesired.

## License

Apache-2.0 — see [LICENSE](LICENSE).

## Citation / audit

If you use this system in research or assurance reports, cite the repository URL and the **commit SHA** you reproduced.

For UK AISI, CISA-style, or independent review: **full reproduction** = Docker build from this tree + checksum of lockfiles (`requirements-docker.txt` as pinned in image) + documented `ENV` (see `Dockerfile`).
