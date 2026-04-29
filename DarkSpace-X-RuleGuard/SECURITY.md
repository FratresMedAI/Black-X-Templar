# Security model

## Threat scope

RuleGuard is intended to **flag policy-violating or safety-critical user/content manipulations** in multi-turn **agent** UIs (indirect injection, credential phishing, tool-argument smuggling, privilege override framing). It is **not** a full replacement for human moderation, DLP, or network isolation.

## Hot path

- The `safeguard_api` → `classify_mini_templar` → `safeguards_adapter.classify_text` path is **designed to run without outbound network** when `DARKSPACE_OFFLINE_ONLY=true` (default in `Dockerfile`).
- **Hugging Face**: Model weights for `sentence-transformers/all-MiniLM-L6-v2` are **baked at image build time**; runtime should not need registry access if the image was built successfully.

## Secrets

- `DARKSPACE_HMAC_SECRET` in `Dockerfile` is a **placeholder** for local builds. **Override in production** via orchestrator secrets; never commit real keys.

## Dependencies

- Pin versions in `requirements-docker.txt`. Rebuild images when upgrading transitive dependencies; run `pytest` before release.

## Reporting issues

Use your organization’s coordinated disclosure channel for production vulnerabilities. For this OSS repository, open a **private** security advisory with the GitHub maintainers where available.
