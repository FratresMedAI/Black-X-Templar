# CONTRIBUTING

Thanks for contributing to DARKSPACE.

## Security-first contribution process

- Read `SECURITY.md` before opening a PR.
- Do not include real credentials, tokens, or private data in commits.
- Use `.env.example` for environment variable documentation.
- Keep changes minimal and auditable.

## Before submitting a PR

- Run regression + compliance smoke suite:
  - `python _smoke_v2.py`
- Run security checks where possible:
  - `bandit -q -r . -x .venv,__pycache__`
  - `semgrep --config=p/ci --error`
  - `pip-audit --strict`

## Documentation integrity requirements

- Do not overstate deployment readiness; preserve the project's controlled-evaluation/prototype scope language.
- Keep residual weakness disclosures up to date in reviewer-facing docs (`README.md`, `GO_NOGO_PACK.md`, `SUBMISSION_CHECKLIST.md`, `FINAL_SUBMISSION_PACKET.md`).
- If a demo-only artifact remains in-repo, ensure it is clearly labeled and split from hardened core deployment dependencies.

## Reporting vulnerabilities

Do not open public issues for unpatched vulnerabilities.
Follow the disclosure guidance in `SECURITY.md`.
