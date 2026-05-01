# SECURITY

## Threat Model

Black-X-Templar is a defensive, auditable AI-security codebase aimed at passive detection, safeguard scoring, and controlled active-response hooks where enabled.

Primary threat classes:
- Prompt-injection and policy-bypass attempts
- Tool-call abuse / MCP-shaped unauthorized actions
- Covert data exfiltration (entropy and drift anomalies)
- Supply-chain risk from third-party dependencies
- Peer-to-peer trust abuse and impersonation

Trust boundaries:
- Local agent/runtime logs and prompts are untrusted input
- External feeds (ThreatFox/NVD) are semi-trusted and validated before persistence
- SQLite audit store is trusted only with integrity controls (hashing, HMAC, and access controls)

## Responsible Disclosure

Report security issues privately to project maintainers with:
- Reproducible steps
- Affected module(s)
- Impact and suggested remediation

Do not open public issues for unpatched vulnerabilities.

## Supply-Chain Security Posture

- SBOM generation is automated in CI (`.github/workflows/security-ci.yml`)
- Dependency vulnerability scanning uses `pip-audit`
- Static analysis uses `bandit` and `semgrep`
- Release SBOM generation uses Syft (SPDX)

## NSA AISC Alignment Notes

This project is implemented to align with core NSA AI Security Center guidance for AI data security and secure AI deployment:

- Data integrity and provenance controls: signed audit pathways (HMAC + hash), verifiable event records, and immutable-style chain-of-custody checks in smoke validation.
- Secure-by-default runtime posture: startup baseline enforcement, least-privilege deployment defaults, and dry-run-first kinetic controls.
- Continuous monitoring expectations: detector telemetry, security metrics persistence, and regression/compliance execution as repeatable evidence.

These controls are designed for transparent review in unclassified and controlled-evaluation environments and can be extended for classified deployment hardening profiles.

## Residual Weaknesses (Transparent)

- Detection validation quality is currently strongest on synthetic/generated adversarial corpora; real-world operational traffic may expose additional bypass patterns.
- Kinetic response includes optional real Keycloak integration, but most mission-specific IdP/SIEM action paths remain integration work for deployment owners.
- Streamlit UI remains in-repo as a demo-only artifact and is not part of the hardened classified deployment path.
- Static-analysis posture enforces medium/high blockers to zero; low-severity test/assert/tooling noise remains expected.

### SLSA Claim

Current baseline: **SLSA Level 1 equivalent**
- Build process is scripted and version-controlled
- Release workflow includes keyless Sigstore signing for SBOM digest provenance artifacts

Target: SLSA Level 2+
- Hosted build provenance
- Signed artifacts and verified provenance policy

## Hardening Requirements

- Never deploy with default `DARKSPACE_HMAC_SECRET`
- Enable `DARKSPACE_P2P_REQUIRE_MUTUAL_AUTH=true` for production P2P mesh
- Provide trusted peer fingerprints via `DARKSPACE_PEER_FINGERPRINTS`
- Use dry-run for kinetic hooks before enabling live action paths
- Restrict DB and runtime directories with least privilege
