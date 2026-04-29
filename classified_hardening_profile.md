# DARKSPACE Classified Hardening Profile (SECRET/TS/SCI)

This profile defines required changes before any classified deployment.

## Scope

Current repository is a research/PoC security platform for controlled evaluation.
Classified deployment requires additional controls below.

## Mandatory changes for classified environments

## 1) Data storage and audit backend

- Replace local SQLite with an approved hardened database service.
- Encrypt at rest with enclave-approved key management.
- Enforce backup/retention policy aligned to mission data handling requirements.

## 2) Identity and access

- Replace local/dev identity assumptions with enterprise IdP integration.
- Enforce strong MFA and role-based access controls for operator functions.
- Map source identity to IdP principal for kinetic actions.

## 3) P2P trust and certificates

- Replace any self-signed/development cert path with DoD PKI or SPIRE-issued identity.
- Require mutual TLS and explicit peer allowlists.
- Add certificate rotation and revocation handling procedures.

## 4) Network and external feeds

- Keep offline-only mode enabled by default.
- Replace public threat feeds with approved classified threat intelligence sources.
- Enforce egress allowlist and deny-by-default policy.

## 5) Runtime and platform hardening

- Deploy as non-root containers with read-only root filesystem.
- Enforce seccomp/AppArmor and dropped Linux capabilities.
- Use immutable image tags and verified provenance.

## 6) Secrets and key management

- Remove operational secrets from environment variables where feasible.
- Inject secrets via approved secret manager and file mounts.
- Implement key rotation and break-glass procedures.

## 7) Monitoring and incident response

- Export metrics/logs to enterprise SIEM/SOC pipeline.
- Add signed alert forwarding and incident workflow runbooks.
- Validate kinetic response behavior in controlled staging before enabling real actions.

## 8) Assurance and compliance evidence

- Run official STIG checks in target enclave tooling.
- Maintain SBOM + provenance for each release artifact.
- Track findings with POA&M and remediation SLAs.
