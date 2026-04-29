# DARKSPACE Maturity Model

## Internal Maturity Levels

- **L1 Passive Visibility**: Logging and passive detections only
- **L2 Controlled Response**: Kinetic dry-run and validated active hooks
- **L3 Adaptive Defense**: Calibrated thresholds with measurable F1/precision/recall
- **L4 Agentic Immune System**: Automated policy adaptation with human-governed safeguards

## NIST AI RMF Mapping

### Govern
- Versioned security thresholds in `config.py`
- CI security checks and SBOM generation
- Documented disclosure and supply-chain posture in `SECURITY.md`

### Map
- Threat modeling for prompt abuse, exfiltration, tool misuse, and P2P trust
- Module-level risk surfaces documented in README and operational docs

### Measure
- DB-backed security metrics (`security_metrics`)
- Regression + compliance suite (`_smoke_v2.py`)
- Calibration pipeline (`calibrate.py`) for false-positive tuning

### Manage
- Kinetic hooks for quarantine and re-auth
- Dry-run-first safety gates
- Runtime baseline enforcement (`config.enforce_security_baseline()`)

## MITRE ATLAS Detection/Mitigation Mapping

| Module | Primary Coverage Focus |
|---|---|
| `rebuff_engine.py` | Prompt injection / instruction override attempts |
| `enforcer.py` | Tool misuse and suspicious command-like patterns |
| `whisper_detector.py` | Covert communication via entropy anomalies |
| `mimicry_hunter.py` | Intent drift / behavioral deviation |
| `ghost_monitor.py` | Suspicious traffic fingerprints and timing anomalies |
| `kinetic_hooks.py` | Incident containment and controlled response |
| `neural_mirror.py` | Agentic adversarial scenario simulation |

## CMMC / DFARS Alignment (Implementation Mapping)

| Control Family | Example Control Focus | DARKSPACE Implementation Evidence |
|---|---|---|
| Access Control (AC) | Restrict privileged actions and enforce policy gates | `config.enforce_security_baseline()` blocks unsafe startup; kinetic actions are toggle-gated and dry-run-first in `kinetic_hooks.py` |
| Audit & Accountability (AU) | Generate, protect, and review audit logs | HMAC/hash-backed logging paths in `app.py`, `enforcer.py`, `kinetic_hooks.py`; review workflows in `_smoke_v2.py` |
| Configuration Management (CM) | Baseline and control security configuration | Versioned thresholds in `config.py`; tracked updates in `CHANGELOG_CONFIG.md`; calibration governance via `calibrate.py` |
| Identification & Authentication (IA) | Validate identities and trusted peers | P2P mTLS, cert fingerprint allowlist, and attestation handling in `p2p_mesh.py` |
| Incident Response (IR) | Detect, triage, and contain security events | Threat scoring + response workflow in `enforcer.py` and `kinetic_hooks.py` with quarantine/reauth/escalation hooks |
| Risk Assessment (RA) | Continuous threat evaluation and control tuning | Neural adversarial simulation in `neural_mirror.py`; threshold tuning and F1 validation via `calibrate.py` |
| System & Information Integrity (SI) | Detect anomalies/injections and protect integrity | Multi-layer detectors (`rebuff_engine.py`, `mimicry_hunter.py`, `whisper_detector.py`, `ghost_monitor.py`) with signed persistence |
| Supply Chain Risk Management (SR) | Dependency/SBOM visibility and provenance | `pip-audit` + CI scans; SBOM artifacts (`sbom.cdx.json`, `sbom.spdx.json`); Sigstore provenance workflow |

## Quantitative Tracking Targets

- `% ATLAS coverage` across simulation corpus and detectors
- `MTTD` for synthetic incidents
- `MTTR` for kinetic response in dry-run and live modes
- `False-positive rate` from calibrated corpora
- `Kinetic action success rate` stored in `security_metrics`

## Honest Maturity Caveats

- Current performance metrics are strongest on controlled/synthetic corpora and should not be interpreted as guaranteed field performance.
- Kinetic maturity is partially demonstrated (dry-run safety + optional Keycloak path) but remains below full mission integration readiness until environment-specific IdP/SIEM hooks are implemented and validated.
- Demo UI maturity is intentionally separate from headless core maturity and should not be treated as classified deployment evidence.
