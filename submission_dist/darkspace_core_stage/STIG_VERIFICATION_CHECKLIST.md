# DARKSPACE Application Security STIG Verification Checklist

Purpose: record official DISA STIG verification evidence for pre-escalation package completeness.

## Scope

- Product: DARKSPACE
- Baseline: current repository state
- Target environment: controlled DoD/partner validation environment
- STIG focus: Application Security and Development controls applicable to Python services and deployment artifacts

---

## Required Inputs

- Official STIG benchmark package and release date
- STIG Viewer (current approved version)
- SCAP/benchmark content approved for the target enclave
- Final code snapshot identifier (tag/hash)

---

## Verification Steps

1. Import applicable STIG checklist into STIG Viewer.
2. Map each applicable control to evidence in repository artifacts:
   - `SECURITY.md`
   - `MATURITY.md`
   - `.github/workflows/security-ci.yml`
   - `_smoke_v2.py`
   - `Dockerfile`
   - `k8s/darkspace-deployment.yaml`
3. Attach latest gate outputs:
   - smoke suite output
   - Bandit JSON report
   - Semgrep JSON report
   - pip-audit output
   - SBOMs (`sbom.cdx.json`, `sbom.spdx.json`)
4. Mark each control status in STIG Viewer:
   - Not a Finding
   - Open
   - Not Applicable
5. For each Open finding, include POA&M entry with owner, due date, and mitigation plan.

---

## Evidence Mapping (Quick Reference)

- Input validation / prompt abuse controls: `rebuff_engine.py`, `enforcer.py`
- Audit integrity / chain-of-custody: `app.py`, `enforcer.py`, `kinetic_hooks.py`
- Runtime policy enforcement: `config.py`
- Incident response hooks: `kinetic_hooks.py`
- P2P trust enforcement: `p2p_mesh.py`
- Continuous monitoring: `security_logging.py`, `security_metrics` (DB)
- Supply-chain controls: CI scans + SBOM artifacts

---

## Sign-Off Block

- STIG Package Version:
- Validation Environment:
- Validator Name/Role:
- Date Completed:
- Open Findings Count:
- POA&M Reference:
- Final Recommendation: GO / CONDITIONAL GO / NO-GO
