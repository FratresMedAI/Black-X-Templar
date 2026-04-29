# DARKSPACE Final Submission Packet

Date: 2026-03-27
Status: Submission-ready package for DoD technical evaluation

## Final Validation Stamp (2026-03-27)

- `python -m pytest -q tests/test_core_security.py` → `5 passed`
- `python _smoke_v2.py` → pass (`neural_mirror 43/43`, `security_baseline OK`)
- `python neural_mirror.py --profile extended --samples 220` → pass (`220/220`)
- `python -m pip_audit -r requirements.txt --strict` → `No known vulnerabilities found`
- `pysemgrep --config=p/ci --error --json --output semgrep-report.json` → `0 findings (0 blocking)`
- `bandit-report.json` blocker parse → `BANDIT_MED_HIGH = 0`

Submission decision: **GO**

## Residual Weaknesses (Explicit)

- Neural Mirror `100%` results are measured on synthetic/generated corpus data; real-world adversarial traffic is expected to uncover additional gaps.
- Kinetic hooks include an optional real Keycloak path, but mission IdP/SIEM integrations remain deployment-specific implementation work.
- Streamlit dashboard is demo-only and split from core dependencies, but still present in-repo as a non-production artifact.
- Bandit medium/high blocker gate is enforced to zero; low-severity test/assert/tooling noise remains.

Prepared by: `Fratres X AI`

## 1) Core Decision Artifacts

- `GO_NOGO_PACK.md`
- `SUBMISSION_CHECKLIST.md`
- `REVIEWER_QUICKSTART.md`
- `EXECUTIVE_SUMMARY.md`
- `SUBMISSION_LETTER.md`
- `production_deployment.md`
- `classified_hardening_profile.md`
- `STIG_VERIFICATION_CHECKLIST.md`

## 2) Security Evidence Artifacts

- `bandit-report.json`
- `semgrep-report.json`
- latest `pip-audit` output log
- latest `_smoke_v2.py` output log
- latest extended Neural Mirror output (`--profile extended --samples 220`)

## 3) Supply Chain Artifacts

- `sbom.cdx.json` (CycloneDX)
- `sbom.spdx.json` (SPDX)
- Sigstore provenance artifacts from CI release workflow

## 4) Runtime/Deployment Artifacts

- `Dockerfile`
- `k8s/darkspace-deployment.yaml`
- `requirements.txt` (headless core)
- `requirements-demo.txt` (demo UI only)
- `preseed_ioc_cache.py` (offline IOC seed utility)

## 5) Validation Commands (authoritative)

```powershell
python _smoke_v2.py
python neural_mirror.py --profile extended --samples 220
python -m bandit -r . -x .venv,__pycache__ -f json -o bandit-report.json
python -m pip_audit -r requirements.txt --strict
$env:PYTHONUTF8='1'; $env:PYTHONIOENCODING='utf-8'; chcp 65001 > $null; & 'C:\Users\Besn Daddy\AppData\Roaming\Python\Python312\Scripts\pysemgrep.exe' --config=p/ci --error --json --output semgrep-report.json
cyclonedx-py requirements --output-file sbom.cdx.json --output-format json requirements.txt
& 'C:\Users\Besn Daddy\AppData\Local\Microsoft\WinGet\Packages\Anchore.Syft_Microsoft.Winget.Source_8wekyb3d8bbwe\syft.exe' dir:. -o spdx-json=sbom.spdx.json
```

## 6) Operational Scope Statement

DARKSPACE is submitted as a controlled-evaluation security platform.
The headless core package is the production-oriented submission path.
The Streamlit dashboard is a demo artifact and is intentionally separated from core dependencies.
