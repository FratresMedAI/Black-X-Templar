# DARKSPACE Packaging Note for Reviewers

## Artifact split (important)

Primary artifact (submission target): **headless core package**
- `requirements.txt`
- Core Python modules (`*.py`) used for CLI/headless operation
- Security/compliance artifacts (SBOMs, reports, checklists)

Secondary artifact: **demo package (full repository)**
- Includes Streamlit UI (`app.py`) and demo-oriented materials
- Uses `requirements-demo.txt` in addition to core requirements

This split is intentional:
- Core package is the hardened, production-oriented evaluation path
- Demo package is for reviewer convenience and operator walkthroughs

Prepared by: `Fratres X AI`
