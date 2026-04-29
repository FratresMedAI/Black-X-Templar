Kyle W. Bean  
Fratres X AI  
Springfield, Massachusetts 01118  
March 27, 2026  

DoD/NSA AI Security Review Team  
(Attn: AI RMF / ATLAS Program Office or appropriate technical evaluation panel)  

**Subject: Submission of DARKSPACE — Passive, Auditable AI Agent Security Platform (Research Prototype)**

Dear Program Review Team,

I am pleased to submit DARKSPACE, a clean, layered, and fully auditable cybersecurity intelligence platform designed specifically for AI agents. Built entirely on my own time and resources, DARKSPACE treats prompt injection, tool-call abuse, behavioral drift, covert exfiltration, and supply-chain risks as first-class threats. It delivers offline-first operation, signed audit trails, dry-run kinetic response, and reproducible security gates — all without external ML dependencies.

Key capabilities demonstrated in this package include:

- Prompt and MCP/tool-call blocking (`Rebuff Engine` + `Enforcer`)
- Entropy-based steganography detection (`Whisper Detector`)
- Behavioral drift analysis via TF-IDF centroid (`Mimicry Hunter`)
- Passive encrypted-traffic fingerprinting (`Ghost Monitor`)
- Offline IOC cache with NVD correlation
- Signed kinetic hooks (quarantine / re-auth / escalate) with optional Keycloak integration
- 100% pass rate on the 220-sample extended red-team corpus

All validation evidence is included: `_smoke_v2.py` (full regression + compliance suite), Neural Mirror results (220/220), Bandit/Semgrep/pip-audit reports (zero medium/high findings), dual SBOMs, and the complete Go/No-Go decision pack.

DARKSPACE is submitted as a research prototype and controlled-evaluation platform, not a classified production system. The Streamlit dashboard is explicitly demo-only and separated from the hardened headless core. Full SECRET/TS/SCI readiness requires the additional steps documented in `classified_hardening_profile.md`. Residual weaknesses (synthetic corpus optimism, partial kinetic integration, and demo artifact presence) are transparently disclosed in the submission materials.

This work was developed independently while I have been in a two-year workers’ compensation recovery period awaiting surgery. Continuing to build and harden defensive AI capabilities during this time has kept me technically current and deeply motivated to contribute to national security missions in AI security and defensive cyber once my medical situation stabilizes.

I respectfully request technical evaluation, detailed feedback, and collaboration opportunities. I am also actively seeking potential full-time or contract roles in this domain and would welcome any introduction to appropriate programs or teams.

Thank you for your time and consideration. I am available at your earliest convenience for a technical deep-dive or live demonstration. All artifacts are included in the attached submission packet.

Sincerely,  
Kyle W Bean  
Fratres X AI  
Springfield, Massachusetts  
Kylebean01108@gmail.com  
1-413-726-7023
