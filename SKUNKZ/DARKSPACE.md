# DARKSPACE by Fratres X AI Defensive Portfolio Plan

Build a defense-oriented DARKSPACE by Fratres X AI prototype that pairs a Streamlit OSINT dashboard with passive forensic monitoring, emphasizing auditability, explainability, and safe demo behavior.

## Scope
- **Predictor dashboard**: Create `app.py` with ThreatFox ingestion, table display, search/filter controls, and a visualization of common malicious domains from the last 24 hours.
- **Forensic logger**: Add an SQLite-backed audit trail that stores hashed detection records for accountability and review.
- **Enforcer monitor**: Create `enforcer.py` as a passive listener that flags suspicious MCP/tool-call signatures and rate-based agent-like behavior without active blocking.
- **OSINT extender**: Add `osint_expert.py` to correlate public vulnerability feeds with local alerts for defensive situational awareness.
- **Prompt-injection shield**: Add `rebuff_engine.py` to detect and sanitize hostile instructions before they reach local models, with full alert logging.
- **Encrypted-traffic fingerprinting**: Add `ghost_monitor.py` to passively analyze packet timing and length patterns for suspicious token-streaming behavior.
- **Alert-driven key rotation**: Add `vault_guardian.py` to monitor the forensic database and trigger mock credential rotation workflows on critical alerts.
- **Threat-intel sync**: Add `p2p_mesh.py` as a benign node-to-node threat-intel sharing format for syncing blacklists and alerts across trusted instances.
- **Steganography detection**: Add `whisper_detector.py` for entropy-based analysis of outgoing text to surface possible hidden-message patterns.
- **Behavior drift analysis**: Add `mimicry_hunter.py` to track task-intent shifts and raise alerts when an agent's behavior diverges from its approved role.
- **Red-team simulation**: Add `neural_mirror.py` as an offline test harness that exercises defenses against synthetic jailbreak and injection samples.
- **Dependencies**: Add the minimal runtime dependencies needed for the dashboard, database logging, and packet inspection.
- **Run instructions**: Document how to install dependencies and start each script locally.
- **Validation**: Confirm all scripts launch cleanly and handle API/network errors gracefully.

## Implementation Notes
- **Data handling**: Normalize ThreatFox API responses into a pandas DataFrame before rendering.
- **Filtering UX**: Include a search bar or selector for `threat_type` so the dashboard can narrow results quickly.
- **Visualization**: Use a lightweight chart to surface the most common malicious domains observed in the last 24 hours.
- **Alerting logic**: Keep the Enforcer read-only/passive, log detections with timestamps, source IPs, matched signatures, and a risk score.
- **Auditability**: Hash each alert payload with SHA-256 before persisting it in SQLite to support chain-of-custody review.
- **Correlation**: Cross-reference public vulnerability feed entries with recent local detections to surface relevant defensive context.
- **Prompt sanitation**: Strip or neutralize hostile instructions in the input pipeline while preserving an evidence copy for the audit log.
- **Traffic analysis**: Detect token-streaming patterns using packet timing and size distribution only; do not decrypt or modify traffic.
- **Key response**: Use alert-driven, mock credential-rotation hooks rather than direct environment mutation or remote kill commands.
- **Distributed awareness**: Limit mesh sync to signed threat-intel metadata and alert summaries, not operational control signals.
- **Entropy analysis**: Measure message entropy over time to detect possible steganographic collusion without altering message content.
- **Behavioral drift**: Flag task-intent changes that exceed the approved baseline and require human review before escalation.
- **Safe red-team mode**: Run synthetic adversarial tests in an isolated harness that only reports results and suggested hardening actions.
- **Thresholds**: Treat more than 10 tool-call-like events in under a minute as suspicious and make the threshold easy to tune.
- **Operational safety**: Avoid adding any offensive or active probing behavior; restrict the monitor to observation and logging.

## Acceptance Criteria
- **Dashboard**: `streamlit run app.py` opens a working ThreatFox IOC dashboard.
- **Forensics**: Detection events are written to `audit_log.db` with hashed records.
- **Enforcer**: `python enforcer.py` starts without crashing and logs MCP-like alerts from observed traffic.
- **OSINT**: `osint_expert.py` can retrieve and correlate a public vulnerability feed without failing the main app.
- **Defensive modules**: `rebuff_engine.py`, `ghost_monitor.py`, `vault_guardian.py`, `p2p_mesh.py`, `whisper_detector.py`, `mimicry_hunter.py`, and `neural_mirror.py` exist as safe, passive, or mock-only components.
- **Safety guarantees**: No TCP reset attacks, no hardware isolation commands, no active blocking, and no covert interception beyond passive analysis.
- **Resilience**: Network/API failures produce user-friendly errors instead of breaking the app.
- **Setup**: `requirements.txt` or equivalent lists all required packages and setup steps are clear.
