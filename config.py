import os

# FRATRES INTERNAL WATERMARK - BxT v2026-Alpha - Do not remove
FRATRES_WATERMARK = "BxT-FR-20260429-Alpha"

CONFIG_VERSION = "2026.03.27"
THRESHOLD_CHANGELOG_PATH = "CHANGELOG_CONFIG.md"

# BxT is intentionally tuned more aggressively than DarkSpace for leaderboard differentiation
BX_T_STRICT_MODE = True
CONFIDENCE_THRESHOLD = 0.75  # stricter than DarkSpace
SAFE_CONFIDENCE_THRESHOLD = CONFIDENCE_THRESHOLD

# ── Database ──────────────────────────────────────────────────────────────────
DB_PATH = os.environ.get("DARKSPACE_DB_PATH", "audit_log.db")

# ── ThreatFox ─────────────────────────────────────────────────────────────────
THREATFOX_API_KEY = os.environ.get("THREATFOX_API_KEY", "")
THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"

# ── OSINT / NVD ───────────────────────────────────────────────────────────────
NVD_FEEDS_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_PARAMS = {"resultsPerPage": 20, "startIndex": 0}
OFFLINE_ONLY = os.environ.get("DARKSPACE_OFFLINE_ONLY", "true").lower() == "true"

# ── Enforcer ──────────────────────────────────────────────────────────────────
ENFORCER_RATE_WINDOW_SECONDS = 60
ENFORCER_RATE_THRESHOLD = 10          # >10 tool-call-like events in 60 s = suspicious

MCP_SIGNATURES = [
    r'"tool"\s*:\s*"[^"]+"',           # JSON tool-call shape
    r'"function_call"\s*:\s*\{',
    r'"action"\s*:\s*"[^"]+".*?"action_input"',
    r'<tool_call>',
    r'\buse_mcp_tool\b',
]

SUSPICIOUS_SIGNATURES = [
    r'\b(password|secret|api.?key|token|auth)\s*[=:]\s*["\']?\S+',
    r'\b(eval|exec|os\.system|subprocess)\s*\(',
    r'(union\s+select|drop\s+table|insert\s+into)',
    r'(\.\.\/|\.\.\\|%2e%2e)',
]

# ── HMAC ──────────────────────────────────────────────────────────────────────
HMAC_SECRET = os.environ.get("DARKSPACE_HMAC_SECRET", "change_me_in_production").encode()

# ── Vault Guardian ────────────────────────────────────────────────────────────
VAULT_CRITICAL_SCORE_THRESHOLD = 8.0
VAULT_CHECK_INTERVAL_SECONDS = 30

# ── P2P Mesh ──────────────────────────────────────────────────────────────────
P2P_PEERS: list[str] = []             # e.g. ["http://peer1:9000", "http://peer2:9000"]
P2P_LISTEN_PORT = 9000
P2P_SYNC_INTERVAL_SECONDS = 300

# ── Whisper Detector ─────────────────────────────────────────────────────────
WHISPER_ENTROPY_THRESHOLD = 3.5       # bits per character (normal English ~3.9)
WHISPER_MIN_MESSAGE_LEN = 80

# ── Mimicry Hunter ────────────────────────────────────────────────────────────
MIMICRY_BASELINE_WINDOW = 50          # events to build baseline
MIMICRY_DRIFT_THRESHOLD = 0.8        # cosine-distance threshold

# ── Neural Mirror ─────────────────────────────────────────────────────────────
NEURAL_MIRROR_SAMPLE_LIMIT = 42       # expanded corpus — run all by default

# ── Kinetic Hooks (v2 active response layer) ──────────────────────────────────
KINETIC_ENABLED              = True   # master on/off switch
KINETIC_QUARANTINE_ENABLED   = True   # invalidate agent session token
KINETIC_REAUTH_ENABLED       = True   # force re-authentication challenge
KINETIC_ESCALATE_ENABLED     = False  # POST to SOC/SIEM webhook (off by default)
KINETIC_ESCALATE_WEBHOOK_URL = os.environ.get("DARKSPACE_ESCALATE_WEBHOOK", "")
KINETIC_CHECK_INTERVAL       = 15     # seconds between threat_log polls

# ── Offline IOC Cache ─────────────────────────────────────────────────────────
IOC_CACHE_TTL_HOURS = 24              # hours before cache is considered stale

# ── P2P Mesh — TLS trust (v2) ─────────────────────────────────────────────────
# Set DARKSPACE_PEER_FINGERPRINTS env var to a comma-separated list of
# trusted peer cert SHA-256 fingerprints (no colons).
# Empty = dev mode (trust all peers). Populate for production deployments.
# Get a peer's fingerprint with: python p2p_mesh.py --show-fingerprint
P2P_REQUIRE_MUTUAL_AUTH = os.environ.get("DARKSPACE_P2P_REQUIRE_MUTUAL_AUTH", "false").lower() == "true"
P2P_TRUSTED_PEER_FINGERPRINTS = [
    f.strip().lower()
    for f in os.environ.get("DARKSPACE_PEER_FINGERPRINTS", "").split(",")
    if f.strip()
]
P2P_TLS_CERT_PATH = os.environ.get("DARKSPACE_P2P_TLS_CERT_PATH", "mesh_certs/node.crt")
P2P_TLS_KEY_PATH = os.environ.get("DARKSPACE_P2P_TLS_KEY_PATH", "mesh_certs/node.key")
P2P_ALLOW_DEV_SELF_SIGNED = os.environ.get("DARKSPACE_P2P_ALLOW_DEV_SELF_SIGNED", "false").lower() == "true"


def validate_security_baseline() -> tuple[bool, list[str]]:
    errors: list[str] = []

    if len(HMAC_SECRET) < 32:
        errors.append("HMAC secret must be at least 32 bytes.")

    if HMAC_SECRET == b"change_me_in_production":
        errors.append("Default HMAC secret is not allowed for production deployment.")

    if not (0 < ENFORCER_RATE_THRESHOLD <= 1000):
        errors.append("ENFORCER_RATE_THRESHOLD must be between 1 and 1000.")

    if not (1 <= ENFORCER_RATE_WINDOW_SECONDS <= 3600):
        errors.append("ENFORCER_RATE_WINDOW_SECONDS must be between 1 and 3600.")

    if not (0.0 <= VAULT_CRITICAL_SCORE_THRESHOLD <= 10.0):
        errors.append("VAULT_CRITICAL_SCORE_THRESHOLD must be in [0, 10].")

    if not (0.0 <= WHISPER_ENTROPY_THRESHOLD <= 8.0):
        errors.append("WHISPER_ENTROPY_THRESHOLD must be in [0, 8].")

    if not (0.0 <= MIMICRY_DRIFT_THRESHOLD <= 1.0):
        errors.append("MIMICRY_DRIFT_THRESHOLD must be in [0, 1].")

    if P2P_REQUIRE_MUTUAL_AUTH and not P2P_TRUSTED_PEER_FINGERPRINTS:
        errors.append("P2P mutual auth is enabled but no trusted peer fingerprints are configured.")

    return len(errors) == 0, errors


def enforce_security_baseline() -> None:
    ok, errors = validate_security_baseline()
    if not ok:
        raise ValueError("Security baseline validation failed: " + " | ".join(errors))


# ── Contest / API bootstrap (minimal; extended settings may be merged from upstream overlays) ─
SAFEGUARD_API_HOST = os.environ.get("SAFEGUARD_API_HOST", "0.0.0.0")
SAFEGUARD_API_PORT = int(os.environ.get("SAFEGUARD_API_PORT", "8080"))


def validate_contest_baseline() -> None:
    """Called on FastAPI startup; keeps boot aligned with bundled contest profile."""
    enforce_security_baseline()
