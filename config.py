import json
import os
import sys

# Windows consoles often default to cp1252; emoji in logs then raises UnicodeEncodeError.
if sys.platform == "win32":
    for _stream in (sys.stdout, sys.stderr):
        try:
            if hasattr(_stream, "reconfigure"):
                _stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

CONFIG_VERSION = "2026.04.23"


def _env_float(key: str, default: float) -> float:
    raw = os.environ.get(key, "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _env_bool(key: str, default: bool) -> bool:
    raw = os.environ.get(key, "").strip().lower()
    if raw in ("1", "true", "yes", "on"):
        return True
    if raw in ("0", "false", "no", "off"):
        return False
    return default
THRESHOLD_CHANGELOG_PATH = "CHANGELOG_CONFIG.md"

# ── Database ──────────────────────────────────────────────────────────────────
DB_PATH = os.environ.get("DARKSPACE_DB_PATH", "audit_log.db")

# ── ThreatFox ─────────────────────────────────────────────────────────────────
THREATFOX_API_KEY = os.environ.get("THREATFOX_API_KEY", "")
THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"

# ── OSINT / NVD ───────────────────────────────────────────────────────────────
NVD_FEEDS_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_PARAMS = {"resultsPerPage": 20, "startIndex": 0}
OFFLINE_ONLY = os.environ.get("DARKSPACE_OFFLINE_ONLY", "false").lower() == "true"

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


# ── Gray Swan Safeguard API ───────────────────────────────────────────────────
SAFEGUARD_API_HOST = "0.0.0.0"
# Arena / containers often set PORT or SAFEGUARD_API_PORT (e.g. 8080).
_p = os.environ.get("SAFEGUARD_API_PORT") or os.environ.get("PORT") or "8000"
SAFEGUARD_API_PORT = int(_p) if str(_p).isdigit() else 8000


def validate_contest_baseline() -> None:
    """Production gate: security config + quick extended-corpus neural mirror smoke."""
    enforce_security_baseline()
    from neural_mirror import run_simulation

    results = run_simulation(limit=10, profile="extended", verbose=False)
    if not results or not all(r["correct"] for r in results):
        bad = next((r for r in results if not r["correct"]), None)
        detail = f" sample={bad['id']}" if bad else ""
        raise ValueError("validate_contest_baseline: neural_mirror extended smoke failed" + detail)


# Gray Swan blue-team extensions
CANARY_TOKEN = "GRAY_SWAN_CANARY_42_DO_NOT_REMOVE"
SMOOTHING_PERTURBATIONS = 8

# 2025 survey extensions
PROACTIVE_ENTROPY_THRESHOLD = 5.5
CONVERSATION_DRIFT_MULTIPLIER = 1.15

# ── LLM-as-a-Judge ──
#
# Backend selection (`DARKSPACE_JUDGE_INFERENCE`):
#   hf      — Hugging Face `transformers` in-process (default)
#   openai  — OpenAI-compatible HTTP (vLLM, TGI, corporate gate). Set:
#               DARKSPACE_GATE_BASE_URL=http://host:port/v1
#               DARKSPACE_GATE_MODEL=<served model id>   # optional; defaults to profile hf_id
#               DARKSPACE_GATE_API_KEY=...               # optional
#   If DARKSPACE_GATE_BASE_URL is set and profile is llama-3.1-405b-instruct-4bit,
#   backend defaults to openai when DARKSPACE_JUDGE_INFERENCE is unset.
#
# Dev / single-GPU Qwen (HF):
#   export DARKSPACE_OFFLINE_ONLY=false
#   export DARKSPACE_LLM_JUDGE=qwen2.5-14b-instruct-4bit
#
# Rules + embeddings only — zero judge load:
#   export DARKSPACE_LLM_JUDGE=no-llm-judge
#
# Small HF judge (CPU/GPU, non-gated):
#   export DARKSPACE_LLM_JUDGE=phi-3-mini
#
# Llama 3.1 405B (gated weights) — typical: vLLM tensor_parallel_size=2 + gate URL:
#   export DARKSPACE_LLM_JUDGE=llama-3.1-405b-instruct-4bit
#   export DARKSPACE_JUDGE_INFERENCE=openai
#   export DARKSPACE_GATE_BASE_URL=http://127.0.0.1:8000/v1
#   export HF_TOKEN=...   # for vLLM weight download / HF hub
#
# CLI: python test_harness.py --judge qwen2.5-14b-instruct-4bit
#      python test_harness.py --judge llama-3.1-405b-instruct-4bit --dataset tests/real_2026_training_dataset.jsonl
_llm_judge_cli_override: str | None = None

JUDGE_MODEL_REGISTRY: dict[str, dict] = {
    "no-llm-judge": {
        "hf_id": "",
        "display_name": "no-llm-judge",
        "consistency_runs": 0,
        "use_4bit": False,
        "bypass_offline_for_judge": False,
        "max_new_tokens": 0,
        "temperature": 0.0,
        "skip_hf_load": True,
    },
    "phi-3-mini": {
        "hf_id": "microsoft/Phi-3-mini-4k-instruct",
        "display_name": "microsoft/Phi-3-mini-4k-instruct",
        "consistency_runs": 3,
        "use_4bit": False,
        "bypass_offline_for_judge": False,
        "max_new_tokens": 80,
        "temperature": 0.0,
        "skip_hf_load": False,
    },
    # Alias: harness/README use this name; must exist or CLI key falls back to wrong spec (was phi-3-mini).
    "phi3-mini-4k-instruct-4bit": {
        "hf_id": "microsoft/Phi-3-mini-4k-instruct",
        "display_name": "microsoft/Phi-3-mini-4k-instruct-4bit",
        "consistency_runs": 4,
        "use_4bit": True,
        "bypass_offline_for_judge": True,
        "max_new_tokens": 80,
        "temperature": 0.0,
        "skip_hf_load": False,
    },
    "qwen2.5-14b-instruct-4bit": {
        "hf_id": "Qwen/Qwen2.5-14B-Instruct",
        "display_name": "qwen2.5-14b-instruct-4bit",
        "consistency_runs": 4,
        "use_4bit": True,
        "bypass_offline_for_judge": True,
        "max_new_tokens": 96,
        "temperature": 0.0,
        "skip_hf_load": False,
    },
    "llama-3.1-405b-instruct-4bit": {
        "hf_id": "hugging-quants/Meta-Llama-3.1-405B-Instruct-AWQ-INT4",
        "display_name": "llama-3.1-405b-instruct-4bit",
        "consistency_runs": 4,
        "use_4bit": True,
        "bypass_offline_for_judge": True,
        "max_new_tokens": 128,
        "temperature": 0.0,
        "skip_hf_load": False,
    },
}

# Optional numeric knobs (used by judge layer; defaults in registry)
QWEN25_JUDGE_MAJORITY_THRESHOLD = 0.625  # 4 runs → need ≥3 safe votes (legacy doc / tuning)
QWEN25_JUDGE_MIN_CONFIDENCE_PARSED = 0.0  # reserved for future thresholding on model JSON confidence


def apply_judge_cli(judge: str | None) -> None:
    """Set active judge from test_harness --judge (before importing safeguard_api)."""
    global _llm_judge_cli_override
    if judge is None or not str(judge).strip():
        _llm_judge_cli_override = None
    else:
        _llm_judge_cli_override = str(judge).strip().lower()


def get_active_judge_key() -> str:
    if _llm_judge_cli_override:
        return _llm_judge_cli_override
    env_j = os.environ.get("DARKSPACE_LLM_JUDGE", "").strip().lower()
    if env_j:
        return env_j
    # Default: fast Qwen 4-bit for iterative FPR tuning (override with no-llm-judge or 405B as needed).
    return "qwen2.5-14b-instruct-4bit"


def get_active_judge_spec() -> dict:
    key = get_active_judge_key()
    return JUDGE_MODEL_REGISTRY.get(key, JUDGE_MODEL_REGISTRY["phi-3-mini"])


def get_llm_judge_display_name() -> str:
    return str(get_active_judge_spec().get("display_name", "unknown"))


def llm_judge_bypass_offline() -> bool:
    """When True, judge runs even if OFFLINE_ONLY=true (Runpod Qwen path)."""
    return bool(get_active_judge_spec().get("bypass_offline_for_judge", False))


# ── winning_2026 FPR/FNR balance (real_2026 dataset; all 24 layers fully sensitive) ─
# Defaults tuned after aligning embedding baselines to tests/real_2026_training_dataset.jsonl.
# Override at runtime: DARKSPACE_SEMANTIC_THRESHOLD, DARKSPACE_SECONDARY_SEMANTIC_FLOOR, etc.
# 0.32 lets too many attacks through the MiniLM gate; 0.34 was the prior sweet spot for real_2026.
SEMANTIC_EMBEDDING_SAFE_THRESHOLD = _env_float("DARKSPACE_SEMANTIC_THRESHOLD", 0.33)
WINNING_JUDGE_BLEND_BASE = _env_float("DARKSPACE_WINNING_BLEND_BASE", 0.60)
WINNING_JUDGE_BLEND_JUDGE = _env_float("DARKSPACE_WINNING_BLEND_JUDGE", 0.40)
BENIGN_CONFIRM_BAND_LOW = _env_float("DARKSPACE_BENIGN_CONFIRM_BAND_LOW", 0.68)
BENIGN_CONFIRM_BAND_HIGH = _env_float("DARKSPACE_BENIGN_CONFIRM_BAND_HIGH", 0.74)
SECONDARY_BENIGN_SEMANTIC_FLOOR = _env_float("DARKSPACE_SECONDARY_SEMANTIC_FLOOR", 0.37)
BENIGN_SECONDARY_CONFIDENCE_BUMP = _env_float("DARKSPACE_BENIGN_SECONDARY_BUMP", 0.02)

SAFE_CONFIDENCE_THRESHOLD = _env_float("DARKSPACE_SAFE_CONFIDENCE_THRESHOLD", 0.50)
SECONDARY_BAND_CHECK = _env_bool("DARKSPACE_SECONDARY_BAND_CHECK", True)
SECONDARY_BAND_LOW = _env_float("DARKSPACE_SECONDARY_BAND_LOW", 0.38)
SECONDARY_BAND_HIGH = _env_float("DARKSPACE_SECONDARY_BAND_HIGH", 0.92)
SECONDARY_CHECK_LIGHT = _env_bool("DARKSPACE_SECONDARY_CHECK_LIGHT", True)
BIPIA_BOUNDARY_CHECK = _env_bool("DARKSPACE_BIPIA_BOUNDARY_CHECK", True)
INSTRUCTION_HIERARCHY_WEIGHT = _env_float("DARKSPACE_INSTRUCTION_HIERARCHY_WEIGHT", 0.90)
FEW_SHOT_CLASSIFIER_LAYER = _env_bool("DARKSPACE_FEW_SHOT_CLASSIFIER_LAYER", True)
# Higher k → fewer benign false positives from numbered-list shape (layer 25).
FEW_SHOT_NUM_EXAMPLES = int(_env_float("DARKSPACE_FEW_SHOT_NUM_EXAMPLES", 5.0))
ENSEMBLE_VOTING_WEIGHT = _env_float("DARKSPACE_ENSEMBLE_VOTING_WEIGHT", 0.93)

# High-precision blocks for named jailbreak *frames* seen in real_2026 / Arena-shaped corpora (low benign FP).
GRAY_SWAN_FRAME_BLOCK_LAYER = _env_bool("DARKSPACE_GRAY_SWAN_FRAME_BLOCK", True)


def judge_max_memory_for_load() -> dict[str, str] | None:
    """Optional per-GPU RAM strings for Accelerate `device_map` (e.g. 2x H200)."""
    raw = os.environ.get("DARKSPACE_JUDGE_MAX_MEMORY_JSON", "").strip()
    if not raw:
        return None
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise ValueError("DARKSPACE_JUDGE_MAX_MEMORY_JSON must be a JSON object")
    return {str(k): str(v) for k, v in parsed.items()}


# ── Judge inference backend: Hugging Face in-process vs OpenAI-compatible (vLLM / gate) ──
#   DARKSPACE_JUDGE_INFERENCE=hf          — load model with transformers (default)
#   DARKSPACE_JUDGE_INFERENCE=openai      — HTTP to DARKSPACE_GATE_BASE_URL (vLLM, etc.)
# Optional: if DARKSPACE_GATE_BASE_URL is set and DARKSPACE_JUDGE_INFERENCE is empty,
#   Llama-3.1-405B profile auto-selects openai (see get_effective_judge_inference_backend).


def is_mock_gate() -> bool:
    return _env_bool("DARKSPACE_MOCK_GATE", False)


def is_runpod_validation() -> bool:
    return _env_bool("DARKSPACE_RUNPOD_VALIDATION", False)


def ready_for_runpod() -> bool:
    return os.environ.get("DARKSPACE_READY_FOR_RUNPOD", "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


def log_prefix() -> str:
    return "[RUNPOD]" if is_runpod_validation() else "[LOCAL-VALIDATED]"


def get_effective_judge_inference_backend() -> str:
    """
    Return 'hf' or 'openai'.

    Auto-route 405B to remote inference when a gate URL is provided and no explicit
    backend was set — matches typical 2×GPU vLLM deployments.
    """
    if is_mock_gate():
        return "openai"
    explicit = os.environ.get("DARKSPACE_JUDGE_INFERENCE", "").strip().lower()
    if explicit in ("openai", "http", "vllm", "gate"):
        return "openai"
    if explicit in ("hf", "huggingface", "transformers", "local"):
        return "hf"
    if explicit:
        return "hf"

    gate = os.environ.get("DARKSPACE_GATE_BASE_URL", "").strip()
    if gate and get_active_judge_key() == "llama-3.1-405b-instruct-4bit":
        return "openai"
    return "hf"


def get_gate_openai_config() -> dict[str, str]:
    """OpenAI-compatible server: base URL, optional API key, model id."""
    base = os.environ.get("DARKSPACE_GATE_BASE_URL", "").strip().rstrip("/")
    api_key = (
        os.environ.get("DARKSPACE_GATE_API_KEY", "")
        or os.environ.get("OPENAI_API_KEY", "")
        or ""
    ).strip()
    model = os.environ.get("DARKSPACE_GATE_MODEL", "").strip()
    return {"base_url": base, "api_key": api_key, "model": model}


# ── 2× H200 + AWQ-INT4 vLLM defaults (override via env; safe for CPU-only builds) ──
DEFAULT_VLLM_MODEL_ID = "hugging-quants/Meta-Llama-3.1-405B-Instruct-AWQ-INT4"
_DEFAULT_VLLM_EXTRA_ARGS = (
    "--quantization awq --gpu-memory-utilization 0.90 --max-model-len 8192 "
    "--max-num-batched-tokens 4096 --dtype auto --enforce-eager --tensor-parallel-size 2"
)


def get_vllm_model_id() -> str:
    return os.environ.get("DARKSPACE_VLLM_MODEL_ID", DEFAULT_VLLM_MODEL_ID).strip()


def get_vllm_extra_args() -> str:
    return os.environ.get("DARKSPACE_VLLM_EXTRA_ARGS", _DEFAULT_VLLM_EXTRA_ARGS).strip()
