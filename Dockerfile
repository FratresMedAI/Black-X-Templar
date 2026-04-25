# Black Templar (DARKSPACE) — Gray Swan Safeguards classifier API
# CPU image: layered guards + MiniLM embeddings; no GPU judge (set DARKSPACE_LLM_JUDGE at runtime to override).
#
# Build for picky registries (avoid OCI index + attestations that some hosts reject):
#   docker build --platform linux/amd64 --provenance=false --sbom=false -t occisorleonum/black-templar-safeguard:gray-swan .
FROM --platform=linux/amd64 python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HF_HUB_DISABLE_PROGRESS_BARS=1 \
    HF_HOME=/app/.hf \
    # Contest-safe defaults (override at `docker run` if needed):
    DARKSPACE_OFFLINE_ONLY=true \
    DARKSPACE_LLM_JUDGE=no-llm-judge \
    DARKSPACE_HMAC_SECRET=0123456789abcdef0123456789abcdef \
    SAFEGUARD_API_PORT=8080 \
    DARKSPACE_SKIP_CONTEST_BASELINE=true

WORKDIR /app

RUN useradd --create-home --shell /bin/bash --uid 1000 safeguard \
    && mkdir -p /app/.hf

COPY requirements-docker.txt sample_ioc_seed.json preseed_ioc_cache.py ./
COPY safeguard_api.py advanced_guards.py config.py gate_inference.py enforcer.py rebuff_engine.py \
     whisper_detector.py mimicry_hunter.py neural_mirror.py ./

RUN pip install --no-cache-dir -r requirements-docker.txt \
    && python preseed_ioc_cache.py --input sample_ioc_seed.json --clear || true \
    && python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2', device='cpu')"

RUN chown -R safeguard:safeguard /app

USER safeguard

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=4)" || exit 1

CMD ["uvicorn", "safeguard_api:app", "--host", "0.0.0.0", "--port", "8080"]
