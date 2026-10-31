# Backend: FastAPI API + live capture. Build context is the repo root; run it through docker compose,
# which adds host networking, NET_RAW only and a read-only filesystem.
FROM python:3.15-slim@sha256:94d3426f1def7db4a106a232ac121bfd975393e5dfd40a619b955fae45fe7913

# tcpdump: Scapy uses it to compile BPF capture filters.
RUN apt-get update \
    && apt-get install -y --no-install-recommends tcpdump \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements.txt

COPY backend backend
COPY models models
COPY simulator simulator
RUN mkdir -p /app/data

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SENTINEL_DB_PATH=/app/data/sentinelstream.db

# 127.0.0.1 only: with host networking, 0.0.0.0 would expose the unauthenticated API to the LAN.
CMD ["uvicorn", "backend.api.main:app", "--host", "127.0.0.1", "--port", "8000"]
