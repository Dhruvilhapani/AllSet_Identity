# Mirrors the shape of AllSet_Broker_Tools' services/fastapi/Dockerfile so both
# deploy the same way on Cloud Run.
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# libpq and gcc are only a fallback for psycopg2-binary. On python:3.11-slim it
# installs from a manylinux wheel and needs neither, but keeping them means the
# build cannot fail the way a local install on a newer interpreter does, where
# no wheel exists and pip silently falls back to compiling from source.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpq-dev gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# The image installs requirements-legacy.txt, which is requirements.txt plus
# psycopg2 — so LEGACY_MIGRATION_ENABLED can be turned on without rebuilding.
# Local development installs requirements.txt alone and needs no compiler.
COPY requirements.txt requirements-legacy.txt ./
RUN pip install --no-cache-dir -r requirements-legacy.txt

COPY app ./app

# Cloud Run provides PORT; 8080 is the default it expects.
ENV PORT=8080
EXPOSE 8080

# One worker: the service is I/O-light (token verification is pure CPU against
# an in-memory key cache) and Cloud Run scales by instance, not by worker.
CMD ["sh", "-c", "gunicorn app.main:app -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:${PORT} --workers 1 --timeout 60"]
