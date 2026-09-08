# Mirrors the shape of AllSet_Broker_Tools' services/fastapi/Dockerfile so both
# deploy the same way on Cloud Run.
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# libpq for psycopg2 (the shadow-migration read of the CMS database), gcc to
# build it. Both dropped from the final image would need a multi-stage build;
# kept simple here since the image is small and rebuilt rarely.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpq-dev gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

# Cloud Run provides PORT; 8080 is the default it expects.
ENV PORT=8080
EXPOSE 8080

# One worker: the service is I/O-light (token verification is pure CPU against
# an in-memory key cache) and Cloud Run scales by instance, not by worker.
CMD ["sh", "-c", "gunicorn app.main:app -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:${PORT} --workers 1 --timeout 60"]
