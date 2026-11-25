# The admin console (admin/) is built in its own stage, so the runtime image
# carries only its static files and no Node.
FROM node:20-slim AS console
WORKDIR /console
COPY admin/package.json admin/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY admin/ ./
RUN npm run build

# Mirrors the shape of AllSet_Broker_Tools' services/fastapi/Dockerfile so both
# deploy the same way on Cloud Run.
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
# Served at /admin by app/console.py.
COPY --from=console /console/dist ./admin/dist

# Cloud Run provides PORT; 8080 is the default it expects.
ENV PORT=8080
EXPOSE 8080

# One worker: the service is I/O-light (token verification is pure CPU against
# an in-memory key cache) and Cloud Run scales by instance, not by worker.
CMD ["sh", "-c", "gunicorn app.main:app -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:${PORT} --workers 1 --timeout 60"]
