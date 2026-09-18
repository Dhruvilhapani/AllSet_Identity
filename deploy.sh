#!/usr/bin/env bash
#
# Manual deploy of AllSet_Identity to GCP Cloud Run.
# Run this by hand every time you want to ship a new version — there is no
# CI/CD pipeline wired up for this project.
#
# Prerequisites (one-time, or whenever a secret changes):
#   1. cp .env.example .env.dev, then fill in real values (Supabase call_logs
#      project keys, ALLSET_SERVICE_KEY). For prod: .env.prod instead.
#   2. ./scripts/setup_gcp_secrets.sh <dev|prod>   — enables APIs, creates the
#      Artifact Registry repo, and syncs secrets from the target's env file
#      into that target's project in Secret Manager.
#
# deploy/env.yaml (the non-secret Cloud Run env vars) is generated
# automatically from the target's .env file every time this script runs —
# that .env file is the single source of truth, you don't need to maintain
# both files.
#
# Usage:
#   ./deploy.sh dev              # dev/staging (allset-491218), reads .env.dev
#   ./deploy.sh prod             # prod (allset-244ab), reads .env.prod
#   REGION=us-central1 PROJECT_ID=my-project ./deploy.sh dev
#
# Run ./scripts/setup_gcp_secrets.sh <dev|prod> once before the first deploy of
# a given target — it bootstraps APIs/Artifact Registry/Secret Manager for
# that target's project.

set -euo pipefail

# ---------------------------------------------------------------------------
# Target — selects which GCP project + env file this run deploys
# ---------------------------------------------------------------------------
if [[ $# -lt 1 ]]; then
  echo "Usage: ./deploy.sh <dev|prod> — target must be given explicitly (no default)." >&2
  exit 1
fi
TARGET="$1"
case "$TARGET" in
  dev)
    DEFAULT_PROJECT_ID="allset-491218"
    DEFAULT_ENV_BASENAME=".env.dev"
    DEFAULT_ENV_VARS_BASENAME="deploy/env.yaml"
    ;;
  prod)
    DEFAULT_PROJECT_ID="allset-244ab"
    DEFAULT_ENV_BASENAME=".env.prod"
    DEFAULT_ENV_VARS_BASENAME="deploy/env.prod.yaml"
    ;;
  *)
    echo "Unknown target '$TARGET' — expected 'dev' or 'prod' (./deploy.sh [dev|prod])." >&2
    exit 1
    ;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Deployments must correspond to a recorded Git revision. Set
# ALLOW_DIRTY_DEPLOY=true only for an intentional emergency build from local
# changes; the image tag still records the current commit when available.
if [[ "${ALLOW_DIRTY_DEPLOY:-false}" != "true" ]] && [[ -n "$(git -C "$SCRIPT_DIR" status --porcelain)" ]]; then
  echo "Working tree has uncommitted changes; commit them before deploying." >&2
  echo "Use ALLOW_DIRTY_DEPLOY=true only for an intentional dirty-tree deploy." >&2
  exit 1
fi

# The image is built from whatever's on disk (gcloud builds submit uploads the
# working tree, not a git ref) — for prod, refuse to ship uncommitted changes
# no matter what ALLOW_DIRTY_DEPLOY says.
if [[ "$TARGET" == "prod" ]]; then
  if [[ -n "$(git -C "$SCRIPT_DIR" status --porcelain)" ]]; then
    echo "Refusing to deploy prod from a dirty working tree — commit or stash first." >&2
    exit 1
  fi
  echo "==> Deploying prod from commit $(git -C "$SCRIPT_DIR" rev-parse --short HEAD)"
fi

# ---------------------------------------------------------------------------
# Config — override via env vars if needed
# ---------------------------------------------------------------------------
PROJECT_ID="${PROJECT_ID:-$DEFAULT_PROJECT_ID}"
REGION="${REGION:-asia-south1}"
REPO_NAME="${REPO_NAME:-allset-identity}"
SERVICE_NAME="${SERVICE_NAME:-allset-identity}"

if [[ -z "$PROJECT_ID" ]]; then
  echo "PROJECT_ID is not set and no default gcloud project is configured." >&2
  echo "Run: gcloud config set project <your-project-id>, or PROJECT_ID=<id> $0" >&2
  exit 1
fi

ENV_FILE="${ENV_FILE:-$SCRIPT_DIR/$DEFAULT_ENV_BASENAME}"
ENV_VARS_FILE="$SCRIPT_DIR/$DEFAULT_ENV_VARS_BASENAME"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "Missing $ENV_FILE — copy .env.example and fill in real values first." >&2
  exit 1
fi

GIT_REVISION="$(git -C "$SCRIPT_DIR" rev-parse --short=12 HEAD 2>/dev/null || echo unknown)"
IMAGE_TAG="$(date +%Y%m%d-%H%M%S)-${GIT_REVISION}"
IMAGE="${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPO_NAME}/${SERVICE_NAME}:${IMAGE_TAG}"

# ---------------------------------------------------------------------------
# Generate deploy/env.yaml (non-secret Cloud Run env vars) from the .env file
# ---------------------------------------------------------------------------
read_env_var() {
  local key="$1"
  # `|| true` keeps a key that's absent from ENV_FILE from killing the whole
  # script under `set -euo pipefail` (grep exits 1 on no match) — missing
  # optional keys should just resolve to "", not abort the deploy.
  { grep -E "^${key}=" "$ENV_FILE" || true; } | tail -n1 | cut -d'=' -f2- \
    | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'\$//"
}

yaml_escape() {
  # Escape backslashes and double quotes for a YAML double-quoted scalar
  printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

echo "==> Generating $ENV_VARS_FILE from $(basename "$ENV_FILE")..."
mkdir -p "$SCRIPT_DIR/deploy"
{
  echo "# Auto-generated by deploy.sh from $(basename "$ENV_FILE") — do not edit by hand."
  echo "# Edit $(basename "$ENV_FILE") instead and re-run ./deploy.sh."
  # A key with an empty value is omitted rather than written as "" — app/core/config.py
  # derives SUPABASE_JWKS_URL/SUPABASE_JWT_ISSUER from SUPABASE_URL via
  # os.environ.get(key, derived_default), which only fires when the key is
  # absent from the environment. An explicit empty string suppresses that
  # derivation and crashes the app at startup (confirmed against a real deploy).
  for key in SUPABASE_URL SUPABASE_JWT_SECRET SUPABASE_JWKS_URL SUPABASE_JWT_ISSUER \
             SUPABASE_JWT_AUDIENCE LEGACY_MIGRATION_ENABLED LEGACY_CMS_DB_HOST \
             LEGACY_CMS_DB_PORT LEGACY_CMS_DB_NAME LEGACY_CMS_DB_USER LEGACY_CMS_DB_SSLMODE \
             CORS_ORIGINS HTTP_TIMEOUT_SECONDS ACCESS_TOKEN_TTL_SECONDS \
             LOGIN_RATE_LIMIT LOGIN_RATE_WINDOW_SECONDS IDENTITY_DEBUG; do
    value="$(read_env_var "$key")"
    [[ -z "$value" ]] && continue
    printf '%s: "%s"\n' "$key" "$(yaml_escape "$value")"
  done
} > "$ENV_VARS_FILE"

# ---------------------------------------------------------------------------
# Build --set-secrets from whatever identity-* secrets actually exist in
# Secret Manager, so one not-yet-created secret (e.g. run before
# setup_gcp_secrets.sh has a value for it) doesn't hard-fail the whole deploy.
# ---------------------------------------------------------------------------
secret_exists() {
  gcloud secrets describe "$1" --project="$PROJECT_ID" &>/dev/null
}

SECRET_PAIRS="SUPABASE_ANON_KEY=identity-supabase-anon-key"
SECRET_PAIRS+=" SUPABASE_SERVICE_ROLE_KEY=identity-supabase-service-role-key"
SECRET_PAIRS+=" ALLSET_SERVICE_KEY=identity-allset-service-key"
SECRET_PAIRS+=" LEGACY_CMS_DB_PASSWORD=identity-legacy-cms-db-password"

SECRETS=""
for pair in $SECRET_PAIRS; do
  target="${pair%%=*}"
  secret_name="${pair#*=}"
  if secret_exists "$secret_name"; then
    SECRETS+="${SECRETS:+,}${target}=${secret_name}:latest"
  else
    echo "WARNING: secret '$secret_name' not found in Secret Manager — skipping $target." >&2
    echo "         Run ./scripts/setup_gcp_secrets.sh $TARGET after adding its value to $(basename "$ENV_FILE") to include it." >&2
  fi
done

echo "==> Project: $PROJECT_ID"
echo "==> Region:  $REGION"
echo "==> Image:   $IMAGE"
echo

# ---------------------------------------------------------------------------
# Build + push the image via Cloud Build (no local Docker daemon required)
# ---------------------------------------------------------------------------
echo "==> Building and pushing image..."
gcloud builds submit \
  --project="$PROJECT_ID" \
  --tag="$IMAGE" \
  "$SCRIPT_DIR"

# ---------------------------------------------------------------------------
# Deploy to Cloud Run
# ---------------------------------------------------------------------------
echo "==> Deploying to Cloud Run..."
DEPLOY_ARGS=(
  --project="$PROJECT_ID"
  --region="$REGION"
  --image="$IMAGE"
  --port=8080
  --env-vars-file="$ENV_VARS_FILE"
  --timeout=60
  --concurrency=40
  --memory=512Mi
  --allow-unauthenticated
)
if [[ -n "$SECRETS" ]]; then
  DEPLOY_ARGS+=(--set-secrets="$SECRETS")
fi
gcloud run deploy "$SERVICE_NAME" "${DEPLOY_ARGS[@]}"

SERVICE_URL="$(gcloud run services describe "$SERVICE_NAME" \
  --project="$PROJECT_ID" --region="$REGION" --format='value(status.url)')"

echo
echo "==> Deployed: $SERVICE_URL"
