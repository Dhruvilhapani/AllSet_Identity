#!/usr/bin/env bash
#
# One-time (idempotent) GCP setup for AllSet_Identity on Cloud Run: enables
# required APIs, creates the Artifact Registry repo, creates/updates Secret
# Manager secrets from the local .env file, and grants the Cloud Run runtime
# service account access to read them.
#
# Run this once before the first ./deploy.sh, and re-run any time a secret
# value changes locally (it adds a new secret version each time; it never
# deletes anything).
#
# Requires: gcloud CLI, authenticated (`gcloud auth login`), .env.dev (or
# .env.prod for the prod target) populated — copy from .env.example.
#
# Usage:
#   ./scripts/setup_gcp_secrets.sh dev              # dev/staging (allset-491218)
#   ./scripts/setup_gcp_secrets.sh prod             # prod (allset-244ab)
#   REGION=us-central1 ./scripts/setup_gcp_secrets.sh dev

set -euo pipefail

# ---------------------------------------------------------------------------
# Target — selects which GCP project + env file this run uses
# ---------------------------------------------------------------------------
if [[ $# -lt 1 ]]; then
  echo "Usage: ./scripts/setup_gcp_secrets.sh <dev|prod> — target must be given explicitly (no default)." >&2
  exit 1
fi
TARGET="$1"
case "$TARGET" in
  dev)
    DEFAULT_PROJECT_ID="allset-491218"
    DEFAULT_ENV_BASENAME=".env.dev"
    ;;
  prod)
    DEFAULT_PROJECT_ID="allset-244ab"
    DEFAULT_ENV_BASENAME=".env.prod"
    ;;
  *)
    echo "Unknown target '$TARGET' — expected 'dev' or 'prod' (./scripts/setup_gcp_secrets.sh [dev|prod])." >&2
    exit 1
    ;;
esac

# ---------------------------------------------------------------------------
# Config — override via env vars if needed, e.g. REGION=us-central1 ./scripts/setup_gcp_secrets.sh
# ---------------------------------------------------------------------------
PROJECT_ID="${PROJECT_ID:-$DEFAULT_PROJECT_ID}"
REGION="${REGION:-asia-south1}"
REPO_NAME="${REPO_NAME:-allset-identity}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="${ENV_FILE:-$ROOT_DIR/$DEFAULT_ENV_BASENAME}"

if [[ -z "$PROJECT_ID" ]]; then
  echo "PROJECT_ID is not set and no default gcloud project is configured." >&2
  echo "Run: gcloud config set project <your-project-id>, or PROJECT_ID=<id> $0" >&2
  exit 1
fi

if [[ ! -f "$ENV_FILE" ]]; then
  echo "Missing $ENV_FILE — copy .env.example and fill in real values first." >&2
  exit 1
fi

echo "==> Project: $PROJECT_ID"
echo "==> Region:  $REGION"
echo

# ---------------------------------------------------------------------------
# Enable required APIs
# ---------------------------------------------------------------------------
echo "==> Enabling required APIs..."
gcloud services enable \
  run.googleapis.com \
  artifactregistry.googleapis.com \
  secretmanager.googleapis.com \
  cloudbuild.googleapis.com \
  --project="$PROJECT_ID"

# ---------------------------------------------------------------------------
# Artifact Registry repo
# ---------------------------------------------------------------------------
if gcloud artifacts repositories describe "$REPO_NAME" \
    --location="$REGION" --project="$PROJECT_ID" &>/dev/null; then
  echo "==> Artifact Registry repo '$REPO_NAME' already exists."
else
  echo "==> Creating Artifact Registry repo '$REPO_NAME'..."
  gcloud artifacts repositories create "$REPO_NAME" \
    --repository-format=docker \
    --location="$REGION" \
    --project="$PROJECT_ID" \
    --description="AllSet Identity images"
fi

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
read_env_var() {
  local key="$1"
  grep -E "^${key}=" "$ENV_FILE" | tail -n1 | cut -d'=' -f2- \
    | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'\$//"
}

CREATED_SECRETS=()

create_or_update_secret() {
  local secret_name="$1"
  local value="$2"

  if [[ -z "$value" ]]; then
    echo "    skipping $secret_name (empty value in $(basename "$ENV_FILE"))"
    return
  fi

  if gcloud secrets describe "$secret_name" --project="$PROJECT_ID" &>/dev/null; then
    echo "    updating secret '$secret_name'..."
  else
    echo "    creating secret '$secret_name'..."
    gcloud secrets create "$secret_name" --replication-policy=automatic --project="$PROJECT_ID"
  fi
  printf '%s' "$value" | gcloud secrets versions add "$secret_name" --data-file=- --project="$PROJECT_ID" >/dev/null
  CREATED_SECRETS+=("$secret_name")
}

# ---------------------------------------------------------------------------
# Sync secrets from .env
# ---------------------------------------------------------------------------
echo "==> Syncing secrets from $(basename "$ENV_FILE") into Secret Manager..."
create_or_update_secret "identity-supabase-anon-key"         "$(read_env_var SUPABASE_ANON_KEY)"
create_or_update_secret "identity-supabase-service-role-key" "$(read_env_var SUPABASE_SERVICE_ROLE_KEY)"
create_or_update_secret "identity-allset-service-key"        "$(read_env_var ALLSET_SERVICE_KEY)"
create_or_update_secret "identity-legacy-cms-db-password"    "$(read_env_var LEGACY_CMS_DB_PASSWORD)"

# ---------------------------------------------------------------------------
# Grant the Cloud Run runtime service account access to the secrets it needs
# ---------------------------------------------------------------------------
PROJECT_NUMBER="$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)')"
RUNTIME_SA="${RUNTIME_SA:-${PROJECT_NUMBER}-compute@developer.gserviceaccount.com}"

echo "==> Granting roles/secretmanager.secretAccessor on synced secrets to $RUNTIME_SA..."
for secret in "${CREATED_SECRETS[@]}"; do
  gcloud secrets add-iam-policy-binding "$secret" \
    --project="$PROJECT_ID" \
    --member="serviceAccount:${RUNTIME_SA}" \
    --role="roles/secretmanager.secretAccessor" \
    --condition=None \
    &>/dev/null
done

echo
echo "==> Done. Runtime service account: $RUNTIME_SA"
echo "    Next: run ./deploy.sh $TARGET (it generates deploy/env.yaml from $(basename "$ENV_FILE") automatically)"
