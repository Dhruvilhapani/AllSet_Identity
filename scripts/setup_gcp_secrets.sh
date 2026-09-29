#!/usr/bin/env bash
#
# One-time (idempotent) GCP setup for AllSet_Identity on Cloud Run: enables
# required APIs, creates the Artifact Registry repo, creates/updates Secret
# Manager secrets from the local .env file, and grants the Cloud Run runtime
# service account access to read them.
#
# Run this once before the first ./deploy.sh, and re-run any time a secret
# value changes locally. A new secret version is added only when the local
# value differs from the current `latest` version; it never deletes anything.
#
# Requires: gcloud CLI, authenticated (`gcloud auth login`), .env.dev (or
# .env.prod for the prod target) populated — copy from .env.example.
#
# Usage:
#   ./scripts/setup_gcp_secrets.sh dev              # dev/staging (allset-491218)
#   ./scripts/setup_gcp_secrets.sh prod             # prod (allset-244ab); asks
#                                                   # you to type the project id
#   DEPLOY_CONFIRM=allset-244ab ./scripts/setup_gcp_secrets.sh prod  # non-interactive
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
DEFAULT_REGION="asia-south1"
DEFAULT_REPO_NAME="allset-identity"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DEFAULT_ENV_FILE="$ROOT_DIR/$DEFAULT_ENV_BASENAME"

# Same guard as deploy.sh: overrides are for dev only; a stray shell export
# must never point a prod run at another project or env file.
if [[ "$TARGET" == "prod" ]]; then
  prod_override_error=false
  for pair in "PROJECT_ID=$DEFAULT_PROJECT_ID" "REGION=$DEFAULT_REGION" \
              "REPO_NAME=$DEFAULT_REPO_NAME" "ENV_FILE=$DEFAULT_ENV_FILE"; do
    var="${pair%%=*}"
    expected="${pair#*=}"
    actual="${!var-}"
    if [[ -n "$actual" && "$actual" != "$expected" ]]; then
      echo "Refusing prod run: $var is set to '$actual' in your shell, but prod requires '$expected'." >&2
      prod_override_error=true
    fi
  done
  if [[ "$prod_override_error" == "true" ]]; then
    echo "Unset the variable(s) above and re-run ./scripts/setup_gcp_secrets.sh prod." >&2
    exit 1
  fi
fi

PROJECT_ID="${PROJECT_ID:-$DEFAULT_PROJECT_ID}"
REGION="${REGION:-$DEFAULT_REGION}"
REPO_NAME="${REPO_NAME:-$DEFAULT_REPO_NAME}"
ENV_FILE="${ENV_FILE:-$DEFAULT_ENV_FILE}"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "Missing $ENV_FILE — copy .env.example and fill in real values first." >&2
  exit 1
fi

echo "==> Project: $PROJECT_ID"
echo "==> Region:  $REGION"
echo

# Prod needs a typed confirmation of the project id; non-interactive runs must
# pass DEPLOY_CONFIRM=<exact project id>.
if [[ "$TARGET" == "prod" ]]; then
  if [[ -n "${DEPLOY_CONFIRM:-}" ]]; then
    if [[ "$DEPLOY_CONFIRM" != "$DEFAULT_PROJECT_ID" ]]; then
      echo "DEPLOY_CONFIRM='$DEPLOY_CONFIRM' does not match the prod project id '$DEFAULT_PROJECT_ID' — aborting." >&2
      exit 1
    fi
    echo "==> Prod run confirmed via DEPLOY_CONFIRM."
  elif [[ -t 0 ]]; then
    read -r -p "Type the prod project id ($DEFAULT_PROJECT_ID) to continue: " reply
    if [[ "$reply" != "$DEFAULT_PROJECT_ID" ]]; then
      echo "Confirmation did not match — aborting." >&2
      exit 1
    fi
  else
    echo "Refusing prod run without confirmation: no TTY to prompt on." >&2
    echo "Re-run with DEPLOY_CONFIRM=$DEFAULT_PROJECT_ID ./scripts/setup_gcp_secrets.sh prod" >&2
    exit 1
  fi
fi

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
  { grep -E "^${key}=" "$ENV_FILE" || true; } | tail -n1 | cut -d'=' -f2- \
    | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'\$//"
}

# All array expansions below use ${arr[@]+"${arr[@]}"}: macOS's /bin/bash is
# 3.2, where "${arr[@]}" on an empty array is an unbound-variable error under
# `set -u`.
SYNCED_SECRETS=()
CREATED_COUNT=0
UPDATED_COUNT=0
UNCHANGED_COUNT=0
SKIPPED_COUNT=0

ERR_FILE="$(mktemp)"
trap 'rm -f "$ERR_FILE"' EXIT

create_or_update_secret() {
  local secret_name="$1"
  local value="$2"
  local current

  if [[ -z "$value" ]]; then
    echo "    skipping $secret_name (empty value in $(basename "$ENV_FILE"))"
    SKIPPED_COUNT=$((SKIPPED_COUNT + 1))
    return
  fi

  if gcloud secrets describe "$secret_name" --project="$PROJECT_ID" --format='value(name)' >/dev/null 2>"$ERR_FILE"; then
    # Compare with the current value without printing either. A secret with no
    # enabled `latest` version (NOT_FOUND / FAILED_PRECONDITION) just gets one.
    if current="$(gcloud secrets versions access latest --secret="$secret_name" --project="$PROJECT_ID" 2>"$ERR_FILE")"; then
      if [[ "$current" == "$value" ]]; then
        echo "    secret '$secret_name' unchanged — no new version."
        UNCHANGED_COUNT=$((UNCHANGED_COUNT + 1))
        SYNCED_SECRETS+=("$secret_name")
        return
      fi
    elif ! grep -qE 'NOT_FOUND|FAILED_PRECONDITION' "$ERR_FILE"; then
      echo "ERROR: could not read the latest version of '$secret_name':" >&2
      sed 's/^/         /' "$ERR_FILE" >&2
      exit 1
    fi
    echo "    updating secret '$secret_name' (value changed)..."
    UPDATED_COUNT=$((UPDATED_COUNT + 1))
  elif grep -q 'NOT_FOUND' "$ERR_FILE"; then
    echo "    creating secret '$secret_name'..."
    gcloud secrets create "$secret_name" --replication-policy=automatic --project="$PROJECT_ID"
    CREATED_COUNT=$((CREATED_COUNT + 1))
  else
    echo "ERROR: could not look up secret '$secret_name' (not a NOT_FOUND):" >&2
    sed 's/^/         /' "$ERR_FILE" >&2
    exit 1
  fi
  printf '%s' "$value" | gcloud secrets versions add "$secret_name" --data-file=- --project="$PROJECT_ID" >/dev/null
  SYNCED_SECRETS+=("$secret_name")
}

# ---------------------------------------------------------------------------
# Sync secrets from .env (names must match SECRET_PAIRS in deploy.sh)
# ---------------------------------------------------------------------------
echo "==> Syncing secrets from $(basename "$ENV_FILE") into Secret Manager..."
create_or_update_secret "identity-supabase-anon-key"         "$(read_env_var SUPABASE_ANON_KEY)"
create_or_update_secret "identity-supabase-service-role-key" "$(read_env_var SUPABASE_SERVICE_ROLE_KEY)"
create_or_update_secret "identity-allset-service-key"        "$(read_env_var ALLSET_SERVICE_KEY)"
create_or_update_secret "identity-supabase-jwt-secret"       "$(read_env_var SUPABASE_JWT_SECRET)"
create_or_update_secret "identity-legacy-cms-db-password"    "$(read_env_var LEGACY_CMS_DB_PASSWORD)"

echo "==> Secrets: $CREATED_COUNT created, $UPDATED_COUNT updated, $UNCHANGED_COUNT unchanged, $SKIPPED_COUNT skipped (empty)."

# ---------------------------------------------------------------------------
# Grant the Cloud Run runtime service account access to the secrets it needs
# ---------------------------------------------------------------------------
PROJECT_NUMBER="$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)')"
RUNTIME_SA="${RUNTIME_SA:-${PROJECT_NUMBER}-compute@developer.gserviceaccount.com}"

echo "==> Granting roles/secretmanager.secretAccessor on synced secrets to $RUNTIME_SA..."
for secret in ${SYNCED_SECRETS[@]+"${SYNCED_SECRETS[@]}"}; do
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
