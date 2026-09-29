#!/usr/bin/env bash
#
# One-time (idempotent) GCP setup for AllSet_Identity on Cloud Run: enables
# required APIs, creates the Artifact Registry repo, creates/updates Secret
# Manager secrets from the local .env file, creates the dedicated Cloud Run
# runtime service account identity-run@<project>.iam.gserviceaccount.com, and
# grants it roles/secretmanager.secretAccessor on each identity-* secret (per
# secret, never project-wide). The app makes no other GCP API calls, so the
# service account gets no other role.
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
#   RUNTIME_SA=other@allset-491218.iam.gserviceaccount.com ./scripts/setup_gcp_secrets.sh dev
#
# RUNTIME_SA (like PROJECT_ID/REGION/...) may be overridden for dev only; prod
# aborts if it is set to anything but identity-run@allset-244ab. An overridden
# service account must already exist - only the default one is created.

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
RUNTIME_SA_ID="identity-run"
DEFAULT_RUNTIME_SA="${RUNTIME_SA_ID}@${DEFAULT_PROJECT_ID}.iam.gserviceaccount.com"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DEFAULT_ENV_FILE="$ROOT_DIR/$DEFAULT_ENV_BASENAME"

# Same guard as deploy.sh: overrides are for dev only; a stray shell export
# must never point a prod run at another project or env file.
if [[ "$TARGET" == "prod" ]]; then
  prod_override_error=false
  for pair in "PROJECT_ID=$DEFAULT_PROJECT_ID" "REGION=$DEFAULT_REGION" \
              "REPO_NAME=$DEFAULT_REPO_NAME" "ENV_FILE=$DEFAULT_ENV_FILE" \
              "RUNTIME_SA=$DEFAULT_RUNTIME_SA"; do
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
# Derived from the (possibly dev-overridden) PROJECT_ID, not DEFAULT_PROJECT_ID.
RUNTIME_SA="${RUNTIME_SA:-${RUNTIME_SA_ID}@${PROJECT_ID}.iam.gserviceaccount.com}"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "Missing $ENV_FILE — copy .env.example and fill in real values first." >&2
  exit 1
fi

echo "==> Project: $PROJECT_ID"
echo "==> Region:  $REGION"
echo "==> Runtime service account: $RUNTIME_SA"
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
  iam.googleapis.com \
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

# gcloud stderr is captured here so NOT_FOUND can be told apart from other errors.
ERR_FILE="$(mktemp)"
trap 'rm -f "$ERR_FILE"' EXIT

# ---------------------------------------------------------------------------
# Dedicated runtime service account (replaces the default compute SA, which
# has roles/editor on the whole project)
# ---------------------------------------------------------------------------
if gcloud iam service-accounts describe "$RUNTIME_SA" --project="$PROJECT_ID" \
    --format='value(email)' >/dev/null 2>"$ERR_FILE"; then
  echo "==> Runtime service account '$RUNTIME_SA' already exists."
elif grep -q 'NOT_FOUND' "$ERR_FILE"; then
  if [[ "$RUNTIME_SA" != "${RUNTIME_SA_ID}@${PROJECT_ID}.iam.gserviceaccount.com" ]]; then
    echo "ERROR: RUNTIME_SA '$RUNTIME_SA' does not exist; only the default ${RUNTIME_SA_ID} account is created by this script." >&2
    exit 1
  fi
  echo "==> Creating runtime service account '$RUNTIME_SA'..."
  gcloud iam service-accounts create "$RUNTIME_SA_ID" \
    --project="$PROJECT_ID" \
    --display-name="allset-identity Cloud Run runtime" \
    --description="Runtime identity for the allset-identity Cloud Run service; reads identity-* secrets only."
else
  echo "ERROR: could not look up service account '$RUNTIME_SA' (not a NOT_FOUND):" >&2
  sed 's/^/         /' "$ERR_FILE" >&2
  exit 1
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

create_or_update_secret() {
  local secret_name="$1"
  local value="$2"
  local current

  if [[ -z "$value" ]]; then
    echo "    skipping $secret_name (empty value in $(basename "$ENV_FILE"))"
    SKIPPED_COUNT=$((SKIPPED_COUNT + 1))
    # deploy.sh binds every identity-* secret that exists, so a secret that is
    # empty locally but already in Secret Manager still needs the grant, or the
    # new revision could not read it and would fail to start.
    if gcloud secrets describe "$secret_name" --project="$PROJECT_ID" --format='value(name)' >/dev/null 2>"$ERR_FILE"; then
      echo "      (it exists in Secret Manager, so deploy.sh will bind it; granting access anyway)"
      SYNCED_SECRETS+=("$secret_name")
    elif ! grep -q 'NOT_FOUND' "$ERR_FILE"; then
      echo "ERROR: could not look up secret '$secret_name' (not a NOT_FOUND):" >&2
      sed 's/^/         /' "$ERR_FILE" >&2
      exit 1
    fi
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
# Grant the runtime service account read access, one secret at a time
# ---------------------------------------------------------------------------
# Existing grants to other members (e.g. the default compute SA, which
# wa-automation uses to read identity-allset-service-key) are left untouched.
# A binding that is already present is left alone (no policy write). A freshly
# created service account can take a few seconds to become visible to IAM, so
# "does not exist" is retried.
GRANTED_COUNT=0
ALREADY_GRANTED_COUNT=0

has_accessor() {
  local policy
  if ! policy="$(gcloud secrets get-iam-policy "$1" --project="$PROJECT_ID" \
      --flatten='bindings[].members' \
      --format='value(bindings.role,bindings.members)' 2>"$ERR_FILE")"; then
    echo "ERROR: could not read the IAM policy of secret '$1':" >&2
    sed 's/^/         /' "$ERR_FILE" >&2
    exit 1
  fi
  printf '%s\n' "$policy" | awk -v m="serviceAccount:${RUNTIME_SA}" \
    '$1 == "roles/secretmanager.secretAccessor" && $2 == m { found = 1 } END { exit !found }'
}

grant_accessor() {
  local secret="$1" attempt=1
  if has_accessor "$secret"; then
    echo "    $secret (already granted)"
    ALREADY_GRANTED_COUNT=$((ALREADY_GRANTED_COUNT + 1))
    return 0
  fi
  while true; do
    if gcloud secrets add-iam-policy-binding "$secret" \
        --project="$PROJECT_ID" \
        --member="serviceAccount:${RUNTIME_SA}" \
        --role="roles/secretmanager.secretAccessor" \
        --condition=None >/dev/null 2>"$ERR_FILE"; then
      echo "    $secret (granted)"
      GRANTED_COUNT=$((GRANTED_COUNT + 1))
      return 0
    fi
    if (( attempt < 6 )) && grep -qiE 'does not exist|not found' "$ERR_FILE"; then
      sleep "${GRANT_RETRY_SECONDS:-5}"
      attempt=$((attempt + 1))
      continue
    fi
    echo "ERROR: could not grant secretAccessor on '$secret' to $RUNTIME_SA:" >&2
    sed 's/^/         /' "$ERR_FILE" >&2
    exit 1
  done
}

echo "==> Granting roles/secretmanager.secretAccessor on identity secrets to $RUNTIME_SA..."
for secret in ${SYNCED_SECRETS[@]+"${SYNCED_SECRETS[@]}"}; do
  grant_accessor "$secret"
done
echo "==> Access: $GRANTED_COUNT granted, $ALREADY_GRANTED_COUNT already granted."

echo
echo "==> Done. Runtime service account: $RUNTIME_SA"
echo "    Next: run ./deploy.sh $TARGET (it generates deploy/env.yaml from $(basename "$ENV_FILE") automatically)"
