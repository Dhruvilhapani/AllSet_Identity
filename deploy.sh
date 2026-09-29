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
#   ./deploy.sh prod             # prod (allset-244ab), reads .env.prod; asks
#                                # you to type the project id to confirm
#   DEPLOY_CONFIRM=allset-244ab ./deploy.sh prod   # non-interactive prod
#   REGION=us-central1 PROJECT_ID=my-project ./deploy.sh dev
#
# PROJECT_ID/REGION/REPO_NAME/SERVICE_NAME/ENV_FILE overrides are honoured for
# dev only; prod aborts if any of them is set to something other than the prod
# default, so a stray shell export can't redirect a prod deploy.
#
# Paths are resolved from this script's location, so it can be run from any
# working directory.
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

DEFAULT_REGION="asia-south1"
DEFAULT_REPO_NAME="allset-identity"
DEFAULT_SERVICE_NAME="allset-identity"
DEFAULT_ENV_FILE="$SCRIPT_DIR/$DEFAULT_ENV_BASENAME"

# Prod must deploy exactly the prod service in the prod project from .env.prod.
# Overrides stay available for dev, but a leftover `export PROJECT_ID=...` (or
# REGION, ...) from another session must never silently redirect a prod run.
if [[ "$TARGET" == "prod" ]]; then
  prod_override_error=false
  for pair in "PROJECT_ID=$DEFAULT_PROJECT_ID" "REGION=$DEFAULT_REGION" \
              "REPO_NAME=$DEFAULT_REPO_NAME" "SERVICE_NAME=$DEFAULT_SERVICE_NAME" \
              "ENV_FILE=$DEFAULT_ENV_FILE"; do
    var="${pair%%=*}"
    expected="${pair#*=}"
    actual="${!var-}"
    if [[ -n "$actual" && "$actual" != "$expected" ]]; then
      echo "Refusing prod deploy: $var is set to '$actual' in your shell, but prod requires '$expected'." >&2
      prod_override_error=true
    fi
  done
  if [[ "$prod_override_error" == "true" ]]; then
    echo "Unset the variable(s) above (e.g. 'unset PROJECT_ID') and re-run ./deploy.sh prod." >&2
    exit 1
  fi
fi

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
REGION="${REGION:-$DEFAULT_REGION}"
REPO_NAME="${REPO_NAME:-$DEFAULT_REPO_NAME}"
SERVICE_NAME="${SERVICE_NAME:-$DEFAULT_SERVICE_NAME}"
ENV_FILE="${ENV_FILE:-$DEFAULT_ENV_FILE}"
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
  # Secrets (anon/service-role keys, ALLSET_SERVICE_KEY, SUPABASE_JWT_SECRET,
  # LEGACY_CMS_DB_PASSWORD) never go in here — they are bound from Secret
  # Manager below.
  for key in SUPABASE_URL SUPABASE_JWKS_URL SUPABASE_JWT_ISSUER \
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
# Plain env vars the app refuses to boot without (app/core/config.py validate())
# ---------------------------------------------------------------------------
is_truthy() {
  # Mirrors config._flag(): 1/true/yes/on, case-insensitive (no ${v,,} — bash 3.2)
  case "$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')" in
    1|true|yes|on) return 0 ;;
    *) return 1 ;;
  esac
}

LEGACY_ENABLED=false
if is_truthy "$(read_env_var LEGACY_MIGRATION_ENABLED)"; then
  LEGACY_ENABLED=true
fi

REQUIRED_PLAIN_VARS="SUPABASE_URL"
if [[ "$LEGACY_ENABLED" == "true" ]]; then
  REQUIRED_PLAIN_VARS+=" LEGACY_CMS_DB_HOST LEGACY_CMS_DB_USER"
fi
for key in $REQUIRED_PLAIN_VARS; do
  if [[ -z "$(read_env_var "$key")" ]]; then
    echo "ERROR: $key is empty in $(basename "$ENV_FILE") but the service requires it at startup." >&2
    exit 1
  fi
done

# ---------------------------------------------------------------------------
# Build --set-secrets from Secret Manager.
#
# --set-secrets REPLACES every secret binding on the service, so a binding we
# leave out here is removed from the live service. Therefore:
#   * a secret the app requires at startup must exist, or we abort;
#   * an optional secret that is genuinely NOT_FOUND is skipped with a warning;
#   * any other lookup error (permission denied, network, auth) aborts rather
#     than being mistaken for "not found".
# ---------------------------------------------------------------------------
# Returns 0 if the secret exists, 1 if Secret Manager says NOT_FOUND, and
# aborts the script on any other error.
secret_exists() {
  local err
  if err="$(gcloud secrets describe "$1" --project="$PROJECT_ID" --format='value(name)' 2>&1 >/dev/null)"; then
    return 0
  fi
  if printf '%s' "$err" | grep -q 'NOT_FOUND'; then
    return 1
  fi
  echo "ERROR: could not look up secret '$1' in project $PROJECT_ID (not a NOT_FOUND):" >&2
  printf '%s\n' "$err" | sed 's/^/         /' >&2
  echo "       Aborting so the binding isn't silently dropped from the live service." >&2
  exit 1
}

# TARGET_ENV_VAR=secret-name pairs. Must stay in sync with
# scripts/setup_gcp_secrets.sh.
SECRET_PAIRS="SUPABASE_ANON_KEY=identity-supabase-anon-key"
SECRET_PAIRS+=" SUPABASE_SERVICE_ROLE_KEY=identity-supabase-service-role-key"
SECRET_PAIRS+=" ALLSET_SERVICE_KEY=identity-allset-service-key"
SECRET_PAIRS+=" SUPABASE_JWT_SECRET=identity-supabase-jwt-secret"
SECRET_PAIRS+=" LEGACY_CMS_DB_PASSWORD=identity-legacy-cms-db-password"

# Required at startup by config.validate(). LEGACY_CMS_DB_PASSWORD becomes
# required when LEGACY_MIGRATION_ENABLED is on; SUPABASE_JWT_SECRET (HS256
# verification for legacy-signed projects, security.py) is required whenever
# the env file sets it, so moving it off plain env vars can't silently drop it.
REQUIRED_SECRET_VARS="SUPABASE_ANON_KEY SUPABASE_SERVICE_ROLE_KEY ALLSET_SERVICE_KEY"
if [[ "$LEGACY_ENABLED" == "true" ]]; then
  REQUIRED_SECRET_VARS+=" LEGACY_CMS_DB_PASSWORD"
fi
if [[ -n "$(read_env_var SUPABASE_JWT_SECRET)" ]]; then
  REQUIRED_SECRET_VARS+=" SUPABASE_JWT_SECRET"
fi

is_required_secret() {
  case " $REQUIRED_SECRET_VARS " in
    *" $1 "*) return 0 ;;
    *) return 1 ;;
  esac
}

SECRETS=""
MISSING_REQUIRED=""
for pair in $SECRET_PAIRS; do
  target="${pair%%=*}"
  secret_name="${pair#*=}"
  if secret_exists "$secret_name"; then
    SECRETS+="${SECRETS:+,}${target}=${secret_name}:latest"
  elif is_required_secret "$target"; then
    MISSING_REQUIRED+=" $secret_name"
  else
    echo "WARNING: optional secret '$secret_name' not found in Secret Manager — skipping $target." >&2
    echo "         Run ./scripts/setup_gcp_secrets.sh $TARGET after adding its value to $(basename "$ENV_FILE") to include it." >&2
  fi
done

if [[ -n "$MISSING_REQUIRED" ]]; then
  echo "ERROR: required secret(s) missing from Secret Manager in $PROJECT_ID:$MISSING_REQUIRED" >&2
  echo "       The service cannot start without them. Run ./scripts/setup_gcp_secrets.sh $TARGET first." >&2
  exit 1
fi

echo "==> Project: $PROJECT_ID"
echo "==> Region:  $REGION"
echo "==> Image:   $IMAGE"
echo "==> Secrets: ${SECRETS//,/ }"
echo

# ---------------------------------------------------------------------------
# Prod needs a typed confirmation of the project id. Non-interactive runs must
# pass DEPLOY_CONFIRM=<exact project id>; anything else aborts.
# ---------------------------------------------------------------------------
if [[ "$TARGET" == "prod" ]]; then
  if [[ -n "${DEPLOY_CONFIRM:-}" ]]; then
    if [[ "$DEPLOY_CONFIRM" != "$DEFAULT_PROJECT_ID" ]]; then
      echo "DEPLOY_CONFIRM='$DEPLOY_CONFIRM' does not match the prod project id '$DEFAULT_PROJECT_ID' — aborting." >&2
      exit 1
    fi
    echo "==> Prod deploy confirmed via DEPLOY_CONFIRM."
  elif [[ -t 0 ]]; then
    read -r -p "Type the prod project id ($DEFAULT_PROJECT_ID) to deploy: " reply
    if [[ "$reply" != "$DEFAULT_PROJECT_ID" ]]; then
      echo "Confirmation did not match — aborting prod deploy." >&2
      exit 1
    fi
  else
    echo "Refusing prod deploy without confirmation: no TTY to prompt on." >&2
    echo "Re-run with DEPLOY_CONFIRM=$DEFAULT_PROJECT_ID ./deploy.sh prod" >&2
    exit 1
  fi
fi

# Remember the currently serving revision (if any) for the rollback hint below.
# Best-effort only: a first deploy has no service yet.
PREVIOUS_REVISION="$(gcloud run services describe "$SERVICE_NAME" \
  --project="$PROJECT_ID" --region="$REGION" \
  --format='value(status.latestReadyRevisionName)' 2>/dev/null || true)"

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

# ---------------------------------------------------------------------------
# Post-deploy verification
# ---------------------------------------------------------------------------
rollback_hint() {
  if [[ -n "$PREVIOUS_REVISION" && "$PREVIOUS_REVISION" != "${READY_REVISION:-}" ]]; then
    echo "       To roll back: gcloud run services update-traffic $SERVICE_NAME --project=$PROJECT_ID --region=$REGION --to-revisions=$PREVIOUS_REVISION=100" >&2
  fi
}

service_field() {
  gcloud run services describe "$SERVICE_NAME" \
    --project="$PROJECT_ID" --region="$REGION" --format="value($1)"
}
# Separate calls: an empty field in one multi-field `value()` line would shift
# the others when split on whitespace.
SERVICE_URL="$(service_field status.url)"
READY_REVISION="$(service_field status.latestReadyRevisionName)"
CREATED_REVISION="$(service_field status.latestCreatedRevisionName)"

if [[ -z "$SERVICE_URL" || -z "$CREATED_REVISION" || "$READY_REVISION" != "$CREATED_REVISION" ]]; then
  echo "ERROR: latest created revision '${CREATED_REVISION:-?}' is not the latest ready revision '${READY_REVISION:-?}'." >&2
  echo "       The new revision did not become ready; check its logs in Cloud Run." >&2
  rollback_hint
  exit 1
fi
echo "==> Revision ready: $READY_REVISION"

# /health is liveness; /v1/auth/roles and /identity/v1/auth/roles are public,
# no-I/O routes that prove both router mounts are live. The /identity/v1 mount
# is what Firebase Hosting's /identity/** rewrite hits (it doesn't strip the
# prefix) — losing it breaks every browser login.
VERIFY_FAILED=false
for path in /health /v1/auth/roles /identity/v1/auth/roles; do
  code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 20 "${SERVICE_URL}${path}" 2>/dev/null)" || code="${code:-000}"
  if [[ "$code" =~ ^2[0-9][0-9]$ ]]; then
    echo "==> GET $path -> $code"
  else
    echo "ERROR: GET ${SERVICE_URL}${path} returned ${code:-000} (expected 2xx)." >&2
    VERIFY_FAILED=true
  fi
done

if [[ "$VERIFY_FAILED" == "true" ]]; then
  echo "ERROR: post-deploy checks failed — revision $READY_REVISION is serving traffic." >&2
  rollback_hint
  exit 1
fi

echo
echo "==> Deployed: $SERVICE_URL ($READY_REVISION)"
