#!/usr/bin/env bash
# Full uninstall of the production (or staging) Docker stack for Vuln Intel Platform.
# Does NOT uninstall Docker itself. Optionally removes .env and/or the repo directory.
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE=".env.production"
COMPOSE_FILE="infra/docker-compose.prod.yml"
PROJECT_NAME="vuln-intel-prod"
STAGING=0
YES=0
REMOVE_ENV=1
REMOVE_IMAGES=1
PURGE_DIR=0
COMPOSE=()
DOCKER=(docker)

usage() {
  cat <<'EOF'
Usage: ./uninstall.sh [options]

Stops and removes the platform Docker stack, volumes, and (by default) built images
and .env.production so the next ./deploy.sh --yes --fresh is a clean slate.

Options:
  --env-file=FILE     Env file (default: .env.production)
  --staging           Target staging stack (.env.staging + docker-compose.staging.yml)
  --keep-env          Keep .env.production / .env.staging
  --keep-images       Do not remove project images
  --purge-dir         After Docker cleanup, delete this entire repo directory
                      (run from outside if you need the shell to survive, or expect logout)
  --yes, -y           Non-interactive (required for --purge-dir)
  -h, --help          Show this help

Typical wipe before reinstall:
  cd /opt/vuln-intel-platform
  ./uninstall.sh --yes
  cd /opt && rm -rf vuln-intel-platform
  git clone https://github.com/terakcsa-cyber/softec.git vuln-intel-platform
  cd vuln-intel-platform
  ./deploy.sh --yes --fresh --origin=https://YOUR_DOMAIN_OR_IP \
    --admin-email=admin@local.dev --admin-password='YourLongPassword1'

One-shot (deletes the clone too):
  ./uninstall.sh --yes --purge-dir
EOF
}

log() { printf '[uninstall] %s\n' "$*"; }
warn() { printf '[uninstall] WARN: %s\n' "$*" >&2; }
die() { printf '[uninstall] ERROR: %s\n' "$*" >&2; exit 1; }

is_tty() { [[ -t 0 && -t 1 ]]; }

confirm() {
  local prompt="$1"
  if [[ "$YES" == "1" ]]; then
    return 0
  fi
  if ! is_tty; then
    die "Refusing interactive confirm without TTY. Re-run with --yes."
  fi
  local ans=""
  read -r -p "[uninstall] $prompt [y/N] " ans
  [[ "$ans" == "y" || "$ans" == "Y" || "$ans" == "yes" || "$ans" == "YES" ]]
}

for arg in "$@"; do
  case "$arg" in
    --env-file=*) ENV_FILE="${arg#*=}" ;;
    --staging)
      STAGING=1
      ENV_FILE=".env.staging"
      COMPOSE_FILE="infra/docker-compose.staging.yml"
      PROJECT_NAME="vuln-intel-staging"
      ;;
    --keep-env) REMOVE_ENV=0 ;;
    --keep-images) REMOVE_IMAGES=0 ;;
    --purge-dir) PURGE_DIR=1 ;;
    --yes|-y) YES=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "[uninstall] Unknown option: $arg" >&2; usage; exit 2 ;;
  esac
done

cd "$ROOT_DIR"

if [[ "$PURGE_DIR" == "1" && "$YES" != "1" ]]; then
  die "--purge-dir requires --yes"
fi

if ! confirm "This will STOP and DELETE containers + volumes for project «${PROJECT_NAME}». Continue?"; then
  die "Aborted."
fi

if ! command -v docker >/dev/null 2>&1; then
  die "Docker CLI not found."
fi

if docker info >/dev/null 2>&1; then
  DOCKER=(docker)
elif command -v sudo >/dev/null 2>&1 && sudo docker info >/dev/null 2>&1; then
  DOCKER=(sudo docker)
  warn "Using sudo for Docker commands."
else
  die "Docker daemon is not reachable."
fi

if "${DOCKER[@]}" compose version >/dev/null 2>&1; then
  COMPOSE=("${DOCKER[@]}" compose)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE=(docker-compose)
else
  die "Docker Compose v2 not found (docker compose)."
fi

if [[ "$ENV_FILE" = /* ]]; then
  app_env_file="$ENV_FILE"
else
  app_env_file="../$ENV_FILE"
fi

compose_down() {
  local env_arg=()
  if [[ -f "$ENV_FILE" ]]; then
    env_arg=(--env-file "$ENV_FILE")
  fi
  # Prefer project name so we still tear down even if compose file/env changed.
  APP_ENV_FILE="$app_env_file" "${COMPOSE[@]}" \
    -p "$PROJECT_NAME" \
    "${env_arg[@]}" \
    -f "$COMPOSE_FILE" \
    down -v --remove-orphans "$@" || true
}

log "Stopping stack and deleting volumes (project=$PROJECT_NAME)..."
if [[ -f "$COMPOSE_FILE" ]]; then
  if [[ "$REMOVE_IMAGES" == "1" ]]; then
    compose_down --rmi local
  else
    compose_down
  fi
else
  warn "Compose file missing ($COMPOSE_FILE); trying project-only teardown."
  "${COMPOSE[@]}" -p "$PROJECT_NAME" down -v --remove-orphans || true
fi

# Belt-and-suspenders: named volumes from compose (project prefix).
log "Removing leftover volumes matching ${PROJECT_NAME}_* ..."
while read -r vol; do
  [[ -z "$vol" ]] && continue
  log "  docker volume rm $vol"
  "${DOCKER[@]}" volume rm -f "$vol" >/dev/null 2>&1 || true
done < <("${DOCKER[@]}" volume ls -q --filter "name=${PROJECT_NAME}_" 2>/dev/null || true)

# Translate proxy image tag used by prod compose.
if [[ "$REMOVE_IMAGES" == "1" ]]; then
  log "Removing known project images (if present)..."
  for img in \
    "${PROJECT_NAME}-api" \
    "${PROJECT_NAME}-web" \
    "${PROJECT_NAME}-ingest" \
    "${PROJECT_NAME}-ai" \
    "vuln-intel-prod-api" \
    "vuln-intel-prod-web" \
    "vuln-intel-prod-ingest" \
    "vuln-intel-prod-ai" \
    "vuln-intel-translate-proxy:local"
  do
    "${DOCKER[@]}" image rm -f "$img" >/dev/null 2>&1 || true
  done
fi

if [[ "$REMOVE_ENV" == "1" ]]; then
  if [[ -f "$ENV_FILE" ]]; then
    log "Removing $ENV_FILE"
    rm -f -- "$ENV_FILE"
  fi
  # Common local leftovers
  rm -f -- .env.production.backup .env.staging.backup 2>/dev/null || true
else
  log "Keeping $ENV_FILE (--keep-env)"
fi

log "Docker cleanup summary:"
"${DOCKER[@]}" ps -a --filter "name=${PROJECT_NAME}" --format 'table {{.Names}}\t{{.Status}}' 2>/dev/null || true
"${DOCKER[@]}" volume ls --filter "name=${PROJECT_NAME}_" 2>/dev/null || true

log "Stack uninstalled."
log "Reinstall: git clone … && cd … && ./deploy.sh --yes --fresh --origin=https://… --admin-email=… --admin-password=…"
log "Tip: keep WEB_PUBLISHED_PORT=3000 and WEB_TLS_PUBLISHED_PORT=443 (do not set both to 443)."

if [[ "$PURGE_DIR" == "1" ]]; then
  log "Purging repo directory: $ROOT_DIR"
  # Schedule delete after this process exits so bash is not deleting its cwd mid-script.
  parent="$(dirname "$ROOT_DIR")"
  base="$(basename "$ROOT_DIR")"
  cd "$parent"
  rm -rf -- "$base"
  log "Directory removed."
fi
