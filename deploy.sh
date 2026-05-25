#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE=".env.production"
ORIGIN=""
WEB_PORT=""
FORCE_ENV=0
INIT_ONLY=0
NO_BUILD=0

usage() {
  cat <<'EOF'
Usage: ./deploy.sh [options]

Options:
  --origin=URL       Public web origin, e.g. https://vuln-intel.example.com
  --port=PORT        Published web port (default: 3000)
  --env-file=FILE    Env file to create/use (default: .env.production)
  --force-env        Regenerate env file even if it already exists
  --init-only        Only create/check env file, do not start containers
  --no-build         Run compose up without --build
  -h, --help         Show this help

Typical first deploy:
  ./deploy.sh --origin=https://vuln-intel.example.com
EOF
}

for arg in "$@"; do
  case "$arg" in
    --origin=*) ORIGIN="${arg#*=}" ;;
    --port=*) WEB_PORT="${arg#*=}" ;;
    --env-file=*) ENV_FILE="${arg#*=}" ;;
    --force-env) FORCE_ENV=1 ;;
    --init-only) INIT_ONLY=1 ;;
    --no-build) NO_BUILD=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "[deploy] Unknown option: $arg" >&2; usage; exit 2 ;;
  esac
done

cd "$ROOT_DIR"

if ! command -v docker >/dev/null 2>&1; then
  echo "[deploy] Docker is required. Install Docker Engine + Compose v2 first." >&2
  exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "[deploy] Docker Compose v2 is required (docker compose ...)." >&2
  exit 1
fi

init_args=( "--out=$ENV_FILE" )
if [[ -n "$ORIGIN" ]]; then init_args+=( "--origin=$ORIGIN" ); fi
if [[ -n "$WEB_PORT" ]]; then init_args+=( "--web-port=$WEB_PORT" ); fi
if [[ "$FORCE_ENV" == "1" ]]; then init_args+=( "--force" ); fi

if [[ ! -f "$ENV_FILE" || "$FORCE_ENV" == "1" ]]; then
  echo "[deploy] Creating $ENV_FILE"
  if command -v node >/dev/null 2>&1; then
    node scripts/init-production-env.mjs "${init_args[@]}"
  else
    echo "[deploy] Local Node.js not found; using temporary node:20-alpine container."
    docker run --rm \
      --user "$(id -u):$(id -g)" \
      -v "$ROOT_DIR:/repo" \
      -w /repo \
      node:20-alpine \
      node scripts/init-production-env.mjs "${init_args[@]}"
  fi
else
  echo "[deploy] Using existing $ENV_FILE (use --force-env to regenerate)."
fi

if [[ "$INIT_ONLY" == "1" ]]; then
  echo "[deploy] Env ready: $ENV_FILE"
  exit 0
fi

if [[ "$ENV_FILE" = /* ]]; then
  app_env_file="$ENV_FILE"
else
  app_env_file="../$ENV_FILE"
fi

echo "[deploy] Validating compose config"
APP_ENV_FILE="$app_env_file" docker compose --env-file "$ENV_FILE" -f infra/docker-compose.prod.yml config >/dev/null

echo "[deploy] Starting production stack"
up_args=( "up" "-d" )
if [[ "$NO_BUILD" != "1" ]]; then up_args+=( "--build" ); fi
APP_ENV_FILE="$app_env_file" docker compose --env-file "$ENV_FILE" -f infra/docker-compose.prod.yml "${up_args[@]}"

published_port="$(grep -E '^WEB_PUBLISHED_PORT=' "$ENV_FILE" | tail -n 1 | cut -d= -f2- || true)"
published_port="${published_port:-3000}"

echo
echo "[deploy] Done."
echo "[deploy] Web: http://127.0.0.1:${published_port}"
echo "[deploy] Logs: docker compose --env-file $ENV_FILE -f infra/docker-compose.prod.yml logs -f api web ingest ai"
