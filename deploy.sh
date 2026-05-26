#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE=".env.production"
ORIGIN=""
WEB_PORT=""
FORCE_ENV=0
INIT_ONLY=0
NO_BUILD=0
YES=0
AUTO_INSTALL=1
COMPOSE=()
DOCKER=(docker)

usage() {
  cat <<'EOF'
Usage: ./deploy.sh [options]

Options:
  --origin=URL          Public web origin, e.g. https://vuln-intel.example.com
  --port=PORT           Published web/HTTPS port (default: interactive, then 443)
  --env-file=FILE       Env file to create/use (default: .env.production)
  --force-env           Regenerate env file even if it already exists
  --init-only           Only create/check env file, do not start containers
  --no-build            Run compose up without --build
  --yes, -y             Non-interactive defaults and automatic dependency install
  --no-auto-install     Do not install missing Docker/Compose packages
  -h, --help            Show this help

Typical first deploy:
  ./deploy.sh --origin=https://vuln-intel.example.com
EOF
}

log() { printf '[deploy] %s\n' "$*"; }
warn() { printf '[deploy] WARN: %s\n' "$*" >&2; }
die() { printf '[deploy] ERROR: %s\n' "$*" >&2; exit 1; }

is_tty() { [[ -t 0 && -t 1 ]]; }
is_linux() { [[ "$(uname -s 2>/dev/null || true)" == "Linux" ]]; }

for arg in "$@"; do
  case "$arg" in
    --origin=*) ORIGIN="${arg#*=}" ;;
    --port=*) WEB_PORT="${arg#*=}" ;;
    --env-file=*) ENV_FILE="${arg#*=}" ;;
    --force-env) FORCE_ENV=1 ;;
    --init-only) INIT_ONLY=1 ;;
    --no-build) NO_BUILD=1 ;;
    --yes|-y) YES=1 ;;
    --no-auto-install) AUTO_INSTALL=0 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "[deploy] Unknown option: $arg" >&2; usage; exit 2 ;;
  esac
done

cd "$ROOT_DIR"

run_as_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo "$@"
  else
    return 1
  fi
}

confirm() {
  local prompt="$1"
  if [[ "$YES" == "1" || ! is_tty ]]; then
    return 0
  fi

  local answer
  read -r -p "$prompt [Y/n] " answer
  [[ -z "$answer" || "$answer" =~ ^[YyДд] ]]
}

prompt_value() {
  local prompt="$1"
  local default_value="$2"
  local answer=""
  if [[ "$YES" == "1" || ! is_tty ]]; then
    printf '%s' "$default_value"
    return 0
  fi

  read -r -p "$prompt [$default_value]: " answer
  printf '%s' "${answer:-$default_value}"
}

read_env_value() {
  local key="$1"
  local file="$2"
  [[ -f "$file" ]] || return 1
  awk -F= -v key="$key" '$1 == key { sub(/^[^=]*=/, ""); print; exit }' "$file"
}

write_env_value() {
  local key="$1"
  local value="$2"
  local file="$3"
  local tmp
  tmp="$(mktemp)"
  if awk -F= -v key="$key" -v value="$value" '
    BEGIN { written = 0 }
    $1 == key { print key "=" value; written = 1; next }
    { print }
    END { if (!written) print key "=" value }
  ' "$file" > "$tmp"; then
    cat "$tmp" > "$file"
  fi
  rm -f "$tmp"
}

validate_port() {
  local port="$1"
  [[ "$port" =~ ^[0-9]+$ && "$port" -ge 1 && "$port" -le 65535 ]]
}

default_host() {
  if command -v hostname >/dev/null 2>&1; then
    hostname -f 2>/dev/null || hostname 2>/dev/null || printf 'localhost'
  else
    printf 'localhost'
  fi
}

derive_port_from_origin() {
  local origin="$1"
  if [[ "$origin" =~ :([0-9]+)(/)?$ ]]; then
    printf '%s' "${BASH_REMATCH[1]}"
  elif [[ "$origin" == https://* ]]; then
    printf '443'
  else
    printf '3000'
  fi
}

normalize_origin() {
  local origin="$1"
  local port="$2"
  origin="${origin%/}"
  if [[ ! "$origin" =~ ^https?:// ]]; then
    origin="https://${origin}"
  fi

  if [[ "$origin" =~ ^https?://[^/:]+$ && "$port" != "443" && "$port" != "80" ]]; then
    origin="${origin}:${port}"
  fi

  printf '%s' "$origin"
}

install_linux_packages() {
  if [[ "$AUTO_INSTALL" != "1" ]]; then
    return 1
  fi
  if ! is_linux; then
    return 1
  fi

  if command -v apt-get >/dev/null 2>&1; then
    log "Installing required packages with apt-get."
    run_as_root apt-get update || return 1
    run_as_root apt-get install -y ca-certificates curl docker.io docker-compose-plugin || return 1
    return 0
  fi

  if command -v dnf >/dev/null 2>&1; then
    log "Installing required packages with dnf."
    run_as_root dnf install -y ca-certificates curl docker docker-compose-plugin || return 1
    return 0
  fi

  if command -v yum >/dev/null 2>&1; then
    log "Installing required packages with yum."
    run_as_root yum install -y ca-certificates curl docker docker-compose-plugin || return 1
    return 0
  fi

  return 1
}

ensure_docker_cli() {
  if command -v docker >/dev/null 2>&1; then
    return 0
  fi

  warn "Docker CLI was not found."
  if confirm "Install Docker and Compose plugin automatically?"; then
    install_linux_packages || die "Could not install Docker automatically. Install Docker Engine manually and rerun ./deploy.sh."
  fi

  command -v docker >/dev/null 2>&1 || die "Docker CLI is still missing after install attempt."
}

ensure_docker_daemon() {
  if "${DOCKER[@]}" info >/dev/null 2>&1; then
    return 0
  fi

  if is_linux && command -v systemctl >/dev/null 2>&1; then
    log "Trying to enable and start Docker daemon."
    run_as_root systemctl enable --now docker >/dev/null 2>&1 || true
  fi

  if docker info >/dev/null 2>&1; then
    DOCKER=(docker)
    return 0
  fi

  if command -v sudo >/dev/null 2>&1 && sudo docker info >/dev/null 2>&1; then
    DOCKER=(sudo docker)
    warn "Using sudo for Docker commands. Add your user to the docker group later if desired."
    return 0
  fi

  die "Docker daemon is not reachable. Start Docker or run this script with a user allowed to access Docker."
}

print_compose_install_help() {
  cat >&2 <<'EOF'
[deploy] Docker Compose v2 is required.

Install it on Ubuntu/Debian:
  sudo apt-get update
  sudo apt-get install -y docker-compose-plugin

Install it on RHEL/CentOS/Fedora:
  sudo dnf install -y docker-compose-plugin

Then verify:
  docker compose version

Standalone `docker-compose` is supported only if it is version v2.
EOF
}

detect_compose() {
  if "${DOCKER[@]}" compose version >/dev/null 2>&1; then
    COMPOSE=("${DOCKER[@]}" compose)
    return 0
  fi

  if command -v docker-compose >/dev/null 2>&1; then
    local version_output
    version_output="$(docker-compose version 2>/dev/null || true)"
    if [[ "$version_output" == *"v2."* || "$version_output" == *"version 2."* ]]; then
      COMPOSE=(docker-compose)
      return 0
    fi

    warn "Found docker-compose, but it is not Compose v2:"
    echo "$version_output" >&2
  fi

  return 1
}

ensure_compose() {
  if detect_compose; then
    return 0
  fi

  warn "Docker Compose v2 was not found."
  if confirm "Install Docker Compose plugin automatically?"; then
    install_linux_packages || true
  fi

  if ! detect_compose; then
    print_compose_install_help
    exit 1
  fi
}

port_in_use() {
  local port="$1"
  if command -v lsof >/dev/null 2>&1; then
    lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1
    return $?
  fi
  if command -v ss >/dev/null 2>&1; then
    ss -ltn "( sport = :$port )" 2>/dev/null | awk 'NR > 1 { found = 1 } END { exit found ? 0 : 1 }'
    return $?
  fi
  return 1
}

prepare_interactive_env_inputs() {
  local env_exists=0
  [[ -f "$ENV_FILE" ]] && env_exists=1

  if [[ "$env_exists" == "1" && "$FORCE_ENV" != "1" ]]; then
    [[ -n "$WEB_PORT" ]] || WEB_PORT="$(read_env_value WEB_PUBLISHED_PORT "$ENV_FILE" || true)"
    [[ -n "$ORIGIN" ]] || ORIGIN="$(read_env_value PUBLIC_WEB_ORIGIN "$ENV_FILE" || true)"
    return 0
  fi

  local default_port default_origin host
  host="$(default_host)"
  default_port="${WEB_PORT:-443}"
  default_origin="${ORIGIN:-https://${host}}"

  if [[ -z "$WEB_PORT" ]]; then
    WEB_PORT="$(prompt_value "Порт, на котором будет доступен web/HTTPS снаружи" "$default_port")"
  fi
  validate_port "$WEB_PORT" || die "Invalid port: $WEB_PORT"

  if [[ -z "$ORIGIN" ]]; then
    default_origin="$(normalize_origin "$default_origin" "$WEB_PORT")"
    ORIGIN="$(prompt_value "Публичный URL приложения" "$default_origin")"
  fi
  ORIGIN="$(normalize_origin "$ORIGIN" "$WEB_PORT")"

  if [[ -z "$WEB_PORT" ]]; then
    WEB_PORT="$(derive_port_from_origin "$ORIGIN")"
  fi

  if [[ "$ORIGIN" == https://* ]]; then
    warn "The app container serves HTTP. Use https:// origin when TLS terminates on this host/reverse proxy/load balancer."
  fi
}

check_host_capacity() {
  if is_linux && [[ -r /proc/meminfo ]]; then
    local mem_kb
    mem_kb="$(awk '/MemTotal/ { print $2 }' /proc/meminfo)"
    if [[ -n "$mem_kb" && "$mem_kb" -lt 8000000 ]]; then
      warn "Host has less than 8 GB RAM. The stack may start slowly or run out of memory."
    fi
  fi

  local free_kb
  free_kb="$(df -Pk "$ROOT_DIR" | awk 'NR == 2 { print $4 }')"
  if [[ -n "$free_kb" && "$free_kb" -lt 10485760 ]]; then
    warn "Less than 10 GB free disk space in project filesystem."
  fi
}

ensure_port_available() {
  local port="$1"
  if [[ -z "$port" ]]; then
    return 0
  fi
  validate_port "$port" || die "Invalid port: $port"

  if port_in_use "$port"; then
    if ! confirm "Port $port already has a listener. Continue and let Docker/Compose handle it?"; then
      die "Choose another port with --port=PORT or free port $port."
    fi
  fi
}

create_or_update_env() {
  local init_args=( "--out=$ENV_FILE" )
  [[ -n "$ORIGIN" ]] && init_args+=( "--origin=$ORIGIN" )
  [[ -n "$WEB_PORT" ]] && init_args+=( "--web-port=$WEB_PORT" )
  [[ "$FORCE_ENV" == "1" ]] && init_args+=( "--force" )

  if [[ ! -f "$ENV_FILE" || "$FORCE_ENV" == "1" ]]; then
    log "Creating $ENV_FILE"
    if command -v node >/dev/null 2>&1; then
      node scripts/init-production-env.mjs "${init_args[@]}"
    else
      log "Local Node.js not found; using temporary node:20-alpine container."
      "${DOCKER[@]}" run --rm \
        --user "$(id -u):$(id -g)" \
        -v "$ROOT_DIR:/repo" \
        -w /repo \
        node:20-alpine \
        node scripts/init-production-env.mjs "${init_args[@]}"
    fi
  else
    log "Using existing $ENV_FILE (use --force-env to regenerate)."
  fi
}

normalize_env_file() {
  [[ -f "$ENV_FILE" ]] || return 0

  local rabbit_url rabbit_user rabbit_pass
  rabbit_url="$(read_env_value RABBITMQ_URL "$ENV_FILE" || true)"
  rabbit_user="$(read_env_value RABBITMQ_DEFAULT_USER "$ENV_FILE" || true)"
  rabbit_pass="$(read_env_value RABBITMQ_DEFAULT_PASS "$ENV_FILE" || true)"

  if [[ -n "$rabbit_user" && -n "$rabbit_pass" ]]; then
    local expected="amqp://${rabbit_user}:${rabbit_pass}@rabbitmq:5672/%2F"
    if [[ "$rabbit_url" == "amqp://${rabbit_user}:${rabbit_pass}@rabbitmq:5672/" || -z "$rabbit_url" ]]; then
      log "Normalizing RABBITMQ_URL for default '/' vhost."
      write_env_value RABBITMQ_URL "$expected" "$ENV_FILE"
    fi
  fi

  local bdu_fallback
  bdu_fallback="$(read_env_value BDU_ALLOW_MIRROR_FALLBACK "$ENV_FILE" || true)"
  if [[ -z "$bdu_fallback" ]]; then
    log "Enabling BDU mirror fallback for resilient first ingest."
    write_env_value BDU_ALLOW_MIRROR_FALLBACK "true" "$ENV_FILE"
  fi
}

validate_env_file() {
  local missing=()
  local key value
  for key in JWT_SECRET DATABASE_URL RABBITMQ_URL REDIS_URL POSTGRES_PASSWORD RABBITMQ_DEFAULT_PASS; do
    value="$(read_env_value "$key" "$ENV_FILE" || true)"
    [[ -n "$value" ]] || missing+=( "$key" )
  done

  if (( ${#missing[@]} > 0 )); then
    die "Missing required values in $ENV_FILE: ${missing[*]}"
  fi

  local jwt
  jwt="$(read_env_value JWT_SECRET "$ENV_FILE" || true)"
  if (( ${#jwt} < 32 )); then
    die "JWT_SECRET in $ENV_FILE is too short."
  fi

  validate_database_credentials
}

validate_database_credentials() {
  local db_url pg_pass url_pass
  db_url="$(read_env_value DATABASE_URL "$ENV_FILE" || true)"
  pg_pass="$(read_env_value POSTGRES_PASSWORD "$ENV_FILE" || true)"
  [[ -n "$db_url" && -n "$pg_pass" ]] || return 0

  if ! command -v node >/dev/null 2>&1; then
    return 0
  fi

  url_pass="$(node -e 'try{const u=new URL(process.argv[1]);process.stdout.write(decodeURIComponent(u.password||""))}catch{process.exit(2)}' "$db_url" 2>/dev/null || true)"
  if [[ -z "$url_pass" ]]; then
    return 0
  fi
  if [[ "$url_pass" != "$pg_pass" ]]; then
    die "DATABASE_URL password does not match POSTGRES_PASSWORD in $ENV_FILE. Run ./deploy.sh --force-env or reset DB volumes (compose down -v)."
  fi
}

wait_for_web() {
  local port="$1"
  local url="http://127.0.0.1:${port}/health"
  local i

  if ! command -v curl >/dev/null 2>&1; then
    warn "curl is not available; skipping local health check."
    return 0
  fi

  log "Waiting for web health: $url"
  for i in $(seq 1 60); do
    if curl -fsS -m 3 "$url" >/dev/null 2>&1; then
      log "Web health check passed."
      return 0
    fi
    sleep 2
  done

  warn "Web health check did not pass yet. Check logs with: ${COMPOSE[*]} --env-file $ENV_FILE -f infra/docker-compose.prod.yml logs -f web api"
  return 0
}

wait_for_bdu_ingest() {
  local app_env_file="$1"
  local pg_user pg_db count i

  pg_user="$(read_env_value POSTGRES_USER "$ENV_FILE" || true)"
  pg_user="${pg_user:-vuln}"
  pg_db="$(read_env_value POSTGRES_DB "$ENV_FILE" || true)"
  pg_db="${pg_db:-vuln_intel}"

  log "Waiting for BDU registry import (bdu_vuln > 0), up to ~25 minutes..."
  for i in $(seq 1 150); do
    count="$(
      APP_ENV_FILE="$app_env_file" "${COMPOSE[@]}" --env-file "$ENV_FILE" -f infra/docker-compose.prod.yml \
        exec -T postgres psql -U "$pg_user" -d "$pg_db" -tAc "SELECT COUNT(*) FROM bdu_vuln" 2>/dev/null \
        | tr -d '[:space:]' || true
    )"
    if [[ -n "$count" && "$count" =~ ^[0-9]+$ && "$count" -gt 0 ]]; then
      log "BDU import ready: bdu_vuln rows=$count"
      return 0
    fi
    sleep 10
  done

  warn "BDU registry is still empty. Check ingest logs:"
  warn "  ${COMPOSE[*]} --env-file $ENV_FILE -f infra/docker-compose.prod.yml logs --tail=80 ingest"
  warn "If TLS to bdu.fstec.ru fails, set BDU_TLS_INSECURE=1 and ensure BDU_ALLOW_MIRROR_FALLBACK=true in $ENV_FILE"
  warn "Manual one-shot: pnpm bdu:sync"
  return 0
}

dump_compose_diagnostics() {
  local app_env_file="$1"
  warn "Production stack failed to start. Collecting diagnostics."

  echo
  echo "===== docker compose ps ====="
  APP_ENV_FILE="$app_env_file" "${COMPOSE[@]}" --env-file "$ENV_FILE" -f infra/docker-compose.prod.yml ps -a || true

  echo
  echo "===== api logs ====="
  APP_ENV_FILE="$app_env_file" "${COMPOSE[@]}" --env-file "$ENV_FILE" -f infra/docker-compose.prod.yml logs --tail=200 api || true

  echo
  echo "===== dependencies logs ====="
  APP_ENV_FILE="$app_env_file" "${COMPOSE[@]}" --env-file "$ENV_FILE" -f infra/docker-compose.prod.yml logs --tail=120 postgres rabbitmq redis || true
}

log "Starting production deploy from $ROOT_DIR"
ensure_docker_cli
ensure_docker_daemon
ensure_compose
check_host_capacity
prepare_interactive_env_inputs
ensure_port_available "$WEB_PORT"
create_or_update_env
normalize_env_file
validate_env_file

if [[ "$INIT_ONLY" == "1" ]]; then
  log "Env ready: $ENV_FILE"
  exit 0
fi

if [[ "$ENV_FILE" = /* ]]; then
  app_env_file="$ENV_FILE"
else
  app_env_file="../$ENV_FILE"
fi

log "Validating compose config"
APP_ENV_FILE="$app_env_file" "${COMPOSE[@]}" --env-file "$ENV_FILE" -f infra/docker-compose.prod.yml config >/dev/null

log "Starting production stack"
up_args=( "up" "-d" )
if [[ "$NO_BUILD" != "1" ]]; then up_args+=( "--build" ); fi
if ! APP_ENV_FILE="$app_env_file" "${COMPOSE[@]}" --env-file "$ENV_FILE" -f infra/docker-compose.prod.yml "${up_args[@]}"; then
  dump_compose_diagnostics "$app_env_file"
  die "Production stack failed. See diagnostics above."
fi

published_port="$(read_env_value WEB_PUBLISHED_PORT "$ENV_FILE" || true)"
published_port="${published_port:-${WEB_PORT:-3000}}"
public_origin="$(read_env_value PUBLIC_WEB_ORIGIN "$ENV_FILE" || true)"
public_origin="${public_origin:-http://127.0.0.1:${published_port}}"

wait_for_web "$published_port"
wait_for_bdu_ingest "$app_env_file"

echo
log "Done."
log "Web: $public_origin"
log "Local health: http://127.0.0.1:${published_port}/health"
log "Logs: ${COMPOSE[*]} --env-file $ENV_FILE -f infra/docker-compose.prod.yml logs -f api web ingest ai"
