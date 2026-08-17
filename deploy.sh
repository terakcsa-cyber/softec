#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE=".env.production"
COMPOSE_FILE="infra/docker-compose.prod.yml"
STAGING=0
ORIGIN=""
WEB_PORT=""
FORCE_ENV=0
INIT_ONLY=0
NO_BUILD=0
YES=0
AUTO_INSTALL=1
KEEP_DATA=0
DEPLOY_MODE=""
ADMIN_EMAIL="${ADMIN_EMAIL:-}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-}"
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
  --fresh               Fresh install: delete Docker volumes (Postgres/Redis/RabbitMQ)
  --update              Platform update: keep Docker volumes (preserve data)
  --keep-data           Alias for --update
  --admin-email=EMAIL   Bootstrap admin email for fresh install (default: admin@example.com)
  --admin-password=PW   Bootstrap admin password (12+ chars). If omitted, will be prompted.
  --yes, -y             Non-interactive defaults and automatic dependency install
  --staging             Staging stack (.env.staging + docker-compose.staging.yml)
  --no-auto-install     Do not install missing Docker/Compose packages
  -h, --help            Show this help

Typical first deploy (server «тачка»):
  git clone <repo> && cd vuln-intel-platform
  ./deploy.sh --origin=https://vuln-intel.example.com
  # then in UI: Settings → Веб / TLS → Let's Encrypt (needs public DNS + :80)

Update without wiping data:
  git pull && ./deploy.sh --yes --update

Full wipe before clean reinstall:
  ./uninstall.sh --yes
EOF
}

log() { printf '[deploy] %s\n' "$*"; }
warn() { printf '[deploy] WARN: %s\n' "$*" >&2; }
die() { printf '[deploy] ERROR: %s\n' "$*" >&2; exit 1; }

is_tty() { [[ -t 0 && -t 1 ]]; }
is_linux() { [[ "$(uname -s 2>/dev/null || true)" == "Linux" ]]; }

quote_env_value() {
  local v="$1"
  # Empty string is allowed; keep as empty.
  if [[ -z "$v" ]]; then
    printf '%s' ""
    return 0
  fi
  # If it contains characters that commonly break dotenv/env_file parsing, wrap in single quotes.
  # Compose supports quoted values; our Node env loader strips matching quotes.
  if [[ "$v" =~ [[:space:]] || "$v" == *"#"* || "$v" == *"\""* || "$v" == *"'"* || "$v" == *"\\"* ]]; then
    # Escape single quotes in single-quoted string: ' -> '\''  (close, escape, reopen)
    local esc="${v//\'/\'\\\'\'}"
    printf "'%s'" "$esc"
    return 0
  fi
  printf '%s' "$v"
}

for arg in "$@"; do
  case "$arg" in
    --origin=*) ORIGIN="${arg#*=}" ;;
    --port=*) WEB_PORT="${arg#*=}" ;;
    --env-file=*) ENV_FILE="${arg#*=}" ;;
    --force-env) FORCE_ENV=1 ;;
    --init-only) INIT_ONLY=1 ;;
    --no-build) NO_BUILD=1 ;;
    --fresh) DEPLOY_MODE="fresh" ;;
    --update) DEPLOY_MODE="update" ;;
    --keep-data) DEPLOY_MODE="update" ;;
    --staging) STAGING=1; ENV_FILE=".env.staging"; COMPOSE_FILE="infra/docker-compose.staging.yml" ;;
    --admin-email=*) ADMIN_EMAIL="${arg#*=}" ;;
    --admin-password=*) ADMIN_PASSWORD="${arg#*=}" ;;
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

choose_deploy_mode() {
  # If explicitly set by args, use it.
  if [[ "$DEPLOY_MODE" == "fresh" ]]; then
    KEEP_DATA=0
  elif [[ "$DEPLOY_MODE" == "update" ]]; then
    KEEP_DATA=1
  else
    # Interactive default: ask. Non-interactive default: fresh.
    if [[ "$YES" == "1" || ! is_tty ]]; then
      KEEP_DATA=0
    else
      echo
      echo "[deploy] Выберите режим:"
      echo "  1) Чистая установка (сбросить данные: удалит Docker volumes Postgres/Redis/RabbitMQ)"
      echo "  2) Обновление платформы (сохранить данные: обновит только контейнеры/код)"
      echo
      local choice=""
      while true; do
        read -r -p "Режим [1/2]: " choice
        case "${choice:-}" in
          1) KEEP_DATA=0; break ;;
          2) KEEP_DATA=1; break ;;
          *) echo "[deploy] Введите 1 или 2." ;;
        esac
      done
    fi
  fi

  if [[ "$KEEP_DATA" == "1" && "$FORCE_ENV" == "1" ]]; then
    die "--force-env несовместим с режимом «Обновление платформы» (обновление сохраняет volumes; force-env меняет пароли). Используйте --fresh или уберите --force-env."
  fi
}

prompt_admin_bootstrap() {
  # Only meaningful for fresh installs, or when env is being regenerated.
  local env_exists=0
  [[ -f "$ENV_FILE" ]] && env_exists=1

  if [[ "$KEEP_DATA" == "1" && "$FORCE_ENV" != "1" ]]; then
    # Update mode: do not touch bootstrap creds.
    return 0
  fi

  # If user passed both values explicitly, just validate.
  local email pw
  email="${ADMIN_EMAIL:-}"
  pw="${ADMIN_PASSWORD:-}"

  if [[ -z "$email" ]]; then
    email="admin@example.com"
    if [[ "$YES" != "1" && is_tty ]]; then
      email="$(prompt_value "Email администратора (bootstrap)" "$email")"
    fi
  fi

  # In non-interactive mode, require explicit password to avoid accidental insecure default.
  if [[ "$YES" == "1" || ! is_tty ]]; then
    if [[ -z "$pw" ]]; then
      die "--admin-password обязателен в неинтерактивном режиме (--yes)."
    fi
  else
    if [[ -z "$pw" ]]; then
      echo
      echo "[deploy] Задайте пароль администратора (12+ символов)."
      while true; do
        read -r -s -p "Пароль: " pw
        echo
        read -r -s -p "Повтор: " pw2
        echo
        if [[ "$pw" != "$pw2" ]]; then
          echo "[deploy] Пароли не совпадают, попробуйте снова."
          continue
        fi
        if (( ${#pw} < 12 )); then
          echo "[deploy] Пароль должен быть минимум 12 символов."
          continue
        fi
        break
      done
    fi
  fi

  if (( ${#pw} < 12 )); then
    die "Admin password must be at least 12 characters."
  fi

  # Persist into env for API bootstrap on first run (only if auth_user is empty).
  ADMIN_EMAIL="$email"
  ADMIN_PASSWORD="$pw"
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
    log "Installing ca-certificates/curl; Docker via official convenience script if needed."
    run_as_root apt-get update || return 1
    run_as_root apt-get install -y ca-certificates curl || return 1
    # Ubuntu universe often lacks docker-compose-plugin; get.docker.com installs Engine + Compose v2.
    if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
      log "Installing Docker Engine + Compose plugin via get.docker.com"
      curl -fsSL https://get.docker.com | run_as_root sh || return 1
    fi
    return 0
  fi

  if command -v dnf >/dev/null 2>&1; then
    log "Installing required packages with dnf."
    run_as_root dnf install -y ca-certificates curl || return 1
    if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
      curl -fsSL https://get.docker.com | run_as_root sh || return 1
    fi
    return 0
  fi

  if command -v yum >/dev/null 2>&1; then
    log "Installing required packages with yum."
    run_as_root yum install -y ca-certificates curl || return 1
    if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
      curl -fsSL https://get.docker.com | run_as_root sh || return 1
    fi
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

  # 443/80 are reserved for tls-proxy; direct web uses WEB_PUBLISHED_PORT (usually 3000).
  if [[ "$port" == "443" || "$port" == "80" ]]; then
    log "Public port $port will be used by tls-proxy; web container stays on WEB_PUBLISHED_PORT (3000 by default)."
  fi

  if port_in_use "$port"; then
    if ! confirm "Port $port already has a listener. Continue and let Docker/Compose handle it?"; then
      die "Choose another port with --port=PORT or free port $port (ss -tlnp | grep :$port)."
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
    local init_script="scripts/init-production-env.mjs"
    [[ "$STAGING" == "1" ]] && init_script="scripts/init-staging-env.mjs"
    if command -v node >/dev/null 2>&1; then
      node "$init_script" "${init_args[@]}"
    else
      log "Local Node.js not found; using temporary node:20-alpine container."
      "${DOCKER[@]}" run --rm \
        --user "$(id -u):$(id -g)" \
        -v "$ROOT_DIR:/repo" \
        -w /repo \
        node:20-alpine \
        node "$init_script" "${init_args[@]}"
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

  # EPSS defaults (FIRST/CSV failover lives in shared epss-ingest; schedule via EpssIngestJob).
  local epss_boot
  epss_boot="$(read_env_value EPSS_BOOT_ON_START "$ENV_FILE" || true)"
  if [[ -z "$epss_boot" ]]; then
    write_env_value EPSS_BOOT_ON_START "true" "$ENV_FILE"
  fi
  local epss_poll
  epss_poll="$(read_env_value EPSS_POLL_INTERVAL_MS "$ENV_FILE" || true)"
  if [[ -z "$epss_poll" ]]; then
    write_env_value EPSS_POLL_INTERVAL_MS "21600000" "$ENV_FILE"
  fi

  # TLS / Let's Encrypt publish defaults (tls-proxy in compose).
  local tls_https
  tls_https="$(read_env_value WEB_TLS_PUBLISHED_PORT "$ENV_FILE" || true)"
  if [[ -z "$tls_https" ]]; then
    if [[ "$STAGING" == "1" ]]; then
      write_env_value WEB_TLS_PUBLISHED_PORT "8443" "$ENV_FILE"
    else
      write_env_value WEB_TLS_PUBLISHED_PORT "443" "$ENV_FILE"
    fi
  fi
  local tls_http
  tls_http="$(read_env_value WEB_TLS_HTTP_PORT "$ENV_FILE" || true)"
  if [[ -z "$tls_http" ]]; then
    if [[ "$STAGING" == "1" ]]; then
      write_env_value WEB_TLS_HTTP_PORT "8080" "$ENV_FILE"
    else
      write_env_value WEB_TLS_HTTP_PORT "80" "$ENV_FILE"
    fi
  fi

  # Public 443/80 belong to tls-proxy. Direct Next.js publish stays on 3000 (or staging default).
  # Avoid the classic misconfig: WEB_PUBLISHED_PORT=443 AND WEB_TLS_PUBLISHED_PORT=443.
  local web_pub
  web_pub="$(read_env_value WEB_PUBLISHED_PORT "$ENV_FILE" || true)"
  tls_https="$(read_env_value WEB_TLS_PUBLISHED_PORT "$ENV_FILE" || true)"
  if [[ -n "$WEB_PORT" && ( "$WEB_PORT" == "443" || "$WEB_PORT" == "80" ) ]]; then
    write_env_value WEB_TLS_PUBLISHED_PORT "$WEB_PORT" "$ENV_FILE"
    if [[ -z "$web_pub" || "$web_pub" == "443" || "$web_pub" == "80" || "$web_pub" == "$WEB_PORT" ]]; then
      local fallback_web="3000"
      [[ "$STAGING" == "1" ]] && fallback_web="3080"
      log "Public port $WEB_PORT → tls-proxy; setting WEB_PUBLISHED_PORT=$fallback_web for direct web."
      write_env_value WEB_PUBLISHED_PORT "$fallback_web" "$ENV_FILE"
      web_pub="$fallback_web"
    fi
  fi
  tls_https="$(read_env_value WEB_TLS_PUBLISHED_PORT "$ENV_FILE" || true)"
  web_pub="$(read_env_value WEB_PUBLISHED_PORT "$ENV_FILE" || true)"
  if [[ -n "$web_pub" && -n "$tls_https" && "$web_pub" == "$tls_https" ]]; then
    local fallback_web="3000"
    [[ "$STAGING" == "1" ]] && fallback_web="3080"
    log "WEB_PUBLISHED_PORT and WEB_TLS_PUBLISHED_PORT both $web_pub; moving web publish to $fallback_web."
    write_env_value WEB_PUBLISHED_PORT "$fallback_web" "$ENV_FILE"
  fi

  # Risk score is deterministic; keep enabled on fresh prod unless operator opted out.
  local score_flag
  score_flag="$(read_env_value AI_SCORE_ENABLED "$ENV_FILE" || true)"
  if [[ -z "$score_flag" ]]; then
    write_env_value AI_SCORE_ENABLED "true" "$ENV_FILE"
    log "Setting AI_SCORE_ENABLED=true (unified risk_score worker)."
  fi

  local le_auto
  le_auto="$(read_env_value LETSENCRYPT_AUTO_RENEW "$ENV_FILE" || true)"
  if [[ -z "$le_auto" ]]; then
    write_env_value LETSENCRYPT_AUTO_RENEW "true" "$ENV_FILE"
  fi

  # Bake git identity into env (also passed as compose build args via shell export).
  if [[ -n "${PLATFORM_GIT_SHA:-}" ]]; then
    write_env_value PLATFORM_GIT_SHA "$PLATFORM_GIT_SHA" "$ENV_FILE"
  fi
  if [[ -n "${PLATFORM_GIT_BRANCH:-}" ]]; then
    write_env_value PLATFORM_GIT_BRANCH "$PLATFORM_GIT_BRANCH" "$ENV_FILE"
  fi

  # In-app updates: absolute host checkout + remote URL (no manual helper compose).
  write_env_value PLATFORM_HOST_REPO_PATH "$ROOT_DIR" "$ENV_FILE"
  export PLATFORM_HOST_REPO_PATH="$ROOT_DIR"

  local apply_enabled repo_url repo_branch
  apply_enabled="$(read_env_value PLATFORM_UPDATE_APPLY_ENABLED "$ENV_FILE" || true)"
  if [[ -z "$apply_enabled" ]]; then
    write_env_value PLATFORM_UPDATE_APPLY_ENABLED "true" "$ENV_FILE"
  fi


  repo_branch="$(read_env_value PLATFORM_UPDATE_BRANCH "$ENV_FILE" || true)"
  if [[ -z "$repo_branch" ]]; then
    write_env_value PLATFORM_UPDATE_BRANCH "${PLATFORM_GIT_BRANCH:-main}" "$ENV_FILE"
  fi
  repo_url="$(read_env_value PLATFORM_UPDATE_REPO_URL "$ENV_FILE" || true)"
  if [[ -z "$repo_url" ]] && command -v git >/dev/null 2>&1 && [[ -d "$ROOT_DIR/.git" ]]; then
    repo_url="$(git -C "$ROOT_DIR" remote get-url origin 2>/dev/null || true)"
    if [[ -n "$repo_url" ]]; then
      write_env_value PLATFORM_UPDATE_REPO_URL "$repo_url" "$ENV_FILE"
    fi
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

  warn "Web health check did not pass yet. Check logs with: ${COMPOSE[*]} --env-file $ENV_FILE -f "$COMPOSE_FILE" logs -f web api"
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
      APP_ENV_FILE="$app_env_file" "${COMPOSE[@]}" --env-file "$ENV_FILE" -f "$COMPOSE_FILE" \
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
  warn "  ${COMPOSE[*]} --env-file $ENV_FILE -f "$COMPOSE_FILE" logs --tail=80 ingest"
  warn "If TLS to bdu.fstec.ru fails, set BDU_TLS_INSECURE=1 and ensure BDU_ALLOW_MIRROR_FALLBACK=true in $ENV_FILE"
  warn "Manual one-shot: pnpm bdu:sync"
  return 0
}

dump_compose_diagnostics() {
  local app_env_file="$1"
  warn "Production stack failed to start. Collecting diagnostics."

  echo
  echo "===== docker compose ps ====="
  APP_ENV_FILE="$app_env_file" "${COMPOSE[@]}" --env-file "$ENV_FILE" -f "$COMPOSE_FILE" ps -a || true

  echo
  echo "===== api logs ====="
  APP_ENV_FILE="$app_env_file" "${COMPOSE[@]}" --env-file "$ENV_FILE" -f "$COMPOSE_FILE" logs --tail=200 api || true

  echo
  echo "===== dependencies logs ====="
  APP_ENV_FILE="$app_env_file" "${COMPOSE[@]}" --env-file "$ENV_FILE" -f "$COMPOSE_FILE" logs --tail=120 postgres rabbitmq redis || true
}

log "Starting ${STAGING:+staging }deploy from $ROOT_DIR"
ensure_docker_cli
ensure_docker_daemon
ensure_compose
check_host_capacity
choose_deploy_mode

# Bake git identity into API image (for Settings → Обновления).
if command -v git >/dev/null 2>&1 && [[ -d "$ROOT_DIR/.git" ]]; then
  export PLATFORM_GIT_SHA="${PLATFORM_GIT_SHA:-$(git -C "$ROOT_DIR" rev-parse HEAD 2>/dev/null || true)}"
  export PLATFORM_GIT_BRANCH="${PLATFORM_GIT_BRANCH:-$(git -C "$ROOT_DIR" rev-parse --abbrev-ref HEAD 2>/dev/null || true)}"
  export PLATFORM_GIT_TAG="${PLATFORM_GIT_TAG:-$(git -C "$ROOT_DIR" describe --tags --exact-match 2>/dev/null || true)}"
fi
export PLATFORM_HOST_REPO_PATH="${PLATFORM_HOST_REPO_PATH:-$ROOT_DIR}"
prepare_interactive_env_inputs
ensure_port_available "$WEB_PORT"
create_or_update_env
normalize_env_file
prompt_admin_bootstrap
if [[ "$KEEP_DATA" != "1" || "$FORCE_ENV" == "1" ]]; then
  # fresh install or env regeneration: write bootstrap creds
  write_env_value AUTH_BOOTSTRAP_EMAIL "$(quote_env_value "$ADMIN_EMAIL")" "$ENV_FILE"
  write_env_value AUTH_BOOTSTRAP_PASSWORD "$(quote_env_value "$ADMIN_PASSWORD")" "$ENV_FILE"
fi
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
APP_ENV_FILE="$app_env_file" "${COMPOSE[@]}" --env-file "$ENV_FILE" -f "$COMPOSE_FILE" config >/dev/null

if [[ "$KEEP_DATA" != "1" ]]; then
  log "Fresh install: stopping stack and deleting volumes (use --keep-data to preserve DB)."
  APP_ENV_FILE="$app_env_file" "${COMPOSE[@]}" --env-file "$ENV_FILE" -f "$COMPOSE_FILE" down -v --remove-orphans >/dev/null 2>&1 || true
fi

log "Starting production stack"
up_args=( "up" "-d" )
if [[ "$NO_BUILD" != "1" ]]; then up_args+=( "--build" ); fi
if ! APP_ENV_FILE="$app_env_file" "${COMPOSE[@]}" --env-file "$ENV_FILE" -f "$COMPOSE_FILE" "${up_args[@]}"; then
  dump_compose_diagnostics "$app_env_file"
  die "Production stack failed. See diagnostics above."
fi

published_port="$(read_env_value WEB_PUBLISHED_PORT "$ENV_FILE" || true)"
published_port="${published_port:-${WEB_PORT:-3000}}"
public_origin="$(read_env_value PUBLIC_WEB_ORIGIN "$ENV_FILE" || true)"
public_origin="${public_origin:-http://127.0.0.1:${published_port}}"

wait_for_web "$published_port"
if [[ "$STAGING" == "1" ]]; then
  log "Staging: skip long BDU ingest wait (enable BDU_INGEST_ENABLED in $ENV_FILE if needed)"
else
  wait_for_bdu_ingest "$app_env_file"
fi

run_post_deploy_smoke() {
  local port="$1"
  log "Running post-deploy smoke (web + internal API)..."

  if ! APP_ENV_FILE="$app_env_file" "${COMPOSE[@]}" --env-file "$ENV_FILE" -f "$COMPOSE_FILE" \
    exec -T api node -e "fetch('http://127.0.0.1:4001/api/health').then(r=>r.json()).then(j=>{if(!j.ok)process.exit(1)}).catch(()=>process.exit(1))" \
    >/dev/null 2>&1; then
    warn "API internal health check failed (api container)"
    return 1
  fi
  log "ok api internal /health"

  # Catch the first-boot footguns we hit in production.
  if ! APP_ENV_FILE="$app_env_file" "${COMPOSE[@]}" --env-file "$ENV_FILE" -f "$COMPOSE_FILE" \
    exec -T api node -e "require('undici'); process.exit(0)" >/dev/null 2>&1; then
    warn "undici failed to load inside api (Node/undici mismatch) — check undici pin"
    return 1
  fi
  log "ok api undici load"

  local score_enabled
  score_enabled="$(read_env_value AI_SCORE_ENABLED "$ENV_FILE" || true)"
  if [[ "${score_enabled,,}" == "false" || "${score_enabled}" == "0" ]]; then
    warn "AI_SCORE_ENABLED=false — risk_score will not update until enabled"
  else
    if APP_ENV_FILE="$app_env_file" "${COMPOSE[@]}" --env-file "$ENV_FILE" -f "$COMPOSE_FILE" \
      logs --tail=40 ai 2>/dev/null | grep -q '\[ai:score\] disabled'; then
      warn "ai container still reports score disabled — rebuild ai image after pull"
    else
      log "ok ai.score consumer expected enabled"
    fi
  fi

  local web_pub tls_pub
  web_pub="$(read_env_value WEB_PUBLISHED_PORT "$ENV_FILE" || true)"
  tls_pub="$(read_env_value WEB_TLS_PUBLISHED_PORT "$ENV_FILE" || true)"
  if [[ -n "$web_pub" && -n "$tls_pub" && "$web_pub" == "$tls_pub" ]]; then
    warn "WEB_PUBLISHED_PORT and WEB_TLS_PUBLISHED_PORT both $web_pub — tls-proxy will fail to bind"
    return 1
  fi

  if ! SMOKE_WEB_URL="http://127.0.0.1:${port}" SMOKE_API_SKIP=1 node "$ROOT_DIR/scripts/post-deploy-smoke.mjs"; then
    warn "Web post-deploy smoke failed"
    return 1
  fi
  return 0
}

if ! run_post_deploy_smoke "$published_port"; then
  warn "Post-deploy smoke reported issues. Stack is up; inspect logs if needed."
fi

if [[ "$STAGING" == "1" && "${SKIP_CHAOS_SMOKE:-0}" != "1" ]]; then
  log "Staging chaos: restart services and verify health..."
  if ! SMOKE_WEB_URL="http://127.0.0.1:${published_port}" ENV_FILE="$ENV_FILE" COMPOSE_FILE="$COMPOSE_FILE" \
    node "$ROOT_DIR/scripts/chaos-restart-smoke.mjs"; then
    warn "Chaos restart smoke failed (stack may still be usable)"
  fi
fi

echo
log "Done."
log "Web: $public_origin"
log "Local health: http://127.0.0.1:${published_port}/health"
log "Logs: ${COMPOSE[*]} --env-file $ENV_FILE -f "$COMPOSE_FILE" logs -f api web ingest ai"
