#!/usr/bin/env bash
# Safe in-app / CLI platform update for vuln-intel-platform.
# - Never runs `docker compose down -v`
# - Never regenerates or overwrites .env / secrets
# - git merge --ff-only only (no force, no history rewrite)
# - Optional Postgres dump before rebuild
#
# Usage (from repo root on the host, or from the one-shot updater container):
#   bash scripts/platform-update.sh
#
# Env:
#   PLATFORM_UPDATE_BRANCH   (default: current branch or main)
#   PLATFORM_UPDATE_REPO_URL (optional HTTPS/SSH URL; used when origin fetch fails / no SSH in updater)
#   PLATFORM_UPDATE_ENV_FILE  (default: .env.production)
#   PLATFORM_UPDATE_COMPOSE_FILE (default: infra/docker-compose.prod.yml)
#   PLATFORM_UPDATE_BACKUP=1   (default: 1) — pg_dump before apply
#   PLATFORM_UPDATE_STATUS_FILE (default: data/platform-update-status.json)
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

ENV_FILE="${PLATFORM_UPDATE_ENV_FILE:-.env.production}"
COMPOSE_FILE="${PLATFORM_UPDATE_COMPOSE_FILE:-infra/docker-compose.prod.yml}"
STATUS_FILE="${PLATFORM_UPDATE_STATUS_FILE:-$ROOT_DIR/data/platform-update-status.json}"
DO_BACKUP="${PLATFORM_UPDATE_BACKUP:-1}"
BRANCH="${PLATFORM_UPDATE_BRANCH:-}"
COMPOSE=(docker compose)

mkdir -p "$(dirname "$STATUS_FILE")"

log() { printf '[platform-update] %s\n' "$*"; }
warn() { printf '[platform-update] WARN: %s\n' "$*" >&2; }
die() {
  write_status "failed" "Ошибка обновления: $*"
  printf '[platform-update] ERROR: %s\n' "$*" >&2
  exit 1
}

json_escape() {
  # Minimal JSON string escape for status payloads.
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\r'/\\r}"
  s="${s//$'\t'/\\t}"
  printf '%s' "$s"
}

write_status() {
  local phase="$1"
  local progress_ru="$2"
  local error_ru="${3:-}"
  local now
  now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  local started="${UPDATE_STARTED_AT:-$now}"
  local finished="null"
  if [[ "$phase" == "done" || "$phase" == "failed" ]]; then
    finished="\"$now\""
  fi
  local err_json="null"
  if [[ -n "$error_ru" ]]; then
    err_json="\"$(json_escape "$error_ru")\""
  fi
  cat >"$STATUS_FILE" <<EOF
{
  "phase": "$(json_escape "$phase")",
  "progressRu": "$(json_escape "$progress_ru")",
  "errorRu": $err_json,
  "startedAt": "$started",
  "finishedAt": $finished,
  "updatedAt": "$now",
  "pid": $$
}
EOF
}

UPDATE_STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
export UPDATE_STARTED_AT

command -v git >/dev/null 2>&1 || die "git не найден"
command -v docker >/dev/null 2>&1 || die "docker не найден"
docker compose version >/dev/null 2>&1 || die "docker compose v2 не найден"

[[ -d "$ROOT_DIR/.git" ]] || die "Каталог $ROOT_DIR не является git-репозиторием"
[[ -f "$ROOT_DIR/$COMPOSE_FILE" ]] || die "Не найден compose-файл: $COMPOSE_FILE"
[[ -f "$ROOT_DIR/$ENV_FILE" ]] || die "Не найден env-файл: $ENV_FILE (секреты не создаём автоматически)"

if [[ -z "$BRANCH" ]]; then
  BRANCH="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
fi
if [[ -z "$BRANCH" || "$BRANCH" == "HEAD" ]]; then
  BRANCH="main"
fi

write_status "preflight" "Проверка состояния репозитория и Docker…"

# Refuse dirty tracked tree (ignore untracked data/, status file, local env).
dirty="$(git status --porcelain --untracked-files=no 2>/dev/null || true)"
if [[ -n "$dirty" ]]; then
  die "Рабочее дерево git грязное. Зафиксируйте или отложите локальные правки перед обновлением."
fi

# Guard: never accept a caller that asks for volume wipe.
if [[ "${PLATFORM_UPDATE_ALLOW_WIPE:-0}" == "1" ]]; then
  die "Отказ: PLATFORM_UPDATE_ALLOW_WIPE запрещён (защита данных)."
fi

if [[ "$ENV_FILE" = /* ]]; then
  app_env_file="$ENV_FILE"
else
  app_env_file="../$ENV_FILE"
fi

write_status "preflight" "Проверка доступности Postgres…"
if ! APP_ENV_FILE="$app_env_file" "${COMPOSE[@]}" --env-file "$ENV_FILE" -f "$COMPOSE_FILE" \
  exec -T postgres pg_isready >/dev/null 2>&1; then
  warn "pg_isready не прошёл — продолжаем, но backup может не удаться"
fi

if [[ "$DO_BACKUP" == "1" || "$DO_BACKUP" == "true" ]]; then
  write_status "backup" "Резервная копия Postgres перед обновлением…"
  backup_dir="$ROOT_DIR/backups"
  mkdir -p "$backup_dir"
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  backup_file="$backup_dir/pre_update_${stamp}.sql.gz"
  pg_user="$(grep -E '^POSTGRES_USER=' "$ENV_FILE" | head -1 | cut -d= -f2- | tr -d \"\' || true)"
  pg_db="$(grep -E '^POSTGRES_DB=' "$ENV_FILE" | head -1 | cut -d= -f2- | tr -d \"\' || true)"
  pg_user="${pg_user:-vuln}"
  pg_db="${pg_db:-vuln_intel}"
  if APP_ENV_FILE="$app_env_file" "${COMPOSE[@]}" --env-file "$ENV_FILE" -f "$COMPOSE_FILE" \
    exec -T postgres pg_dump -U "$pg_user" -d "$pg_db" | gzip -9 >"$backup_file"; then
    log "Backup: $backup_file"
  else
    rm -f "$backup_file" || true
    die "Не удалось сделать pg_dump. Обновление отменено (данные важнее)."
  fi
fi

before_sha="$(git rev-parse HEAD)"
write_status "fetch" "Загрузка обновлений с remote (ветка $BRANCH)…"

# Prefer PLATFORM_UPDATE_REPO_URL when set: one-shot updater containers usually have no SSH agent,
# while UI "check" already works via this URL. Fetch into refs/remotes/origin/<branch> without
# permanently rewriting `origin` (host may keep SSH remote for interactive use).
REPO_URL="${PLATFORM_UPDATE_REPO_URL:-}"
fetch_err=""
if [[ -n "$REPO_URL" ]]; then
  log "Fetch via PLATFORM_UPDATE_REPO_URL → origin/$BRANCH"
  if ! fetch_err="$(git fetch --prune "$REPO_URL" "+refs/heads/${BRANCH}:refs/remotes/origin/${BRANCH}" 2>&1)"; then
    die "git fetch не удался по PLATFORM_UPDATE_REPO_URL (проверьте URL/токен/сеть): ${fetch_err:-unknown}"
  fi
else
  origin_url="$(git remote get-url origin 2>/dev/null || true)"
  log "Fetch via origin${origin_url:+ ($origin_url)}"
  if ! fetch_err="$(git fetch --prune origin "$BRANCH" 2>&1)"; then
    die "git fetch не удался (origin=${origin_url:-none}). Для Docker apply задайте HTTPS PLATFORM_UPDATE_REPO_URL или смонтируйте SSH-ключи: ${fetch_err:-unknown}"
  fi
fi

remote_sha="$(git rev-parse "origin/$BRANCH" 2>/dev/null || true)"
[[ -n "$remote_sha" ]] || die "Не удалось определить origin/$BRANCH после fetch"

if [[ "$before_sha" == "$remote_sha" ]]; then
  write_status "done" "Обновлений нет — уже на $before_sha"
  log "Already up to date ($before_sha)"
  exit 0
fi

write_status "pull" "Применение коммитов (fast-forward only)…"
git merge --ff-only "origin/$BRANCH" || die "fast-forward merge невозможен (локальная история разошлась с remote)"

after_sha="$(git rev-parse HEAD)"
after_branch="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
[[ "$after_branch" == "HEAD" ]] && after_branch="$BRANCH"
log "Updated $before_sha -> $after_sha"

# Keep env/build-args in sync so UI "current version" matches checkout after rebuild.
upsert_env() {
  local key="$1" val="$2"
  if grep -qE "^${key}=" "$ENV_FILE" 2>/dev/null; then
    sed -i "s|^${key}=.*|${key}=${val}|" "$ENV_FILE"
  else
    printf '%s=%s\n' "$key" "$val" >>"$ENV_FILE"
  fi
}
upsert_env PLATFORM_GIT_SHA "$after_sha"
upsert_env PLATFORM_GIT_BRANCH "${after_branch:-main}"
export PLATFORM_GIT_SHA="$after_sha"
export PLATFORM_GIT_BRANCH="${after_branch:-main}"

write_status "build" "Сборка и перезапуск контейнеров без удаления volumes…"
# Explicitly never pass -v / --fresh. Only up -d --build.
# Ensure compose can inject absolute host path for /host-repo mount consumers.
export PLATFORM_HOST_REPO_PATH="${PLATFORM_HOST_REPO_PATH:-$ROOT_DIR}"
if ! APP_ENV_FILE="$app_env_file" \
  PLATFORM_HOST_REPO_PATH="$PLATFORM_HOST_REPO_PATH" \
  PLATFORM_GIT_SHA="$PLATFORM_GIT_SHA" \
  PLATFORM_GIT_BRANCH="$PLATFORM_GIT_BRANCH" \
  "${COMPOSE[@]}" --env-file "$ENV_FILE" -f "$COMPOSE_FILE" \
  up -d --build --remove-orphans; then
  die "docker compose up --build завершился с ошибкой. Volumes не трогались; проверьте логи."
fi

write_status "restart" "Ожидание health web/api…"
web_port="$(grep -E '^WEB_PUBLISHED_PORT=' "$ENV_FILE" | head -1 | cut -d= -f2- | tr -d \"\' || true)"
web_port="${web_port:-3000}"
ok=0
for _ in $(seq 1 60); do
  if command -v curl >/dev/null 2>&1; then
    if curl -fsS -m 3 "http://127.0.0.1:${web_port}/health" >/dev/null 2>&1; then
      ok=1
      break
    fi
  fi
  sleep 2
done

if [[ "$ok" != "1" ]]; then
  if command -v curl >/dev/null 2>&1; then
    warn "Health web ещё не ответил — стек мог подняться с задержкой"
  else
    warn "curl недоступен — пропускаем health-ожидание; проверьте compose ps вручную"
  fi
fi

write_status "done" "Обновление завершено: ${before_sha:0:7} → ${after_sha:0:7}. Данные и .env сохранены."
log "Done. $before_sha -> $after_sha"
