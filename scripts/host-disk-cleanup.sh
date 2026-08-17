#!/bin/sh
# Safe disk housekeeping for vuln-intel-platform.
# Never: docker volume prune, compose down -v, .env, named volumes (pg/redis/rabbit).
#
# Usage (from repo root on the host, or from the API container with docker.sock):
#   sh scripts/host-disk-cleanup.sh                 # machine (full unused Docker)
#   sh scripts/host-disk-cleanup.sh --mode daily    # conservative (images unused ≥7d)
#   sh scripts/host-disk-cleanup.sh --mode backups --keep 3
#
# Env:
#   PLATFORM_UPDATE_BACKUP_KEEP  default keep for backups/*.sql.gz (3)
#   DISK_CLEANUP_LOG_MAX_BYTES   truncate container json logs above this (50MiB machine / 100MiB daily)
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

MODE="machine"
KEEP="${PLATFORM_UPDATE_BACKUP_KEEP:-3}"
SKIP_BACKUPS=0
SKIP_DOCKER=0
SKIP_GIT=0

while [ $# -gt 0 ]; do
  case "$1" in
    --mode) MODE="${2:-machine}"; shift 2 ;;
    --keep) KEEP="${2:-3}"; shift 2 ;;
    --skip-backups) SKIP_BACKUPS=1; shift ;;
    --skip-docker) SKIP_DOCKER=1; shift ;;
    --skip-git) SKIP_GIT=1; shift ;;
    -h|--help)
      sed -n '2,14p' "$0"
      exit 0
      ;;
    *)
      printf 'unknown arg: %s\n' "$1" >&2
      exit 2
      ;;
  esac
done

case "$MODE" in
  backups|daily|machine) ;;
  *)
    printf 'invalid --mode %s (backups|daily|machine)\n' "$MODE" >&2
    exit 2
    ;;
esac

log() { printf '[disk-cleanup] %s\n' "$*"; }
warn() { printf '[disk-cleanup] WARN: %s\n' "$*" >&2; }

keep_n="$KEEP"
# shellcheck disable=SC2003
keep_n="$(expr "$keep_n" + 0 2>/dev/null || echo 3)"
if [ "$keep_n" -lt 1 ]; then keep_n=1; fi
if [ "$keep_n" -gt 50 ]; then keep_n=50; fi

prune_backups() {
  dir="$ROOT_DIR/backups"
  if [ ! -d "$dir" ]; then
    log "backups: no directory"
    return 0
  fi
  n=0
  # Names are pre_update_|vuln_intel_*.sql.gz — no spaces.
  # shellcheck disable=SC2046
  for name in $(ls -1t "$dir" 2>/dev/null | grep -E '^(pre_update_|vuln_intel_).+\.sql\.gz$' || true); do
    [ -n "$name" ] || continue
    n=$((n + 1))
    if [ "$n" -le "$keep_n" ]; then
      continue
    fi
    rm -f "$dir/$name"
    log "backups: removed $name"
  done
  log "backups: keep=$keep_n"
}

docker_ok() {
  command -v docker >/dev/null 2>&1 && docker version >/dev/null 2>&1
}

truncate_json_logs() {
  max_bytes="$1"
  docker_ok || return 0
  docker ps -aq 2>/dev/null | while IFS= read -r id; do
    [ -n "$id" ] || continue
    path="$(docker inspect --format '{{.LogPath}}' "$id" 2>/dev/null || true)"
    [ -n "$path" ] && [ -f "$path" ] || continue
    sz="$(wc -c < "$path" 2>/dev/null | tr -d ' ' || echo 0)"
    [ -n "$sz" ] || sz=0
    if [ "$sz" -gt "$max_bytes" ]; then
      : > "$path" 2>/dev/null || warn "cannot truncate $path"
      log "logs: truncated $id (${sz} bytes)"
    fi
  done
}

prune_docker() {
  docker_ok || {
    warn "Docker CLI unavailable — skip"
    return 0
  }
  log "docker: container prune (stopped only)"
  docker container prune -f 2>/dev/null || true

  if [ "$MODE" = "machine" ]; then
    log "docker: image prune -af (unused; running images kept; no volumes)"
    docker image prune -af 2>/dev/null || true
    log "docker: builder prune -af"
    docker builder prune -af 2>/dev/null || true
    max_log="${DISK_CLEANUP_LOG_MAX_BYTES:-52428800}"
  else
    log "docker: image prune unused older than 168h"
    docker image prune -af --filter until=168h 2>/dev/null || true
    log "docker: builder prune older than 72h"
    docker builder prune -af --filter until=72h 2>/dev/null || true
    max_log="${DISK_CLEANUP_LOG_MAX_BYTES:-104857600}"
  fi

  log "docker: network prune (unused)"
  docker network prune -f 2>/dev/null || true
  truncate_json_logs "$max_log"
  log "docker: system df"
  docker system df 2>/dev/null || true
}

prune_git() {
  if [ ! -d "$ROOT_DIR/.git" ]; then
    return 0
  fi
  if [ "$MODE" = "machine" ]; then
    log "git: gc --prune=now"
    git -C "$ROOT_DIR" gc --prune=now --quiet 2>/dev/null || true
  else
    log "git: gc --auto"
    git -C "$ROOT_DIR" gc --auto --quiet 2>/dev/null || true
  fi
}

prune_staging() {
  for d in "${TMPDIR:-/tmp}/vuln-intel-bdu" "$ROOT_DIR/data/bdu-staging"; do
    if [ -d "$d" ]; then
      log "staging: wipe $d"
      rm -rf "$d"/* "$d"/.[!.]* 2>/dev/null || true
    fi
  done
}

vacuum_journal() {
  if ! command -v journalctl >/dev/null 2>&1; then
    return 0
  fi
  uid="$(id -u 2>/dev/null || echo 1)"
  if [ "$uid" != "0" ]; then
    return 0
  fi
  days=14
  if [ "$MODE" = "machine" ]; then
    days=7
  fi
  log "journalctl: vacuum-time=${days}d"
  journalctl --vacuum-time="${days}d" >/dev/null 2>&1 || true
}

log "mode=$MODE keep=$keep_n root=$ROOT_DIR"

if [ "$SKIP_BACKUPS" -eq 0 ]; then
  prune_backups
fi

if [ "$MODE" != "backups" ] && [ "$SKIP_DOCKER" -eq 0 ]; then
  prune_docker
fi

if [ "$MODE" != "backups" ] && [ "$SKIP_GIT" -eq 0 ]; then
  prune_git
fi

if [ "$MODE" != "backups" ]; then
  prune_staging
  vacuum_journal
fi

log "done (volumes and .env untouched)"
