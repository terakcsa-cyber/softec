#!/usr/bin/env bash
# PostgreSQL backup for vuln-intel-platform.
# Usage: ./scripts/pg-backup.sh [output_dir]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="${1:-${ROOT}/backups}"
mkdir -p "$OUT_DIR"

ENV_FILE="${ENV_FILE:-${ROOT}/.env.production}"
if [[ -f "$ENV_FILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi

POSTGRES_USER="${POSTGRES_USER:-vuln}"
POSTGRES_DB="${POSTGRES_DB:-vuln_intel}"
POSTGRES_HOST="${POSTGRES_HOST:-127.0.0.1}"
POSTGRES_PORT="${POSTGRES_PORT:-5432}"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
FILE="${OUT_DIR}/vuln_intel_${STAMP}.sql.gz"

echo "Backing up ${POSTGRES_DB}@${POSTGRES_HOST}:${POSTGRES_PORT} -> ${FILE}"

if command -v docker >/dev/null 2>&1 && docker compose -f "${ROOT}/infra/docker-compose.prod.yml" ps postgres 2>/dev/null | grep -q Up; then
  docker compose --env-file "$ENV_FILE" -f "${ROOT}/infra/docker-compose.prod.yml" \
    exec -T postgres pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" | gzip -9 >"$FILE"
else
  PGPASSWORD="${POSTGRES_PASSWORD:-}" pg_dump -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$POSTGRES_DB" | gzip -9 >"$FILE"
fi

echo "done: ${FILE} ($(du -h "$FILE" | cut -f1))"
