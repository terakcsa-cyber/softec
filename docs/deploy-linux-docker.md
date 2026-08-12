# Deploy на Linux через Docker Compose

Документ описывает безопасный перенос проекта на отдельный Linux-сервер. Основной сценарий — запуск всего стека через `infra/docker-compose.prod.yml`.

## Самый простой запуск

```bash
git clone <repo-url> vuln-intel-platform
cd vuln-intel-platform
./deploy.sh
```

Скрипт сам:

- проверит Docker и Docker daemon;
- если возможно, доставит Docker/Compose plugin через пакетный менеджер;
- создаст `.env.production`, если его ещё нет;
- сгенерирует сильные секреты;
- предложит выбрать публичный web/HTTPS порт;
- проверит Docker Compose config;
- соберёт и поднимет production stack.

Если есть домен:

```bash
./deploy.sh --origin=https://vuln-intel.example.com
```

Если нужен другой порт:

```bash
./deploy.sh --port=8443 --origin=https://vuln-intel.example.com:8443
```

## Требования

- Linux-хост с Docker Engine и Docker Compose v2. Если их нет, `./deploy.sh` попробует поставить их автоматически через `apt-get`, `dnf` или `yum`.
- Доступ к Git-репозиторию.
- Node.js/pnpm не обязательны для `./deploy.sh`: если Node.js нет на хосте, скрипт запустит генератор env в одноразовом Docker-контейнере `node:20-alpine`.
- 4+ CPU, 16+ GB RAM для комфортного старта; больше, если включена локальная LLM.
- Открытый наружу: `WEB_PUBLISHED_PORT` (web HTTP, часто 3000) и `WEB_TLS_PUBLISHED_PORT` / `WEB_TLS_HTTP_PORT` (tls-proxy HTTPS + ACME :80).

Если автоматическая установка Compose v2 не прошла, установите compose plugin вручную:

```bash
sudo apt-get update
sudo apt-get install -y docker-compose-plugin
docker compose version
```

Скрипт также поддерживает standalone `docker-compose`, но только версии v2.

Важно: контейнер `web` внутри Docker слушает HTTP. HTTPS обеспечивает сервис `tls-proxy` (Caddy) на `WEB_TLS_PUBLISHED_PORT` (prod 443) + HTTP `:80` для ACME. Сертификат: **Настройки → Веб / TLS** → Let's Encrypt (публичный DNS + порт 80), **HTTPS для IP** (самоподписанный с SAN IP, DNS не нужен; предупреждение браузера), или опционально LE IP shortlived. `deploy.sh` проставляет `PLATFORM_GIT_SHA`, EPSS boot/poll и TLS-порты в env. Указывайте `https://` в `PUBLIC_WEB_ORIGIN` после выпуска сертификата (для IP: `https://x.x.x.x`).

## Подготовка

```bash
git clone <repo-url> vuln-intel-platform
cd vuln-intel-platform
./deploy.sh --init-only
```

`./deploy.sh --init-only` создаёт `.env.production`, генерирует сильные случайные значения для `JWT_SECRET`, `POSTGRES_PASSWORD`, `RABBITMQ_DEFAULT_PASS` и сразу согласует `DATABASE_URL` / `RABBITMQ_URL`.
При интерактивном запуске скрипт спросит публичный порт web/HTTPS и публичный URL приложения.

Если `.env.production` уже существует, скрипт не перезаписывает его. Для осознанной пересборки env:

```bash
./deploy.sh --init-only --force-env
```

Для сервера с доменом сразу задайте публичный origin:

```bash
./deploy.sh --init-only --origin=https://vuln-intel.example.com
```

Если запускаете по IP/порту, можно оставить дефолт `http://localhost:3000` и потом при необходимости поменять `PUBLIC_WEB_ORIGIN` / `API_CORS_ORIGIN` в `.env.production`.

## Запуск

Проверить compose-конфиг:

```bash
docker compose --env-file .env.production -f infra/docker-compose.prod.yml config
```

Собрать и запустить:

```bash
./deploy.sh
```

Посмотреть состояние:

```bash
docker compose --env-file .env.production -f infra/docker-compose.prod.yml ps
docker compose --env-file .env.production -f infra/docker-compose.prod.yml logs -f api web ingest ai
```

Health checks:

```bash
curl -fsS http://127.0.0.1:${WEB_PUBLISHED_PORT:-3000}/health
curl -fsS http://127.0.0.1:${WEB_PUBLISHED_PORT:-3000}/api/health
```

## Первый пользователь

При первом запуске, если таблица `auth_user` пустая, API автоматически создаёт bootstrap-администратора:

- email: `admin@vuln-intel.local`
- пароль: `ChangeMe!Admin1`
- при первом входе обязательна смена пароля.

Чтобы задать свои начальные реквизиты, укажите переменные в `.env.production` до первого старта API:

```env
AUTH_BOOTSTRAP_EMAIL=sec@example.com
AUTH_BOOTSTRAP_PASSWORD=UseYourOwnLongPassword1
```

`AUTH_BOOTSTRAP_PASSWORD` должен быть не короче 12 символов. После первого входа смените пароль и дальше управляйте пользователями в **Settings → Пользователи**: создавать аккаунты может пользователь с ролью `admin`.

```bash
docker compose --env-file .env.production -f infra/docker-compose.prod.yml up -d api
```

## Security defaults

- Не коммитьте `.env.production`.
- `AUTH_ALLOW_REGISTER=false` для production.
- Даже если `AUTH_ALLOW_REGISTER=true`, production-регистрация дополнительно требует `AUTH_ALLOW_REGISTER_IN_PRODUCTION=true`; держите его `false`.
- `ALLOW_INTERNAL_API_BEARER=false`; включать только для доверенного service-to-service контура.
- Роли RBAC хранятся в `auth_user.role`: `viewer` — чтение, `analyst` — рабочие изменения, `admin` — ops и пользователи.
- **`ADMIN_EMAILS`** — legacy allowlist для admin-only API по email; пустое значение не делает всех пользователей admin.
- **`DLQ_BOOT_RETRY=false`** в production (ручной retry через API после диагностики).
- Наружу: `web` (`WEB_PUBLISHED_PORT`) и `tls-proxy` (`WEB_TLS_PUBLISHED_PORT` / `:80` для ACME). `api`, `postgres`, `redis`, `rabbitmq` — только Docker network.
- HTTPS: встроенный **tls-proxy** + **Настройки → Веб / TLS** (Let's Encrypt для домена; для голого IP — self-signed с IP SAN, DNS не нужен). Внешний reverse proxy опционален.

Подробнее: [ADMIN_GUIDE.md](./ADMIN_GUIDE.md), [MATURITY.md](./MATURITY.md).

## Полное удаление

```bash
./uninstall.sh --yes
```

Сносит containers, volumes, project images и `.env.production`. Docker Engine не трогает.

Потом чистая установка:

```bash
cd /opt
rm -rf vuln-intel-platform
git clone https://github.com/terakcsa-cyber/softec.git vuln-intel-platform
cd vuln-intel-platform
./deploy.sh --yes --fresh \
  --origin=https://vulnintel.example.com \
  --admin-email=admin@local.dev \
  --admin-password='YourLongPassword1'
```

Важно: публичный HTTPS — `WEB_TLS_PUBLISHED_PORT=443` (tls-proxy). Прямой web — `WEB_PUBLISHED_PORT=3000`. Не ставь оба в `443`.

## Backup и restore

Postgres backup:

```bash
docker compose --env-file .env.production -f infra/docker-compose.prod.yml exec -T postgres \
  sh -c 'pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB"' > backup.sql
```

Restore в чистую БД:

```bash
docker compose --env-file .env.production -f infra/docker-compose.prod.yml exec -T postgres \
  sh -c 'psql -U "$POSTGRES_USER" "$POSTGRES_DB"' < backup.sql
```

Volumes:

- `vuln-intel-prod_pg_data`
- `vuln-intel-prod_redis_data`
- `vuln-intel-prod_rabbitmq_data`

Не запускайте `down -v`, если нужно сохранить данные.

## Обновление версии

### Из UI

**Настройки → Обновления** (admin): «Проверить обновления», затем при необходимости «Применить обновление».

Для one-click apply в Docker см. `infra/docker-compose.update-helper.yml` и раздел в [ADMIN_GUIDE.md](./ADMIN_GUIDE.md#13-обновление-и-откат).

### Из CLI (всегда data-safe)

```bash
bash scripts/platform-update.sh
# или:
git pull
./deploy.sh --yes --update
```

Схема БД поддерживается API при старте через `SchemaService` / `MigrationService`.

Важно: по умолчанию `deploy.sh` без `--update` / `--keep-data` в неинтерактивном режиме делает **чистую установку** и удаляет Docker volumes.  
Для сохранения данных всегда используйте:

```bash
./deploy.sh --yes --update
# или
./deploy.sh --yes --keep-data
```

При интерактивном запуске без `--yes` скрипт спросит режим:
- **Чистая установка** — сброс данных (удалит volumes)
- **Обновление платформы** — данные сохраняются (volumes не трогаются)

Явные флаги:

```bash
./deploy.sh --fresh
./deploy.sh --update
```

## Preflight перед переносом

На dev-машине перед пушем:

```bash
pnpm typecheck
pnpm test
pnpm lint
APP_ENV_FILE=../.env.production.example docker compose --env-file .env.production.example -f infra/docker-compose.prod.yml config
```

`pnpm security:sast` — рекомендуется перед релизом (см. [SECURITY_SAST_FINDINGS.md](./SECURITY_SAST_FINDINGS.md)).
