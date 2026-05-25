# Deploy на Linux через Docker Compose

Документ описывает безопасный перенос проекта на отдельный Linux-сервер. Основной сценарий — запуск всего стека через `infra/docker-compose.prod.yml`.

## Требования

- Linux-хост с Docker Engine и Docker Compose v2.
- Доступ к Git-репозиторию.
- 4+ CPU, 16+ GB RAM для комфортного старта; больше, если включены ASV/Nuclei, Metasploit или локальная LLM.
- Открытый наружу порт только для web (`WEB_PUBLISHED_PORT`, по умолчанию `3000`) или reverse proxy перед ним.

## Подготовка

```bash
git clone <repo-url> vuln-intel-platform
cd vuln-intel-platform
cp .env.production.example .env.production
```

Обязательно замените все `CHANGE_ME` в `.env.production`.

Минимальные секреты:

```bash
openssl rand -base64 48  # JWT_SECRET
openssl rand -base64 32  # POSTGRES_PASSWORD
openssl rand -base64 32  # RABBITMQ_DEFAULT_PASS
```

Проверьте, что URL и пароли согласованы:

- `DATABASE_URL` должен использовать тот же пароль, что `POSTGRES_PASSWORD`, и host `postgres`.
- `RABBITMQ_URL` должен использовать тот же пароль, что `RABBITMQ_DEFAULT_PASS`, и host `rabbitmq`.
- `UPSTREAM_API_BASE` внутри Docker должен быть `http://api:4001/api`.
- `API_CORS_ORIGIN` должен совпадать с публичным origin web или reverse proxy.

## Запуск

Проверить compose-конфиг:

```bash
docker compose --env-file .env.production -f infra/docker-compose.prod.yml config
```

Собрать и запустить:

```bash
docker compose --env-file .env.production -f infra/docker-compose.prod.yml up -d --build
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

При пустой таблице пользователей API создаёт первого пользователя из:

- `AUTH_BOOTSTRAP_EMAIL`
- `AUTH_BOOTSTRAP_PASSWORD`

Пароль должен быть не короче 12 символов. После первого успешного входа уберите или замените bootstrap-переменные в `.env.production` и перезапустите `api`.

```bash
docker compose --env-file .env.production -f infra/docker-compose.prod.yml up -d api
```

## Security defaults

- Не коммитьте `.env.production`.
- `AUTH_ALLOW_REGISTER=false` для production.
- Даже если `AUTH_ALLOW_REGISTER=true`, production-регистрация дополнительно требует `AUTH_ALLOW_REGISTER_IN_PRODUCTION=true`; держите его `false`.
- `ALLOW_INTERNAL_API_BEARER=false`; включать только для доверенного service-to-service контура.
- Наружу публикуется только `web`; `api`, `postgres`, `redis`, `rabbitmq` доступны только внутри Docker network.
- Используйте reverse proxy с TLS перед `web` для реального production-доступа.
- ASV/Nuclei и Metasploit по умолчанию выключены. Включайте только для разрешённых целей и после оценки риска активного сканирования.

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

```bash
git pull
docker compose --env-file .env.production -f infra/docker-compose.prod.yml build
docker compose --env-file .env.production -f infra/docker-compose.prod.yml up -d
```

Схема БД поддерживается API при старте через `SchemaService`; отдельной команды миграции сейчас нет.

## Preflight перед переносом

На dev-машине перед пушем:

```bash
pnpm typecheck
APP_ENV_FILE=../.env.production.example docker compose --env-file .env.production.example -f infra/docker-compose.prod.yml config
```

`pnpm lint` сейчас может падать на существующем web lint debt. Это не блокирует этот release-prep, но остаток нужно закрыть отдельным cleanup-проходом.
