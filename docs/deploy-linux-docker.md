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
- 4+ CPU, 16+ GB RAM для комфортного старта; больше, если включены ASV/Nuclei, Metasploit или локальная LLM.
- Открытый наружу порт только для web (`WEB_PUBLISHED_PORT`, по умолчанию `3000`) или reverse proxy перед ним.

Если автоматическая установка Compose v2 не прошла, установите compose plugin вручную:

```bash
sudo apt-get update
sudo apt-get install -y docker-compose-plugin
docker compose version
```

Скрипт также поддерживает standalone `docker-compose`, но только версии v2.

Важно: контейнер `web` внутри Docker слушает HTTP. Указывайте `https://` origin, если TLS завершается на reverse proxy/load balancer/хосте перед приложением. Сам `deploy.sh` выбирает и публикует порт, но не выпускает TLS-сертификаты.

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

При первом запуске, если таблица `auth_user` пустая, откройте web UI и перейдите на `/login`. Вместо обычной формы входа появится первичная настройка:

- email администратора;
- пароль администратора;
- повтор пароля.

Пароль должен быть не короче 12 символов. После создания администратора настройка автоматически закрывается: повторно открыть её нельзя, пока в БД есть хотя бы один пользователь.

Для headless-развёртывания остаётся fallback: можно заранее задать `AUTH_BOOTSTRAP_EMAIL` и `AUTH_BOOTSTRAP_PASSWORD` в `.env.production`. Тогда API создаст первого пользователя автоматически, если `auth_user` пустая. После первого успешного входа уберите bootstrap-переменные и перезапустите `api`.

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
./deploy.sh --yes
```

Схема БД поддерживается API при старте через `SchemaService`; отдельной команды миграции сейчас нет.

## Preflight перед переносом

На dev-машине перед пушем:

```bash
pnpm typecheck
APP_ENV_FILE=../.env.production.example docker compose --env-file .env.production.example -f infra/docker-compose.prod.yml config
```

`pnpm lint` сейчас может падать на существующем web lint debt. Это не блокирует этот release-prep, но остаток нужно закрыть отдельным cleanup-проходом.
