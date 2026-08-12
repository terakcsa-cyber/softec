# Руководство администратора Vuln Intel Platform

Полное руководство по развёртыванию, настройке, эксплуатации и устранению неполадок. Предполагается доступ к серверу, Docker и переменным окружения.

**Связанные документы:** [deploy-linux-docker.md](./deploy-linux-docker.md), [MATURITY.md](./MATURITY.md), [SECURITY_SURFACE.md](./SECURITY_SURFACE.md), [USER_GUIDE.md](./USER_GUIDE.md).

---

## Содержание

1. [Архитектура](#1-архитектура)
2. [Требования к инфраструктуре](#2-требования-к-инфраструктуре)
3. [Локальная разработка](#3-локальная-разработка)
4. [Production deploy](#4-production-deploy)
5. [Переменные окружения (справочник)](#5-переменные-окружения-справочник)
6. [Аутентификация и RBAC](#6-аутентификация-и-rbac)
7. [Конвейеры данных (ingest)](#7-конвейеры-данных-ingest)
8. [Очереди RabbitMQ и DLQ](#8-очереди-rabbitmq-и-dlq)
9. [Text engine / AI workers](#9-text-engine--ai-workers)
10. [Threat Digest (prepare / send)](#10-threat-digest-prepare--send)
11. [Интеграции](#11-интеграции)
12. [Резервное копирование и восстановление](#12-резервное-копирование-и-восстановление)
13. [Обновление и откат](#13-обновление-и-откат)
14. [CI/CD и качество](#14-cicd-и-качество)
15. [Безопасность (чеклист)](#15-безопасность-чеклист)
16. [Runbook: типовые инциденты](#16-runbook-типовые-инциденты)
17. [Скрипты и команды](#17-скрипты-и-команды)
18. [System Health UI и мониторинг](#18-system-health-ui-и-мониторинг)
19. [Staging environment](#19-staging-environment)

---

## 1. Архитектура

```
                    ┌─────────────┐
   Browser ────────►│  apps/web   │  Next.js BFF + UI
                    │  :3000      │
                    └──────┬──────┘
                           │ JWT / proxy
                    ┌──────▼──────┐
                    │  apps/api   │  NestJS REST
                    │  (internal) │
                    └──┬───┬───┬──┘
           ┌───────────┘   │   └───────────┐
           ▼               ▼               ▼
    ┌────────────┐  ┌────────────┐  ┌────────────┐
    │ apps/ingest│  │  apps/ai   │  │  Postgres  │
    │ NVD,EPSS,  │  │ enrich,    │  │  Redis     │
    │ BDU,patch  │  │ score      │  │  RabbitMQ  │
    └────────────┘  └────────────┘  └────────────┘
```

| Сервис | Роль |
|--------|------|
| **web** | UI, BFF (`/api/*` → Nest), статика |
| **api** | Auth, CVE, stats, публикация в очереди |
| **ingest** | NVD/EPSS/KEV/BDU/advisories, boot jobs |
| **ai** | Consumers: `ai.enrich`, `ai.score` |
| **postgres** | Единый источник данных |
| **redis** | Кэш enrich, сессии вспомогательные |
| **rabbitmq** | Topic exchange `vuln.events`, DLX `vuln.dlx` |

В **production** наружу публикуется только **web**. API доступен внутри Docker network.

---

## 2. Требования к инфраструктуре

### Минимум (пилот, до 50k CVE)

| Ресурс | Значение |
|--------|----------|
| CPU | 4 vCPU |
| RAM | 16 GB |
| Disk | 50 GB SSD |
| OS | Linux (Ubuntu 22.04+), Docker 24+ |

### Рекомендуется (production + опциональный LLM)

| Ресурс | Значение |
|--------|----------|
| CPU | 8–16 vCPU |
| RAM | 32 GB |
| Disk | 200+ GB (NVD catalog, PG) |
| Network | Исходящий HTTPS к NVD, EPSS, CISA; LAN к Ollama |

### Порты

| Порт | Сервис | Публикация |
|------|--------|------------|
| 3000 (или custom) | web | Да (+ TLS proxy) |
| 4001 | api | Только dev |
| 5432 | postgres | Нет |
| 6379 | redis | Нет |
| 5672, 15672 | rabbitmq | Нет |

---

## 3. Локальная разработка

```bash
pnpm infra:up          # postgres, redis, rabbitmq
cp .env.example .env   # JWT_SECRET обязателен
pnpm install
pnpm dev               # api + web + ingest + ai
```

### Важные команды infra

| Команда | Действие |
|---------|----------|
| `pnpm infra:up` | Запуск контейнеров |
| `pnpm infra:stop` | Stop без удаления volumes |
| `pnpm infra:down` | `docker compose down` **без -v** |
| `pnpm infra:wipe` | **Удаляет volumes** — только осознанно |

### Проверки разработчика

```bash
pnpm typecheck
pnpm test
pnpm lint
```

---

## 4. Production deploy

### Быстрый путь

```bash
git clone <repo> vuln-intel-platform && cd vuln-intel-platform
./deploy.sh --origin=https://vuln.example.com
```

Интерактивно выберите:
- **Чистая установка** — удаляет Docker volumes (новая БД).
- **Обновление платформы** — сохраняет данные.

### Неинтерактивно

```bash
# Обновление с сохранением данных
./deploy.sh --yes --update --origin=https://vuln.example.com

# Чистая установка
./deploy.sh --yes --fresh --admin-email=sec@example.com --admin-password='...'
```

### После deploy

```bash
curl -fsS http://127.0.0.1:3000/health
curl -fsS http://127.0.0.1:3000/api/health
docker compose --env-file .env.production -f infra/docker-compose.prod.yml ps
```

### TLS

Встроенный сервис `tls-proxy` (Caddy) в `infra/docker-compose.prod.yml` / `staging.yml` завершает HTTPS и проксирует на `web:3000`.

```
Internet → TLS :443 (tls-proxy) → web:3000
         → HTTP  :80  → ACME webroot (/.well-known/acme-challenge/) + redirect HTTPS
```

**One-click из UI (admin):** Настройки → **Веб / TLS**

1. **Домен:** **Получить Let's Encrypt** — certbot HTTP-01 (webroot) в контейнере `api`, затем копирование `fullchain`/`privkey` в volume `tls_certs` и reload `tls-proxy`. Нужны: публичный DNS на этот хост, порт **80** снаружи (`WEB_TLS_HTTP_PORT`), email для ACME-аккаунта. Checkbox «Staging CA» — тестовый УЦ (браузеры не доверяют; безопаснее для dry-run).
2. **Голый IP (без DNS):** в поле «Домен или IP» укажите адрес (например `203.0.113.10`) → **HTTPS для IP (самоподписанный)**. Сертификат с SAN `IP:…` (+ localhost/127.0.0.1) пишется в `tls_certs`, tls-proxy/local proxy перечитывает файлы. Браузер покажет предупреждение о недоверенном УЦ — это ожидаемо. DNS A-запись **не нужна**.
3. **Опционально LE для IP** (certbot ≥ 5.4 в образе API): кнопка «LE для IP (~6 дн.)» — `--ip-address` + shortlived-профиль Let's Encrypt (~160 часов). Нужен публичный IP и порт **80**; DNS не нужен. Авто-renew при сроке &lt; `LETSENCRYPT_IP_RENEW_DAYS` (default 2).
4. **Обновить LE** — `certbot renew` + повторная установка в `tls_certs` (если issuer = Let's Encrypt).
5. **Самоподписанный (lab)** — для домена во внутренней сети / localhost.

Volumes: `tls_certs` (или `tls_staging_certs`), общий ACME webroot (`acme_webroot` / `acme_staging_webroot`), certbot state (`letsencrypt_data` / `letsencrypt_staging_data`). В образе API: `certbot≥5.4` (pip).

Порты: `WEB_TLS_PUBLISHED_PORT` (prod default 443), `WEB_TLS_HTTP_PORT` (80). Прямой HTTP к web (`WEB_PUBLISHED_PORT`) остаётся доступен для отладки. После выпуска LE выставьте `PUBLIC_WEB_ORIGIN` / `API_CORS_ORIGIN` на `https://…` (для IP: `https://203.0.113.10`).

**Авто-renew:** при issuer=Let's Encrypt API раз в сутки проверяет срок и вызывает `certbot renew`, если осталось &lt; `LETSENCRYPT_RENEW_DAYS` (default 30) для домена или &lt; `LETSENCRYPT_IP_RENEW_DAYS` (default 2) для shortlived/IP. Отключить: `LETSENCRYPT_AUTO_RENEW=false`. Ручная кнопка «Обновить LE» всегда доступна.

**Ограничения:** localhost / `.local` — LE не выдаст (используйте self-signed); без публичного :80 HTTP-01 не пройдёт; staging с портом 8080 по умолчанию не подходит для LE без проброса 80; IP HTTPS без DNS = self-signed (или LE shortlived при доступном :80).

---

## 5. Переменные окружения (справочник)

Полный шаблон: `.env.example` (dev) и генерация `.env.production` через `deploy.sh`.

### Обязательные (production)

| Переменная | Описание |
|------------|----------|
| `JWT_SECRET` | ≥32 символов, подпись JWT |
| `DATABASE_URL` | Postgres connection string |
| `REDIS_URL` | Redis |
| `RABBITMQ_URL` | AMQP |
| `POSTGRES_PASSWORD` | Пароль БД (compose) |

### Безопасность

| Переменная | Default | Описание |
|------------|---------|----------|
| `AUTH_BOOTSTRAP_EMAIL` | `admin@vuln-intel.local` | Email bootstrap-администратора при пустой `auth_user` |
| `AUTH_BOOTSTRAP_PASSWORD` | `ChangeMe!Admin1` | Bootstrap-пароль; пользователь обязан сменить его при первом входе |
| `ADMIN_EMAILS` | (пусто) | Legacy allowlist для admin-only API по email. Пусто не повышает всех пользователей до admin |
| `AUTH_ALLOW_REGISTER` | false | Публичная регистрация |
| `AUTH_ALLOW_REGISTER_IN_PRODUCTION` | false | Доп. флаг для prod |
| `ALLOW_INTERNAL_API_BEARER` | false | Сервисный bearer в prod |
| `INTERNAL_API_BEARER` | — | Только dev/BFF fallback |
| `API_CORS_ORIGIN` | — | Origins через запятую |

### NVD / Ingest

| Переменная | Default | Описание |
|------------|---------|----------|
| `NVD_API_KEY` | — | Ключ NVD 2.0 (рекомендуется) |
| `NVD_FANOUT_ENRICH` | false | Per-CVE enrich при upsert NVD. `false` отключает fanout для всех движков (рекомендуется: зрелость через hot24) |
| `NVD_FANOUT_SCORE_HOT_ONLY` | true | Score только hot CVE |
| `NVD_PUB_HOT_SYNC` | true | Отдельный проход по published |
| `INTEGRATIONS_BOOT` | true | Boot job при старте ingest |
| `EPSS_BOOT_ON_START` | true | Импорт EPSS если таблица пуста |

### Hot24 reliability

| Переменная | Default | Описание |
|------------|---------|----------|
| `HOT24_AI_SWEEP` | false | Только для `TEXT_ENGINE=llm`: включить mass hot24. Для baseline/translate hot24 идёт через `TEXT_ENGINE_BG_ENRICH` |
| `HOT24_AI_SWEEP_LIMIT` | 200 | Лимит за проход |
| `HOT24_AI_SWEEP_ON_START_MS` | 0 | AI sweep при старте (text-engine подставит дефолт, если BG enrich on) |
| `HOT24_AI_SWEEP_INTERVAL_MS` | 0 | Периодический sweep (0 → text-engine дефолт ~90с при BG enrich) |
| `HOT24_SCORE_SWEEP` | true* | Догон risk_score (*только если `ai.score` включён) |
| `HOT24_SCORE_STALE_HOURS` | 6 | Пересчёт если score старше |
| `HOT24_SCORE_BOOT` | true* | Score sweep при boot (*если score не выключен) |
| `AI_SCORE_ENABLED` | `true` | Unified risk_score; `false` только чтобы поставить scoring на паузу |
| `AI_SCORE_VIA_QUEUE` | false | Legacy Rabbit `ai.score`. По умолчанию score пишется **inline** в ingest/API |
| `AI_SCORE_INLINE_CONCURRENCY` | 48 | Параллель inline upsert |
| `BACKLOG_SCORE_SWEEP` | true* | Фоновый догон всего корпуса без `risk_score` (*если `AI_SCORE_ENABLED`) |
| `BACKLOG_SCORE_SWEEP_LIMIT` | 2500 | CVE за один проход backlog |
| `BACKLOG_SCORE_SWEEP_INTERVAL_MS` | 12000 | Интервал backlog score |
| `AI_SCORE_SKIP_FRESH_HOURS` | 2 | Пропуск дублей NVD score (только queue path) |
| `DLQ_BOOT_RETRY` | false | Авто-replay DLQ при старте (prod: false) |
| `DLQ_BOOT_RETRY_LIMIT` | 200 | Лимит на очередь |

> **`risk_score`:** по умолчанию **inline** (без Rabbit). Очередь `ai.score` — только `AI_SCORE_VIA_QUEUE=true`. Отключение расчёта: `AI_SCORE_ENABLED=false`. Readiness **не** считает `dlq.ai.score`, пока scoring inline/выключен.

### Text engine / LLM

| Переменная | Пример | Описание |
|------------|--------|----------|
| `TEXT_ENGINE` | `baseline` | `baseline` без внешних вызовов, `translate` через LibreTranslate, `llm` через LLM pipeline |
| `LIBRETRANSLATE_URL` | local `http://127.0.0.1:5050`, prod `http://libretranslate:5000` | Endpoint для `TEXT_ENGINE=translate`. Локально сейчас LT-compatible **MyMemory bridge** (`infra/translate-proxy`), т.к. Argos CDN часто недоступен |
| `LLM_ENDPOINT` | `http://192.168.1.69:11434/v1/chat/completions` | OpenAI-compatible; используется только при `TEXT_ENGINE=llm` |
| `LLM_MODEL` | `qwen2.5:7b` | Модель для `llm` |
| `LLM_API_KEY` | — | Пусто для Ollama |
| `LLM_TIMEOUT_MS` | 300000 | Таймаут HTTP |
| `LLM_MAX_PARALLEL` | 3 | Параллельность к Ollama |
| `AI_ENRICH_PREFETCH` | 10 | RabbitMQ prefetch |
| `AI_ENRICH_MAX_DEPTH` | 2000 | Soft cap: ingest skips enrich publish when queue depth ≥ value (`0` = unlimited) |
| `AI_ENRICH_INFLIGHT_TTL_HOURS` | 6 | Publish-time coalesce TTL (`enrich:inflight:{cve}:{engine}`) |
| `AI_ENRICH_QUEUE_PUBLISHED_MAX_AGE_HOURS` | 24 | Worker skips old published CVE jobs |
| `AI_ENRICH_QUEUE_PUBLISHED_MAX_AGE_HOURS` | 24 | Фильтр очереди |

### EPSS

Ежедневный CSV.gz (мульти-mirror / FIRST failover + integrity checks), boot при пустой/stale таблице; poll по умолчанию ~6ч (`EPSS_POLL_INTERVAL_MS`). После ingest score **сразу** пишется в `risk_score` (inline). Ручной sync: System Health → Управление или `pnpm epss:sync` / `POST /api/stats/ops/epss/sync`.

**UI:** Overview показывает **EPSS · база** (корпус). Низкий EPSS среди CVE за 24ч ожидаем: дневной feed отстаёт от NVD ~сутки — не трактовать как сбой sync.

| Переменная | Default | Описание |
|------------|---------|----------|
| `EPSS_BOOT_ON_START` | true | Импорт при старте если пусто/stale |
| `EPSS_POLL_INTERVAL_MS` | 86400000 | Интервал job |
| `EPSS_FEED_URL` | (FIRST) | Опциональный primary URL; иначе empiricalsecurity + cyentia |
| `EPSS_FETCH_RETRIES` | 5 | Попытки по URL-ам |
| `EPSS_FAIL_RETRY_MS` | 300000 | Backoff при сбое цикла |
| `EPSS_MAX_DECOMPRESSED_BYTES` | 64MB | Лимит gzip |
| `EPSS_BOOT_RESCORE_LIMIT` | 5000 | Сколько CVE пересчитать после boot |
| `EPSS_RESCORE_LIMIT` | 20000 | Лимит rescore после полного ingest |

---

## 6. Аутентификация и RBAC

### Модель

- Глобальный `JwtAuthGuard` на всех API routes кроме `@Public()`.
- Пользователи и роли хранятся в таблице `auth_user`.
- TOTP опционально per user.

### Bootstrap администратора

Если `auth_user` пуста, API при старте создаёт администратора:

- email: `admin@vuln-intel.local`
- пароль: `ChangeMe!Admin1`
- `must_change_password=true`, поэтому при первом входе пользователь обязан сменить пароль.

```env
AUTH_BOOTSTRAP_EMAIL=sec@example.com
AUTH_BOOTSTRAP_PASSWORD=UseYourOwnLongPassword1
```

Задайте эти переменные до первого старта API, если нужны свои начальные реквизиты. После создания пользователей управляйте доступом через UI, а bootstrap-пароль не используйте как рабочий.

### Роли

| Роль | Права |
|------|-------|
| `viewer` | Только чтение; `POST`/`PUT`/`PATCH`/`DELETE` блокируются `WriteRoleGuard` |
| `analyst` | Чтение и рабочие write-операции: задачи, карточки, ручное enrich, triage |
| `admin` | Права analyst + admin-only операции: DLQ/ops, digest prepare/send, настройки и пользователи |

### Управление пользователями

Администратор создаёт и редактирует пользователей в **Settings → Пользователи**: email, роль, `enabled`, требование смены пароля и reset password. Self-service регистрация по умолчанию выключена.

### ADMIN_EMAILS

`ADMIN_EMAILS` остаётся legacy allowlist для admin-only API по email. Основной источник прав — `auth_user.role`; пустой `ADMIN_EMAILS` **не** делает всех пользователей admin.

### INTERNAL_API_BEARER

В production **отключён** без `ALLOW_INTERNAL_API_BEARER=true`. Не включайте без reverse proxy и IP allowlist.

---

## 7. Конвейеры данных (ingest)

### NVD

- Watermark по `lastModified`.
- Catalog backfill (исторические CVE).
- Hot window sync по `published` (24–27ч + gap backfill).
- Fanout enrich/score только для CVE ≤24ч.

### EPSS

- Ежедневный poll + boot import.
- Shared module `ingestEpssFeed` с retries и gzip limit.
- После import — score queue для changed CVE.

### KEV / VulnCheck

- CISA KEV catalog.
- VulnCheck KEV (токен в UI или `VULNCHECK_API_TOKEN`).

### BDU ФСТЭК

- `vulxml.zip` с bdu.fstec.ru.
- `BDU_TLS_INSECURE=true` только если на VPS TLS к ФСТЭК ломается (часто у зарубежных хостеров); иначе оставьте выключенным.
- Полный dump XML может быть >512MB: ingest парсит `<vul>` чанками (не грузит весь файл одной JS-строкой).
- Зеркало GitHub (`BDU_ALLOW_MIRROR_FALLBACK=true`) — запасной снимок, может отставать.

### Boot sequence (при старте ingest)

```
t+2.5s  IntegrationsBootJob
          ├─ DLQ replay (если включено)
          ├─ EPSS import (если пусто)
          └─ hot24 score sweep
t+4s    ThreatIntelBootJob
          ├─ VulnCheck KEV
          └─ exploit intel refresh
t+8s    HOT24 AI sweep (nvd job)
```

### Ручные скрипты

```bash
pnpm epss:sync
pnpm rescore:hot24
pnpm bdu:sync
pnpm nvd:pub-catchup
```

---

## 8. Очереди RabbitMQ и DLQ

### Основные очереди

| Очередь | Producer | Consumer |
|---------|----------|----------|
| `ai.enrich` | api, ingest | apps/ai |
| `ai.score` | ingest, api | apps/ai |
| `dlq.ai.enrich` | DLX | admin retry |
| `dlq.ai.score` | DLX | admin retry |

### Мониторинг

```bash
# Через API (нужен JWT админа)
GET /api/stats/queue
```

Ответ включает: `enrich`, `score`, `dlqEnrich`, `dlqScore`, `llm`, `nvd`, `bdu`.

### DLQ: когда растёт

| Причина | Действие |
|---------|----------|
| Внешний движок down / timeout | Починить Ollama/LLM или LibreTranslate, затем `POST /api/stats/dlq/retry?queue=dlq.ai.enrich` |
| Zod validation | Проверить sample: `GET /api/stats/dlq/sample` |
| OOM в worker | Уменьшить prefetch, увеличить RAM |

### Retry (admin API)

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  "https://vuln.example.com/api/stats/dlq/retry?queue=dlq.ai.enrich&limit=100"
```

Replay генерирует новый `idempotencyKey` с суффиксом `:dlq:uuid`.

### Boot replay

`DLQ_BOOT_RETRY=true` — автоматически при старте ingest. **В production рекомендуется false** — только ручной retry после диагностики.

---

## 9. Text engine / AI workers

### Проверка health

```bash
GET /api/stats/queue
# → llm.ok, llm.endpoint, llm.ms
```

### Режимы TEXT_ENGINE

| Режим | Поведение |
|-------|-----------|
| `baseline` | Default: локальные шаблоны NVD/BDU/CWE без внешних AI-вызовов |
| `translate` | `baseline` + EN→RU через LibreTranslate-compatible `/translate`, если задан `LIBRETRANSLATE_URL` |
| `llm` | Полный LLM pipeline через `LLM_ENDPOINT` / `LLM_MODEL` / ключи |

Manual enrich и `threat-digest/prepare` работают без LLM в режимах `baseline` и `translate`: API синхронно готовит обогащение через текущий text engine и не ждёт очередь LLM.

### Ollama на LAN

```env
LLM_ENDPOINT=http://192.168.1.69:11434/v1/chat/completions
LLM_MODEL=qwen2.5:7b
LLM_MAX_PARALLEL=3
LLM_OLLAMA_UNDICI=true
```

Убедитесь, что контейнер `ai` достучится до IP (не `localhost` хоста).

### Enrich dedupe

Worker пропускает CVE с успешным `enrichment_ai`. Исключения: `enrich:digest:`, `:dlq:`, `enrich:manual:`.

### Score dedupe / inline

По умолчанию `risk_score` пишется **inline** (`upsertRiskScoreForCve`) — очередей и DLQ нет.  
Фоновый **`BACKLOG_SCORE_SWEEP`** догоняет весь корпус (CVE без строки в `risk_score`), ~2500 каждые 12с.  
`AI_SCORE_SKIP_FRESH_HOURS` относится только к legacy `AI_SCORE_VIA_QUEUE=true`.  
После миграции с очереди: `rabbitmqctl purge_queue ai.score` и `dlq.ai.score`.

Force: System Health → Hot24 rescore (hot24 + backlog batch) / `pnpm rescore:hot24`.

### Auto enrich / queue guards

```env
NVD_FANOUT_ENRICH=false
TEXT_ENGINE_BG_ENRICH=true
BACKLOG_AI_SWEEP=false
AI_ENRICH_MAX_DEPTH=2000
```

Рекомендуемый prod-профиль: **без per-CVE fanout**, зрелость hot-окна через **hot24** под `TEXT_ENGINE_BG_ENRICH`.  
`HOT24_AI_SWEEP=false` **не** останавливает hot24 для `baseline`/`translate` — только для `llm`. Полный стоп BG: `TEXT_ENGINE_BG_ENRICH=false`.

Защиты от хвоста 10k+:
- **inflight coalesce** — один outstanding job на CVE+engine (`enrich:inflight:…`);
- **`AI_ENRICH_MAX_DEPTH`** — ingest не публикует, пока глубина ≥ порога;
- backlog с `NOT EXISTS` по дневному ключу + inflight.

Manual enrich / digest в `baseline`/`translate` часто идут in-process в API без очереди. Старый хвост можно purge в RabbitMQ.

---

## 10. Threat Digest (prepare / send)

### API flow

```
POST /api/stats/threat-digest/prepare?hotLimit=20
  → jobId, total, enqueued

GET /api/stats/threat-digest/prepare/status?jobId=...
  → done, total, completed

POST /api/stats/threat-digest/telegram
  → отправка в Telegram + PDF
```

### Idempotency

`enrich:digest:{cveId}:{YYYY-MM-DD}` — один enrich на CVE в день.

### Ownership

`audit_log.metadata.actorUserId` — только создатель (или admin) видит status.

### PDF

Генерируется `ThreatDigestPdfService` — fact sheets с текстом из `enrichment_ai`, созданным текущим `TEXT_ENGINE`.

---

## 11. Интеграции

### Telegram

UI: **Настройки → Интеграции → Telegram**  
Поля: `botToken`, `chatId`, `enabled`.

### VulnCheck

UI: ключ `vulncheck` или env `VULNCHECK_API_TOKEN`.

### MaxPatrol VM

UI: **Настройки → Интеграции → MaxPatrol VM**.

### ФСТЭК feed

```env
FSTEC_TG_CHANNEL=bdufstecru
FSTEC_FEED_SOURCE=tg   # или rss
```

---

## 12. Резервное копирование и восстановление

### Postgres dump

```bash
docker compose --env-file .env.production -f infra/docker-compose.prod.yml exec -T postgres \
  sh -c 'pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB"' | gzip > backup-$(date +%F).sql.gz
```

### Restore

```bash
gunzip -c backup.sql.gz | docker compose --env-file .env.production -f infra/docker-compose.prod.yml exec -T postgres \
  sh -c 'psql -U "$POSTGRES_USER" "$POSTGRES_DB"'
```

### Volumes

- `vuln-intel-prod_pg_data`
- `vuln-intel-prod_redis_data`
- `vuln-intel-prod_rabbitmq_data`

**Никогда** `docker compose down -v` на production без бэкапа.

### Cron пример

```cron
0 3 * * * /opt/vuln-intel/backup.sh
```

---

## 13. Обновление и откат

### Обновление из UI (рекомендуется на prod)

В **Настройки → Обновления** (роль `admin`):

1. **Проверить обновления** — сверка текущего SHA с git remote (`origin` / `PLATFORM_UPDATE_REPO_URL`).
2. При наличии коммитов ahead — просмотр changelog и **Применить обновление** (если включён safe-apply).

Безопасность apply:

- никогда не вызывается `docker compose down -v` / `--fresh`;
- `.env*` и секреты не перезаписываются;
- только `git merge --ff-only`;
- перед apply по умолчанию `pg_dump` в `backups/`;
- job выполняется one-shot контейнером, чтобы rebuild `api`/`web` не убивал процесс.

Для one-click apply в Docker подключите helper (нужен абсолютный путь к checkout на хосте):

```bash
export PLATFORM_HOST_REPO_PATH=/opt/vuln-intel-platform
# в .env.production: PLATFORM_UPDATE_APPLY_ENABLED=true
docker compose --env-file .env.production \
  -f infra/docker-compose.prod.yml \
  -f infra/docker-compose.update-helper.yml \
  up -d api
```

Без helper доступна только проверка; apply откажет с понятным RU-сообщением.

Эквивалент CLI:

```bash
bash scripts/platform-update.sh
# или:
git pull
./deploy.sh --yes --update
```

### Обновление вручную

```bash
cd vuln-intel-platform
git pull
./deploy.sh --yes --update
```

Схема БД применяется API при старте (`SchemaService` + `MigrationService`).

### Откат

```bash
git checkout <previous-tag>
./deploy.sh --yes --update
```

Если схема менялась несовместимо — restore из backup.

---

## 14. CI/CD и качество

### GitHub Actions (`.github/workflows/ci.yml`)

**Job `quality`:**
- `pnpm typecheck`
- `pnpm test` (unit + coverage gate ≥40% на critical shared)
- `pnpm lint` (zero warnings)
- `pnpm security:sast` (audit high + Semgrep, continue-on-error)
- Playwright E2E (optional, `E2E_*` secrets)

**Job `integration`:**
- `pnpm test:integration` — testcontainers postgres (migrations) + rabbitmq

**Job `dast`:**
- `pnpm security:dast` (offline curl probes, continue-on-error)

### Локально перед релизом

```bash
pnpm typecheck && pnpm test && pnpm lint
pnpm test:integration    # Docker required
pnpm security:sast
# при поднятом стеке:
WEB_BASE=http://127.0.0.1:3001 API_BASE=http://127.0.0.1:4001 pnpm security:dast
```

### Уровень зрелости

См. [MATURITY.md](./MATURITY.md) — текущие оценки и пробелы.

---

## 15. Безопасность (чеклист)

### Перед go-live

- [ ] `JWT_SECRET` — криптостойкий, уникальный
- [ ] Bootstrap-пароль изменён; рабочие администраторы имеют роль `admin`
- [ ] `AUTH_ALLOW_REGISTER=false`
- [ ] `ALLOW_INTERNAL_API_BEARER=false`
- [ ] `DLQ_BOOT_RETRY=false`
- [ ] TLS: `tls-proxy` + сертификат из Настройки → Веб / TLS (или внешний reverse proxy)
- [ ] Postgres/Redis/RabbitMQ не в public network
- [ ] `.env.production` в `.gitignore`
- [ ] Firewall: только 443 (и SSH)
- [ ] TOTP для admin accounts
- [ ] Backup cron настроен

### Периодически

- [ ] `pnpm security:sast` / Dependabot
- [ ] Ротация `JWT_SECRET` (плановая)
- [ ] Аудит `audit_log` на подозрительные dlq/clear
- [ ] Проверка `dlq.*` depth

---

## 16. Runbook: типовые инциденты

### INC-01: Очередь ai.enrich > 500

**Симптомы:** UI health, растущий `enrich` в stats/queue.  
**Диагностика:** `llm.ok`, логи `apps/ai` / `[ingest:nvd] … backpressure` / `skippedInflight`, sample DLQ.  
**Защиты (с main):** publish-time **inflight coalesce** (1 CVE в полёте), **`AI_ENRICH_MAX_DEPTH`** (default 2000), `NVD_FANOUT_ENRICH=false` реально отключает per-CVE fanout.  
**Решение:**
1. Починить connectivity внешнего движка (`llm`/`translate`) или временно `TEXT_ENGINE=baseline`.
2. `dlq/retry` если есть DLQ.
3. Убедиться: `NVD_FANOUT_ENRICH=false`, `BACKLOG_AI_SWEEP=false`; для полной остановки BG — `TEXT_ENGINE_BG_ENRICH=false` (не путать с `HOT24_AI_SWEEP`, он только для `TEXT_ENGINE=llm`).
4. Purge `ai.enrich`, если это старый авто-хвост до апдейта; digest/hot24 догонят недозревшие.
5. При необходимости ужесточить: `AI_ENRICH_MAX_DEPTH=500`.

### INC-02: Risk scores «не обновляются»

**Симптомы:** Пользователь видит большое число в summary.  
**Пояснение:** Это COUNT всех scores, не очередь.  
**Проверка:** `AI_SCORE_ENABLED=true`, hot24/inline upsert (не очередь), System Health → Hot24 rescore или `pnpm rescore:hot24`. Старый `dlq.ai.score` при inline можно purge.

### INC-03: 401 для всех пользователей UI

**Причина:** JWT_SECRET сменился, истёк token, clock skew.  
**Решение:** Перелогин; проверить `JWT_SECRET` не менялся между api рестартами без re-login.

### INC-04: Digest не ждёт LLM

**Ожидаемо**, если `TEXT_ENGINE=baseline` или `translate`: prepare готовит enrichment без LLM и сразу возвращает completed.
Если нужен именно LLM-текст, задайте `TEXT_ENGINE=llm`, проверьте `LLM_ENDPOINT`/ключи и дождитесь `prepare status completed=true`.

### INC-05: EPSS пустой после fresh install

**Ожидание:** Boot import в первые 30с.  
**Проверка:** логи `[ingest:integrations-boot] epss`, `pnpm epss:sync`.  
**Env:** `EPSS_BOOT_ON_START=true`.

**Не путать с:** EPSS ≈0 среди CVE, опубликованных за последние ~24ч — feed FIRST обычно на день позади NVD; покрытие смотрите по корпусу (Overview «EPSS · база»).

### INC-06: RabbitMQ PRECONDITION_FAILED

**Причина:** Параметры очереди изменились (x-max-priority).  
**Решение:** Удалить очередь `ai.enrich` в RabbitMQ UI, перезапустить ai+api.

### INC-07: Данные пропали после deploy

**Причина:** Запущен `--fresh` вместо `--update`.  
**Профилактика:** Всегда `--update` на prod; backup перед `--fresh`.

---

## 17. Скрипты и команды

| Команда | Назначение |
|---------|------------|
| `./deploy.sh` | Production deploy |
| `bash scripts/platform-update.sh` | Safe update (ff-only + compose up --build, no volume wipe) |
| `pnpm dev` | Локальный стек |
| `pnpm infra:up/down/wipe` | Docker infra |
| `pnpm epss:sync` | Ручной EPSS import |
| `pnpm rescore:hot24` | Score queue для hot CVE |
| `pnpm bdu:sync` | BDU выгрузка |
| `pnpm nvd:pub-catchup` | Догон published |
| `pnpm security:sast` | Audit + Semgrep |
| `pnpm security:dast` | Curl smoke + ZAP |
| `pnpm dlq:replay:score` | CLI replay score DLQ |
| `pnpm test` | Unit tests shared |
| `pnpm test:e2e` | Playwright (web+api должны быть подняты) |
| `pnpm test:integration` | Testcontainers + chaos restart |
| `pnpm audit:high` | 0 high/critical gate |
| `pnpm deploy:staging` | `./deploy.sh --staging` |
| `pnpm deploy:staging:init` | Создать `.env.staging` |
| `pnpm migrate` | SQL migrations |
| `pnpm smoke:post-deploy` | Health + BFF smoke |
| `pnpm smoke:integration` | Post-deploy + metrics + reconciliation |
| `pnpm backup:pg` | PostgreSQL dump |
| `./scripts/pg-backup.sh` | То же (bash) |

---

## 18. System Health UI и мониторинг

### Модуль «Здоровье системы» (web)

В боковой панели (иконка пульса) — **единая точка** для техопераций:

| Вкладка | Содержимое |
|---------|------------|
| **Обзор** | Readiness bar, `/api/health`, сводка очередей, reconciliation |
| **Очереди** | Глубина очередей ingest/ai |
| **DLQ** | Просмотр, retry, clear (только **admin**) |
| **Конвейеры** | Сверка источников + статус threat-intel / digest jobs |
| **Управление** | Ops (admin): EPSS / BDU / NVD hot-sync / hot24 rescore; TI refresh |

Мониторинг **не дублируется** в Overview / Settings / Threat — только ссылка «→ Здоровье системы».

### RBAC (роли)

| Роль | Права |
|------|-------|
| `admin` | Все write-операции + DLQ/ops + digest prepare/send + управление пользователями |
| `analyst` | Чтение + мутации задач/CVE/triage/manual enrich (не admin-only) |
| `viewer` | Только чтение; `WriteRoleGuard` блокирует POST/PUT/PATCH/DELETE |

Роль хранится в `auth_user.role` и попадает в JWT. `ADMIN_EMAILS` — только legacy allowlist для admin-only API; если он пустой, дополнительных admin-прав не выдаётся.

### Prometheus + Grafana (опционально)

```bash
docker compose -f infra/docker-compose.yml \
  -f infra/monitoring/docker-compose.monitoring.yml up -d
```

| Сервис | URL (default) |
|--------|----------------|
| Prometheus | http://localhost:9099 |
| Grafana | http://localhost:3009 (admin / `$GRAFANA_ADMIN_PASSWORD`) |

- Scrape: API `/api/metrics`, AI `:9090`, ingest `:9091`
- Alert rules: `infra/monitoring/prometheus/alerts.yml` (DLQ depth, ingest lag)
- Dashboard: `infra/monitoring/grafana/dashboards/vuln-intel.json` (auto-provision)

### Reconciliation

`GET /api/stats/reconciliation` (auth) — сверка счётчиков источников (NVD, EPSS, KEV) с `audit_log`.  
Фоновый poll каждые 6ч (`RECONCILE_ENABLED=true`, `RECONCILE_STALE_HOURS=12`).

### Env (мониторинг / ops)

```env
METRICS_ENABLED=true
METRICS_POLL_QUEUES=true
METRICS_BEARER=          # опционально для /api/metrics
RECONCILE_ENABLED=true
RECONCILE_STALE_HOURS=12
GRAFANA_ADMIN_PASSWORD=  # для monitoring compose
SMOKE_BEARER=            # для smoke:integration
```

---

## 19. Staging environment

Pre-production стек с **изолированными volumes** и портом **3080**.

```bash
pnpm deploy:staging:init
./deploy.sh --staging --yes --admin-password='YourLongPassword123'
```

| Файл | Назначение |
|------|------------|
| `.env.staging.example` | Шаблон |
| `infra/docker-compose.staging.yml` | Compose stack |
| `scripts/chaos-restart-smoke.mjs` | Restart api→ingest→ai→web + health poll |

По умолчанию: `BDU_INGEST_ENABLED=false`, reconciliation + metrics on.  
Chaos smoke после deploy (отключить: `SKIP_CHAOS_SMOKE=1`).

---

*Для пользователей интерфейса: [USER_GUIDE.md](./USER_GUIDE.md)*
