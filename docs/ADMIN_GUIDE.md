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
6. [Аутентификация и ADMIN_EMAILS](#6-аутентификация-и-admin_emails)
7. [Конвейеры данных (ingest)](#7-конвейеры-данных-ingest)
8. [Очереди RabbitMQ и DLQ](#8-очереди-rabbitmq-и-dlq)
9. [LLM / AI workers](#9-llm--ai-workers)
10. [Threat Digest (prepare / send)](#10-threat-digest-prepare--send)
11. [Интеграции](#11-интеграции)
12. [ASV / Nuclei / Metasploit](#12-asv--nuclei--metasploit)
13. [Резервное копирование и восстановление](#13-резервное-копирование-и-восстановление)
14. [Обновление и откат](#14-обновление-и-откат)
15. [CI/CD и качество](#15-cicd-и-качество)
16. [Безопасность (чеклист)](#16-безопасность-чеклист)
17. [Runbook: типовые инциденты](#17-runbook-типовые-инциденты)
18. [Скрипты и команды](#18-скрипты-и-команды)
19. [System Health UI и мониторинг](#19-system-health-ui-и-мониторинг)
20. [Staging environment](#20-staging-environment)

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
    │ ASV worker │  │ score,ASV  │  │  RabbitMQ  │
    └────────────┘  └────────────┘  └────────────┘
```

| Сервис | Роль |
|--------|------|
| **web** | UI, BFF (`/api/*` → Nest), статика |
| **api** | Auth, CVE, stats, ASV REST, публикация в очереди |
| **ingest** | NVD/EPSS/KEV/BDU/advisories, boot jobs, ASV scan consumer |
| **ai** | Consumers: `ai.enrich`, `ai.score`, `ai.asv-*` |
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

### Рекомендуется (production + ASV + LLM fanout)

| Ресурс | Значение |
|--------|----------|
| CPU | 8–16 vCPU |
| RAM | 32 GB |
| Disk | 200+ GB (NVD catalog, Nuclei templates, PG) |
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

`deploy.sh` **не** выпускает сертификаты. Используйте nginx/Caddy/Traefik:

```
Internet → TLS :443 → reverse proxy → web:3000
```

Задайте `PUBLIC_WEB_ORIGIN` и `API_CORS_ORIGIN` в `.env.production`.

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
| `ADMIN_EMAILS` | (пусто) | Список email админов через запятую. Пусто = все JWT пользователи = админы (dev mode) |
| `AUTH_ALLOW_REGISTER` | false | Публичная регистрация |
| `AUTH_ALLOW_REGISTER_IN_PRODUCTION` | false | Доп. флаг для prod |
| `ALLOW_INTERNAL_API_BEARER` | false | Сервисный bearer в prod |
| `INTERNAL_API_BEARER` | — | Только dev/BFF fallback |
| `API_CORS_ORIGIN` | — | Origins через запятую |

### NVD / Ingest

| Переменная | Default | Описание |
|------------|---------|----------|
| `NVD_API_KEY` | — | Ключ NVD 2.0 (рекомендуется) |
| `NVD_FANOUT_ENRICH` | true | Enrich только CVE ≤24ч |
| `NVD_FANOUT_SCORE_HOT_ONLY` | true | Score только hot CVE |
| `NVD_PUB_HOT_SYNC` | true | Отдельный проход по published |
| `INTEGRATIONS_BOOT` | true | Boot job при старте ingest |
| `EPSS_BOOT_ON_START` | true | Импорт EPSS если таблица пуста |

### Hot24 reliability

| Переменная | Default | Описание |
|------------|---------|----------|
| `HOT24_AI_SWEEP` | true | Догон enrich для 24ч |
| `HOT24_AI_SWEEP_LIMIT` | 200 | Лимит за проход |
| `HOT24_AI_SWEEP_ON_START_MS` | 8000 | Задержка sweep при старте |
| `HOT24_AI_SWEEP_INTERVAL_MS` | 0 | Периодический sweep (0=выкл) |
| `HOT24_SCORE_SWEEP` | true | Догон risk_score |
| `HOT24_SCORE_STALE_HOURS` | 6 | Пересчёт если score старше |
| `HOT24_SCORE_BOOT` | true | Score sweep при boot |
| `AI_SCORE_SKIP_FRESH_HOURS` | 2 | Пропуск дублей NVD score |
| `DLQ_BOOT_RETRY` | false | Авто-replay DLQ при старте (prod: false) |
| `DLQ_BOOT_RETRY_LIMIT` | 200 | Лимит на очередь |

### LLM

| Переменная | Пример | Описание |
|------------|--------|----------|
| `LLM_ENDPOINT` | `http://192.168.1.69:11434/v1/chat/completions` | OpenAI-compatible |
| `LLM_MODEL` | `qwen2.5:7b` | Модель |
| `LLM_API_KEY` | — | Пусто для Ollama |
| `LLM_TIMEOUT_MS` | 300000 | Таймаут HTTP |
| `LLM_MAX_PARALLEL` | 3 | Параллельность к Ollama |
| `AI_ENRICH_PREFETCH` | 10 | RabbitMQ prefetch |
| `AI_ENRICH_QUEUE_PUBLISHED_MAX_AGE_HOURS` | 24 | Фильтр очереди |

### EPSS

| Переменная | Описание |
|------------|----------|
| `EPSS_MAX_DECOMPRESSED_BYTES` | Лимит gzip (default 64MB) |
| `EPSS_FAIL_RETRY_MS` | Backoff при сбое |
| `EPSS_BOOT_RESCORE_LIMIT` | Сколько CVE пересчитать после boot import |

---

## 6. Аутентификация и ADMIN_EMAILS

### Модель

- Глобальный `JwtAuthGuard` на всех API routes кроме `@Public()`.
- Пользователи в таблице `auth_user`.
- TOTP опционально per user.

### ADMIN_EMAILS

Контролирует доступ к **дорогим** операциям:

- `POST /api/stats/dlq/*`
- `POST /api/stats/threat-digest/prepare`
- `POST /api/stats/threat-digest/telegram`

```env
ADMIN_EMAILS=admin@example.com,sec@example.com
```

**Production:** задайте явно. Если пусто — любой залогиненный пользователь = админ (только для dev).

### Bootstrap первого пользователя

1. UI `/login` (если `auth_user` пуста), или
2. `AUTH_BOOTSTRAP_EMAIL` + `AUTH_BOOTSTRAP_PASSWORD` в env (headless).

После создания — **удалите** bootstrap пароль из env.

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
- `BDU_TLS_INSECURE=true` только для dev при проблемах с УЦ.

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
| `asv.scan` | api | ingest |
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
| LLM down / timeout | Починить Ollama, `POST /api/stats/dlq/retry?queue=dlq.ai.enrich` |
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

## 9. LLM / AI workers

### Проверка health

```bash
GET /api/stats/queue
# → llm.ok, llm.endpoint, llm.ms
```

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

### Score dedupe

`AI_SCORE_SKIP_FRESH_HOURS=2` — пропуск для NVD fanout дублей.  
Force recompute: `score:epss:*`, `score:hot24h:*`, `:dlq:`.

### Отключить fanout при проблемах с LLM

```env
NVD_FANOUT_ENRICH=false
HOT24_AI_SWEEP=false
```

Очередь можно purge в RabbitMQ UI после стабилизации.

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

Генерируется `ThreatDigestPdfService` — fact sheets с LLM-текстом из `enrichment_ai`.

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

## 12. ASV / Nuclei / Metasploit

### Включение Nuclei

```env
ASV_NUCLEI_ENABLED=1
ASV_NUCLEI_RUNNER=docker
ASV_NUCLEI_IMAGE=projectdiscovery/nuclei:latest
ASV_NUCLEI_TEMPLATES_DIR=/var/lib/vuln-intel/nuclei-templates
```

Первый запуск скачивает ~1GB шаблонов.

### Metasploit

```env
MSF_ENABLED=1
```

Только **ручной** запуск из UI. Docker socket должен быть доступен ingest.

### Юридическое

Сканирование и Metasploit — только с **письменным разрешением** владельца активов.

---

## 13. Резервное копирование и восстановление

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

## 14. Обновление и откат

### Обновление

```bash
cd vuln-intel-platform
git pull
./deploy.sh --yes --update
```

Схема БД применяется API при старте (`SchemaService`).

### Откат

```bash
git checkout <previous-tag>
./deploy.sh --yes --update
```

Если схема менялась несовместимо — restore из backup.

---

## 15. CI/CD и качество

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

## 16. Безопасность (чеклист)

### Перед go-live

- [ ] `JWT_SECRET` — криптостойкий, уникальный
- [ ] `ADMIN_EMAILS` задан
- [ ] `AUTH_ALLOW_REGISTER=false`
- [ ] `ALLOW_INTERNAL_API_BEARER=false`
- [ ] `DLQ_BOOT_RETRY=false`
- [ ] TLS на reverse proxy
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

## 17. Runbook: типовые инциденты

### INC-01: Очередь ai.enrich > 500

**Симптомы:** UI health, растущий `enrich` в stats/queue.  
**Диагностика:** `llm.ok`, логи `apps/ai`, sample DLQ.  
**Решение:**
1. Починить LLM connectivity.
2. `dlq/retry` если есть DLQ.
3. Временно `NVD_FANOUT_ENRICH=false` если catch-up не нужен.
4. После стабилизации — включить fanout обратно.

### INC-02: Risk scores «не обновляются»

**Симптомы:** Пользователь видит большое число в summary.  
**Пояснение:** Это COUNT всех scores, не очередь.  
**Проверка:** `ai.score` depth ≈ 0, `HOT24_SCORE_SWEEP=true`, `pnpm rescore:hot24`.

### INC-03: 401 для всех пользователей UI

**Причина:** JWT_SECRET сменился, истёк token, clock skew.  
**Решение:** Перелогин; проверить `JWT_SECRET` не менялся между api рестартами без re-login.

### INC-04: Digest отправился без LLM

**После фикса 2026-07:** UI блокирует send. Если старая версия web — обновить deploy.  
**Проверка:** prepare status `completed=true` перед send.

### INC-05: EPSS пустой после fresh install

**Ожидание:** Boot import в первые 30с.  
**Проверка:** логи `[ingest:integrations-boot] epss`, `pnpm epss:sync`.  
**Env:** `EPSS_BOOT_ON_START=true`.

### INC-06: RabbitMQ PRECONDITION_FAILED

**Причина:** Параметры очереди изменились (x-max-priority).  
**Решение:** Удалить очередь `ai.enrich` в RabbitMQ UI, перезапустить ai+api.

### INC-07: Данные пропали после deploy

**Причина:** Запущен `--fresh` вместо `--update`.  
**Профилактика:** Всегда `--update` на prod; backup перед `--fresh`.

---

## 18. Скрипты и команды

| Команда | Назначение |
|---------|------------|
| `./deploy.sh` | Production deploy |
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

## 19. System Health UI и мониторинг

### Модуль «Здоровье системы» (web)

В боковой панели (иконка пульса) — **единая точка** для техопераций:

| Вкладка | Содержимое |
|---------|------------|
| **Обзор** | `/api/health`, сводка очередей, reconciliation |
| **Очереди** | Глубина очередей ingest/ai |
| **DLQ** | Просмотр, retry, clear (только **admin**) |
| **Конвейеры** | Статус threat-intel refresh, digest prepare jobs |
| **Управление** | Ручной refresh TI, ссылки в настройки |

Мониторинг **не дублируется** в Overview / Settings / Threat — только ссылка «→ Здоровье системы».

### RBAC (роли)

| Роль | Права |
|------|-------|
| `admin` | Все write-операции + DLQ + digest prepare |
| `analyst` | Чтение + мутации задач/CVE (не admin-only) |
| `viewer` | Только чтение; `WriteRoleGuard` блокирует POST/PUT/PATCH/DELETE |

Роль хранится в `auth_user.role`, попадает в JWT. Legacy: если `ADMIN_EMAILS` не задан — все пользователи считаются admin.

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

## 20. Staging environment

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
