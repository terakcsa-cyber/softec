# Платформа разведки уязвимостей (Vuln Intel Platform)

Монорепозиторий на **pnpm + Turbo** для сбора и нормализации данных об уязвимостях (CVE, EPSS, KEV, бюллетени вендоров), обогащения карточек CVE/BDU и веб‑интерфейса для аналитики.

**Документация:** [docs/README.md](docs/README.md) — полный индекс.  
**Пользователям:** [docs/USER_GUIDE.md](docs/USER_GUIDE.md) · **Администраторам:** [docs/ADMIN_GUIDE.md](docs/ADMIN_GUIDE.md) · **Зрелость:** [docs/MATURITY.md](docs/MATURITY.md)

Цели проекта:

- быстрый поиск и просмотр CVE с метриками и контекстом;
- фоновые конвейеры ingest (NVD / EPSS / KEV / BDU) + очереди RabbitMQ с DLQ;
- режимы текстового обогащения: локальный `baseline` по умолчанию, `translate` через LibreTranslate или опциональный `llm` (+ фоновый BG enrich);
- эксплуатация на сервере: `./deploy.sh`, встроенный **tls-proxy** / Let's Encrypt, обновления из UI.

---

## Состав системы (приложения)

| Приложение | Стек | Назначение |
|------------|------|------------|
| `apps/web` | Next.js (App Router) | UI, BFF‑маршруты (`/api/...`), прокси к Nest API |
| `apps/api` | NestJS | HTTP API: аутентификация, CVE, статистика, публикация задач в очередь |
| `apps/ingest` | NestJS | NVD / KEV / EPSS, patch‑advisories |
| `apps/ai` | NestJS | Воркеры: enrich CVE, score |
| `packages/shared` | TypeScript | Общие типы, утилиты, схемы |

Инфраструктура для локальной разработки: **`infra/docker-compose.yml`** — Postgres, Redis, RabbitMQ.

---

## Ключевые возможности

### Дашборд и CVE

- Сводка по платформе, «свежесть» источников, горячие CVE, вендоры.
- Список уязвимостей с фильтрами, **полноэкранная карточка CVE** с вкладками («Общая», «Уязвимые продукты», «Исправления», «Источники»).
- **Приоритизация “bank‑grade”**: локальный скоринг и объяснения (CVSS, EPSS, KEV, сигналы эксплуатации), отдельный **Perimeter‑score** (сеть/вектор + vendor/product эвристики).
- Блок «Угрозы за 24 часа» с динамическими категориями (All/KEV/CVSS≥9/EPSS≥0.5), сортировкой и корректной раскраской карточек по наиболее сильному сигналу.
- **Экспорт в XLSX** (для CVE): комплексный анализ, источники, риск‑разбор и attack‑map/граф (формируется сервером и скачивается из UI с `Authorization`).
- Интеграции: **NVD**, **CISA KEV**, **EPSS**, **RSS/Atom** бюллетеней вендоров (в т.ч. русскоязычные источники по умолчанию).

### Задачник по уязвимостям (Vulnerability Task Tracker)

Модуль для небольшого круга ответственных (1–2 пользователя), чтобы **вести кампании по вендору/продукту** и не терять контекст по обработке CVE.

- **Задача может содержать несколько CVE** (many‑to‑many).
- Статусы: `new`, `in_progress`, `closed`.
- Хранение решений и артефактов: контекст, план, заметки, **evidence** для проверки и закрытия.
- **Audit trail**: события изменений (кто/что/когда).
- **TaskScore**: серверная агрегация срочности по CVE (priority/perimeter/risk/EPSS/KEV) + мультипликатор по статусу, с объясняющими причинами.
- Интеграция с карточкой CVE: видно количество открытых задач, можно быстро **создать задачу из CVE** или **добавить CVE в существующую** через поиск, с открытием задачи в модуле.

### Patch management

- Нормализованная лента `vendor_advisory`, детали записи, live‑уведомления (при наличии настроек).

### ФСТЭК / БДУ

- Парсинг ленты (по умолчанию публичная страница `t.me/s/...`, без обязательного RSSHub).
- Настраиваемые `FSTEC_*` переменные (см. `.env.example`).

### Здоровье сервисов

- UI: `/health`.
- BFF: `GET /api/health` — параллельные проверки API и зависимостей (для авторизованного пользователя передаётся `Authorization`).

**Очереди RabbitMQ (основные)**:

| Очередь | Потребитель | Назначение |
|---------|-------------|------------|
| `ai.enrich` | `apps/ai` | Обогащение CVE/BDU через текущий `TEXT_ENGINE` |
| `ai.score` | `apps/ai` | Пересчёт скоринга |

Для каждой очереди объявляются **DLQ** (`dlq.*`) и привязка к exchange `vuln.dlx`.

**Важно про DLQ**: если в дашборде «Очереди» вы видите, например, `dlq.ai.enrich > 0`, это означает, что часть задач enrich была **отклонена (`rejected`)** воркером и больше не будет обработана автоматически. Обычно это связано с недоступностью внешнего движка (`llm`/`translate`) или проблемами валидации. В UI можно безопасно выполнить **Retry** (вернуть сообщения в основную очередь) после устранения причины.

## Интеграции и внешние данные

- **NVD (NIST)** — CVE (рекомендуется `NVD_API_KEY`).
- **CISA KEV** — каталог известных эксплуатируемых CVE.
- **EPSS** — ежедневный CSV.gz, пересчёт скоринга через очереди.
- **Vendor advisories** — настраиваемый список RSS/Atom (или встроенный набор источников).
- **ФСТЭК BDU** — Telegram/RSS (`FSTEC_*`) + официальная выгрузка `vulxml.zip` с bdu.fstec.ru в `bdu_vuln` (`BDU_*`, ingest); BDU приклеивается к CVE или отдельной карточкой.
- **Postgres** — основное хранилище.
- **Redis** — кэш enrich, вспомогательные ключи.
- **RabbitMQ** — события и воркеры.

---

## Структура репозитория

```
apps/api       — NestJS HTTP API
apps/ingest    — NestJS: NVD/KEV/EPSS/patch
apps/ai        — NestJS: enrich + score workers
apps/web       — Next.js UI + BFF
packages/shared — общий код
infra          — Docker Compose (Postgres, Redis, RabbitMQ) + init SQL
scripts        — dev.mjs (оркестратор портов), утилиты
```

---

## Быстрый старт (локальная разработка)

### Требования

- **Node.js** ≥ 20  
- **pnpm** 10 (версия зафиксирована в `package.json`)  
- **Docker** — для Postgres / Redis / RabbitMQ  

### 1. Поднять инфраструктуру

```bash
pnpm infra:up
```

Будут запущены:

- Postgres: `localhost:5432`, БД `vuln_intel`, пользователь/пароль `vuln` / `vuln`
- Redis: `localhost:6379`
- RabbitMQ: `localhost:5672`, UI управления `http://localhost:15672` (`vuln` / `vuln`)

Остановка **без удаления томов** (данные БД сохраняются):

```bash
pnpm infra:stop    # docker compose stop
pnpm infra:down    # docker compose down (без -v)
```

**Явное удаление данных** (только осознанно):

```bash
pnpm infra:wipe    # docker compose down -v
```

### 2. Переменные окружения

```bash
cp .env.example .env
```

Обязательно задайте **`JWT_SECRET`** (не короче 32 символов).

Bootstrap admin создаётся автоматически, если `auth_user` пуста: default `admin@vuln-intel.local` / `ChangeMe!Admin1`. Переопределите через `AUTH_BOOTSTRAP_EMAIL` / `AUTH_BOOTSTRAP_PASSWORD` до первого старта API; при первом входе администратор обязан сменить пароль.

Рекомендуется:

- `NVD_API_KEY` — лимиты NVD;
- `TEXT_ENGINE=baseline` по умолчанию: digest/manual enrich работают без LLM;
- `TEXT_ENGINE=translate` + `LIBRETRANSLATE_URL` — baseline + перевод через LibreTranslate-compatible `/translate`;
- `TEXT_ENGINE=llm`, `LLM_ENDPOINT`, `LLM_API_KEY` (если нужен ключ), `LLM_MODEL` — только если нужен LLM pipeline;
- `ai.score` / risk score: по умолчанию **inline** в ingest/API (без Rabbit); фоновый `BACKLOG_SCORE_SWEEP` догоняет весь корпус без `risk_score`; пауза — `AI_SCORE_ENABLED=false`; legacy очередь — `AI_SCORE_VIA_QUEUE=true`.

RBAC: `viewer` — только чтение; `analyst` — чтение и рабочие изменения; `admin` — всё это плюс ops и управление пользователями. Пользователей создаёт администратор в **Settings → Пользователи**.

### 3. Установка зависимостей

```bash
pnpm install
```

### 4. Запуск всех сервисов разработки

```bash
pnpm dev
```

Скрипт **`scripts/dev.mjs`**:

- подбирает **свободные** порты (базово API с `API_PORT_BASE`, web с `WEB_PORT_BASE`, по умолчанию 4001 и 3001, с шагом при занятости);
- собирает **`packages/shared`**;
- запускает **`turbo dev`** (api, web, ingest, ai).

В консоли появятся фактические URL, например:

- Web: `http://127.0.0.1:3001` (или следующий свободный)
- API: `http://127.0.0.1:4001/api`

Если вам нужно, чтобы **web всегда был строго на `3001`**, освободите порты (остановите лишние dev‑процессы) и задайте базовый порт:

```bash
WEB_PORT_BASE=3001 API_PORT_BASE=4001 pnpm dev
```

### Troubleshooting: web dev отдаёт 500 (Next.js devtools / RSC manifest)

Иногда Next.js в dev падает с ошибкой вида:

- `Could not find the module ... segment-explorer-node.js#SegmentViewNode in the React Client Manifest`

В этом случае перезапустите dev: по умолчанию `scripts/dev.mjs` отключает devtools в Next (через `NEXT_DISABLE_DEVTOOLS=1`) как workaround.

Переменные **`UPSTREAM_API_BASE`** и **`NEXT_PUBLIC_API_BASE`** для дочерних процессов выставляются **согласованно** с выбранным портом API — не подменяйте их вручную при работе через `pnpm dev`, если не уверены.

Более быстрый перезапуск без очистки кэша Next:

```bash
pnpm dev:fast
```

### Файл `.dev.lock`

Если прошлый `pnpm dev` завершился аварийно, может остаться **`.dev.lock`**. Тогда новый запуск напишет, что dev уже запущен. Удалите lock вручную после проверки, что старых процессов нет:

```bash
rm -f .dev.lock
```

---

## Production deploy через Docker Compose

Для переноса на Linux-сервер используйте production compose:

```bash
./deploy.sh
```

`deploy.sh` автоматически создаёт `.env.production`, генерирует сильные секреты, проверяет compose config, собирает и поднимает stack. При интерактивном запуске спросит режим: **«Чистая установка»** (удалит Docker volumes Postgres/Redis/RabbitMQ) или **«Обновление платформы»** (данные сохраняются). Флаги: `--fresh` / `--update` (или `--keep-data`). Наружу публикуется только web (`WEB_PUBLISHED_PORT`, по умолчанию **3000**); API и зависимости остаются внутри Docker network. Подробная инструкция: `docs/deploy-linux-docker.md`.

### Enrich: queue guards (enterprise)

Per-CVE NVD fanout is off by default (`NVD_FANOUT_ENRICH=false`). For `baseline`/`translate`, card text matures **inline** in ingest (hot24 + backlog) under `TEXT_ENGINE_BG_ENRICH` — no Rabbit required. Translate backlog uses fast `baseline_ru` (cards mature without MyMemory).

- **`BACKLOG_AI_SWEEP`**: on unless `=false` (remove old `BACKLOG_AI_SWEEP=false` from prod env);
- **`AI_ENRICH_VIA_QUEUE=true`**: legacy Rabbit path (default only for `TEXT_ENGINE=llm`);
- **`AI_ENRICH_MAX_DEPTH`**: soft cap when using the queue.

`HOT24_AI_SWEEP` only gates **`TEXT_ENGINE=llm`**. To stop all BG text enrich: `TEXT_ENGINE_BG_ENRICH=false`.

---

## Аппаратные ориентиры

### Ноутбук / один разработчик

- CPU: 4–8 ядер  
- RAM: 8–16 ГБ (с Docker + Next + несколькими Nest — комфортнее 16 ГБ)  
- Диск: 10–30 ГБ свободно (объём БД, `node_modules`, кэши)  

### Небольшая команда / непрерывный ingest

- CPU: 8–16 ядер  
- RAM: 16–32 ГБ  
- Диск: 50–200+ ГБ в зависимости от ретеншена  

### ИИ (Ollama на LAN / GPU)

- Разумно ограничивать параллелизм: `LLM_MAX_PARALLEL`, `AI_ENRICH_PREFETCH`.

---

## Распространённые проблемы

### `Dev already running … .dev.lock`

См. раздел про **`.dev.lock`** выше.

### RabbitMQ `PRECONDITION_FAILED` (например, на `ai.enrich`)

Параметры очереди изменились между версиями. Удалите проблемную очередь в UI RabbitMQ (или через CLI) и перезапустите приложения — очереди пересоздадутся.

### ФСТЭК / Telegram

Если сеть режет `t.me`, переключите источник на RSS (`FSTEC_FEED_SOURCE`, `FSTEC_TG_RSS_URL`).

### EPSS / KEV / NVD не обновляются

Проверьте `GET /api/stats/summary`, сетевой доступ с хоста ingest и логи `apps/ingest`.

---

## Безопасность

- **Не коммитьте** файл `.env` (он в `.gitignore`). В репозитории только **`.env.example`** без секретов.  
- Любой утёкший ключ — **немедленно отозвать** и ротировать.  
- В production: надёжный `JWT_SECRET`, отключение лишних dev‑флагов (`AUTH_ALLOW_REGISTER` и т.д.).  
- Сервисный **`INTERNAL_API_BEARER`**: в `NODE_ENV=production` не принимается, пока явно не задано **`ALLOW_INTERNAL_API_BEARER=true`** (иначе только JWT).  
- CORS API в production: **`API_CORS_ORIGIN`** — список origin через запятую; без переменной CORS для браузера отключён (удобно при доступе к API только с того же хоста через reverse proxy).  

### SAST / DAST (сканеры в репозитории)

- Инвентаризация поверхности: `docs/SECURITY_SURFACE.md`.  
- SAST: `pnpm security:sast` (pnpm audit по воркспейсу + Semgrep; отчёт `semgrep-out.json`, см. `docs/SECURITY_SAST_FINDINGS.md`). Строгий режим Semgrep: `SEMGREP_STRICT=1 pnpm security:sast`.  
- Локальный DAST smoke + опционально ZAP baseline: `pnpm security:dast`; ZAP: `RUN_ZAP=1 pnpm security:dast` (нужен Docker).

### CI и тесты

```bash
pnpm typecheck        # все пакеты
pnpm test             # unit + coverage gate (≥40% critical shared)
pnpm test:integration # testcontainers + chaos restart (Docker)
pnpm audit:high       # 0 high/critical vulnerabilities
pnpm lint             # eslint + next lint (0 warnings)
pnpm test:e2e         # Playwright (web+api подняты)
```

GitHub Actions (`.github/workflows/ci.yml`):

- **quality** — typecheck, test, audit:high, lint, SAST, E2E (optional)
- **integration** — testcontainers + chaos
- **dast** — curl smoke (optional)

### Staging (pre-production)

Изолированный Docker-стек на порту **3080** (отдельные volumes от production):

```bash
pnpm deploy:staging:init
./deploy.sh --staging --yes --admin-password='YourLongPassword123'
```

После деплоя: post-deploy smoke + chaos restart (`api` → `ingest` → `ai` → `web`).  
Отключить chaos: `SKIP_CHAOS_SMOKE=1 ./deploy.sh --staging …`

### Production deploy

---

## Лицензия и вклад

Уточните в корне репозитория наличие файла `LICENSE` и внутренние правила команды (code review, ветки, CI). Для предложений по изменениям используйте pull request в основную ветку (`main`).
