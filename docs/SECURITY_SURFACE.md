# Поверхность атаки (инвентаризация)

Обновлено: автоматически в рамках security hardening.

## Nest API (`apps/api`, префикс `/api`)

Глобально: `JwtAuthGuard` + исключения `@Public()` (см. `apps/api/src/auth/`).

| Контроллер | Базовый путь | Методы (кратко) |
|------------|--------------|-----------------|
| `HealthController` | `/health` | GET (public) |
| `CveController` | `/cves` | GET list, GET `:id`, POST `lookup`, POST `bdu-links`, POST `:id/enrich` |
| `StatsController` | `/stats` | GET summary/vendors/queue/readiness/reconciliation, GET/POST dlq/*, POST ops/{epss,bdu,nvd,hot24}/* (admin) |
| `VendorAdvisoryController` | `/vendor-advisories` | GET list, GET `:id`, GET vendors |
| `VulnTaskController` | `/vuln-tasks` | CRUD + CVE links + by-cve |
| `IntegrationSettingsController` | `/settings/integrations` | GET, PUT |
| `WebTlsController` | `/settings/tls` | GET status; POST generate / acme / acme/renew (admin) |
| `PlatformUpdateController` | `/settings/updates` | GET status, POST check/apply (admin; apply opt-in) |
| `AuthController` | `/auth` | login, refresh, register (условно), 2fa, me, users CRUD (admin) |

## Next.js BFF (`apps/web/src/app/api/**`)

Прокси на upstream (`getUpstreamApiBase()` + `forwardAuthHeaders` или server-only internal bearer для fstec sync).

Список маршрутов: см. `apps/web/src/app/api/**/route.ts` (auth, cves, stats/ops/*, stats/readiness, vendor-advisories, vuln-tasks, voc, fstec/feed, patch/feed, health, settings/integrations, settings/tls[+letsencrypt], settings/updates).

## Внешние HTTP (SSRF‑риск)

| Источник | URL | Примечание |
|----------|-----|------------|
| `apps/web/src/app/api/fstec/feed/route.ts` | `https://t.me/s/...`, опционально RSS из `FSTEC_TG_RSS_URL` | Валидация `http(s)` + allowlist хостов |
| `apps/web/src/app/api/patch/feed/route.ts` | `https://t.me/s/...` | Фиксированный шаблон |
| `apps/ingest/src/jobs/nvd-ingest.job.ts` | NVD API | |
| `apps/ingest/src/jobs/epss-ingest.job.ts` | EPSS | |
| `apps/ingest/src/jobs/vendor-advisory-ingest.job.ts` | `feedUrl` из конфига | Доверенный список источников |
| `apps/ingest/src/jobs/kev-ingest.job.ts` | CISA KEV | |
| `apps/api/src/routes/stats.controller.ts` | health checks к внешним URL? | Проверить |

## Динамический SQL

Основные места: `apps/api/src/routes/cve.controller.ts`, `vendor-advisory.controller.ts`, `vuln-task.service.ts` (список задач — `escapePgLikePattern` + `LIKE … ESCAPE` в `apps/api/src/pg-like.util.ts`).

## Секреты / сервисный доступ

- `INTERNAL_API_BEARER`: только при явном разрешении в production (`ALLOW_INTERNAL_API_BEARER=true`), иначе только non-production.
- `JWT_SECRET`: обязателен, длина ≥ 32.
