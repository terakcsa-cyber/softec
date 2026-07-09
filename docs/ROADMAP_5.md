# Roadmap: зрелость 5/5

Целевое состояние — **5/5 по всем осям** из [MATURITY.md](./MATURITY.md).

## Фаза A — фундамент ✅

- [x] Prometheus + metrics sidecars
- [x] Unit-тесты (21) + coverage gate ≥40% (факт ~66% critical)
- [x] Playwright E2E + lint zero warnings
- [x] `pnpm audit:high` — 0 high/critical (overrides + bumps)

## Фаза B — security ✅

- [x] RBAC roles + WriteRoleGuard + ThrottlerGuard
- [x] Security E2E (viewer 403, digest prepare)
- [x] DAST job в CI

## Фаза C — ops hardening ✅

- [x] Migrations, backup, smoke scripts
- [x] Grafana + alerts + System Health UI
- [x] Reconciliation service
- [x] `deploy.sh` post-deploy smoke
- [x] **Staging**: `.env.staging`, `docker-compose.staging.yml`, `./deploy.sh --staging`

## Фаза D — тестирование ✅

- [x] Testcontainers (postgres + rabbitmq + migrations)
- [x] **Chaos**: restart resilience tests + `scripts/chaos-restart-smoke.mjs` на staging
- [x] CI: quality + integration + audit gate + DAST/E2E optional

## Критерии «5/5» по осям

| Ось | Статус |
|-----|--------|
| Функциональность | **5/5** |
| Надёжность | **5/5** |
| Безопасность | **5/5** |
| Тестирование | **5/5** |
| Наблюдаемость | **5/5** |
| Документация | **5/5** |
| Деплой/ops | **5/5** |
| Качество кода | **5/5** |

**Итог: 5/5** — enterprise-ready baseline.

## Команды

```bash
pnpm test                    # unit + coverage gate
pnpm test:integration        # testcontainers + chaos
pnpm audit:high              # CI gate
pnpm test:e2e                # Playwright
./deploy.sh --staging --yes --admin-password='...'   # staging + chaos smoke
./deploy.sh --update         # production + post-deploy smoke
pnpm smoke:integration       # running stack
```

## Staging

```bash
pnpm deploy:staging:init     # .env.staging
./deploy.sh --staging --yes --admin-password='YourLongPassword123'
# Web: http://127.0.0.1:3080
# SKIP_CHAOS_SMOKE=1 — отключить restart smoke
```

## Env

```env
DEPLOY_ENV=staging
RECONCILE_ENABLED=true
METRICS_POLL_QUEUES=true
ADMIN_EMAILS=admin@example.com
SKIP_INTEGRATION=1           # локально без Docker
SKIP_CHAOS_SMOKE=1           # staging deploy без chaos
```
