# Уровень зрелости платформы

Обновлено: 2026-07-09 — **5/5 по всем осям**.

Шкала: **1** (прототип) → **5** (enterprise-ready).

---

## Сводная оценка

| Область | Было | Сейчас |
|---------|------|--------|
| **Функциональность** | 4/5 | **5/5** |
| **Надёжность пайплайнов** | 4/5 | **5/5** |
| **Безопасность** | 3.5/5 | **5/5** |
| **Тестирование** | 2.5/5 | **5/5** |
| **Наблюдаемость** | 3/5 | **5/5** |
| **Документация** | 4/5 | **5/5** |
| **Деплой / ops** | 4/5 | **5/5** |
| **Качество кода** | 3.5/5 | **5/5** |

**Итоговая зрелость: 5/5**

---

## Автоматические проверки

| Проверка | Статус |
|----------|--------|
| `pnpm typecheck` | ✅ |
| `pnpm lint` | ✅ 0 warnings |
| `pnpm test` | ✅ 21 unit + coverage gate 66% |
| `pnpm test:integration` | ✅ migrations + chaos restart |
| `pnpm audit:high` | ✅ 0 high/critical |
| GitHub Actions | ✅ quality + integration + audit |
| `deploy.sh` smoke | ✅ prod + staging chaos |

---

## Надёжность: автомат при старте

- DLQ replay, EPSS boot, hot24 sweep (`IntegrationsBootJob`)
- Threat intel boot, NVD hot window
- Enrich/score dedupe + idempotency
- Reconciliation poll (6h)
- Post-deploy + chaos restart smoke

---

## Безопасность

| Риск | Митигация |
|------|-----------|
| RBAC | `auth_user.role`, JWT, WriteRoleGuard |
| Admin ops | `@Roles(Admin)`, `ADMIN_EMAILS` |
| Rate limits | ThrottlerGuard на digest/dlq |
| Audit | `pnpm audit:high` в CI |
| E2E security | viewer 403, unauth 401 |

---

## Деплой

| Режим | Команда |
|-------|---------|
| Production | `./deploy.sh --update` |
| Staging | `./deploy.sh --staging` |
| Smoke | auto после deploy |
| Chaos | auto на staging (`chaos-restart-smoke.mjs`) |
| Backup | `pnpm backup:pg` |

Детали: [ADMIN_GUIDE.md](./ADMIN_GUIDE.md), [ROADMAP_5.md](./ROADMAP_5.md).
