# SAST: Semgrep + pnpm audit

## Запуск

```bash
pnpm security:sast
```

Генерируется `semgrep-out.json` (в корне, не коммитить). Пакеты: `p/typescript`, `p/nodejs`, `p/react`, `p/jwt`, `p/ssrf`, `p/sql-injection`, `p/secrets`.

## Triage (приоритет)

| Класс                         | Действие |
|------------------------------|----------|
| SQL / string concat к БД     | Исправить: только параметризованные запросы + `escapePgLikePattern` для LIKE |
| SSRF (`fetch` по URL из env) | Allowlist хостов, блок частных IP, таймауты |
| JWT / auth bypass            | Guards, internal bearer только с флагом в prod |
| Секреты в коде               | Удалить, ротировать, вынести в env |
| Зависимости (audit high)     | Обновить или задокументировать risk acceptance |

После правок повторить `pnpm security:sast` и зафиксировать дату прогона здесь.

**Последний прогон (CI/локально):** _заполнить вручную после `pnpm security:sast`._
