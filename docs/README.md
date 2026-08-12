# Документация Vuln Intel Platform

Полный набор руководств для эксплуатации и ежедневной работы с платформой.

| Документ | Аудитория | Содержание |
|----------|-----------|------------|
| [USER_GUIDE.md](./USER_GUIDE.md) | Аналитик, инженер ИБ, оператор | Вход, Overview, CVE, задачи (Jira-like), Threat buckets, VOC, Settings (TLS/Updates), типовые сценарии |
| [ADMIN_GUIDE.md](./ADMIN_GUIDE.md) | DevOps, администратор, владелец продукта | Деплой, tls-proxy/LE, EPSS, TEXT_ENGINE BG, обновления UI, очереди, runbook |
| [deploy-linux-docker.md](./deploy-linux-docker.md) | Администратор | One-command `./deploy.sh` на Linux-сервер («тачка») |
| [MATURITY.md](./MATURITY.md) | Руководство / аудит | Текущий уровень зрелости, метрики, пробелы, roadmap |
| [ROADMAP_5.md](./ROADMAP_5.md) | Команда | План доведения до 5/5 по всем осям |
| [SECURITY_SURFACE.md](./SECURITY_SURFACE.md) | Security / админ | Поверхность атаки, эндпоинты, SSRF |
| [SECURITY_SAST_FINDINGS.md](./SECURITY_SAST_FINDINGS.md) | Security | Semgrep / audit findings |
| [SECURITY_DAST.md](./SECURITY_DAST.md) | Security | Локальный DAST smoke |

Корневой [README.md](../README.md) — обзор архитектуры и быстрый старт для разработчиков.
