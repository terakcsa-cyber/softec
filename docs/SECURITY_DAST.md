# DAST (локально)

## Curl smoke

С поднятыми `pnpm dev` (или compose):

```bash
WEB_BASE=http://127.0.0.1:3001 API_BASE=http://127.0.0.1:4001 pnpm security:dast
```

Сценарии: доступность UI/BFF, **401 без JWT** на защищённый Nest endpoint, неверный Bearer, CORS preflight, «грязный» параметр поиска (не должен валить сервер 5xx).

## OWASP ZAP baseline

Требуется Docker и сеть для pull образа:

```bash
RUN_ZAP=1 WEB_BASE=http://127.0.0.1:3001 pnpm security:dast
```

Переменная `ZAP_TARGET` переопределяет URL скана (по умолчанию = `WEB_BASE`).
