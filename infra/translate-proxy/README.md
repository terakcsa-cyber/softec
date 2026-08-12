# Translate proxy (LibreTranslate-compatible)

Локальный shim с API как у LibreTranslate (`POST /translate`, `GET /languages`), пока официальные Argos-модели с `argos-net.com` недоступны/тормозят.

Сейчас backend: **MyMemory** (бесплатно, без ключа для лёгкой нагрузки).

Когда Argos CDN снова нормальный — можно вернуть образ `libretranslate/libretranslate` в `docker-compose.yml`.
