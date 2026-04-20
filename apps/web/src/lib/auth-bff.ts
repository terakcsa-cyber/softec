/**
 * Клиентские запросы к auth идут на Next BFF (`/api/auth/...`), а не напрямую на Nest —
 * так нет CORS и не нужен совпадающий NEXT_PUBLIC_API_BASE с портом API.
 */
export const AUTH_BFF_PREFIX = "/api/auth";
