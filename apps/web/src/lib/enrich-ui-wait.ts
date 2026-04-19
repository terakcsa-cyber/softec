/**
 * Сколько ждём ИИ-сводку после POST /enrich (poll + «нет ответа»).
 * На сервере Ollama по умолчанию LLM_TIMEOUT_MS=300000 — UI не должен сдаваться раньше.
 */
export const ENRICH_UI_WAIT_MS = 360_000;

/** GET /cves/:id пока крутится enrich после POST — реже, чтобы не засорять логи Next (раньше 2s). */
export const CVE_POLL_WHILE_ENRICH_MS = 6_000;

/** Режим «только фон» (manual enrich выключен на сервере): редкая проверка появления сводки. */
export const CVE_POLL_BACKGROUND_ONLY_MS = 15_000;
