/**
 * Next.js BFF проксирует на Nest API. В `pnpm dev` родительский `scripts/dev.mjs` выставляет
 * UPSTREAM_API_BASE на фактический порт API — его нужно использовать, иначе POST /enrich уйдёт не туда.
 */
export function getUpstreamApiBase(): string {
  const explicit = process.env.UPSTREAM_API_BASE?.trim();
  if (explicit) return explicit.replace(/\/+$/, "");
  const pub = process.env.NEXT_PUBLIC_API_BASE?.trim();
  if (pub) return pub.replace(/\/+$/, "");
  /** Локальный API по умолчанию; при смене порта задайте UPSTREAM_API_BASE (делает `pnpm dev`). */
  if (process.env.NODE_ENV === "development") {
    return "http://127.0.0.1:4001/api";
  }
  throw new Error(
    "Задайте UPSTREAM_API_BASE или NEXT_PUBLIC_API_BASE (например http://127.0.0.1:4001/api)"
  );
}
