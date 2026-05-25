/**
 * Клиентская логика enrich для БДУ (без импорта @vuln-intel/shared с node:crypto).
 */

const LLM_NOT_CONFIGURED_OUTPUT_TEXT = "LLM not configured.";
const LLM_NOT_CONFIGURED_SUMMARY_PREFIX = "LLM not configured";
const ENRICH_FAILURE_MARKER = "_enrich_error";

function isLlmNotConfiguredEnrichment(row: {
  output_text?: string | null;
  output_json?: unknown;
}): boolean {
  if (row.output_text === LLM_NOT_CONFIGURED_OUTPUT_TEXT) return true;
  const oj = row.output_json;
  if (!oj || typeof oj !== "object" || Array.isArray(oj)) return false;
  const summary = (oj as Record<string, unknown>).summary;
  return typeof summary === "string" && summary.startsWith(LLM_NOT_CONFIGURED_SUMMARY_PREFIX);
}

function isLlmEnrichFailureRow(row: { output_json?: unknown }): boolean {
  const oj = row.output_json;
  if (!oj || typeof oj !== "object" || Array.isArray(oj)) return false;
  return (oj as Record<string, unknown>)[ENRICH_FAILURE_MARKER] === true;
}

export type BduDetailsLike = {
  found?: boolean;
  ai?: unknown;
  bdu?: unknown;
};

export function parseAiOutputJson(o: unknown): Record<string, unknown> | null {
  if (o != null && typeof o === "object" && !Array.isArray(o)) return o as Record<string, unknown>;
  if (typeof o === "string") {
    try {
      const p = JSON.parse(o) as unknown;
      if (p != null && typeof p === "object" && !Array.isArray(p)) return p as Record<string, unknown>;
    } catch {
      /* ignore */
    }
  }
  return null;
}

function parseBduPublicationMs(publicationDate: string | null | undefined): number | null {
  if (!publicationDate) return null;
  const m = /^(\d{2})\.(\d{2})\.(\d{4})$/.exec(publicationDate.trim());
  if (!m) return null;
  const t = Date.UTC(Number(m[3]), Number(m[2]) - 1, Number(m[1]));
  return Number.isFinite(t) ? t : null;
}

export function isBduPublicationInLast24h(publicationDate: string | null | undefined): boolean {
  const t = parseBduPublicationMs(publicationDate);
  if (t == null) return false;
  return t >= Date.now() - 24 * 60 * 60 * 1000;
}

function readPublicationDate(bdu: unknown): string | null | undefined {
  if (bdu == null || typeof bdu !== "object" || Array.isArray(bdu)) return undefined;
  const row = bdu as Record<string, unknown>;
  const v = row.publicationDate ?? row.publication_date;
  return typeof v === "string" ? v : null;
}

export function needsOnDemandBduEnrich(d: BduDetailsLike | null | undefined): boolean {
  if (!d?.found) return false;
  const ai = d.ai as { output_text?: string | null; output_json?: unknown } | null | undefined;
  if (!ai) return true;
  const oj = parseAiOutputJson(ai.output_json ?? null);
  const row = oj != null ? { ...ai, output_json: oj } : ai;
  return isLlmNotConfiguredEnrichment(row) || isLlmEnrichFailureRow(row);
}

export function shouldAutoEnrichBduOnOpen(d: BduDetailsLike | null | undefined): boolean {
  if (!needsOnDemandBduEnrich(d)) return false;
  return isBduPublicationInLast24h(readPublicationDate(d?.bdu));
}
