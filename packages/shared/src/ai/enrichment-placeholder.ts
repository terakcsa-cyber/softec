/**
 * When the LLM is unavailable (no API key / local URL), the ai worker still persists
 * a row so the pipeline stays consistent. That row must not block real enrichment
 * after configuration is fixed.
 */
export const LLM_NOT_CONFIGURED_OUTPUT_TEXT = "LLM not configured.";

export const LLM_NOT_CONFIGURED_SUMMARY_PREFIX = "LLM not configured";

export function isLlmNotConfiguredEnrichment(row: {
  output_text?: string | null;
  output_json?: unknown;
}): boolean {
  if (row.output_text === LLM_NOT_CONFIGURED_OUTPUT_TEXT) return true;
  const oj = row.output_json;
  if (!oj || typeof oj !== "object" || Array.isArray(oj)) return false;
  const summary = (oj as Record<string, unknown>).summary;
  return typeof summary === "string" && summary.startsWith(LLM_NOT_CONFIGURED_SUMMARY_PREFIX);
}

/** Persisted when the LLM call failed (403, network, etc.) — shown in UI and not treated as “cached success”. */
export const ENRICH_FAILURE_MARKER = "_enrich_error";

export function isLlmEnrichFailureRow(row: { output_json?: unknown }): boolean {
  const oj = row.output_json;
  if (!oj || typeof oj !== "object" || Array.isArray(oj)) return false;
  return (oj as Record<string, unknown>)[ENRICH_FAILURE_MARKER] === true;
}

export function enrichFailureOutputJson(summary: string, explanation: string): Record<string, unknown> {
  return {
    [ENRICH_FAILURE_MARKER]: true,
    summary,
    explanation,
    attackFlow: [],
    exploitNarrative: null,
    consequences: [],
    graph: { nodes: [], edges: [] }
  };
}
