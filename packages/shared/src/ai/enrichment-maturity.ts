import type { TextEngineMode } from "../llm/vuln-context-engine.js";
import { isLlmEnrichFailureRow, isLlmNotConfiguredEnrichment } from "./enrichment-placeholder.js";

export type EnrichmentMaturityRow = {
  output_text?: string | null;
  output_json?: unknown;
  model?: string | null;
  prompt_version?: string | null;
};

/**
 * Whether a persisted enrichment row is “mature” for the active text engine.
 * In translate mode, plain baseline rows are not enough — cards should be rebuilt.
 */
export function isMatureEnrichmentForTextEngine(
  row: EnrichmentMaturityRow | null | undefined,
  textEngine: TextEngineMode
): boolean {
  if (!row) return false;
  if (isLlmNotConfiguredEnrichment(row) || isLlmEnrichFailureRow(row)) return false;
  if (row.output_text == null && row.output_json == null) return false;

  if (textEngine === "translate") {
    const src =
      row.output_json && typeof row.output_json === "object" && !Array.isArray(row.output_json)
        ? String((row.output_json as Record<string, unknown>)._display_source ?? "")
        : "";
    return (
      src === "translated" ||
      src === "baseline_ru" ||
      row.model === "translate" ||
      row.prompt_version === "translate-v1"
    );
  }

  return true;
}
