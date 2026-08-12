/**
 * Клиентская логика enrich для БДУ (без импорта @vuln-intel/shared с node:crypto).
 */

import {
  buildBaselineEnrichmentFromBdu,
  type BduBaselineInput
} from "./bdu-baseline-enrichment";
import { isUsableAttackGraph } from "./baseline-enrichment";

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

function isGarbageEnrichSummary(value: unknown): boolean {
  if (typeof value !== "string") return true;
  const t = value.trim();
  if (!t || t.startsWith("{") || t.startsWith("[")) return true;
  if (t.length > 1800) return true;
  if (t.includes('"attackFlow"') && t.includes('"description"')) return true;
  return false;
}

export type BduDetailsLike = {
  found?: boolean;
  ai?: unknown;
  bdu?: unknown;
  textEngine?: "baseline" | "translate" | "llm" | string;
  /** Optional linked NVD raw for richer baseline (CWE/CVSS). */
  linkedCveRaw?: unknown;
};

function asObj(v: unknown): Record<string, unknown> | null {
  return v != null && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}

function bduInputFromDetails(bdu: unknown, bduId: string): BduBaselineInput {
  const o = asObj(bdu) ?? {};
  return {
    name: typeof o.name === "string" ? o.name : `БДУ ${bduId}`,
    description: (o.description as string | null | undefined) ?? null,
    solution: (o.solution as string | null | undefined) ?? null,
    software_names:
      (o.software_names as string | null | undefined) ??
      (o.softwareNames as string | null | undefined) ??
      null,
    severity: (o.severity as string | null | undefined) ?? null,
    exploit_status:
      (o.exploit_status as string | null | undefined) ??
      (o.exploitStatus as string | null | undefined) ??
      null,
    has_exploit: Boolean(o.has_exploit ?? o.hasExploit)
  };
}

function mergeWithBaseline(
  baseline: Record<string, unknown>,
  fromAi: Record<string, unknown>,
  idLabel: string
): Record<string, unknown> {
  const pick = (aiVal: unknown, baseVal: unknown) => {
    if (Array.isArray(aiVal) && aiVal.length > 0) return aiVal;
    if (typeof aiVal === "string" && aiVal.trim()) return aiVal;
    if (aiVal != null && typeof aiVal === "object" && !Array.isArray(aiVal)) return aiVal;
    return baseVal;
  };

  const aiSummary = typeof fromAi.summary === "string" ? fromAi.summary.trim() : "";
  const aiTitle = typeof fromAi.title === "string" ? fromAi.title.trim() : "";
  const summary =
    aiSummary && !isGarbageEnrichSummary(aiSummary) && !aiSummary.startsWith("LLM not configured")
      ? aiSummary
      : String(baseline.summary ?? "");
  const title =
    aiTitle &&
    aiTitle !== "Комплексный анализ уязвимости" &&
    !aiTitle.startsWith("ИИ не настроен") &&
    !aiTitle.startsWith("LLM not configured")
      ? aiTitle
      : String(baseline.title ?? idLabel);

  const aiClass = typeof fromAi.vulnerabilityClass === "string" ? fromAi.vulnerabilityClass.trim() : "";
  const baseClass =
    typeof baseline.vulnerabilityClass === "string" ? baseline.vulnerabilityClass.trim() : "";
  const vulnerabilityClass =
    baseClass && (!aiClass || /^CWE-\d+$/i.test(aiClass)) ? baseClass : aiClass || baseClass || null;

  return {
    ...baseline,
    ...fromAi,
    title,
    summary,
    description: pick(fromAi.description, baseline.description),
    vulnerabilityClass,
    attackFlow: pick(fromAi.attackFlow, baseline.attackFlow),
    remediation: pick(fromAi.remediation, baseline.remediation),
    nextSteps: pick(fromAi.nextSteps, baseline.nextSteps),
    questions: pick(fromAi.questions, baseline.questions),
    consequences:
      Array.isArray(fromAi.consequences) && fromAi.consequences.length > 0
        ? fromAi.consequences
        : baseline.consequences,
    exploitation: pick(fromAi.exploitation, baseline.exploitation),
    applicability: pick(fromAi.applicability, baseline.applicability),
    graph: isUsableAttackGraph(fromAi.graph) ? fromAi.graph : baseline.graph,
    _display_source: fromAi._display_source ?? "ai_resolved"
  };
}

export function parseAiOutputJson(
  o: unknown,
  ctx?: { bduId?: string; bdu?: unknown; linkedCveRaw?: unknown }
): Record<string, unknown> | null {
  if (ctx?.bduId) {
    const baseline = buildBaselineEnrichmentFromBdu(
      ctx.bduId,
      bduInputFromDetails(ctx.bdu, ctx.bduId),
      ctx.linkedCveRaw
    );
    let fromAi: Record<string, unknown> | null = null;
    if (o != null && typeof o === "object" && !Array.isArray(o)) fromAi = o as Record<string, unknown>;
    else if (typeof o === "string") {
      try {
        const p = JSON.parse(o) as unknown;
        if (p != null && typeof p === "object" && !Array.isArray(p)) fromAi = p as Record<string, unknown>;
      } catch {
        /* ignore */
      }
    }
    if (!fromAi) return baseline;
    return mergeWithBaseline(baseline, fromAi, `БДУ ${ctx.bduId}`);
  }

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

export function needsOnDemandBduEnrich(d: BduDetailsLike | null | undefined): boolean {
  if (!d?.found) return false;
  const ai = d.ai as {
    output_text?: string | null;
    output_json?: unknown;
    model?: string | null;
    prompt_version?: string | null;
  } | null | undefined;
  if (!ai) return true;
  const oj = parseAiOutputJson(ai.output_json ?? null);
  const row = oj != null ? { ...ai, output_json: oj } : ai;
  return isLlmNotConfiguredEnrichment(row) || isLlmEnrichFailureRow(row);
}

/**
 * Enrich on BDU card open is intentionally disabled.
 * Cards mature via background TEXT_ENGINE fanout/sweeps only; open shows client-side baseline RU.
 */
export function shouldAutoEnrichBduOnOpen(_d: BduDetailsLike | null | undefined): boolean {
  return false;
}
