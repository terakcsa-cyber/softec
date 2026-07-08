import { augmentEnrichmentWithNvdFixes } from "../cve/nvd-fix-signals.js";
import { buildBaselineEnrichmentFromNvd } from "../cve/baseline-enrichment.js";
import {
  buildBaselineEnrichmentFromBdu,
  type BduBaselineInput
} from "../bdu/baseline-enrichment.js";

type JsonObj = Record<string, unknown>;

function asObj(v: unknown): JsonObj | null {
  if (v != null && typeof v === "object" && !Array.isArray(v)) return v as JsonObj;
  return null;
}

function stripCodeFences(raw: string): string {
  let t = raw.trim();
  if (t.startsWith("```")) {
    t = t.replace(/^```(?:json)?\s*/i, "").replace(/\s*```\s*$/m, "");
  }
  return t.trim();
}

function tryParseJsonObject(raw: string): JsonObj | null {
  const stripped = stripCodeFences(raw);
  try {
    const v = JSON.parse(stripped) as unknown;
    return asObj(v);
  } catch {
    const first = stripped.indexOf("{");
    const last = stripped.lastIndexOf("}");
    if (first >= 0 && last > first) {
      try {
        const v = JSON.parse(stripped.slice(first, last + 1)) as unknown;
        return asObj(v);
      } catch {
        return null;
      }
    }
    return null;
  }
}

/** summary/title испорчены сырым JSON или обрезком ответа модели. */
export function isGarbageEnrichSummary(value: unknown): boolean {
  if (typeof value !== "string") return true;
  const t = value.trim();
  if (!t) return true;
  if (t.startsWith("{") || t.startsWith("[")) return true;
  if (t.length > 1800) return true;
  if (t.includes('"attackFlow"') && t.includes('"description"')) return true;
  return false;
}

function str(v: unknown): string | null {
  return typeof v === "string" && v.trim() ? v.trim() : null;
}

function strArr(v: unknown): string[] {
  return Array.isArray(v) ? v.map((x) => String(x)).filter(Boolean) : [];
}

function pickDisplayFields(src: JsonObj): JsonObj {
  return {
    title: str(src.title) ?? undefined,
    summary: str(src.summary) ?? undefined,
    description: str(src.description) ?? undefined,
    vulnerabilityClass: str(src.vulnerabilityClass),
    attackFlow: strArr(src.attackFlow),
    exploitation: asObj(src.exploitation) ?? undefined,
    consequences: strArr(src.consequences),
    remediation: strArr(src.remediation),
    applicability: asObj(src.applicability) ?? undefined,
    nextSteps: strArr(src.nextSteps),
    questions: strArr(src.questions),
    sources: Array.isArray(src.sources) ? src.sources : [],
    graph: asObj(src.graph) ?? undefined,
    uncertainties: strArr(src.uncertainties),
    exploitNarrative: str(src.exploitNarrative)
  };
}

function isUsableAiTitle(t: string | null): boolean {
  return !isGenericEnrichmentTitle(t);
}

/** Шаблонные заголовки локальной LLM — не показывать в UI/ТГ. */
export function isGenericEnrichmentTitle(title: string | null | undefined): boolean {
  if (!title?.trim()) return true;
  const t = title.trim();
  if (t === "Комплексный анализ уязвимости" || t === "Анализ уязвимости") return true;
  if (t.startsWith("ИИ не настроен") || t.startsWith("LLM not configured")) return true;
  if (/^Комплексный анализ\s+(CVE-|BDU:)/i.test(t)) return true;
  if (/^Модель вернула не-JSON/i.test(t)) return true;
  return false;
}

/** Убирает служебные префиксы из summary/description enrichment. */
export function stripEnrichmentBoilerplate(text: string): string {
  let t = text.trim();
  const patterns = [
    /^Описание\s*\(как в источнике\)\s*:\s*/i,
    /^Кратко:\s*(CVE-\d{4}-\d+|BDU:[\w-]+)\s*[—–-]\s*/i,
    /^Комплексный анализ\s+(CVE-\d{4}-\d+|BDU:[\w-]+)\s*[—–-]\s*/i
  ];
  for (const p of patterns) {
    t = t.replace(p, "");
  }
  return t.replace(/\s+/g, " ").trim();
}

/**
 * Чинит строки enrichment_ai после «частичного» ответа локальной LLM:
 * хорошие поля остаются в raw_model_json, а summary превращается в JSON-мусор.
 */
export function resolveEnrichmentDisplayJson(stored: unknown, nvdRaw?: unknown): JsonObj | null {
  const o = asObj(stored);
  if (!o) {
    if (typeof stored === "string") return resolveEnrichmentDisplayJson(tryParseJsonObject(stored), nvdRaw);
    return null;
  }

  const title = str(o.title);
  const summary = str(o.summary);
  const summaryOk = summary && !isGarbageEnrichSummary(summary);

  let resolved: JsonObj = o;
  if (!(summaryOk && title && title !== "Комплексный анализ уязвимости")) {
    const nested = asObj(o.raw_model_json);
    if (nested) {
      const nestedSummary = str(nested.summary);
      if (nestedSummary && !isGarbageEnrichSummary(nestedSummary)) {
        resolved = { ...o, ...pickDisplayFields(nested) };
      }
    }

    if (summary && isGarbageEnrichSummary(summary)) {
      const inner = tryParseJsonObject(summary);
      if (inner) {
        const innerSummary = str(inner.summary);
        if (innerSummary && !isGarbageEnrichSummary(innerSummary)) {
          resolved = { ...o, ...pickDisplayFields(inner) };
        }
      }
    }
  }

  const nvdSource = nvdRaw ?? resolved.raw_model_json ?? o.raw_model_json;
  return augmentEnrichmentWithNvdFixes(resolved, nvdSource);
}

/** Единая сводка для карточки CVE: чинит ИИ-строку или строит baseline из NVD. */
export function resolveCveCardEnrichment(
  stored: unknown,
  cveId: string,
  nvdRaw: unknown
): JsonObj {
  const baseline = buildBaselineEnrichmentFromNvd(cveId, nvdRaw);
  const fromAi = stored != null ? resolveEnrichmentDisplayJson(stored, nvdRaw) : null;
  if (!fromAi) return baseline;

  return mergeResolvedWithBaseline(baseline, fromAi, `Уязвимость ${cveId}`);
}

function mergeResolvedWithBaseline(
  baseline: JsonObj,
  fromAi: JsonObj,
  idLabel: string
): JsonObj {
  const pick = (_key: string, aiVal: unknown, baseVal: unknown) => {
    if (Array.isArray(aiVal) && aiVal.length > 0) return aiVal;
    if (typeof aiVal === "string" && aiVal.trim()) return aiVal;
    if (aiVal != null && typeof aiVal === "object") return aiVal;
    return baseVal;
  };

  const aiSummary = str(fromAi.summary);
  const aiTitle = str(fromAi.title);
  const summary =
    aiSummary && !isGarbageEnrichSummary(aiSummary) && !aiSummary.startsWith("LLM not configured")
      ? aiSummary
      : str(baseline.summary) ?? "";

  const title =
    aiTitle && isUsableAiTitle(aiTitle) ? aiTitle : str(baseline.title) ?? idLabel;

  const cleanSummary = stripEnrichmentBoilerplate(summary) || summary;
  const rawDescription = pick("description", fromAi.description, baseline.description) as string;
  const cleanDescription =
    typeof rawDescription === "string"
      ? stripEnrichmentBoilerplate(rawDescription) || rawDescription
      : rawDescription;

  const aiClass = str(fromAi.vulnerabilityClass);
  const baseClass = str(baseline.vulnerabilityClass);
  const vulnerabilityClass =
    baseClass && (!aiClass || /^CWE-\d+$/i.test(aiClass)) ? baseClass : aiClass || baseClass || null;

  return {
    ...baseline,
    ...fromAi,
    title,
    summary: cleanSummary,
    description: cleanDescription,
    vulnerabilityClass,
    attackFlow: pick("attackFlow", fromAi.attackFlow, baseline.attackFlow),
    remediation: pick("remediation", fromAi.remediation, baseline.remediation),
    nextSteps: pick("nextSteps", fromAi.nextSteps, baseline.nextSteps),
    consequences:
      Array.isArray(fromAi.consequences) && fromAi.consequences.length > 0
        ? fromAi.consequences
        : baseline.consequences,
    exploitation: pick("exploitation", fromAi.exploitation, baseline.exploitation),
    _display_source: fromAi._display_source ?? "ai_resolved"
  };
}

/** Единая сводка для карточки БДУ: чинит ИИ или строит baseline из БДУ + связанного CVE. */
export function resolveBduCardEnrichment(
  stored: unknown,
  bduId: string,
  bdu: BduBaselineInput,
  linkedCveRaw?: unknown
): JsonObj {
  const baseline = buildBaselineEnrichmentFromBdu(bduId, bdu, linkedCveRaw);
  const fromAi = stored != null ? resolveEnrichmentDisplayJson(stored, linkedCveRaw) : null;
  if (!fromAi) return baseline;
  return mergeResolvedWithBaseline(baseline, fromAi, `БДУ ${bduId}`);
}
