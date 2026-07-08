import { augmentEnrichmentWithNvdFixes } from "../cve/nvd-fix-signals.js";
import {
  defaultAttackFlowSteps,
  extractNvdVulnerabilityClass
} from "../cve/baseline-enrichment.js";

type JsonObj = Record<string, unknown>;

export type BduBaselineInput = {
  name: string;
  description?: string | null;
  solution?: string | null;
  software_names?: string | null;
  severity?: string | null;
  exploit_status?: string | null;
  has_exploit?: boolean;
};

function str(v: unknown): string {
  return typeof v === "string" ? v.trim() : "";
}

function shortRuSummary(text: string, max = 420): string {
  const t = text.replace(/\s+/g, " ").trim();
  if (!t) return "";
  if (t.length <= max) return t;
  const cut = t.slice(0, max);
  const last = Math.max(cut.lastIndexOf(". "), cut.lastIndexOf(" "));
  return `${(last > 80 ? cut.slice(0, last) : cut).trim()}…`;
}

/** Минимальная карточка БДУ без LLM — с подмешиванием CWE/патчей из связанного CVE. */
export function buildBaselineEnrichmentFromBdu(
  bduId: string,
  bdu: BduBaselineInput,
  linkedCveRaw?: unknown
): JsonObj {
  const desc = str(bdu.description) || str(bdu.name);
  const summary = shortRuSummary(desc) || `Запись БДУ ${bduId} в реестре ФСТЭК.`;
  const fromCve = linkedCveRaw ? extractNvdVulnerabilityClass(linkedCveRaw) : null;
  const vulnClass = str(bdu.severity) || fromCve || null;
  const solutionText = str(bdu.solution);
  const solutionLines = solutionText ? solutionText.split(/\n+/).map((s) => s.trim()).filter(Boolean) : [];

  const base: JsonObj = {
    title: str(bdu.name) || `БДУ ${bduId}`,
    summary,
    description: desc.length > 2800 ? `${desc.slice(0, 2800)}…` : desc,
    vulnerabilityClass: vulnClass,
    attackFlow: defaultAttackFlowSteps(linkedCveRaw),
    exploitation: {
      publicExploit: bdu.has_exploit ? "yes" : "no",
      exploitNotes: str(bdu.exploit_status) || null
    },
    consequences: vulnClass ? [`Класс/уровень по БДУ: ${vulnClass}`] : [],
    remediation: solutionLines,
    applicability: {
      status: "unknown",
      notes: str(bdu.software_names)
        ? `Затронутое ПО (БДУ): ${str(bdu.software_names).slice(0, 500)}`
        : "Сверить версии ПО с карточкой БДУ ФСТЭК."
    },
    nextSteps: solutionLines.length
      ? ["Сверить установленные версии с перечнем ПО в БДУ", "Применить рекомендуемое решение из БДУ"]
      : ["Открыть карточку БДУ на bdu.fstec.ru и уточнить меры"],
    questions: [],
    sources: [],
    graph: { nodes: [], edges: [] },
    uncertainties: [],
    _display_source: "bdu_baseline"
  };

  return linkedCveRaw ? augmentEnrichmentWithNvdFixes(base, linkedCveRaw) : base;
}
