import { augmentEnrichmentWithNvdFixes } from "../cve/nvd-fix-signals.js";
import {
  buildBaselineAttackGraph,
  defaultAttackFlowSteps,
  extractNvdExploitationHint,
  extractNvdVulnerabilityClass,
  isCvssAttackVectorNetwork
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

function uniq(xs: Array<string | null | undefined>, limit = 8): string[] {
  const out: string[] = [];
  for (const x of xs) {
    const v = str(x).replace(/\s+/g, " ");
    if (!v) continue;
    if (out.some((y) => y.toLowerCase() === v.toLowerCase())) continue;
    out.push(v);
    if (out.length >= limit) break;
  }
  return out;
}

function splitSolutionLines(solution: string): string[] {
  if (!solution) return [];
  return uniq(
    solution
      .split(/\n+|;+(?=\s*[А-ЯA-Z])/)
      .map((s) => s.replace(/^[\s•\-–—]+/, "").trim())
      .filter((s) => s.length >= 6),
    8
  );
}

function normalizeBduTitle(bduId: string, name: string, softwareNames: string): string {
  const base = str(name);
  if (!base) return `БДУ ${bduId}`;
  if (/^уязвимость\b/i.test(base)) return base;
  const product = softwareNames.split(/[,;\n]/)[0]?.trim();
  return product ? `Уязвимость в ${product}: ${base}` : `Уязвимость: ${base}`;
}

function buildBduSummary(opts: {
  bduId: string;
  desc: string;
  title: string;
  severity: string;
  vulnClass: string | null;
  hasExploit: boolean;
  exploitStatus: string;
  solutionLines: string[];
  softwareNames: string;
}): string {
  const parts = [shortRuSummary(opts.desc || opts.title, 260) || `Запись БДУ ${opts.bduId} в реестре ФСТЭК.`];
  if (opts.vulnClass) parts.push(`Класс/уровень: ${opts.vulnClass}.`);
  else if (opts.severity) parts.push(`Уровень опасности по БДУ: ${opts.severity}.`);
  if (opts.softwareNames) parts.push(`Затронутое ПО: ${shortRuSummary(opts.softwareNames, 180)}.`);
  if (opts.hasExploit || opts.exploitStatus) {
    parts.push(
      opts.hasExploit
        ? `Эксплуатация: ${opts.exploitStatus || "есть сведения об эксплойте"}.`
        : `Статус эксплуатации: ${opts.exploitStatus}.`
    );
  }
  if (opts.solutionLines[0]) parts.push(`Рекомендация ФСТЭК: ${opts.solutionLines[0]}`);
  return parts.join(" ");
}

/** Минимальная карточка БДУ без LLM — с подмешиванием CWE/патчей из связанного CVE. */
export function buildBaselineEnrichmentFromBdu(
  bduId: string,
  bdu: BduBaselineInput,
  linkedCveRaw?: unknown
): JsonObj {
  const desc = str(bdu.description) || str(bdu.name);
  const fromCve = linkedCveRaw ? extractNvdVulnerabilityClass(linkedCveRaw) : null;
  const severity = str(bdu.severity);
  const vulnClass = fromCve || severity || null;
  const solutionText = str(bdu.solution);
  const solutionLines = splitSolutionLines(solutionText);
  const softwareNames = str(bdu.software_names);
  const title = normalizeBduTitle(bduId, str(bdu.name), softwareNames);
  const exploitStatus = str(bdu.exploit_status);
  const hasExploit = Boolean(bdu.has_exploit);
  const summary = buildBduSummary({
    bduId,
    desc,
    title,
    severity,
    vulnClass,
    hasExploit,
    exploitStatus,
    solutionLines,
    softwareNames
  });
  const attackFlow = defaultAttackFlowSteps(linkedCveRaw);
  const productHint = softwareNames.split(/[,;\n]/)[0]?.trim() || null;

  const base: JsonObj = {
    title,
    summary,
    description: desc.length > 2800 ? `${desc.slice(0, 2800)}…` : desc,
    vulnerabilityClass: vulnClass,
    attackFlow,
    exploitation: {
      publicExploit: hasExploit ? "yes" : "no",
      exploitNotes: exploitStatus || (linkedCveRaw ? extractNvdExploitationHint(linkedCveRaw, hasExploit) : null)
    },
    consequences: uniq(
      [
        fromCve ? `Класс уязвимости по связанной CVE: ${fromCve}` : null,
        severity ? `Уровень опасности по БДУ: ${severity}` : null,
        hasExploit ? "Есть сведения об эксплойте/эксплуатации, требуется приоритетная проверка." : null,
        softwareNames ? `Затронутое ПО: ${shortRuSummary(softwareNames, 160)}` : null
      ],
      5
    ),
    remediation: solutionLines.length
      ? solutionLines
      : uniq(
          [
            "Проверить карточку БДУ ФСТЭК и бюллетень вендора на наличие исправления.",
            softwareNames ? "Сверить перечень затронутого ПО БДУ с инвентарём активов." : null
          ],
          4
        ),
    applicability: {
      status: "unknown",
      notes: softwareNames
        ? `Затронутое ПО (БДУ): ${softwareNames.slice(0, 500)}`
        : "Сверить версии ПО с карточкой БДУ ФСТЭК."
    },
    nextSteps: solutionLines.length
      ? uniq([
          "Сверить установленные версии с перечнем ПО в БДУ.",
          "Применить рекомендуемое решение из БДУ.",
          hasExploit ? "Проверить журналы и периметр на признаки эксплуатации." : null
        ])
      : ["Открыть карточку БДУ на bdu.fstec.ru и уточнить меры."],
    questions: uniq(
      [
        softwareNames
          ? "Какие версии ПО из перечня БДУ установлены на критичных активах?"
          : "Какие активы соответствуют записи БДУ по вендору/продукту?",
        "Есть ли экспозиция затронутого компонента извне (интернет/VPN)?",
        hasExploit ? "Есть ли признаки эксплуатации в журналах/SOC по этой БДУ/связанной CVE?" : null
      ],
      4
    ),
    sources: [],
    graph: buildBaselineAttackGraph({
      entityId: `BDU:${bduId}`,
      attackFlow,
      summary,
      product: productHint,
      vulnClass,
      cvssNetwork: hasExploit || isCvssAttackVectorNetwork(linkedCveRaw)
    }),
    uncertainties: [],
    _display_source: "bdu_baseline"
  };

  return linkedCveRaw ? augmentEnrichmentWithNvdFixes(base, linkedCveRaw) : base;
}
