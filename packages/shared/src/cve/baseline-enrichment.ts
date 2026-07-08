import { augmentEnrichmentWithNvdFixes } from "./nvd-fix-signals.js";

type JsonObj = Record<string, unknown>;

function asObj(v: unknown): JsonObj | null {
  return v != null && typeof v === "object" && !Array.isArray(v) ? (v as JsonObj) : null;
}

function str(v: unknown): string {
  return typeof v === "string" ? v.trim() : "";
}

function firstDescription(raw: JsonObj): string {
  const descs = raw.descriptions;
  if (Array.isArray(descs)) {
    for (const d of descs) {
      const o = asObj(d);
      const val = str(o?.value);
      if (val) return val.replace(/\s+/g, " ").trim();
    }
  }
  const legacy = raw.cve;
  const leg = asObj(legacy);
  const dd = leg?.descriptions;
  if (Array.isArray(dd)) {
    for (const d of dd) {
      const o = asObj(d);
      const val = str(o?.value);
      if (val) return val.replace(/\s+/g, " ").trim();
    }
  }
  return "";
}

function extractCweLabels(raw: JsonObj): string[] {
  const out: string[] = [];
  const sources: unknown[] = [];
  if (Array.isArray(raw.weaknesses)) sources.push(...raw.weaknesses);
  const nested = asObj(raw.cve);
  if (Array.isArray(nested?.weaknesses)) sources.push(...nested.weaknesses);
  const vulns = raw.vulnerabilities;
  if (Array.isArray(vulns) && vulns[0]) {
    const cve = asObj(asObj(vulns[0])?.cve);
    if (Array.isArray(cve?.weaknesses)) sources.push(...cve.weaknesses);
  }

  for (const w of sources) {
    const wo = asObj(w);
    const descs = wo?.description;
    if (Array.isArray(descs)) {
      for (const d of descs) {
        const val = str(asObj(d)?.value);
        if (val && !out.includes(val)) out.push(val);
      }
    }
    const type = str(wo?.type);
    if (/^CWE-\d+$/i.test(type) && !out.some((x) => x.toUpperCase() === type.toUpperCase())) {
      out.push(type.toUpperCase());
    }
  }
  return out;
}

const CWE_SHORT_NAMES: Record<string, string> = {
  "CWE-20": "Improper Input Validation",
  "CWE-22": "Path Traversal",
  "CWE-78": "OS Command Injection",
  "CWE-79": "Cross-site Scripting (XSS)",
  "CWE-89": "SQL Injection",
  "CWE-94": "Code Injection",
  "CWE-119": "Memory Buffer Overflow",
  "CWE-120": "Buffer Copy without Size Check",
  "CWE-125": "Out-of-bounds Read",
  "CWE-190": "Integer Overflow",
  "CWE-200": "Information Exposure",
  "CWE-287": "Improper Authentication",
  "CWE-306": "Missing Authentication",
  "CWE-352": "CSRF",
  "CWE-362": "Race Condition",
  "CWE-400": "Uncontrolled Resource Consumption",
  "CWE-416": "Use After Free",
  "CWE-434": "Unrestricted File Upload",
  "CWE-476": "NULL Pointer Dereference",
  "CWE-502": "Deserialization of Untrusted Data",
  "CWE-611": "XXE",
  "CWE-787": "Out-of-bounds Write",
  "CWE-798": "Hard-coded Credentials",
  "CWE-862": "Missing Authorization",
  "CWE-918": "SSRF"
};

function formatCweLabel(raw: string): string {
  const m = raw.match(/CWE-(\d+)/i);
  if (!m) return raw;
  const code = `CWE-${m[1]}`;
  const name = CWE_SHORT_NAMES[code];
  return name ? `${code} — ${name}` : code;
}

/** Класс уязвимости из NVD (CWE + краткое имя). */
export function extractNvdVulnerabilityClass(raw: unknown): string | null {
  const o = asObj(raw);
  if (!o) return null;
  const labels = extractCweLabels(o).map(formatCweLabel);
  return labels.length > 0 ? labels.join(", ") : null;
}

const CVSS_AV_RU: Record<string, string> = {
  NETWORK: "сетевая",
  ADJACENT: "смежная сеть",
  LOCAL: "локальная",
  PHYSICAL: "физический доступ"
};

/** Подсказка по эксплуатации из CVSS NVD, если ИИ не дал деталей. */
export function extractNvdExploitationHint(raw: unknown, exploitKnown = false): string | null {
  if (exploitKnown) return "В KEV / известна активная эксплуатация";
  const o = asObj(raw);
  if (!o) return null;
  const metrics = asObj(o.metrics);
  for (const key of ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]) {
    const arr = metrics?.[key];
    if (!Array.isArray(arr) || !arr[0]) continue;
    const cvssData = asObj(asObj(arr[0])?.cvssData);
    const av = str(cvssData?.attackVector).toUpperCase();
    const ac = str(cvssData?.attackComplexity).toUpperCase();
    const pr = str(cvssData?.privilegesRequired).toUpperCase();
    const parts: string[] = [];
    if (av) parts.push(`вектор ${CVSS_AV_RU[av] ?? av.toLowerCase()}`);
    if (ac === "LOW") parts.push("низкая сложность атаки");
    if (pr === "NONE") parts.push("без привилегий");
    if (parts.length > 0) return `По CVSS: ${parts.join(", ")}`;
  }
  return null;
}

function shortRuSummary(text: string, max = 420): string {
  const t = text.replace(/\s+/g, " ").trim();
  if (!t) return "";
  if (t.length <= max) return t;
  const cut = t.slice(0, max);
  const last = Math.max(cut.lastIndexOf(". "), cut.lastIndexOf(" "));
  return `${(last > 80 ? cut.slice(0, last) : cut).trim()}…`;
}

function defaultAttackFlow(cvssNetwork: boolean): string[] {
  return cvssNetwork
    ? [
        "Злоумышленник находит сетевую точку входа, где обрабатываются входные данные.",
        "Передаёт специально сформированный запрос или данные в уязвимый компонент.",
        "Уязвимая логика некорректно обрабатывает ввод и достигает опасного кода.",
        "Возникает заявленное воздействие (компрометация, утечка, отказ в обслуживании)."
      ]
    : [
        "Злоумышленник получает возможность влиять на входные данные уязвимого компонента.",
        "Эксплуатирует дефект проверок или обработки данных.",
        "Достигает заявленного воздействия в пределах модели угроз CVE."
      ];
}

/** Схема атаки по умолчанию для карточек/TG без ИИ. */
export function defaultAttackFlowSteps(raw?: unknown): string[] {
  const o = asObj(raw) ?? {};
  return defaultAttackFlow(cvssAttackVectorNetwork(o));
}

function cvssAttackVectorNetwork(raw: JsonObj): boolean {
  const metrics = asObj(raw.metrics);
  for (const key of ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]) {
    const arr = metrics?.[key];
    if (!Array.isArray(arr) || !arr[0]) continue;
    const cvssData = asObj(asObj(arr[0])?.cvssData);
    const av = str(cvssData?.attackVector);
    if (av.toUpperCase() === "NETWORK") return true;
  }
  return false;
}

/**
 * Минимальная «карточка» из NVD без вызова LLM — для всех CVE с raw в БД.
 */
export function buildBaselineEnrichmentFromNvd(cveId: string, raw: unknown): JsonObj {
  const o = asObj(raw) ?? {};
  const desc = firstDescription(o);
  const cwes = extractCweLabels(o);
  const vulnClass = cwes.length > 0 ? cwes.map(formatCweLabel).join(", ") : null;
  const productHint = (() => {
    const configs = o.configurations;
    if (!Array.isArray(configs) || !configs[0]) return null;
    const nodes = asObj(configs[0])?.nodes;
    if (!Array.isArray(nodes) || !nodes[0]) return null;
    const m = asObj(nodes[0])?.cpeMatch;
    if (!Array.isArray(m) || !m[0]) return null;
    const criteria = str(asObj(m[0])?.criteria);
    if (!criteria.includes("linux_kernel")) return null;
    return "Linux kernel";
  })();

  const title = productHint
    ? `Уязвимость в ${productHint} (${cveId})`
    : `Уязвимость ${cveId}`;

  const summary =
    shortRuSummary(desc) ||
    `Запись ${cveId} в NVD. Откройте детали или запросите ИИ-обогащение для развёрнутого анализа.`;

  const description =
    desc.length > 2800 ? `${desc.slice(0, 2800)}…` : desc || summary;

  const base: JsonObj = {
    title,
    summary,
    description,
    vulnerabilityClass: vulnClass,
    attackFlow: defaultAttackFlowSteps(o),
    exploitation: { publicExploit: "unknown", exploitNotes: null },
    consequences: vulnClass ? [`Возможная реализация класса: ${vulnClass}`] : [],
    remediation: [],
    applicability: { status: "unknown", notes: "Требуется сверка версий ПО в вашем окружении." },
    nextSteps: [],
    questions: [
      "Какие версии затронутого ПО установлены на критичных активах?",
      "Есть ли экспозиция уязвимого компонента извне (интернет/VPN)?"
    ],
    sources: [],
    graph: { nodes: [], edges: [] },
    uncertainties: [],
    _display_source: "nvd_baseline"
  };

  return augmentEnrichmentWithNvdFixes(base, o);
}
