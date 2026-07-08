/** Клиентская копия packages/shared/src/cve/baseline-enrichment.ts */
import { augmentEnrichmentWithNvdFixes } from "./nvd-fix-signals";

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
  return "";
}

function extractCweLabels(raw: JsonObj): string[] {
  const out: string[] = [];
  const weak = raw.weaknesses;
  if (!Array.isArray(weak)) return out;
  for (const w of weak) {
    const wo = asObj(w);
    const descs = wo?.description;
    if (!Array.isArray(descs)) continue;
    for (const d of descs) {
      const val = str(asObj(d)?.value);
      if (val && !out.includes(val)) out.push(val);
    }
  }
  return out;
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

export function buildBaselineEnrichmentFromNvd(cveId: string, raw: unknown): JsonObj {
  const o = asObj(raw) ?? {};
  const desc = firstDescription(o);
  const cwes = extractCweLabels(o);
  const vulnClass = cwes.length > 0 ? cwes.join(", ") : null;
  const title = `Уязвимость ${cveId}`;
  const summary =
    shortRuSummary(desc) ||
    `Запись ${cveId} в NVD. Запросите ИИ-обогащение для развёрнутого анализа.`;
  const description = desc.length > 2800 ? `${desc.slice(0, 2800)}…` : desc || summary;

  return augmentEnrichmentWithNvdFixes(
    {
      title,
      summary,
      description,
      vulnerabilityClass: vulnClass,
      attackFlow: defaultAttackFlow(cvssAttackVectorNetwork(o)),
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
    },
    o
  );
}
