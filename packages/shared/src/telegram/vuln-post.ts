import {
  isGarbageEnrichSummary,
  isGenericEnrichmentTitle,
  stripEnrichmentBoilerplate
} from "../ai/enrichment-display.js";
export type VulnTelegramPostInput = {
  identifier: string;
  title: string;
  description: string;
  vulnerabilityClass: string | null;
  cvssScore: number | null;
  exploitation: string;
  status: string;
  attackFlow?: string[];
  /** Последствия / ущерб — не пересказ сути. */
  risks?: string[];
  recommendations: string[];
  sourceUrls: string[];
  affectedVersions?: string[];
};

export function cvssSeverityLabel(score: number | null | undefined): { label: string; emoji: string } {
  if (score == null || !Number.isFinite(score)) return { label: "—", emoji: "⚪" };
  if (score >= 9) return { label: "Критический", emoji: "🔴" };
  if (score >= 7) return { label: "Высокий", emoji: "🟠" };
  if (score >= 4) return { label: "Средний", emoji: "🟡" };
  return { label: "Низкий", emoji: "🟢" };
}

const HTML_ENTITY_MAP: Record<string, string> = {
  amp: "&",
  apos: "'",
  copy: "(c)",
  gt: ">",
  hellip: "…",
  laquo: "«",
  lt: "<",
  mdash: "—",
  nbsp: " ",
  ndash: "–",
  quot: "\"",
  raquo: "»",
  rdquo: "\"",
  reg: "(R)",
  rsquo: "'",
  trade: "(TM)"
};

function decodeHtmlEntities(s: string): string {
  let out = s;
  const fromCode = (code: number, fallback: string) =>
    Number.isFinite(code) && code >= 0 && code <= 0x10ffff ? String.fromCodePoint(code) : fallback;
  for (let i = 0; i < 2; i += 1) {
    out = out.replace(/&(#x?[0-9a-f]+|[a-z][a-z0-9]+);/gi, (m, entity: string) => {
      const e = entity.toLowerCase();
      if (e.startsWith("#x")) {
        const code = Number.parseInt(e.slice(2), 16);
        return fromCode(code, m);
      }
      if (e.startsWith("#")) {
        const code = Number.parseInt(e.slice(1), 10);
        return fromCode(code, m);
      }
      return HTML_ENTITY_MAP[e] ?? m;
    });
  }
  return out;
}

export function sanitizeTelegramText(raw: string | null | undefined, opts?: { multiline?: boolean; max?: number }): string {
  const multiline = opts?.multiline ?? false;
  const max = opts?.max ?? 0;
  let text = String(raw ?? "");
  text = text.replace(/<\s*br\s*\/?\s*>/gi, "\n").replace(/<\/\s*p\s*>/gi, "\n");
  text = text.replace(/<[^>]+>/g, " ");
  text = decodeHtmlEntities(text);
  text = text
    .replace(/\r\n?/g, "\n")
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, " ")
    .replace(/\u00a0/g, " ");

  const cleaned = multiline
    ? text
        .split("\n")
        .map((line) => line.replace(/[ \t]+/g, " ").trim())
        .filter(Boolean)
        .join("\n")
        .replace(/\n{3,}/g, "\n\n")
        .trim()
    : text.replace(/\s+/g, " ").trim();

  if (!max || cleaned.length <= max) return cleaned;
  return `${cleaned.slice(0, Math.max(0, max - 1)).trimEnd()}…`;
}

function bulletLines(items: string[], prefix = "• "): string {
  const lines = items.map((s) => sanitizeTelegramText(s, { max: 360 })).filter(Boolean).slice(0, 6);
  if (lines.length === 0) return "—";
  return lines.map((l) => `${prefix}${l}`).join("\n");
}

function numberedLines(items: string[], maxItems = 6): string {
  const lines = items.map((s) => sanitizeTelegramText(s, { max: 260 })).filter(Boolean).slice(0, maxItems);
  if (lines.length === 0) return "—";
  return lines.map((l, i) => `${i + 1}. ${l}`).join("\n");
}

function trimBlock(s: string, max = 2800): string {
  const t = sanitizeTelegramText(s, { multiline: true });
  if (t.length <= max) return t;
  return `${t.slice(0, max - 1).trimEnd()}…`;
}

function firstNonEmpty(...values: Array<string | null | undefined>): string {
  for (const value of values) {
    const t = sanitizeTelegramText(value);
    if (t) return t;
  }
  return "—";
}

function extractIds(identifier: string, urls: string[]) {
  const upperId = String(identifier ?? "").trim().toUpperCase();
  const cveFromId = /^CVE-\d{4}-\d+$/i.test(upperId) ? upperId : null;
  const bduFromId = /^BDU:/i.test(upperId) ? upperId : null;
  const cveFromUrl =
    urls
      .map((u) => u.match(/CVE-\d{4}-\d+/i)?.[0]?.toUpperCase() ?? null)
      .find(Boolean) ?? null;
  const bduFromUrl =
    urls
      .map((u) => u.match(/\/vul\/(\d{4}-\d+)/i)?.[1] ?? null)
      .find(Boolean) ?? null;
  return {
    cveId: cveFromId ?? cveFromUrl ?? "—",
    bduId: bduFromId ?? (bduFromUrl ? `BDU:${bduFromUrl}` : "—")
  };
}

function looksLikeIdOrCwe(value: string): boolean {
  const t = value.trim();
  if (!t) return true;
  if (/^(?:CVE-\d{4}-\d+|BDU:[\w.-]+|CWE-\d+)\b/i.test(t)) return true;
  if (/\bCWE-\d+\b/i.test(t) && !/[А-Яа-яЁё]{5,}/.test(t)) return true;
  return false;
}

/** Product/component label for the post headline — not a CWE code or boilerplate. */
function cleanProductLabel(raw: string | null | undefined): string | null {
  let t = sanitizeTelegramText(raw);
  if (!t) return null;
  t = t
    .replace(/^CVE-\d{4}-\d+\s*[:—–-]\s*/i, "")
    .replace(/^BDU:[\w.-]+\s*[:—–-]\s*/i, "")
    .replace(/^(?:уязвимость|vulnerability)\s+(?:в|in)\s+/i, "")
    .replace(/\s*\(?\s*CWE-\d+\s*\)?/gi, " ")
    .replace(/\s+/g, " ")
    .trim();
  if (!t || t.length > 90 || t.length < 2) return null;
  if (isGenericEnrichmentTitle(t) || looksLikeIdOrCwe(t)) return null;
  if (/^уязв/i.test(t)) return null;
  if (/^(?:n\/a|unknown|неизвестно|компонент|component|product)$/i.test(t)) return null;
  return t;
}

function extractProduct(title: string, description: string): string {
  const fromTitle = cleanProductLabel(title);
  if (fromTitle) return fromTitle;
  const cleanDesc = sanitizeTelegramText(description);
  const m =
    cleanDesc.match(/\b(?:in|в)\s+([A-Za-z][A-Za-z0-9_.:+#\-\/ ]{1,70}?)(?:[.,;:]| allows| is affected| has| library| component)/i) ??
    cleanDesc.match(/\b([A-Za-z][A-Za-z0-9_.:+#\-\/]{1,50})\s+(?:library|package|component|client|server)\b/i);
  return cleanProductLabel(m?.[1]) ?? "—";
}

function maturePostNarrative(raw: string | null | undefined): string {
  let t = String(raw ?? "").trim();
  t = t.replace(/^(?:Описание\s+(?:NVD|источника)\s*:\s*)+/i, "");
  t = t.replace(/^(?:Кратко:\s*)+/i, "");
  t = t.replace(/^(?:Класс уязвимости:\s*)?(?:CWE-\d+\s*[—–:-]\s*)+/i, "");
  return t.trim();
}

function matureVulnType(raw: string | null | undefined): string {
  let t = sanitizeTelegramText(raw);
  if (!t || looksLikeIdOrCwe(t) || isGenericEnrichmentTitle(t)) return "—";
  t = t.replace(/\bCWE-\d+\s*[—–:-]?\s*/gi, "").replace(/\s+/g, " ").trim();
  if (!t || t.length < 4 || looksLikeIdOrCwe(t) || /^уязв/i.test(t)) return "—";
  return t.length > 160 ? `${t.slice(0, 157)}…` : t;
}

function extractCwe(vulnerabilityClass: string | null, description: string): string {
  const joined = `${vulnerabilityClass ?? ""} ${description}`;
  const m = joined.match(/CWE-\d+/i);
  return m?.[0]?.toUpperCase() ?? "—";
}

function splitSentences(text: string, maxItems = 4): string[] {
  return text
    .split(/(?<=[.!?])\s+/)
    .map((s) => sanitizeTelegramText(s, { max: 260 }))
    .filter(Boolean)
    .slice(0, maxItems);
}

function formatAffectedVersions(versions: string[] | undefined): string {
  const cleaned = (versions ?? []).map((item) => sanitizeTelegramText(item, { max: 80 })).filter(Boolean);
  if (!cleaned.length) return "—";
  return cleaned.slice(0, 6).join("; ");
}

/** Читаемый для руководства ход атаки: цепочка со стрелками + нумерованные шаги. */
export function formatAttackFlowBlock(steps: string[] | undefined): string[] {
  const cleaned = (steps ?? [])
    .map((step) => sanitizeTelegramText(step, { max: 220 }))
    .map((step) => step.replace(/^(условие|точка входа|слабое место|результат|impact|entry|weakness|condition)\s*:\s*/i, "").trim())
    .filter((step) => step.length >= 3)
    .filter((step) => !/инвентаризац|уточняется по инвентар/i.test(step))
    .slice(0, 5);
  if (!cleaned.length) {
    return ["🔸 Ход атаки уточняется по открытым источникам"];
  }
  const labels = cleaned.map((step) => attackStepLabel(step));
  const chain = labels.join(" → ");
  const numbered = cleaned.map((step, index) => {
    const mark = ["①", "②", "③", "④", "⑤"][index] ?? `${index + 1}.`;
    return `${mark} ${step}${index < cleaned.length - 1 ? "\n   ↓" : ""}`;
  });
  return [`🔗 ${chain}`, "", ...numbered];
}

function attackStepLabel(step: string): string {
  const before = step.split(/[:—–-]/)[0]?.trim() ?? step;
  const label = before.length <= 48 ? before : `${before.slice(0, 45)}…`;
  return sanitizeTelegramText(label, { max: 52 });
}

function bulletize(items: string[], min = 3, fallback?: string[]): string[] {
  const base = items.map((s) => sanitizeTelegramText(s, { max: 280 })).filter(Boolean);
  if (base.length >= min) return base.slice(0, 6);
  return [...base, ...(fallback ?? [])].filter(Boolean).slice(0, 6);
}

/** Текст поста для Telegram-канала по шаблону банка. */
export function formatVulnTelegramPost(input: VulnTelegramPostInput): string {
  const sev = cvssSeverityLabel(input.cvssScore);
  const description = sanitizeTelegramText(maturePostNarrative(input.description), {
    multiline: true,
    max: 1800
  });
  const title = sanitizeTelegramText(input.title, { max: 220 });
  const ids = extractIds(input.identifier, input.sourceUrls);
  const product = extractProduct(title, description);
  const cwe = extractCwe(input.vulnerabilityClass, description);
  const cvssV3 = input.cvssScore != null && Number.isFinite(input.cvssScore) ? input.cvssScore.toFixed(1) : "—";
  const level = input.cvssScore != null && Number.isFinite(input.cvssScore) ? sev.label : "—";
  const vulnType = matureVulnType(input.vulnerabilityClass);
  const component = product !== "—" ? product : "—";
  const exploit = firstNonEmpty(input.exploitation);
  const summaryLines = splitSentences(description, 3);
  const riskFallback = [
    "утечка или несанкционированный доступ к данным",
    "нарушение целостности или доступности затронутого продукта",
    "эскалация воздействия при публичной эксплуатации"
  ];
  const riskSource = (input.risks ?? [])
    .map((line) => sanitizeTelegramText(line, { max: 280 }))
    .filter(Boolean)
    .filter((line) => !summaryLines.some((essence) => sameTelegramLine(essence, line)));
  const riskLines = bulletize(riskSource, 2, riskFallback).filter(
    (line) => !summaryLines.some((essence) => sameTelegramLine(essence, line))
  );
  const recommendationLines = bulletize(input.recommendations, 2, [
    "проверить, входит ли используемая версия в затронутый диапазон",
    "установить обновление или патч вендора",
    "проверить связанные продукты и встроенные зависимости"
  ]);
  const links = input.sourceUrls.map((u) => sanitizeTelegramText(u)).filter(Boolean).slice(0, 5);

  const headline =
    product !== "—"
      ? `🚩 Уязвимость в ${product}`
      : `🚩 Уязвимость ${ids.cveId !== "—" ? ids.cveId : ids.bduId !== "—" ? ids.bduId : sanitizeTelegramText(input.identifier)}`;

  const essenceLead = summaryLines[0] || firstNonEmpty(description, title);
  const attackBlock = formatAttackFlowBlock(input.attackFlow);

  const parts = [
    headline,
    "",
    `ℹ️ ${essenceLead}`,
    "",
    "📋 Карточка:",
    `🔸 БДУ: ${ids.bduId}`,
    `🔸 CVE: ${ids.cveId}`,
    `🔸 Уровень: ${level} · CVSSv3 ${cvssV3}`,
    `🔸 Продукт: ${product}`,
    `🔸 Тип: ${vulnType}`,
    `🔸 CWE: ${cwe}`,
    `🔸 Затронутые версии: ${formatAffectedVersions(input.affectedVersions)}`,
    `🔸 Эксплуатация: ${exploit}`,
    "",
    "🔝 Суть уязвимости:",
    ...summaryLines.map((line) => `🔸 ${line}`),
    "",
    "🧭 Ход атаки:",
    ...attackBlock,
    "",
    "⚠️ Возможные риски:",
    ...riskLines.map((line) => `🔸 ${line}`),
    "",
    "🛠 Что сделать:",
    ...recommendationLines.map((line) => `🔸 ${line}`),
    "",
    `✅ Статус: ${sanitizeTelegramText(input.status, { max: 360 }) || "Согласно процессу уязвимость взята в работу."}`,
    "",
    "🌐 Источники:",
    ...(links.length > 0 ? links : ["—"])
  ];

  let text = parts.map((p) => sanitizeTelegramText(p, { multiline: true })).join("\n");
  if (text.length > 4090) text = `${text.slice(0, 4087)}…`;
  return text;
}

/** Статус от аналитика (светофор + текст) — единственное поле, которое вводится вручную перед постом. */
export function normalizeTelegramUserStatus(raw: string, preset?: "yellow" | "red" | "green" | "white"): string {
  const t = sanitizeTelegramText(raw);
  if (!t) throw new Error("Укажите статус для блока «Статус» в посте");
  const emoji =
    preset === "red"
      ? "🔴"
      : preset === "green"
        ? "🟢"
        : preset === "white"
          ? "⚪"
          : preset === "yellow"
            ? "🟡"
            : null;
  if (/^[🟡🔴🟢⚪]/.test(t)) return t;
  if (emoji) return `${emoji} ${t}`;
  return `🟡 ${t}`;
}

/** Краткое описание из NVD CVE JSON 2.0 (поле `cve.raw`). */
export function extractNvdCveDescription(raw: unknown, lang = "en"): string | null {
  if (raw == null || typeof raw !== "object") return null;
  const top = raw as Record<string, unknown>;
  const tryDescriptions = (descs: unknown): string | null => {
    if (!Array.isArray(descs)) return null;
    const en = descs.find(
      (d) => d && typeof d === "object" && (d as Record<string, unknown>).lang === lang
    ) as Record<string, unknown> | undefined;
    const pick = en ?? (descs[0] as Record<string, unknown> | undefined);
    const v = pick?.value;
    return typeof v === "string" && v.trim() ? v.trim() : null;
  };
  const direct = top.description;
  if (typeof direct === "string" && direct.trim()) return direct.trim();
  const vulns = top.vulnerabilities;
  if (Array.isArray(vulns) && vulns.length > 0) {
    const cve = (vulns[0] as Record<string, unknown>)?.cve;
    if (cve && typeof cve === "object") {
      const fromCve = tryDescriptions((cve as Record<string, unknown>).descriptions);
      if (fromCve) return fromCve;
    }
  }
  const cve = top.cve;
  if (cve && typeof cve === "object") {
    const fromCve = tryDescriptions((cve as Record<string, unknown>).descriptions);
    if (fromCve) return fromCve;
  }
  return tryDescriptions(top.descriptions);
}

export function parseAiOutputJsonLoose(o: unknown): Record<string, unknown> | null {
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

function extractAttackFlow(ai: Record<string, unknown> | null): string[] {
  if (!ai) return [];
  if (Array.isArray(ai.attackFlow)) {
    return ai.attackFlow.map(String).map((s) => s.trim()).filter(Boolean);
  }
  const attack = ai.attack;
  if (attack && typeof attack === "object" && !Array.isArray(attack)) {
    const stages = Array.isArray((attack as { stages?: unknown }).stages)
      ? ((attack as { stages: unknown[] }).stages)
      : [];
    const fromStages = stages.flatMap((stage) => {
      if (!stage || typeof stage !== "object") return [];
      const row = stage as { title?: unknown; detail?: unknown };
      const title = typeof row.title === "string" ? row.title.trim() : "";
      const detail = typeof row.detail === "string" ? row.detail.trim() : "";
      if (!title && !detail) return [];
      return [title && detail ? `${title}: ${detail}` : title || detail];
    });
    if (fromStages.length) return fromStages;
  }
  const graph = ai.graph;
  if (graph && typeof graph === "object" && !Array.isArray(graph)) {
    const g = graph as Record<string, unknown>;
    const nodes = Array.isArray(g.nodes) ? g.nodes : [];
    const edges = Array.isArray(g.edges) ? g.edges : [];
    const labelById = new Map<string, string>();
    for (const node of nodes) {
      if (node && typeof node === "object" && !Array.isArray(node)) {
        const n = node as Record<string, unknown>;
        const id = typeof n.id === "string" ? n.id : null;
        const label = typeof n.label === "string" ? n.label : null;
        if (id && label) labelById.set(id, label);
      }
    }
    const flow: string[] = [];
    for (const edge of edges) {
      if (edge && typeof edge === "object" && !Array.isArray(edge)) {
        const e = edge as Record<string, unknown>;
        const from = typeof e.from === "string" ? labelById.get(e.from) ?? e.from : null;
        const to = typeof e.to === "string" ? labelById.get(e.to) ?? e.to : null;
        const label = typeof e.label === "string" ? e.label : null;
        if (from && to) flow.push([from, label, to].filter(Boolean).join(" → "));
      }
    }
    return flow;
  }
  return [];
}

function pickPostNarrative(...candidates: (string | null | undefined)[]): string {
  for (const c of candidates) {
    if (!c?.trim()) continue;
    const cleaned = stripEnrichmentBoilerplate(c.trim());
    if (!cleaned || isGarbageEnrichSummary(cleaned) || isGenericEnrichmentTitle(cleaned)) continue;
    return cleaned;
  }
  return "";
}

export function buildVulnPostFromAiJson(
  identifier: string,
  ai: Record<string, unknown> | null,
  ctx: {
    userStatus: string;
    cvssScore?: number | null;
    exploitKnown?: boolean;
    epssScore?: number | null;
    fallbackDescription?: string | null;
    fallbackTitle?: string | null;
    fallbackVulnerabilityClass?: string | null;
    fallbackAttackFlow?: string[];
    fallbackExploitation?: string | null;
    extraLinks?: string[];
    extraRemediation?: string[];
  }
): VulnTelegramPostInput {
  const aiTitle = typeof ai?.title === "string" ? ai.title.trim() : "";
  const title =
    aiTitle && !isGenericEnrichmentTitle(aiTitle)
      ? aiTitle
      : ctx.fallbackTitle?.trim() || `Уязвимость ${identifier}`;

  const pointNote = typeof ai?.pointNote === "string" ? ai.pointNote : "";
  const isPointFacture = /фактур/i.test(pointNote) || Array.isArray(ai?.facts);
  const fromAi = isPointFacture
    ? ""
    : pickPostNarrative(
        typeof ai?.description === "string" ? ai.description : null,
        typeof ai?.summary === "string" ? ai.summary : null
      );
  const nvdFallback = ctx.fallbackDescription?.trim()
    ? stripEnrichmentBoilerplate(ctx.fallbackDescription.trim()) || ctx.fallbackDescription.trim()
    : "";
  const description = fromAi || nvdFallback || "Описание уточняется по данным NVD/БДУ.";
  const risks = collectTelegramRisks(ai);

  const aiClass =
    typeof ai?.vulnerabilityClass === "string" && ai.vulnerabilityClass.trim()
      ? ai.vulnerabilityClass.trim()
      : null;
  const nvdClass = ctx.fallbackVulnerabilityClass?.trim() || null;
  const vulnClass =
    nvdClass && (!aiClass || /^CWE-\d+$/i.test(aiClass)) ? nvdClass : aiClass || nvdClass || null;

  let exploitation = "";
  const ex = ai?.exploitation;
  if (ex && typeof ex === "object" && !Array.isArray(ex)) {
    const pe = String((ex as Record<string, unknown>).publicExploit ?? "").toLowerCase();
    const notes = (ex as Record<string, unknown>).exploitNotes;
    if (pe === "yes") exploitation = "Публичный эксплойт / PoC возможен";
    else if (pe === "no") exploitation = "Публичный эксплойт не подтверждён";
    else if (ctx.fallbackExploitation?.trim()) exploitation = ctx.fallbackExploitation.trim();
    else exploitation = "Статус эксплуатации уточняется";
    if (typeof notes === "string" && notes.trim()) exploitation += `. ${notes.trim()}`;
  } else if (ctx.exploitKnown) {
    exploitation = "В KEV / известна активная эксплуатация";
  } else if (ctx.fallbackExploitation?.trim()) {
    exploitation = ctx.fallbackExploitation.trim();
  } else {
    exploitation = "Статус эксплуатации уточняется";
  }
  if (ctx.epssScore != null && Number.isFinite(ctx.epssScore)) {
    exploitation += ` · EPSS ${(ctx.epssScore * 100).toFixed(2)}%`;
  }

  const status = normalizeTelegramUserStatus(ctx.userStatus);
  const attackFlowFromAi = extractAttackFlow(ai);
  const fallbackFlow = (ctx.fallbackAttackFlow ?? []).map(String).filter(Boolean);
  const attackFlow =
    attackFlowFromAi.length > 0
      ? attackFlowFromAi
      : fallbackFlow.length > 0
        ? fallbackFlow
        : [];

  const remediation = [
    ...(Array.isArray(ai?.remediation) ? ai.remediation.map(String) : []),
    ...(Array.isArray(ai?.nextSteps) ? ai.nextSteps.map(String) : []),
    ...(ctx.extraRemediation ?? [])
  ]
    .map((s) => s.trim())
    .filter(Boolean);
  const uniqRem: string[] = [];
  for (const r of remediation) {
    if (!uniqRem.includes(r)) uniqRem.push(r);
  }

  const sourceUrls: string[] = [];
  const pushUrl = (u: unknown) => {
    if (typeof u !== "string") return;
    const t = u.trim();
    if (t.startsWith("http") && !sourceUrls.includes(t)) sourceUrls.push(t);
  };
  if (Array.isArray(ai?.sources)) {
    for (const s of ai.sources) {
      if (s && typeof s === "object" && !Array.isArray(s)) pushUrl((s as Record<string, unknown>).url);
    }
  }
  for (const u of ctx.extraLinks ?? []) pushUrl(u);
  if (identifier.startsWith("CVE-")) {
    const nvd = `https://nvd.nist.gov/vuln/detail/${identifier}`;
    if (!sourceUrls.includes(nvd)) sourceUrls.unshift(nvd);
  }

  return {
    identifier,
    title,
    description,
    vulnerabilityClass: vulnClass,
    cvssScore: ctx.cvssScore ?? null,
    exploitation,
    status,
    attackFlow,
    risks,
    recommendations:
      uniqRem.length > 0
        ? uniqRem
        : [
            "проверить, входит ли используемая версия продукта в затронутый диапазон",
            "установить обновление или патч по рекомендации вендора"
          ],
    sourceUrls
  };
}

function sameTelegramLine(left: string, right: string): boolean {
  const norm = (value: string) =>
    value
      .toLowerCase()
      .replace(/[^\p{L}\p{N}\s]/gu, " ")
      .replace(/\s+/g, " ")
      .trim();
  const a = norm(left);
  const b = norm(right);
  if (!a || !b) return false;
  if (a === b) return true;
  if (a.length > 40 && b.includes(a.slice(0, 40))) return true;
  if (b.length > 40 && a.includes(b.slice(0, 40))) return true;
  return false;
}

function looksLikeRiskLine(line: string): boolean {
  return /утечк|компромет|доступ к данн|произвольн|удалённ|удаленн|исполнен|отказ в обслуживан|DoS|RCE|эскалац|захват|подмен|нарушен|чтение файл|запись файл|безопасност/i.test(
    line
  );
}

function looksLikeFactNotRisk(line: string): boolean {
  return /KEV|EPSS|dateAdded|добавлен|перцентил|процентил|BOD\s*\d|бэкпорт|backport|исправленн|закрывающ|верси/i.test(
    line
  );
}

function collectTelegramRisks(ai: Record<string, unknown> | null): string[] {
  if (!ai) return [];
  const out: string[] = [];
  const push = (value: unknown) => {
    const line = String(value ?? "").trim();
    if (!line || line.length < 12 || line.length > 280) return;
    if (looksLikeFactNotRisk(line) && !looksLikeRiskLine(line)) return;
    if (!looksLikeRiskLine(line) && !/^Возможн/i.test(line)) return;
    if (out.some((item) => sameTelegramLine(item, line))) return;
    out.push(line);
  };

  const attack = ai.attack;
  if (attack && typeof attack === "object" && !Array.isArray(attack)) {
    const stages = Array.isArray((attack as { stages?: unknown }).stages)
      ? ((attack as { stages: unknown[] }).stages)
      : [];
    for (const stage of stages) {
      if (!stage || typeof stage !== "object") continue;
      const row = stage as { role?: unknown; title?: unknown; detail?: unknown };
      if (row.role !== "impact") continue;
      push([row.title, row.detail].filter(Boolean).join(": "));
      push(row.detail);
    }
  }

  for (const line of extractAttackFlow(ai)) {
    if (/результат|impact|чтение|запись|исполнен|компромет|доступ/i.test(line)) push(line);
  }

  if (Array.isArray(ai.consequences)) {
    for (const item of ai.consequences) push(item);
  }
  if (Array.isArray(ai.risks)) {
    for (const item of ai.risks) push(item);
  }

  const ex = ai.exploitation;
  if (ex && typeof ex === "object" && !Array.isArray(ex)) {
    const notes = (ex as { exploitNotes?: unknown }).exploitNotes;
    if (typeof notes === "string" && looksLikeRiskLine(notes)) push(notes);
  }

  return out.slice(0, 6);
}
