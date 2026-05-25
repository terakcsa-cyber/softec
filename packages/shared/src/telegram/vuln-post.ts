export type VulnTelegramPostInput = {
  identifier: string;
  title: string;
  description: string;
  vulnerabilityClass: string | null;
  cvssScore: number | null;
  exploitation: string;
  status: string;
  attackFlow?: string[];
  recommendations: string[];
  sourceUrls: string[];
};

export function cvssSeverityLabel(score: number | null | undefined): { label: string; emoji: string } {
  if (score == null || !Number.isFinite(score)) return { label: "—", emoji: "⚪" };
  if (score >= 9) return { label: "Critical", emoji: "🔴" };
  if (score >= 7) return { label: "High", emoji: "🟠" };
  if (score >= 4) return { label: "Medium", emoji: "🟡" };
  return { label: "Low", emoji: "🟢" };
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

/** Текст поста для Telegram-канала по шаблону банка. */
export function formatVulnTelegramPost(input: VulnTelegramPostInput): string {
  const sev = cvssSeverityLabel(input.cvssScore);
  const cvssLine =
    input.cvssScore != null && Number.isFinite(input.cvssScore)
      ? `${input.cvssScore.toFixed(1)} (${sev.label})`
      : "—";

  const parts = [
    "🚀 Комплексный анализ уязвимости",
    `💥 ${sanitizeTelegramText(input.title, { max: 220 }) || "Уязвимость"}`,
    `🔝 Идентификатор уязвимости: ${sanitizeTelegramText(input.identifier, { max: 80 })}`,
    "🟠 Описание:",
    trimBlock(input.description || "—", 1800),
    `⚙️ Класс: ${sanitizeTelegramText(input.vulnerabilityClass, { max: 160 }) || "—"}`,
    `🔹 Уровень опасности по CVSS: ${cvssLine}`,
    `❗️ Эксплуатация: ${sanitizeTelegramText(input.exploitation, { max: 360 }) || "—"}`,
    `🚨 Статус: ${sanitizeTelegramText(input.status, { max: 360 }) || "🟡 В работе — требуется уточнение контекста"}`,
    ...(input.attackFlow?.length ? ["🧭 Схема атаки:", numberedLines(input.attackFlow)] : []),
    "⚙️ Рекомендации (в проработке):",
    bulletLines(input.recommendations),
    "🌐 Ссылки на источник:",
    input.sourceUrls.length > 0
      ? input.sourceUrls.map((u) => sanitizeTelegramText(u)).filter(Boolean).join("\n")
      : "—"
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
    extraLinks?: string[];
    extraRemediation?: string[];
  }
): VulnTelegramPostInput {
  const title =
    (typeof ai?.title === "string" && ai.title.trim()) ||
    ctx.fallbackTitle?.trim() ||
    `Уязвимость ${identifier}`;

  const descParts: string[] = [];
  if (typeof ai?.description === "string" && ai.description.trim()) descParts.push(ai.description.trim());
  else if (typeof ai?.summary === "string" && ai.summary.trim()) descParts.push(ai.summary.trim());
  else if (ctx.fallbackDescription?.trim()) descParts.push(ctx.fallbackDescription.trim());
  if (Array.isArray(ai?.consequences)) {
    const c = ai.consequences.map(String).filter(Boolean);
    if (c.length) descParts.push(c.join(" "));
  }
  const description = descParts.join("\n\n") || "Описание уточняется по данным NVD/БДУ и ИИ-анализа.";

  const vulnClass =
    typeof ai?.vulnerabilityClass === "string" && ai.vulnerabilityClass.trim()
      ? ai.vulnerabilityClass.trim()
      : null;

  let exploitation = "";
  const ex = ai?.exploitation;
  if (ex && typeof ex === "object" && !Array.isArray(ex)) {
    const pe = String((ex as Record<string, unknown>).publicExploit ?? "").toLowerCase();
    const notes = (ex as Record<string, unknown>).exploitNotes;
    if (pe === "yes") exploitation = "Публичный эксплойт / PoC возможен";
    else if (pe === "no") exploitation = "Публичный эксплойт не подтверждён";
    else exploitation = "Статус эксплуатации уточняется";
    if (typeof notes === "string" && notes.trim()) exploitation += `. ${notes.trim()}`;
  } else if (ctx.exploitKnown) {
    exploitation = "В KEV / известна активная эксплуатация";
  } else {
    exploitation = "Требуется локальный/сетевой контекст — уточняется по инвентаризации";
  }
  if (ctx.epssScore != null && Number.isFinite(ctx.epssScore)) {
    exploitation += ` · EPSS ${(ctx.epssScore * 100).toFixed(2)}%`;
  }

  const status = normalizeTelegramUserStatus(ctx.userStatus);
  const attackFlow = extractAttackFlow(ai);

  const remediation = [
    ...(Array.isArray(ai?.remediation) ? ai.remediation.map(String) : []),
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

  return {
    identifier,
    title,
    description,
    vulnerabilityClass: vulnClass,
    cvssScore: ctx.cvssScore ?? null,
    exploitation,
    status,
    attackFlow,
    recommendations:
      uniqRem.length > 0
        ? uniqRem
        : ["уточнить затронутые версии ПО в инвентаризации", "применить обновление / компенсирующие меры по рекомендации вендора"],
    sourceUrls
  };
}
