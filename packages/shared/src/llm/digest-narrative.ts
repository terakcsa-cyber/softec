import {
  completeOpenAiChatText,
  llmEndpointRequiresApiKey,
  type VulnContextLlmConfig
} from "./vuln-context-engine.js";

export const DIGEST_LLM_DEFAULT_ENDPOINT = "https://api.deepseek.com";
export const DIGEST_LLM_DEFAULT_MODEL = "deepseek-chat";

export const DIGEST_NARRATIVE_SKIPPED =
  "Рассказ не сформирован: ключ дайджеста не задан.";

export const DIGEST_NARRATIVE_FAILED =
  "Рассказ не сформирован: текстовый движок не ответил.";

export const DIGEST_NARRATIVE_REJECTED =
  "Фрагмент рассказа не включён: в нём были числа или CVE, которых нет в фактах каталога.";

export const DIGEST_PROMPT_MAX_CHARS = 8_000;

export type DigestNarrativeSection = {
  title: string;
  status: "empty" | "error" | "ready" | "loading";
  note: string;
  metrics: Array<{ label: string; value: string }>;
  bars: Array<{ label: string; display: string }>;
  tables: Array<{ columns: string[]; rows: string[][] }>;
};

export type DigestCveNote = {
  cveId: string;
  description: string;
  vendor?: string;
  product?: string;
  cvss?: string;
  epss?: string;
  kev?: string;
};

export type DigestNarrativeFacts = {
  title: string;
  windowLabel: string;
  issuedAt: string;
  coverage: string;
  sections: DigestNarrativeSection[];
  cveNotes: DigestCveNote[];
};

export type DigestStoryParts = {
  lead: string;
  summary: string;
  cases: string;
  close: string;
};

export type DigestNarrativeOutcome = DigestStoryParts & {
  status: "generated" | "skipped" | "failed";
  text: string;
};

const CVE_RE = /CVE-\d{4}-\d{4,7}/gi;
const NUMBER_RE = /\d{1,3}(?:[ \u00a0\u202f]\d{3})+|\d+(?:[.,]\d+)?/g;

/** Числа из текста: группировка «12 345» схлопывается в 12345, запятая становится точкой. */
export function digestNumericTokens(text: string): string[] {
  const found: string[] = [];
  for (const match of text.matchAll(NUMBER_RE)) {
    const raw = match[0];
    if (/[ \u00a0\u202f]/.test(raw)) found.push(raw.replace(/[ \u00a0\u202f]/g, ""));
    else found.push(raw.replace(",", "."));
  }
  return found;
}

export function digestFactsText(facts: DigestNarrativeFacts): string {
  const lines: string[] = [
    `Название: ${facts.title}`,
    `Окно: ${facts.windowLabel}`,
    `Сформирован: ${facts.issuedAt}`,
    `Покрытие: ${facts.coverage}`
  ];
  for (const section of facts.sections) {
    lines.push(`Раздел: ${section.title}`);
    lines.push(`Статус: ${section.status}`);
    if (section.note) lines.push(section.note);
    for (const metric of section.metrics) lines.push(`${metric.label}: ${metric.value}`);
    for (const bar of section.bars) lines.push(`${bar.label}: ${bar.display}`);
    for (const table of section.tables) {
      if (table.columns.length) lines.push(table.columns.join(" | "));
      for (const row of table.rows) lines.push(row.join(" | "));
    }
  }
  for (const note of facts.cveNotes) {
    const bits = [note.cveId, note.vendor, note.product, note.cvss, note.epss, note.kev, note.description].filter(
      (part) => typeof part === "string" && part.trim()
    );
    lines.push(bits.join(" | "));
  }
  return lines.join("\n");
}

export function capDigestPrompt(factsText: string, maxChars = DIGEST_PROMPT_MAX_CHARS): string {
  if (factsText.length <= maxChars) return factsText;
  const lines = factsText.split("\n");
  const kept: string[] = [];
  let size = 0;
  for (const line of lines) {
    const next = size + line.length + 1;
    if (next > maxChars) break;
    kept.push(line);
    size = next;
  }
  return kept.join("\n");
}

export function buildMonthlyDigestPrompt(factsText: string): string {
  const facts = capDigestPrompt(factsText);
  return [
    "Подготовь зрелый ежемесячный дайджест уязвимостей на русском языке.",
    "Тон: обзор threat intelligence. Рядом с фактом — короткое пояснение, что он значит для vulnerability management.",
    "Пиши только про календарный месяц из FACTS.",
    "Источник истины — только блок FACTS. Это агрегаты и ограниченный список CVE каталога за этот месяц.",
    "Запрещено выдумывать CVE, количества, проценты, дельты, продукты и вендоров.",
    "Запрещено сравнивать месяц с предыдущим, если такого сравнения нет в FACTS.",
    "Запрещено описывать движение EPSS внутри месяца, если в FACTS нет истории EPSS с числом точек больше нуля.",
    "Копируй числа как в FACTS и не округляй их.",
    "Если числа нет в FACTS, не пиши его.",
    "Не пиши про хосты, серверы, активы, IP и инфраструктуру.",
    "Не описывай эксплуатацию, не давай шаги атаки и не приводи код.",
    "Не назначай SLA и не выдумывай очереди задач.",
    "Каждое предложение заканчивается точкой.",
    "Без markdown и без списков.",
    "Верни ровно четыре блока с метками:",
    "LEAD: главный вывод месяца, 4–6 предложений. Что опубликовано, что тяжёлое по CVSS, что вошло в CISA KEV, какие вендоры и продукты заметны, что видно по эксплойту, PoC и EPSS.",
    "SUMMARY: как читать цифры месяца вместе. Поясни разницу между публикацией CVE, датой добавления в KEV и текущим снимком EPSS. Без новых чисел.",
    "CASES: по одному или двум предложениям на каждый CVE из FACTS. Первое предложение начинается с идентификатора CVE. Опирайся на продукт, CVSS, EPSS, отметку KEV и короткое описание из FACTS. Не добавляй другие CVE.",
    "CLOSE: одна короткая формулировка, как читать этот месячный выпуск. Без новых чисел.",
    "",
    "FACTS:",
    facts
  ].join("\n");
}

export function buildDigestNarrativePrompt(factsText: string): string {
  const facts = capDigestPrompt(factsText);
  return [
    "Напиши рассказ дайджеста уязвимостей на русском языке: вывод, пояснение цифр и короткие кейсы.",
    "Источник истины — только блок FACTS.",
    "Запрещено выдумывать CVE, количества, проценты, дельты, продукты и вендоров.",
    "Копируй числа как в FACTS и не округляй их.",
    "Если числа нет в FACTS, не пиши его.",
    "Не сравнивай период с предыдущим и не пиши дельты.",
    "Не пиши про хосты, серверы, IP и инфраструктуру.",
    "Не описывай эксплуатацию и не приводи код.",
    "Каждое предложение заканчивается точкой.",
    "Без markdown и без списков.",
    "Верни ровно четыре блока с метками:",
    "LEAD: главный вывод окна, 3–5 предложений.",
    "SUMMARY: пояснение, как читать цифры сводки вместе, без новых чисел.",
    "CASES: по одному предложению на CVE из FACTS. Предложение начинается с идентификатора CVE. Не добавляй другие CVE.",
    "CLOSE: одна короткая формулировка, как читать выпуск. Без новых чисел.",
    "",
    "FACTS:",
    facts
  ].join("\n");
}

export function splitDigestStory(raw: string): DigestStoryParts {
  const text = raw.replace(/```/g, "\n");
  const hits: Array<{ key: keyof DigestStoryParts; start: number }> = [];
  const re = /(?:^|\n)\s*(LEAD|SUMMARY|CASES|CLOSE)\s*:/gi;
  let match: RegExpExecArray | null;
  while ((match = re.exec(text))) {
    const label = match[1];
    if (!label) continue;
    const key = label.toLowerCase() as keyof DigestStoryParts;
    hits.push({ key, start: match.index + match[0].length });
  }
  const empty: DigestStoryParts = { lead: "", summary: "", cases: "", close: "" };
  if (!hits.length) return { ...empty, lead: text.trim() };
  for (let i = 0; i < hits.length; i++) {
    const current = hits[i];
    const next = hits[i + 1];
    if (!current) continue;
    const end = next ? text.lastIndexOf("\n", next.start) : text.length;
    const body = text.slice(current.start, Math.max(current.start, end)).trim();
    if (!empty[current.key]) empty[current.key] = body;
  }
  return empty;
}

export function composeDigestStory(raw: string, factsText: string): DigestStoryParts {
  const parts = splitDigestStory(raw);
  return {
    lead: filterDigestNarrative(parts.lead, factsText),
    summary: filterDigestNarrative(parts.summary, factsText),
    cases: filterDigestNarrative(parts.cases, factsText),
    close: filterDigestNarrative(parts.close, factsText)
  };
}

function splitSentences(text: string): string[] {
  return text
    .replace(/```/g, " ")
    .replace(/\s+/g, " ")
    .split(/(?<=[.!?])\s+/)
    .map((part) => part.trim())
    .filter(Boolean);
}

/** Убирает предложения, где есть CVE или число, которого нет в фактах. */
export function filterDigestNarrative(narrative: string, factsText: string): string {
  const allowed = new Set(digestNumericTokens(factsText));
  const cves = new Set([...factsText.matchAll(CVE_RE)].map((match) => match[0].toUpperCase()));
  const factsHavePercent = factsText.includes("%");
  const kept: string[] = [];
  for (const sentence of splitSentences(narrative)) {
    if (/дельт|по сравнению/i.test(sentence)) continue;
    if (sentence.includes("%") && !factsHavePercent) continue;
    const ids = [...sentence.matchAll(CVE_RE)].map((match) => match[0].toUpperCase());
    if (ids.some((id) => !cves.has(id))) continue;
    const numbers = digestNumericTokens(sentence);
    if (numbers.some((token) => !allowed.has(token))) continue;
    kept.push(sentence);
  }
  return kept.join(" ").trim();
}

export type DigestLlmStored = {
  endpoint?: unknown;
  model?: unknown;
  apiKey?: unknown;
};

/** Конфиг только для выпуска дайджеста. Env и активный профиль LLM сюда не подмешиваются. */
export function digestLlmConfigFromStored(doc: DigestLlmStored | null | undefined): VulnContextLlmConfig {
  const endpoint =
    typeof doc?.endpoint === "string" && doc.endpoint.trim()
      ? doc.endpoint.trim()
      : DIGEST_LLM_DEFAULT_ENDPOINT;
  const model =
    typeof doc?.model === "string" && doc.model.trim()
      ? doc.model.trim()
      : endpoint.toLowerCase().includes("deepseek")
        ? DIGEST_LLM_DEFAULT_MODEL
        : "gpt-4.1-mini";
  const apiKey = typeof doc?.apiKey === "string" ? doc.apiKey.trim() : "";
  return { endpoint, apiKey, model, promptVersion: "digest-v1" };
}

/** Ключ дайджеста есть, либо endpoint локальный и ключ ему не нужен. Режим text engine не участвует. */
export function isDigestNarrativeConfigured(llm: Pick<VulnContextLlmConfig, "endpoint" | "apiKey">): boolean {
  return Boolean(llm.apiKey.trim()) || !llmEndpointRequiresApiKey(llm.endpoint);
}

/** Слайды презентации для руководства (без титульного — его рисует PDF). */
export const OPEN_DIGEST_SECTIONS = [
  "Executive Summary",
  "Месяц в цифрах",
  "Динамика CVE",
  "Критичность уязвимостей",
  "Реальная эксплуатация",
  "Топ уязвимостей",
  "Zero-day и критические события",
  "CVSS против EPSS",
  "Главные тренды",
  "Технологии под давлением",
  "Риски для крупной организации",
  "План на 72 часа",
  "План на 14–90 дней",
  "KPI и развитие VM",
  "Выводы для руководства",
  "Методология и источники"
] as const;

export type OpenDigestKpi = { value: string; label: string };
export type OpenDigestTable = { columns: string[]; rows: string[][] };
export type OpenDigestChartBar = { label: string; value: number };
export type OpenDigestChart = {
  id: string;
  /** К какому слайду привязать (title из OPEN_DIGEST_SECTIONS). */
  slide: string;
  title: string;
  kind: "bars" | "compare";
  bars: OpenDigestChartBar[];
};
export type OpenDigestSection = {
  title: string;
  /** Короткий аналитический заголовок слайда, если отличается от title. */
  headline?: string;
  paragraphs: string[];
  bullets: string[];
  table: OpenDigestTable | null;
};
export type OpenDigestDocument = {
  focus: string;
  lead: string;
  audience: string;
  kpis: OpenDigestKpi[];
  sections: OpenDigestSection[];
  closing: string;
};

const OPEN_DIGEST_SYSTEM = [
  "Ты ведущий аналитик Vulnerability Management, Threat Intelligence и Vulnerability Research.",
  "Сначала исследуй открытый интернет (web_search): NVD, CVE.org, CISA KEV, FIRST EPSS, бюллетени вендоров, CERT, исследования эксплуатации.",
  "Затем сверь найденное с переданным сырьём платформы и собери презентацию 16:9 для CISO.",
  "Ответь одним JSON-объектом без markdown.",
  "Пиши по-русски. На слайдах нужна фактура: конкретные CVE, даты, продукты, числа из источников.",
  "Не используй внутренний каталог VulnControl.",
  "Не пиши про хосты, IP, CMDB, Jira и сканеры.",
  "Не приводи код эксплуатации.",
  "Не называй CVE активно эксплуатируемой только из-за высокого CVSS/PoC/EPSS — только при KEV или явном подтверждении в источниках.",
  "Прогнозы отделяй от фактов."
].join(" ");

export function buildOpenWebDigestPrompt(monthLabel: string, sourcesText: string): string {
  return [
    `# РОЛЬ`,
    `Собери ежемесячный обзор ландшафта уязвимостей за ${monthLabel} как презентацию для CISO.`,
    "Обязательно используй web_search по открытому интернету: что публиковали NVD/CVE, что добавили в CISA KEV, какие PoC/эксплуатации и бюллетени вендоров подтверждены.",
    "Ниже — сырьё, которое платформа уже сняла с открытых фидов. Используй его как проверенную базу чисел и дополни своими находками из поиска.",
    "",
    "# ТРЕБОВАНИЯ К СОДЕРЖАНИЮ",
    "Это не новостная лента и не монолитный текст. Нужны плотные слайды с фактами: CVE, продукты, даты KEV, EPSS, сравнение с прошлым месяцем если есть в источниках.",
    "Каждый bullet — конкретный факт или управленческий вывод, а не общая фраза.",
    "Если сравнение месяцев или число недоступны — не выдумывай.",
    "",
    "# ФОРМАТ JSON",
    "Поля: focus, lead, audience, kpis, sections, closing.",
    "focus — одна строка фокуса месяца.",
    "lead — 3–5 предложений с цифрами и CVE.",
    "audience — кому это нужно, 1–2 предложения.",
    "kpis: до 4 элементов. value — число из источников, label — смысл.",
    "closing — финальная формулировка для руководства.",
    "sections — слайды строго с title:",
    OPEN_DIGEST_SECTIONS.map((title, index) => `${index + 1}. ${title}`).join("\n"),
    "У каждого section: title, headline (вывод-заголовок), paragraphs (1–2), bullets (4–7 фактов), table (или null).",
    "table обязателен у «Топ уязвимостей»: columns [CVE, Продукт, Сигнал, Риск], rows до 8.",
    "На планах — действия по конкретным продуктам/CVE из источников.",
    "",
    "СЫРЬЁ ПЛАТФОРМЫ (открытые фиды):",
    sourcesText.slice(0, 22_000)
  ].join("\n");
}

export function parseOpenWebDigest(
  raw: string,
  sourcesText: string,
  opts?: { webExpanded?: boolean }
): OpenDigestDocument | null {
  const parsed = readDigestJson(raw);
  if (!parsed) return null;
  const factPool = opts?.webExpanded ? `${sourcesText}\n${raw}` : sourcesText;
  const allowedCves = new Set([...factPool.matchAll(CVE_RE)].map((match) => match[0].toUpperCase()));
  const allowedNumbers = new Set(digestNumericTokens(factPool));
  const keep = (value: string) => cleanDigestSentence(value, allowedCves, allowedNumbers);
  const focus = keep(str(parsed.focus)).slice(0, 280);
  const lead = keep(str(parsed.lead)).slice(0, 1400);
  const audience = keep(str(parsed.audience)).slice(0, 700);
  const closing = keep(str(parsed.closing)).slice(0, 700);
  if (lead.length < 80) return null;
  const kpis = (Array.isArray(parsed.kpis) ? parsed.kpis : []).flatMap((item) => {
    if (!item || typeof item !== "object") return [];
    const row = item as { value?: unknown; label?: unknown };
    const value = str(row.value).slice(0, 24);
    const label = keep(str(row.label)).slice(0, 80);
    if (!value || !label) return [];
    const numbers = digestNumericTokens(value).filter((token) => !/^\d$/.test(token));
    if (numbers.some((token) => !allowedNumbers.has(token))) return [];
    return [{ value, label }];
  }).slice(0, 4);
  const sections = alignDigestSections(parsed.sections, keep);
  if (sections.length < 6) return null;
  return { focus, lead, audience, kpis, sections, closing };
}

export function renderOpenDigestText(doc: OpenDigestDocument): string {
  const lines: string[] = [];
  if (doc.focus) lines.push(doc.focus, "");
  lines.push(doc.lead, "");
  if (doc.audience) lines.push(doc.audience, "");
  if (doc.kpis.length) {
    lines.push(doc.kpis.map((item) => `${item.value} ${item.label}`).join("   "), "");
  }
  doc.sections.forEach((section, index) => {
    lines.push(`${index + 1}. ${section.title}`);
    for (const paragraph of section.paragraphs) lines.push(paragraph);
    for (const bullet of section.bullets) lines.push(`• ${bullet}`);
    if (section.table && section.table.rows.length) {
      lines.push(section.table.columns.join(" | "));
      for (const row of section.table.rows) lines.push(row.join(" | "));
    }
    lines.push("");
  });
  if (doc.closing) lines.push(doc.closing);
  return lines.join("\n").replace(/\n{3,}/g, "\n\n").trim();
}

export async function runOpenWebDigest(args: {
  monthLabel: string;
  sourcesText: string;
  llm: VulnContextLlmConfig;
}): Promise<{ status: "generated" | "skipped" | "failed"; text: string; searched: boolean; document: OpenDigestDocument | null }> {
  const configured = isDigestNarrativeConfigured(args.llm);
  if (!configured) return { status: "skipped", text: DIGEST_NARRATIVE_SKIPPED, searched: false, document: null };
  const prompt = buildOpenWebDigestPrompt(args.monthLabel, args.sourcesText);
  const searched = await requestDeepSeekWebDigest(args.llm, prompt);
  if (searched.ok) {
    const fromSearch = parseOpenWebDigest(searched.text, args.sourcesText, { webExpanded: true });
    if (fromSearch) {
      return {
        status: "generated",
        text: renderOpenDigestText(fromSearch),
        searched: searched.searched,
        document: fromSearch
      };
    }
  }
  const chat = await completeOpenAiChatText(args.llm, prompt, {
    temperature: 0.35,
    maxTokens: 9_000,
    maxChars: 24_000,
    timeoutMs: 180_000,
    system: OPEN_DIGEST_SYSTEM
  });
  if (!chat.ok) {
    const text = chat.reason === "not_configured" ? DIGEST_NARRATIVE_SKIPPED : DIGEST_NARRATIVE_FAILED;
    return { status: chat.reason === "not_configured" ? "skipped" : "failed", text, searched: false, document: null };
  }
  const document = parseOpenWebDigest(chat.text, args.sourcesText, { webExpanded: Boolean(searched.ok) });
  if (!document) {
    return {
      status: "failed",
      text: "Отчёт не собран: в ответе не осталось фактов, которые есть в открытых выгрузках.",
      searched: false,
      document: null
    };
  }
  return { status: "generated", text: renderOpenDigestText(document), searched: false, document };
}

function readDigestJson(raw: string): Record<string, unknown> | null {
  const trimmed = raw.trim().replace(/^```(?:json)?/i, "").replace(/```$/, "").trim();
  const start = trimmed.indexOf("{");
  const end = trimmed.lastIndexOf("}");
  if (start < 0 || end <= start) return null;
  try {
    const value = JSON.parse(trimmed.slice(start, end + 1)) as unknown;
    return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

function str(value: unknown): string {
  return String(value ?? "").replace(/\s+/g, " ").trim();
}

function cleanDigestSentence(value: string, allowedCves: Set<string>, allowedNumbers: Set<string>): string {
  const parts = value
    .replace(/\s+/g, " ")
    .split(/(?<=[.!?])\s+/)
    .map((part) => part.trim())
    .filter(Boolean);
  const kept: string[] = [];
  for (const part of parts.length ? parts : [value.trim()]) {
    if (!part || /хост|рабоч(?:ая|ие) станц|\bIP\b|CMDB|Jira|сканер/i.test(part)) continue;
    const ids = [...part.matchAll(CVE_RE)].map((match) => match[0].toUpperCase());
    if (ids.some((id) => !allowedCves.has(id))) continue;
    const numbers = digestNumericTokens(part).filter((token) => !/^\d$/.test(token));
    if (numbers.some((token) => !allowedNumbers.has(token))) continue;
    kept.push(part);
  }
  return kept.join(" ").trim();
}

function alignDigestSections(
  value: unknown,
  keep: (text: string) => string
): OpenDigestSection[] {
  const items = Array.isArray(value) ? value : [];
  const parsed = items.flatMap((item) => {
    if (!item || typeof item !== "object") return [];
    const row = item as { title?: unknown; headline?: unknown; paragraphs?: unknown; bullets?: unknown; table?: unknown };
    const headline = keep(str(row.headline)).slice(0, 160);
    return [{
      title: str(row.title),
      headline: headline || undefined,
      paragraphs: textList(row.paragraphs, keep, 3, 520),
      bullets: textList(row.bullets, keep, 6, 220),
      table: readTable(row.table, keep)
    }];
  });
  const byTitle = new Map<string, OpenDigestSection>();
  for (const section of parsed) {
    const canon = matchDigestSectionTitle(section.title);
    if (!canon || byTitle.has(canon)) continue;
    byTitle.set(canon, {
      ...section,
      title: canon,
      headline: section.headline || undefined
    });
  }
  return OPEN_DIGEST_SECTIONS.filter((title) => byTitle.has(title)).map((title) => byTitle.get(title)!);
}

function matchDigestSectionTitle(raw: string): (typeof OPEN_DIGEST_SECTIONS)[number] | null {
  const title = raw.trim();
  if (!title) return null;
  const exact = OPEN_DIGEST_SECTIONS.find((item) => item === title);
  if (exact) return exact;
  const lower = title.toLowerCase();
  const aliases: Array<[RegExp, (typeof OPEN_DIGEST_SECTIONS)[number]]> = [
    [/executive|резюме|summary/i, "Executive Summary"],
    [/месяц в цифр|метрик/i, "Месяц в цифрах"],
    [/динамик.*cve|публикац/i, "Динамика CVE"],
    [/критичност|cvss(?!.*epss)/i, "Критичность уязвимостей"],
    [/реальн.*эксплуат|kev|poc/i, "Реальная эксплуатация"],
    [/топ|top[- ]?10|значим/i, "Топ уязвимостей"],
    [/zero[- ]?day|критическ.*событ/i, "Zero-day и критические события"],
    [/cvss.*epss|epss/i, "CVSS против EPSS"],
    [/тренд/i, "Главные тренды"],
    [/технолог|продукт.*давлен/i, "Технологии под давлением"],
    [/риск.*организ/i, "Риски для крупной организации"],
    [/72\s*час|срочн/i, "План на 72 часа"],
    [/14|90\s*дн|среднесроч|стратег/i, "План на 14–90 дней"],
    [/kpi|зрелост/i, "KPI и развитие VM"],
    [/вывод.*руковод/i, "Выводы для руководства"],
    [/методолог|источник/i, "Методология и источники"]
  ];
  for (const [re, canon] of aliases) {
    if (re.test(lower) || re.test(title)) return canon;
  }
  return OPEN_DIGEST_SECTIONS.find((item) => lower.includes(item.toLowerCase().slice(0, 12))) ?? null;
}

function textList(value: unknown, keep: (text: string) => string, max: number, limit: number): string[] {
  if (!Array.isArray(value)) return [];
  return value
    .map((item) => keep(str(item)).slice(0, limit))
    .filter((item) => item.length > 0)
    .slice(0, max);
}

function readTable(value: unknown, keep: (text: string) => string): OpenDigestTable | null {
  if (!value || typeof value !== "object") return null;
  const row = value as { columns?: unknown; rows?: unknown };
  const columns = Array.isArray(row.columns) ? row.columns.map((item) => str(item).slice(0, 40)).filter(Boolean).slice(0, 4) : [];
  if (columns.length < 2) return null;
  const rows = Array.isArray(row.rows)
    ? row.rows.flatMap((item) => {
        if (!Array.isArray(item)) return [];
        const cells = item.map((cell) => keep(str(cell)).slice(0, 180));
        if (cells.length < columns.length || cells.some((cell) => !cell)) return [];
        if (!/CVE-\d{4}-\d{4,7}/i.test(cells[0] ?? "")) return [];
        return [cells.slice(0, columns.length)];
      }).slice(0, 10)
    : [];
  if (!rows.length) return null;
  return { columns, rows };
}

async function requestDeepSeekWebDigest(
  llm: VulnContextLlmConfig,
  prompt: string
): Promise<{ ok: true; text: string; searched: boolean } | { ok: false }> {
  let url: URL;
  try {
    url = new URL(llm.endpoint.trim());
  } catch {
    return { ok: false };
  }
  if (!url.hostname.toLowerCase().includes("deepseek")) return { ok: false };
  url.pathname = "/responses";
  url.search = "";
  url.hash = "";
  try {
    const res = await fetch(url.toString(), {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${llm.apiKey}`
      },
      body: JSON.stringify({
        model: llm.model.trim() || DIGEST_LLM_DEFAULT_MODEL,
        temperature: 0.3,
        max_output_tokens: 10_000,
        tools: [{ type: "web_search" }],
        tool_choice: { type: "web_search" },
        input: `${OPEN_DIGEST_SYSTEM}\n\n${prompt}`
      }),
      signal: AbortSignal.timeout(150_000)
    });
    if (!res.ok) return { ok: false };
    const data = (await res.json()) as { output_text?: unknown; output?: unknown[] };
    const text = typeof data.output_text === "string" ? data.output_text.trim() : "";
    const fromItems = Array.isArray(data.output)
      ? data.output
          .flatMap((item) => {
            if (!item || typeof item !== "object") return [];
            const row = item as { type?: string; content?: unknown };
            if (row.type !== "message" || !Array.isArray(row.content)) return [];
            return row.content.flatMap((block) => {
              if (!block || typeof block !== "object") return [];
              const textBlock = block as { type?: string; text?: string };
              return textBlock.type === "output_text" && textBlock.text ? [textBlock.text] : [];
            });
          })
          .join("\n")
          .trim()
      : "";
    const body = (text || fromItems).slice(0, 24_000);
    if (!body) return { ok: false };
    const searched = Array.isArray(data.output) && data.output.some((item) => {
      const type = item && typeof item === "object" ? (item as { type?: string }).type : "";
      return type === "web_search_call" || type === "web_search";
    });
    return { ok: true, text: body, searched: searched || body.length > 400 };
  } catch {
    return { ok: false };
  }
}

export async function runDigestNarrative(args: {
  facts: DigestNarrativeFacts;
  llm: VulnContextLlmConfig;
  kind?: "window" | "month";
}): Promise<DigestNarrativeOutcome> {
  const factsText = digestFactsText(args.facts);
  const configured = isDigestNarrativeConfigured(args.llm);
  const blank: DigestStoryParts = { lead: "", summary: "", cases: "", close: "" };
  if (!configured) {
    return { status: "skipped", text: DIGEST_NARRATIVE_SKIPPED, ...blank, lead: DIGEST_NARRATIVE_SKIPPED };
  }
  const prompt =
    args.kind === "month" ? buildMonthlyDigestPrompt(factsText) : buildDigestNarrativePrompt(factsText);
  const chat = await completeOpenAiChatText(args.llm, prompt, {
    temperature: 0,
    maxTokens: 1400
  });
  if (!chat.ok) {
    const text = chat.reason === "not_configured" ? DIGEST_NARRATIVE_SKIPPED : DIGEST_NARRATIVE_FAILED;
    return {
      status: chat.reason === "not_configured" ? "skipped" : "failed",
      text,
      ...blank,
      lead: text
    };
  }
  const parts = composeDigestStory(chat.text, factsText);
  const text = [parts.lead, parts.summary, parts.cases, parts.close].filter(Boolean).join("\n\n");
  if (!text) return { status: "failed", text: DIGEST_NARRATIVE_REJECTED, ...blank, lead: DIGEST_NARRATIVE_REJECTED };
  return { status: "generated", text, ...parts };
}
