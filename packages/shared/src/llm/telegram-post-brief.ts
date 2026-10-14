import { completeOpenAiChatText, type VulnContextLlmConfig } from "./vuln-context-engine.js";
import { DIGEST_LLM_DEFAULT_MODEL, isDigestNarrativeConfigured } from "./digest-narrative.js";
import type { VulnTelegramPostInput } from "../telegram/vuln-post.js";

const SYSTEM = [
  "Ты редактор зрелых постов про уязвимости для Telegram-канала банка.",
  "Пиши только по-русски, деловым аналитическим стилем, без воды и без канцелярита.",
  "Ответ — один JSON-объект без markdown.",
  "Не выдумывай CVE, версии, даты, EPSS, KEV и ссылки, которых нет в материалах.",
  "Суть, ход атаки и риски — разные блоки: суть = что сломано, ход атаки = короткие шаги, риски = последствия.",
  "Ход атаки — 3–4 коротких шага для руководства, без кода и без жаргона.",
  "Не пиши про хосты, IP, инвентаризацию и периметр.",
  "Не приводи код эксплуатации."
].join(" ");

export type TelegramPostBrief = {
  lead: string;
  essence: string[];
  attackFlow: string[];
  risks: string[];
  recommendations: string[];
  vulnType: string | null;
  exploitation: string | null;
  product: string | null;
};

export async function matureTelegramPostWithDeepSeek(args: {
  input: VulnTelegramPostInput;
  llm: VulnContextLlmConfig;
  extras?: {
    productHint?: string | null;
    facts?: string[];
    attackFlow?: string[];
    affectedVersions?: string[];
  };
}): Promise<{ ok: true; input: VulnTelegramPostInput; usedLlm: boolean } | { ok: false; reason: "not_configured" | "failed" }> {
  if (!isDigestNarrativeConfigured(args.llm)) return { ok: false, reason: "not_configured" };
  const prompt = buildPrompt(args.input, args.extras);
  const chat = await completeOpenAiChatText(args.llm, prompt, {
    temperature: 0.25,
    maxTokens: 2200,
    maxChars: 6000,
    timeoutMs: 90_000,
    system: SYSTEM
  });
  if (!chat.ok) return { ok: false, reason: "failed" };
  const brief = parseBrief(chat.text);
  if (!brief) return { ok: false, reason: "failed" };
  return { ok: true, usedLlm: true, input: applyBrief(args.input, brief, args.extras ?? {}) };
}

function buildPrompt(
  input: VulnTelegramPostInput,
  extras?: {
    productHint?: string | null;
    facts?: string[];
    attackFlow?: string[];
    affectedVersions?: string[];
  }
): string {
  return [
    `Собери зрелый русскоязычный каркас поста для ${input.identifier}.`,
    "Если исходное описание на английском — переведи смысл, не копируй дословно.",
    "Поля JSON: lead, essence, attackFlow, risks, recommendations, vulnType, exploitation, product.",
    "lead — одно короткое предложение для шапки ℹ️.",
    "essence — 2–4 предложения сути (механика), массив строк.",
    "attackFlow — 3–4 коротких шага хода атаки для руководства. Формат шага: «Короткий заголовок: одно предложение». Порядок: условие/вход → слабость → результат.",
    "risks — 2–4 последствия, не повторяй essence и не дублируй attackFlow.",
    "recommendations — 2–4 действия по закрытию из материалов.",
    "vulnType — короткий тип по-русски (например «обход ограничения пути»), без CWE-кода если есть нормальное имя.",
    "exploitation — одна строка статуса эксплуатации по-русски.",
    "product — название продукта по-русски/как принято, если видно из материалов.",
    "",
    "МАТЕРИАЛЫ:",
    `Идентификатор: ${input.identifier}`,
    `Заголовок: ${input.title}`,
    `Описание: ${input.description}`,
    `Класс: ${input.vulnerabilityClass ?? "—"}`,
    `CVSS: ${input.cvssScore ?? "—"}`,
    `Эксплуатация сейчас: ${input.exploitation}`,
    extras?.productHint ? `Продукт из каталога: ${extras.productHint}` : "",
    extras?.affectedVersions?.length ? `Версии: ${extras.affectedVersions.join("; ")}` : "",
    extras?.facts?.length ? `Фактура:\n- ${extras.facts.slice(0, 8).join("\n- ")}` : "",
    extras?.attackFlow?.length ? `Схема атаки:\n- ${extras.attackFlow.slice(0, 6).join("\n- ")}` : "",
    input.risks?.length ? `Черновик рисков:\n- ${input.risks.join("\n- ")}` : "",
    input.recommendations.length ? `Черновик рекомендаций:\n- ${input.recommendations.join("\n- ")}` : "",
    input.sourceUrls.length ? `Ссылки: ${input.sourceUrls.slice(0, 6).join(" ")}` : ""
  ]
    .filter(Boolean)
    .join("\n")
    .slice(0, 12_000);
}

function parseBrief(raw: string): TelegramPostBrief | null {
  const parsed = readJson(raw);
  if (!parsed) return null;
  const essence = lines(parsed.essence);
  const attackFlow = lines(parsed.attackFlow);
  const risks = lines(parsed.risks);
  const recommendations = lines(parsed.recommendations);
  const lead = clean(parsed.lead) || essence[0] || "";
  if (essence.length < 1 || lead.length < 20) return null;
  return {
    lead: lead.slice(0, 400),
    essence: essence.slice(0, 4),
    attackFlow: attackFlow.slice(0, 5),
    risks: risks.slice(0, 4),
    recommendations: recommendations.slice(0, 4),
    vulnType: clean(parsed.vulnType).slice(0, 120) || null,
    exploitation: clean(parsed.exploitation).slice(0, 280) || null,
    product: clean(parsed.product).slice(0, 90) || null
  };
}

function applyBrief(
  input: VulnTelegramPostInput,
  brief: TelegramPostBrief,
  extras?: { productHint?: string | null; affectedVersions?: string[]; attackFlow?: string[] }
): VulnTelegramPostInput {
  const description = [brief.lead, ...brief.essence.filter((line) => line !== brief.lead)].join(" ");
  const product = brief.product || extras?.productHint || null;
  const attackFlow =
    brief.attackFlow.length > 0
      ? brief.attackFlow
      : extras?.attackFlow?.length
        ? extras.attackFlow
        : input.attackFlow;
  return {
    ...input,
    title: product && !/CVE-\d{4}-\d+/i.test(product) ? product : input.title,
    description: description.slice(0, 4000) || input.description,
    vulnerabilityClass: brief.vulnType || input.vulnerabilityClass,
    exploitation: brief.exploitation || input.exploitation,
    attackFlow,
    risks: brief.risks.length ? brief.risks : input.risks,
    recommendations: brief.recommendations.length ? brief.recommendations : input.recommendations,
    affectedVersions: extras?.affectedVersions?.length ? extras.affectedVersions : input.affectedVersions
  };
}

function readJson(raw: string): Record<string, unknown> | null {
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

function clean(value: unknown): string {
  return String(value ?? "")
    .replace(/```[\s\S]*?```/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function lines(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value
      .map((item) => clean(item))
      .filter((line) => line.length > 8 && line.length < 320)
      .filter((line) => !/инвентаризац|рабоч(?:ая|ие) станц|\bIP\b|хост/i.test(line));
  }
  const one = clean(value);
  return one ? [one] : [];
}

/** @internal model hint for callers that log */
export const TELEGRAM_POST_LLM_MODEL = DIGEST_LLM_DEFAULT_MODEL;
