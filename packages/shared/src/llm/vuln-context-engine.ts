import { Agent, fetch as undiciFetch } from "undici";
import {
  LLM_NOT_CONFIGURED_OUTPUT_TEXT,
  LLM_NOT_CONFIGURED_SUMMARY_PREFIX
} from "../ai/enrichment-placeholder.js";
import { isGenericEnrichmentTitle } from "../ai/enrichment-display.js";
import { augmentEnrichmentWithNvdFixes } from "../cve/nvd-fix-signals.js";
import { buildBaselineEnrichmentFromBdu, type BduBaselineInput } from "../bdu/baseline-enrichment.js";
import { buildBaselineEnrichmentFromNvd } from "../cve/baseline-enrichment.js";
import { DEFAULT_SYSTEM_POLICY, sha256Hex, stableJsonStringify } from "../security/prompt-safety.js";
import {
  buildVocTaskBriefFallback,
  type VocTaskBriefInput,
  type VocTaskBriefOutput
} from "../voc/task-brief.js";
import {
  buildVocPlaybookFromContext,
  playbookFromStepLabels,
  type VocPlaybookContextInput
} from "../voc/playbook-context.js";
import type { VocPlaybook } from "../voc/verification.js";

export type { VocTaskBriefInput, VocTaskBriefOutput };

export type VulnContextLlmConfig = {
  endpoint: string;
  apiKey: string;
  model: string;
  promptVersion: string;
};

export type TextEngineMode = "baseline" | "translate" | "llm";

export type TextEngineSettings = {
  textEngine: TextEngineMode;
  translateEndpoint: string;
};

export function normalizeTextEngineMode(value: unknown): TextEngineMode {
  const s = typeof value === "string" ? value.trim().toLowerCase() : "";
  return s === "translate" || s === "llm" ? s : "baseline";
}

function defaultModelForEndpoint(endpoint: string): string {
  const u = endpoint.toLowerCase();
  if (u.includes("dashscope")) return "qwen-turbo";
  if (u.includes("x.ai")) return "grok-4.20-reasoning";
  return "gpt-4.1-mini";
}

function trimEnv(s: string | undefined): string {
  if (s == null) return "";
  const t = s.trim();
  if (
    (t.startsWith('"') && t.endsWith('"') && t.length >= 2) ||
    (t.startsWith("'") && t.endsWith("'") && t.length >= 2)
  ) {
    return t.slice(1, -1).trim();
  }
  return t;
}

export function getTextEngineSettingsFromEnv(): TextEngineSettings {
  return {
    textEngine: normalizeTextEngineMode(process.env.TEXT_ENGINE),
    translateEndpoint: trimEnv(process.env.LIBRETRANSLATE_URL)
  };
}

export function mergeTextEngineSettings(
  base: TextEngineSettings,
  patch: Partial<TextEngineSettings> | null | undefined
): TextEngineSettings {
  if (!patch) return base;
  return {
    textEngine: normalizeTextEngineMode(patch.textEngine ?? base.textEngine),
    translateEndpoint:
      typeof patch.translateEndpoint === "string" ? patch.translateEndpoint.trim() : base.translateEndpoint
  };
}

export function getVulnContextLlmConfigFromEnv(): VulnContextLlmConfig {
  const endpoint =
    trimEnv(process.env.LLM_ENDPOINT) || "https://api.openai.com/v1/chat/completions";
  return {
    endpoint,
    apiKey: trimEnv(
      process.env.LLM_API_KEY ?? process.env.XAI_API_KEY ?? process.env.DASHSCOPE_API_KEY ?? ""
    ),
    model: trimEnv(process.env.LLM_MODEL) || defaultModelForEndpoint(endpoint),
    promptVersion: trimEnv(process.env.LLM_PROMPT_VERSION) || "v1"
  };
}

/** Слияние env-базы с переопределениями из БД (активный профиль в админке). */
export function mergeVulnContextLlmConfig(
  base: VulnContextLlmConfig,
  patch: Partial<VulnContextLlmConfig> | null | undefined
): VulnContextLlmConfig {
  if (!patch) return base;
  return {
    endpoint: typeof patch.endpoint === "string" && patch.endpoint.trim().length > 0 ? patch.endpoint.trim() : base.endpoint,
    apiKey: patch.apiKey !== undefined ? patch.apiKey : base.apiKey,
    model: typeof patch.model === "string" && patch.model.trim().length > 0 ? patch.model.trim() : base.model,
    promptVersion:
      typeof patch.promptVersion === "string" && patch.promptVersion.trim().length > 0
        ? patch.promptVersion.trim()
        : base.promptVersion
  };
}

type LlmJson = Record<string, unknown>;

type LlmGraph = {
  nodes: { id: string; label: string; type: "attacker" | "vector" | "asset" | "service" | "impact" }[];
  edges: { from: string; to: string; label: string }[];
};

function contentFromMessage(msg: Record<string, unknown> | undefined): string | null {
  if (!msg) return null;
  const c = msg.content;
  if (typeof c === "string") {
    const t = c.trim();
    return t.length > 0 ? t : null;
  }
  if (Array.isArray(c)) {
    const parts = c
      .map((p: unknown) => {
        if (typeof p === "string") return p;
        if (p && typeof p === "object") {
          const o = p as { type?: string; text?: string; content?: string };
          if (typeof o.text === "string") return o.text;
          if (typeof o.content === "string") return o.content;
        }
        return "";
      })
      .filter(Boolean);
    const joined = parts.join("\n").trim();
    return joined.length > 0 ? joined : null;
  }
  const reasoning = msg.reasoning_content;
  if (typeof reasoning === "string" && reasoning.trim().length > 0) return reasoning.trim();
  return null;
}

function extractAssistantContent(data: unknown): string | null {
  const choices = (data as { choices?: unknown[] })?.choices;
  if (!Array.isArray(choices) || choices.length === 0) return null;

  for (const raw of choices) {
    if (!raw || typeof raw !== "object") continue;
    const choice = raw as {
      message?: Record<string, unknown>;
      delta?: Record<string, unknown>;
      text?: string;
    };
    if (typeof choice.text === "string" && choice.text.trim().length > 0) {
      return choice.text.trim();
    }
    const msg = (choice.message ?? choice.delta) as Record<string, unknown> | undefined;
    const fromMsg = contentFromMessage(msg);
    if (fromMsg) return fromMsg;
  }
  return null;
}

/** x.ai POST /v1/responses — text lives in output[].content[] (output_text blocks). */
function extractXaiResponsesText(data: unknown): string | null {
  const root = data as { output?: unknown; error?: unknown };
  if (root.error && typeof root.error === "object") {
    const e = root.error as { message?: string; code?: string };
    const msg = [e.code, e.message].filter(Boolean).join(": ");
    if (msg.length > 0) throw new Error(`x.ai API error: ${msg}`);
  }
  const output = root.output;
  if (!Array.isArray(output)) return null;
  const parts: string[] = [];
  for (const item of output) {
    if (!item || typeof item !== "object") continue;
    const o = item as { type?: string; role?: string; content?: unknown };
    if (o.type !== "message" || o.role !== "assistant") continue;
    const content = o.content;
    if (typeof content === "string") {
      const t = content.trim();
      if (t.length > 0) parts.push(t);
      continue;
    }
    if (!Array.isArray(content)) continue;
    for (const block of content) {
      if (!block || typeof block !== "object") continue;
      const b = block as { type?: string; text?: string };
      if (b.type === "output_text" && typeof b.text === "string") parts.push(b.text);
    }
  }
  const joined = parts.join("\n").trim();
  return joined.length > 0 ? joined : null;
}

function isXaiResponsesEndpoint(endpoint: string): boolean {
  try {
    const u = new URL(endpoint);
    return u.hostname.includes("x.ai") && u.pathname.replace(/\/$/, "").endsWith("/responses");
  } catch {
    const lower = endpoint.toLowerCase();
    return lower.includes("x.ai") && lower.includes("/responses");
  }
}

function extractModelText(data: unknown, endpoint: string): string | null {
  if (isXaiResponsesEndpoint(endpoint)) {
    return extractXaiResponsesText(data);
  }
  return extractAssistantContent(data);
}

function stripCodeFences(s: string): string {
  let t = s.trim();
  const embedded = t.match(/```(?:json)?\s*\r?\n?([\s\S]*?)\r?\n?```/i);
  if (embedded?.[1]) return embedded[1].trim();
  const block = /^```(?:json)?\s*\r?\n?([\s\S]*?)\r?\n?```$/im;
  const m = t.match(block);
  if (m?.[1]) return m[1].trim();
  if (t.startsWith("```")) {
    t = t.replace(/^```(?:json)?\s*/i, "").replace(/\s*```\s*$/m, "");
  }
  return t.trim();
}

function tryParseLlmJson(raw: string): LlmJson | null {
  const stripped = stripCodeFences(raw);
  try {
    const v = JSON.parse(stripped) as unknown;
    if (v && typeof v === "object" && !Array.isArray(v)) return v as LlmJson;
    return null;
  } catch {
    const first = stripped.indexOf("{");
    const last = stripped.lastIndexOf("}");
    if (first >= 0 && last > first) {
      try {
        const v = JSON.parse(stripped.slice(first, last + 1)) as unknown;
        if (v && typeof v === "object" && !Array.isArray(v)) return v as LlmJson;
      } catch {
        /* fall through */
      }
    }
    return null;
  }
}

function isCleanSummaryText(s: unknown): s is string {
  if (typeof s !== "string") return false;
  const t = s.trim();
  if (!t || t.startsWith("{") || t.startsWith("[")) return false;
  if (t.length > 2000) return false;
  if (t.includes('"attackFlow"') && t.includes('"description"')) return false;
  return true;
}

function strOrEmpty(v: unknown): string {
  return typeof v === "string" ? v.trim() : "";
}

function strArray(v: unknown): string[] {
  return Array.isArray(v) ? v.map((x) => String(x)).filter(Boolean) : [];
}

function defaultExploitation(parsed: LlmJson) {
  const e = parsed.exploitation;
  if (e && typeof e === "object" && !Array.isArray(e)) return e;
  return { publicExploit: "unknown" as const, exploitNotes: null };
}

function defaultApplicability(parsed: LlmJson) {
  const a = parsed.applicability;
  if (a && typeof a === "object" && !Array.isArray(a)) return a;
  return { status: "unknown" as const, notes: null };
}

function defaultGraph(parsed: LlmJson) {
  const g = parsed.graph;
  if (g && typeof g === "object" && !Array.isArray(g)) return g;
  return { nodes: [], edges: [] };
}

/** Частичный, но читаемый ответ модели (без graph/remediation и т.д.) — не заливать raw JSON в summary. */
function coercePartialAnalysisEnvelope(parsed: LlmJson): LlmJson | null {
  const summary = strOrEmpty(parsed.summary);
  if (!isCleanSummaryText(summary)) return null;
  const title = strOrEmpty(parsed.title) || "Анализ уязвимости";
  let description = strOrEmpty(parsed.description);
  if (description.length > 2800) description = `${description.slice(0, 2800)}…`;
  return {
    title,
    summary,
    description,
    vulnerabilityClass:
      typeof parsed.vulnerabilityClass === "string" ? parsed.vulnerabilityClass : null,
    attackFlow: strArray(parsed.attackFlow),
    exploitation: defaultExploitation(parsed),
    consequences: strArray(parsed.consequences),
    remediation: strArray(parsed.remediation),
    applicability: defaultApplicability(parsed),
    nextSteps: strArray(parsed.nextSteps),
    questions: strArray(parsed.questions),
    sources: Array.isArray(parsed.sources) ? parsed.sources : [],
    graph: defaultGraph(parsed),
    uncertainties: strArray(parsed.uncertainties),
    exploitNarrative: typeof parsed.exploitNarrative === "string" ? parsed.exploitNarrative : null
  };
}

function normalizeOutputJson(parsed: LlmJson | null, rawContent: string): LlmJson {
  const rawSnippet = rawContent.length > 12_000 ? `${rawContent.slice(0, 12_000)}…` : rawContent;
  if (!parsed) {
    return {
      title: "Модель вернула не-JSON",
      summary: "Модель вернула не-JSON. Использую текст как черновик.",
      description: rawSnippet.slice(0, 4000),
      vulnerabilityClass: null,
      attackFlow: [],
      exploitation: {
        publicExploit: "unknown",
        exploitNotes: null
      },
      exploitNarrative: null,
      consequences: [],
      remediation: [],
      graph: { nodes: [], edges: [] },
      applicability: {
        status: "unknown",
        notes: "Не удалось распарсить структурированный ответ модели."
      },
      nextSteps: [],
      questions: [],
      sources: [],
      uncertainties: [],
      raw_text: rawSnippet
    };
  }

  // v2+ schema: the new "bank-grade" analysis block.
  const hasV2Shape =
    typeof parsed.title === "string" &&
    typeof parsed.summary === "string" &&
    typeof parsed.description === "string" &&
    Array.isArray(parsed.attackFlow) &&
    Array.isArray(parsed.consequences) &&
    Array.isArray(parsed.remediation) &&
    Array.isArray(parsed.nextSteps) &&
    Array.isArray(parsed.questions) &&
    Array.isArray(parsed.sources) &&
    parsed.graph != null &&
    typeof parsed.graph === "object" &&
    parsed.applicability != null &&
    typeof parsed.applicability === "object" &&
    parsed.exploitation != null &&
    typeof parsed.exploitation === "object";

  if (hasV2Shape && isCleanSummaryText(parsed.summary)) return parsed;

  const partial = parsed ? coercePartialAnalysisEnvelope(parsed) : null;
  if (partial) {
    const attackFlow = partial.attackFlow;
    const graph = partial.graph as { nodes?: unknown[]; edges?: unknown[] } | undefined;
    const graphEmpty =
      !graph ||
      ((!graph.nodes || graph.nodes.length === 0) && (!graph.edges || graph.edges.length === 0));
    if (graphEmpty && Array.isArray(attackFlow) && attackFlow.length > 0) {
      return {
        ...partial,
        graph: deriveGraphFromAttackFlow({
          cveId: typeof parsed?.id === "string" ? parsed.id : "CVE",
          attackFlow: attackFlow.map(String),
          summary: typeof partial.summary === "string" ? partial.summary : undefined,
          explanation: typeof partial.description === "string" ? partial.description : undefined
        })
      };
    }
    return partial;
  }

  const vuln = (parsed.vulnerability as Record<string, unknown> | undefined) ?? undefined;
  const vulnTitle = vuln && typeof vuln.title === "string" ? vuln.title : null;
  const vulnDesc = vuln && typeof vuln.description === "string" ? vuln.description : null;
  const rootId = typeof parsed.id === "string" ? parsed.id : null;
  const rootDesc = typeof parsed.description === "string" ? parsed.description : null;

  const vulnTitleTrim = (vulnTitle ?? "").trim();
  const fallbackSummary =
    vulnTitleTrim && !isGenericEnrichmentTitle(vulnTitleTrim)
      ? vulnTitleTrim
      : rootDesc?.trim() || rawSnippet.slice(0, 4000);
  const fallbackDescription = (vulnDesc ?? "").trim() || rootDesc?.trim() || rawSnippet.slice(0, 4000);

  // Some local models (e.g. smaller Qwen) can ignore schema instructions.
  // Normalize into the expected envelope so downstream UI/code has stable keys.
  return {
    title:
      vulnTitleTrim && !isGenericEnrichmentTitle(vulnTitleTrim)
        ? vulnTitleTrim
        : rootId
          ? `Уязвимость ${rootId}`
          : "Уязвимость",
    summary: fallbackSummary,
    description: fallbackDescription,
    vulnerabilityClass: null,
    attackFlow: [],
    exploitation: {
      publicExploit: "unknown",
      exploitNotes: null
    },
    exploitNarrative: null,
    consequences: [],
    remediation: [],
    applicability: {
      status: "unknown",
      notes: null
    },
    nextSteps: [],
    questions: [],
    sources: [],
    graph: { nodes: [], edges: [] },
    uncertainties: [],
    raw_model_json: parsed
  };
}

function readTokenUsage(usage: unknown): { inTok?: number; outTok?: number } {
  if (!usage || typeof usage !== "object") return {};
  const u = usage as Record<string, unknown>;
  const inTok =
    (typeof u.prompt_tokens === "number" ? u.prompt_tokens : undefined) ??
    (typeof u.input_tokens === "number" ? u.input_tokens : undefined) ??
    (typeof u.promptTokens === "number" ? u.promptTokens : undefined);
  const outTok =
    (typeof u.completion_tokens === "number" ? u.completion_tokens : undefined) ??
    (typeof u.output_tokens === "number" ? u.output_tokens : undefined) ??
    (typeof u.completionTokens === "number" ? u.completionTokens : undefined);
  return {
    inTok: typeof inTok === "number" ? inTok : undefined,
    outTok: typeof outTok === "number" ? outTok : undefined
  };
}

/** Разворачивает цепочку Error.cause и errno — иначе Node даёт голое «fetch failed». */
function formatLlmTransportError(err: unknown): string {
  const parts: string[] = [];
  const seen = new Set<string>();
  let cur: unknown = err;
  for (let depth = 0; depth < 10 && cur != null; depth++) {
    if (cur instanceof Error) {
      const line = cur.message.trim();
      if (line.length > 0 && !seen.has(line)) {
        seen.add(line);
        parts.push(line);
      }
      const ne = cur as NodeJS.ErrnoException & {
        code?: string;
        syscall?: string;
        address?: string;
        port?: number;
      };
      const meta = [
        ne.code ? `code=${ne.code}` : "",
        ne.syscall ? `syscall=${ne.syscall}` : "",
        ne.address != null ? `address=${ne.address}` : "",
        ne.port != null ? `port=${ne.port}` : ""
      ]
        .filter(Boolean)
        .join(" ");
      if (meta.length > 0 && !seen.has(meta)) {
        seen.add(meta);
        parts.push(meta);
      }
      cur = cur.cause;
    } else {
      const s = String(cur).trim();
      if (s.length > 0 && !seen.has(s)) parts.push(s);
      break;
    }
  }
  return parts.length > 0 ? parts.join(" · ") : "unknown error";
}

function hintForLlmTransportFailure(detail: string): string {
  const d = detail.toLowerCase();
  if (d.includes("econnrefused") || d.includes("econnreset") || d.includes("enotfound")) {
    return " Подсказка: до хоста с Ollama нет TCP (firewall, другой IP, Ollama слушает только 127.0.0.1 на той машине — нужен 0.0.0.0:11434). Проверьте ping и curl с машины, где запущен API.";
  }
  if (d.includes("etimedout") || d.includes("timeout")) {
    return " Подсказка: таймаут сети или долгий ответ GPU — проверьте Wi‑Fi/VPN, LLM_TIMEOUT_MS и очередь на Ollama.";
  }
  if (d.includes("enetunreach") || d.includes("ehostunreach")) {
    return " Подсказка: маршрут до 192.168.x недоступен (VPN, другая подсеть, отключённый интерфейс).";
  }
  return "";
}

let ollamaUndiciAgent: Agent | undefined;

function getOllamaUndiciAgent(overallTimeoutMs: number): Agent {
  if (ollamaUndiciAgent) return ollamaUndiciAgent;
  const connectMs = Math.max(
    15_000,
    Math.min(600_000, Number(process.env.LLM_OLLAMA_CONNECT_TIMEOUT_MS ?? 120_000))
  );
  const useIpv4 = process.env.LLM_OLLAMA_FORCE_IPV4 !== "false";
  ollamaUndiciAgent = new Agent({
    connect: useIpv4 ? { family: 4, timeout: connectMs } : { timeout: connectMs },
    connectTimeout: connectMs,
    headersTimeout: Math.min(600_000, overallTimeoutMs + 30_000),
    bodyTimeout: Math.min(600_000, overallTimeoutMs + 30_000)
  });
  return ollamaUndiciAgent;
}

function isPrivateNetworkHost(hostname: string): boolean {
  const h = hostname.trim().toLowerCase();
  if (h === "localhost" || h.endsWith(".local")) return true;
  if (h === "host.docker.internal") return true;
  if (h === "127.0.0.1") return true;

  // IPv4 RFC1918 + link-local (common for LAN Ollama).
  const m = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  const a = Number(m[1]);
  const b = Number(m[2]);
  const c = Number(m[3]);
  const d = Number(m[4]);
  const ok = [a, b, c, d].every((n) => Number.isInteger(n) && n >= 0 && n <= 255);
  if (!ok) return false;

  if (a === 10) return true;
  if (a === 192 && b === 168) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 169 && b === 254) return true;
  return false;
}

function requiresApiKey(endpoint: string): boolean {
  const u = endpoint.toLowerCase();
  if (u.includes("ollama")) return false;
  try {
    const url = new URL(endpoint);
    if (isPrivateNetworkHost(url.hostname)) return false;
  } catch {
    // Fallback heuristic for non-URL endpoints.
    if (u.includes("127.0.0.1") || u.includes("localhost")) return false;
    if (u.includes("192.168.") || u.includes("10.") || u.includes("172.16.") || u.includes("172.17.")) return false;
  }
  return true;
}

/** LAN/локальный Ollama (OpenAI-совместимый /v1/chat/completions). */
export function isLikelyOllamaOpenAiEndpoint(endpoint: string): boolean {
  const u = endpoint.trim().toLowerCase();
  if (u.includes("ollama")) return true;
  if (u.includes(":11434")) return true;
  try {
    const url = new URL(endpoint);
    return url.port === "11434";
  } catch {
    return false;
  }
}

function effectiveOllamaMaxOutputTokens(): number {
  const raw = process.env.LLM_OLLAMA_MAX_TOKENS?.trim();
  if (raw != null && raw !== "" && !Number.isNaN(Number(raw))) {
    return Math.max(256, Math.min(16_384, Number(raw)));
  }
  /** JSON-сводка обычно укладывается в 2–4k токенов; лимит ускоряет ответ и снижает риск таймаута. */
  return 4096;
}

function effectiveLlmTimeoutMs(endpoint: string): number {
  const raw = process.env.LLM_TIMEOUT_MS?.trim();
  if (raw != null && raw !== "" && !Number.isNaN(Number(raw))) {
    return Math.max(5_000, Number(raw));
  }
  // Ollama/LAN: 7B на GPU и очередь из ai.enrich часто >120s; без LLM_TIMEOUT_MS даём 5 мин.
  return isLikelyOllamaOpenAiEndpoint(endpoint) ? 300_000 : 45_000;
}

function effectiveRawJsonMaxChars(endpoint: string): number {
  const raw = process.env.LLM_RAW_MAX_CHARS?.trim();
  if (raw != null && raw !== "" && !Number.isNaN(Number(raw))) {
    return Math.max(2_000, Math.min(50_000, Number(raw)));
  }
  return isLikelyOllamaOpenAiEndpoint(endpoint) ? 8_000 : 12_000;
}

/** Явно: нужен ли Bearer для этого endpoint (false = локальный/LAN Ollama и т.п.). */
export function llmEndpointRequiresApiKey(endpoint: string): boolean {
  return requiresApiKey(endpoint);
}

function toLowerText(x: unknown): string {
  return typeof x === "string" ? x.toLowerCase() : "";
}

function deriveGraphFromAttackFlow(args: {
  cveId: string;
  attackFlow: string[];
  summary?: string;
  explanation?: string;
}): LlmGraph {
  const text = `${args.summary ?? ""}\n${args.explanation ?? ""}\n${args.attackFlow.join("\n")}`.toLowerCase();

  const extras: { id: string; label: string; type: LlmGraph["nodes"][number]["type"] }[] = [];
  const extraEdges: LlmGraph["edges"] = [];

  const has = (...needles: string[]) => needles.some((n) => text.includes(n));

  const techniqueLabel = has("десериал", "deserialize", "serialization")
    ? "Техника: десериализация"
    : has("инъекц", "injection")
      ? "Техника: инъекция"
      : has("ssrf")
        ? "Техника: SSRF"
        : has("xss")
          ? "Техника: XSS"
          : has("path traversal", "directory traversal", "обход пут", "../")
            ? "Техника: Path Traversal"
            : null;

  if (techniqueLabel) {
    extras.push({ id: "technique", label: techniqueLabel, type: "vector" });
    extraEdges.push({ from: "vector", to: "technique", label: "эксплуатирует" });
    extraEdges.push({ from: "technique", to: "service", label: "триггерит" });
  }

  const protoLabels: string[] = [];
  if (has("http", "https", "заголов", "header")) protoLabels.push("HTTP");
  if (has("ldap")) protoLabels.push("LDAP");
  if (has("jndi")) protoLabels.push("JNDI");
  if (has("dns")) protoLabels.push("DNS");

  if (protoLabels.length > 0) {
    extras.push({ id: "proto", label: `Протоколы: ${protoLabels.join(", ")}`, type: "vector" });
    extraEdges.push({ from: "vector", to: "proto", label: "канал" });
    extraEdges.push({ from: "proto", to: "service", label: "достигает" });
  }

  const impactLabel =
    text.includes("rce") || text.includes("выполн") || text.includes("код")
      ? "Выполнение кода"
      : text.includes("утеч") || text.includes("конфиденц")
        ? "Утечка данных"
        : text.includes("dos") || text.includes("отказ") || text.includes("доступност")
          ? "Отказ в обслуживании"
          : "Компрометация";

  const vectorLabel =
    text.includes("http") || text.includes("заголов") || text.includes("header") || text.includes("api")
      ? "Сетевой запрос (HTTP/API)"
      : text.includes("email") || text.includes("письм")
        ? "Письмо/вложение"
        : text.includes("file") || text.includes("файл")
          ? "Файл/документ"
          : "Входной вектор";

  const serviceLabel =
    text.includes("log4j") ? "Уязвимый компонент: Log4j" : `Уязвимый компонент (${args.cveId})`;

  const nodes: LlmGraph["nodes"] = [
    { id: "attacker", label: "Злоумышленник", type: "attacker" },
    { id: "vector", label: vectorLabel, type: "vector" },
    { id: "service", label: serviceLabel, type: "service" },
    { id: "asset", label: "Целевая система/сервис", type: "asset" },
    { id: "impact", label: `Воздействие: ${impactLabel}`, type: "impact" }
  ];

  const edges: LlmGraph["edges"] = [
    { from: "attacker", to: "vector", label: "использует" },
    { from: "vector", to: "service", label: "доставляет payload" },
    { from: "service", to: "asset", label: "затрагивает" },
    { from: "asset", to: "impact", label: "приводит к" }
  ];

  return { nodes: [...nodes, ...extras], edges: [...edges, ...extraEdges] };
}

export type VulnContextLlmResult = {
  inputHash: string;
  outputJson: LlmJson;
  outputText?: string;
  tokensInput?: number;
  tokensOutput?: number;
  costUsd?: number;
  model: string;
  promptVersion: string;
};

function libreTranslateUrl(endpoint: string): string {
  const raw = endpoint.trim();
  if (!raw) return "";
  try {
    const url = new URL(raw);
    if (!url.pathname.replace(/\/+$/g, "").endsWith("/translate")) {
      url.pathname = `${url.pathname.replace(/\/+$/g, "")}/translate`;
    }
    return url.toString();
  } catch {
    return raw.replace(/\/+$/g, "").endsWith("/translate") ? raw : `${raw.replace(/\/+$/g, "")}/translate`;
  }
}

function likelyEnglishText(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const s = value.trim();
  if (s.length < 12) return false;
  const asciiLetters = (s.match(/[A-Za-z]/g) ?? []).length;
  const cyrillic = (s.match(/[А-Яа-яЁё]/g) ?? []).length;
  return asciiLetters >= 8 && asciiLetters > cyrillic;
}

async function translateLibreText(text: string, endpoint: string): Promise<string> {
  const url = libreTranslateUrl(endpoint);
  if (!url) return text;
  const timeoutMs = Math.max(1000, Math.min(30_000, Number(process.env.TEXT_TRANSLATE_TIMEOUT_MS ?? 8000)));
  const maxAttempts = Math.max(1, Math.min(4, Number(process.env.TEXT_TRANSLATE_RETRIES ?? 2)));
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify({ q: text, source: "en", target: "ru", format: "text" }),
        signal: AbortSignal.timeout(timeoutMs)
      });
      // 429/5xx: keep RU baseline text; BG sweep upgrades when quota recovers.
      if (res.status === 429 || res.status >= 500) {
        if (attempt + 1 < maxAttempts) {
          await new Promise((r) => setTimeout(r, 400 * (attempt + 1)));
          continue;
        }
        return text;
      }
      if (!res.ok) return text;
      const data = (await res.json()) as { translatedText?: unknown; error?: unknown };
      if (typeof data.error === "string" && data.error.trim()) return text;
      const translated = typeof data.translatedText === "string" ? data.translatedText.trim() : "";
      return translated || text;
    } catch {
      if (attempt + 1 < maxAttempts) {
        await new Promise((r) => setTimeout(r, 400 * (attempt + 1)));
        continue;
      }
      return text;
    }
  }
  return text;
}

async function maybeTranslateEnrichment(
  base: Record<string, unknown>,
  settings: TextEngineSettings
): Promise<Record<string, unknown>> {
  if (settings.textEngine !== "translate" || !settings.translateEndpoint.trim()) return base;
  const next: Record<string, unknown> = { ...base };
  const endpoint = settings.translateEndpoint;
  // MyMemory / free proxies: serialize field calls to avoid 429 (do not Promise.all hammer).
  const gapMs = Math.max(0, Math.min(2_000, Number(process.env.TEXT_TRANSLATE_GAP_MS ?? 150)));
  const pause = async () => {
    if (gapMs > 0) await new Promise((r) => setTimeout(r, gapMs));
  };

  const stringKeys = ["title", "summary", "description", "vulnerabilityClass"] as const;
  const arrayKeys = ["remediation", "attackFlow", "nextSteps", "questions", "consequences"] as const;

  for (const key of stringKeys) {
    if (likelyEnglishText(next[key])) {
      next[key] = await translateLibreText(String(next[key]), endpoint);
      await pause();
    }
  }

  for (const key of arrayKeys) {
    const arr = next[key];
    if (!Array.isArray(arr) || arr.length === 0) continue;
    const out: unknown[] = [];
    for (const item of arr) {
      if (likelyEnglishText(item)) {
        out.push(await translateLibreText(String(item), endpoint));
        await pause();
      } else {
        out.push(item);
      }
    }
    next[key] = out;
  }

  // Mixed RU/EN description: translate the English NVD body if the whole field was skipped.
  if (typeof next.description === "string") {
    const m = /(Описание NVD:\s*)([\s\S]+)$/m.exec(next.description);
    if (m && likelyEnglishText(m[2])) {
      const translatedBody = await translateLibreText(m[2], endpoint);
      next.description = `${next.description.slice(0, m.index)}${m[1]}${translatedBody}`;
    }
  }

  const stillEnglish =
    stringKeys.some((k) => likelyEnglishText(next[k])) ||
    arrayKeys.some((k) => Array.isArray(next[k]) && next[k].some((item) => likelyEnglishText(item))) ||
    (typeof next.description === "string" &&
      (() => {
        const m = /Описание NVD:\s*([\s\S]+)$/m.exec(next.description);
        return m ? likelyEnglishText(m[1]) : false;
      })());

  return {
    ...next,
    _display_source: stillEnglish ? "baseline_ru" : "translated"
  };
}

export type RunTextEngineOpts = {
  /** Phase 1: write baseline_ru immediately without calling the translate endpoint. */
  skipTranslate?: boolean;
};

export async function runCveTextEngine(
  cveId: string,
  raw: Record<string, unknown>,
  settings: TextEngineSettings,
  opts?: RunTextEngineOpts
): Promise<VulnContextLlmResult> {
  const baseline = buildBaselineEnrichmentFromNvd(cveId, raw);
  const skipTranslate = Boolean(opts?.skipTranslate) || settings.textEngine !== "translate";
  const outputJson = skipTranslate
    ? settings.textEngine === "translate"
      ? { ...baseline, _display_source: "baseline_ru" }
      : baseline
    : await maybeTranslateEnrichment(baseline, settings).catch(() =>
        settings.textEngine === "translate" ? { ...baseline, _display_source: "baseline_ru" } : baseline
      );
  const inputHash = await sha256Hex(
    stableJsonStringify({
      cveId,
      raw,
      textEngine: settings.textEngine,
      phase: skipTranslate && settings.textEngine === "translate" ? "baseline_ru" : "full"
    })
  );
  const translated =
    settings.textEngine === "translate" &&
    (outputJson._display_source === "translated" || outputJson._display_source === "baseline_ru");
  return {
    inputHash,
    outputJson,
    outputText: typeof outputJson.summary === "string" ? outputJson.summary : undefined,
    model: translated ? "translate" : "baseline",
    promptVersion: settings.textEngine === "translate" ? "translate-v1" : "baseline-v1"
  };
}

export async function runBduTextEngine(
  bduId: string,
  bdu: BduBaselineInput,
  linkedCveRaw: unknown,
  settings: TextEngineSettings,
  opts?: RunTextEngineOpts
): Promise<VulnContextLlmResult> {
  const baseline = buildBaselineEnrichmentFromBdu(bduId, bdu, linkedCveRaw);
  const skipTranslate = Boolean(opts?.skipTranslate) || settings.textEngine !== "translate";
  const outputJson = skipTranslate
    ? settings.textEngine === "translate"
      ? { ...baseline, _display_source: "baseline_ru" }
      : baseline
    : await maybeTranslateEnrichment(baseline, settings).catch(() =>
        settings.textEngine === "translate" ? { ...baseline, _display_source: "baseline_ru" } : baseline
      );
  const inputHash = await sha256Hex(
    stableJsonStringify({
      bduId,
      bdu,
      linkedCveRaw,
      textEngine: settings.textEngine,
      phase: skipTranslate && settings.textEngine === "translate" ? "baseline_ru" : "full"
    })
  );
  const translated =
    settings.textEngine === "translate" &&
    (outputJson._display_source === "translated" || outputJson._display_source === "baseline_ru");
  return {
    inputHash,
    outputJson,
    outputText: typeof outputJson.summary === "string" ? outputJson.summary : undefined,
    model: translated ? "translate" : "baseline",
    promptVersion: settings.textEngine === "translate" ? "translate-v1" : "baseline-v1"
  };
}

export type LlmAnalysisKind = "cve" | "bdu";

export type LlmAnalysisPromptOpts = {
  kind?: LlmAnalysisKind;
  /** Для БДУ — номер без префикса (2026-07273). */
  entityId?: string;
};

/**
 * OpenAI-compatible chat completion → structured CVE context JSON.
 * Used by the `ai` worker and (for reliability) the API inline enrich path.
 */
export async function runVulnContextLlm(
  cveId: string,
  raw: Record<string, unknown>,
  config: VulnContextLlmConfig,
  promptOpts?: LlmAnalysisPromptOpts
): Promise<VulnContextLlmResult> {
  const kind: LlmAnalysisKind = promptOpts?.kind ?? "cve";
  const subjectLabel =
    kind === "bdu"
      ? `записи БДУ ФСТЭК ${promptOpts?.entityId ?? cveId.replace(/^BDU:/i, "")}`
      : cveId;
  const payload = {
    cveId,
    kind,
    raw,
    promptVersion: config.promptVersion
  };
  const inputHash = await sha256Hex(stableJsonStringify(payload));

  const logLlm = process.env.LLM_LOG_REQUESTS !== "false";

  if (!config.apiKey && requiresApiKey(config.endpoint)) {
    if (logLlm) {
      // eslint-disable-next-line no-console
      console.warn(
        `[llm] skip HTTP (public API needs LLM_API_KEY / XAI_API_KEY / DASHSCOPE_API_KEY). endpoint=${config.endpoint} cve=${cveId}`
      );
    }
    return {
      inputHash,
      model: config.model,
      promptVersion: config.promptVersion,
      outputJson: {
        title: "ИИ не настроен (LLM not configured)",
        summary: `${LLM_NOT_CONFIGURED_SUMMARY_PREFIX} (set LLM_API_KEY, XAI_API_KEY, or DASHSCOPE_API_KEY, or use local Ollama / LAN LLM and LLM_ENDPOINT).`,
        description: "Configure LLM_API_KEY (or XAI_API_KEY for x.ai) to enable AI context engine.",
        vulnerabilityClass: null,
        attackFlow: [],
        exploitation: { publicExploit: "unknown", exploitNotes: null },
        exploitNarrative: null,
        consequences: [],
        graph: { nodes: [], edges: [] }
      },
      outputText: LLM_NOT_CONFIGURED_OUTPUT_TEXT
    };
  }

  const schemaHint = {
    title: "string",
    summary: "string",
    description: "string",
    vulnerabilityClass: "string | null",
    attackFlow: ["step strings"],
    exploitation: {
      publicExploit: "'yes'|'no'|'unknown'",
      exploitNotes: "string | null"
    },
    exploitNarrative: "string | null (legacy; optional)",
    consequences: ["string"],
    remediation: ["string"],
    applicability: {
      status: "'applicable'|'not_applicable'|'unknown'",
      notes: "string | null"
    },
    nextSteps: ["string"],
    questions: ["string (questions for clarification)"],
    sources: [
      {
        url: "string",
        label: "string | null",
        kind: "'vendor'|'nvd'|'epss'|'kev'|'advisory'|'exploit'|'other'|null"
      }
    ],
    graph: {
      nodes: [{ id: "string", label: "string", type: "attacker|vector|asset|service|impact" }],
      edges: [{ from: "nodeId", to: "nodeId", label: "string" }]
    },
    uncertainties: ["string"]
  };

  const headers: Record<string, string> = {
    "content-type": "application/json"
  };
  if (config.apiKey.length > 0) {
    headers.authorization = `Bearer ${config.apiKey}`;
  }

  const userContent =
    (kind === "bdu"
      ? `Сгенерируй КОМПЛЕКСНЫЙ АНАЛИЗ УЯЗВИМОСТИ для ${subjectLabel} (реестр БДУ ФСТЭК России) по шаблону банка.\n` +
        `Используй поля raw (описание, CVSS, эксплуатация, ПО, связанные CVE). Не выдумывай CVE — только из raw.linkedCves / raw.cveIds.\n`
      : `Сгенерируй КОМПЛЕКСНЫЙ АНАЛИЗ УЯЗВИМОСТИ для ${subjectLabel} по шаблону банка.\n`) +
    `Цель: человекочитаемый отчёт + структурированные поля для автоматизации.\n` +
    `Все текстовые поля пиши НА РУССКОМ. Верни ТОЛЬКО raw JSON (без markdown, без \`\`\`, без пояснений).\n` +
    `Не копируй в ответ поля из входного raw (descriptions, weaknesses, references, metrics, configurations, published и т.п.) — только ключи схемы ниже.\n` +
    `Top-level объект ДОЛЖЕН совпадать с формой и ключами ниже:\n${JSON.stringify(schemaHint, null, 2)}\n\n` +
    `Требования:\n` +
    `- title: короткий заголовок (например, \"Критическая уязвимость в Linux Kernel (n_gsm)\").\n` +
    `- summary: 2–4 предложения для менеджера (что, где, эффект).\n` +
    `- description: 1–3 абзаца технически (что за баг, условия эксплуатации, ограничения).\n` +
    `- vulnerabilityClass: например \"Race Condition → Use-After-Free\" / \"RCE\" / \"SSRF\".\n` +
    `- exploitation.publicExploit: \"yes\" если есть публичный PoC/эксплойт, \"no\" если явно нет, иначе \"unknown\".\n` +
    `- applicability.status: \"applicable\" если уязвимость обычно релевантна в реальных окружениях и требует проверки; \"not_applicable\" если только узкая/редкая конфигурация; иначе \"unknown\".\n` +
    `- attackFlow: обязательно 4–10 коротких шагов от входной точки до воздействия.\n` +
    `- graph: построй простой граф (attacker→vector→service/asset→impact). Узлы с понятными label.\n` +
    `- remediation: конкретные шаги фикса/минимизации (обязательно 2–6 пунктов, не пустой массив).\n` +
    `- Если raw.mpvmContext есть: используй реальные активы, установленное ПО/пакеты и версии из MaxPatrol VM. В remediation указывай конкретные версии/пакеты/активы для патчинга и не давай общие рекомендации вместо доступного inventory-контекста.\n` +
    `- nextSteps: что делать прямо сейчас (обязательно 2–5 пунктов: аудит, проверки, заявка на патч).\n` +
    `- questions: если не хватает данных (версия, модуль, конфигурация) — задай 3–8 вопросов.\n` +
    `- sources: заполни ссылками из raw (fstecUrl, linked CVE NVD, advisories). Не выдумывай ссылки.\n\n` +
    `Пример (упрощённый):\n` +
    `{\n` +
    `  \"title\": \"Критическая уязвимость в ...\",\n` +
    `  \"summary\": \"...\",\n` +
    `  \"description\": \"...\",\n` +
    `  \"vulnerabilityClass\": \"...\",\n` +
    `  \"attackFlow\": [\"...\"],\n` +
    `  \"exploitation\": { \"publicExploit\": \"unknown\", \"exploitNotes\": null },\n` +
    `  \"consequences\": [\"...\"],\n` +
    `  \"remediation\": [\"...\"],\n` +
    `  \"applicability\": { \"status\": \"unknown\", \"notes\": null },\n` +
    `  \"nextSteps\": [\"...\"],\n` +
    `  \"questions\": [\"...\"],\n` +
    `  \"sources\": [{\"url\":\"https://...\",\"label\":\"...\",\"kind\":\"advisory\"}],\n` +
    `  \"graph\": { \"nodes\": [{\"id\":\"attacker\",\"label\":\"Злоумышленник\",\"type\":\"attacker\"}], \"edges\": [] },\n` +
    `  \"uncertainties\": []\n` +
    `}\n\n` +
    `${kind === "bdu" ? "Данные реестра БДУ" : "Неверифицированный CVE-ввод"}:\n${JSON.stringify(raw).slice(0, effectiveRawJsonMaxChars(config.endpoint))}`;

  const useXaiResponses = isXaiResponsesEndpoint(config.endpoint);
  const ollama = isLikelyOllamaOpenAiEndpoint(config.endpoint);
  const requestBody = useXaiResponses
    ? {
        model: config.model,
        temperature: 0,
        max_output_tokens: 8192,
        store: false,
        input: [
          { role: "system" as const, content: DEFAULT_SYSTEM_POLICY },
          { role: "user" as const, content: userContent }
        ]
      }
    : {
        model: config.model,
        temperature: 0,
        messages: [
          { role: "system" as const, content: DEFAULT_SYSTEM_POLICY },
          { role: "user" as const, content: userContent }
        ],
        ...(ollama
          ? ({
              stream: false as const,
              max_tokens: effectiveOllamaMaxOutputTokens()
            } as const)
          : {})
      };

  const timeoutMs = effectiveLlmTimeoutMs(config.endpoint);
  const maxAttempts = Math.max(1, Math.min(5, Number(process.env.LLM_HTTP_RETRIES ?? 2)));

  if (logLlm) {
    // eslint-disable-next-line no-console
    console.log(
      `[llm] POST cve=${cveId} model=${config.model} endpoint=${config.endpoint} timeoutMs=${timeoutMs} ollama=${ollama}`
    );
  }

  let res: Response | undefined;
  let lastErr: Error | null = null;
  const useOllamaUndici =
    ollama && process.env.LLM_OLLAMA_UNDICI !== "false";

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    const t0 = Date.now();
    try {
      const init = {
        method: "POST" as const,
        headers,
        body: JSON.stringify(requestBody),
        signal: AbortSignal.timeout(timeoutMs)
      };
      const fetched: Response = useOllamaUndici
        ? ((await undiciFetch(config.endpoint, {
            ...init,
            dispatcher: getOllamaUndiciAgent(timeoutMs)
          })) as unknown as Response)
        : await fetch(config.endpoint, init);
      res = fetched;

      if (fetched.ok) {
        if (logLlm) {
          const ms = Date.now() - t0;
          // Ollama access logs show 200 per request — mirror status here so ai worker logs match server traffic.
          // eslint-disable-next-line no-console
          console.log(`[llm] HTTP ${fetched.status} cve=${cveId} attempt=${attempt} ms=${ms}`);
        }
        break;
      }

      const text = await fetched.text().catch(() => "");
      const errSnippet = text.length > 2500 ? `${text.slice(0, 2500)}…` : text;
      lastErr = new Error(`LLM request failed: ${fetched.status} ${fetched.statusText} ${errSnippet}`);

      const retryable =
        fetched.status === 500 ||
        fetched.status === 502 ||
        fetched.status === 503 ||
        fetched.status === 504 ||
        fetched.status === 429;
      if (!retryable || attempt === maxAttempts) {
        throw lastErr;
      }
      const backoff = 2000 + Math.floor(Math.random() * 1000);
      if (logLlm) {
        // eslint-disable-next-line no-console
        console.warn(
          `[llm] retry ${attempt}/${maxAttempts} after HTTP ${fetched.status} in ${backoff}ms cve=${cveId}`
        );
      }
      await new Promise((r) => setTimeout(r, backoff));
    } catch (err) {
      const detail = formatLlmTransportError(err);
      const hint = hintForLlmTransportFailure(detail);
      lastErr = new Error(
        `LLM fetch failed (endpoint=${config.endpoint} timeoutMs=${timeoutMs}): ${detail}${hint}`
      );
      if (attempt === maxAttempts) throw lastErr;
      const backoff = 1500 + Math.floor(Math.random() * 800);
      if (logLlm) {
        // eslint-disable-next-line no-console
        console.warn(
          `[llm] retry ${attempt}/${maxAttempts} after transport error in ${backoff}ms: ${formatLlmTransportError(err)}`
        );
      }
      await new Promise((r) => setTimeout(r, backoff));
      continue;
    }
  }

  if (!res?.ok) {
    throw lastErr ?? new Error("LLM request failed");
  }

  const data = (await res.json()) as unknown;
  const content = extractModelText(data, config.endpoint);
  if (content == null || content.length === 0) {
    const preview = JSON.stringify(data).slice(0, 800);
    throw new Error(`LLM response missing assistant content (preview: ${preview})`);
  }

  const parsed = tryParseLlmJson(content);
  let outputJson = normalizeOutputJson(parsed, content);

  const attackFlow = (outputJson as { attackFlow?: unknown }).attackFlow;
  if (Array.isArray(attackFlow) && attackFlow.length === 0) {
    const metrics = (raw as { metrics?: unknown })?.metrics as
      | {
          cvssMetricV31?: Array<{ cvssData?: { attackVector?: string } }>;
          cvssMetricV30?: Array<{ cvssData?: { attackVector?: string } }>;
          cvssMetricV2?: Array<{ cvssData?: { accessVector?: string } }>;
        }
      | undefined;
    const av =
      metrics?.cvssMetricV31?.[0]?.cvssData?.attackVector ??
      metrics?.cvssMetricV30?.[0]?.cvssData?.attackVector ??
      metrics?.cvssMetricV2?.[0]?.cvssData?.accessVector ??
      null;
    const bduHasExploit = kind === "bdu" && (raw as { hasExploit?: boolean }).hasExploit === true;
    const viaNetwork =
      bduHasExploit || String(av ?? "").toUpperCase().includes("NETWORK");
    outputJson = {
      ...outputJson,
      attackFlow: viaNetwork
        ? [
            "Злоумышленник находит доступную по сети точку входа (веб/API/служба), где обрабатываются пользовательские данные.",
            "Передаёт специально сформированный запрос/параметр/заголовок, который попадает в уязвимый компонент.",
            "Уязвимая логика некорректно обрабатывает входные данные и выполняет опасную операцию (например, интерпретация/lookup/десериализация).",
            "В результате достигается воздействие (например, выполнение кода/утечка данных/DoS) и возможна дальнейшая эскалация."
          ]
        : [
            "Злоумышленник получает возможность влиять на входные данные уязвимого компонента (локально или через цепочку вызовов).",
            "Подготавливает и подаёт вредоносный ввод, который приводит к достижению уязвимого участка кода.",
            "Из‑за ошибки в проверках/обработке данных происходит небезопасное действие (переполнение/обход/инъекция и т.п.).",
            "Возникает воздействие (RCE/утечка/DoS) с последующей пост‑эксплуатацией."
          ]
    };
  }

  const outGraph = (outputJson as { graph?: unknown }).graph;
  const graphOk =
    outGraph &&
    typeof outGraph === "object" &&
    Array.isArray((outGraph as any).nodes) &&
    Array.isArray((outGraph as any).edges) &&
    ((outGraph as any).nodes.length > 0 || (outGraph as any).edges.length > 0);

  const finalAttackFlow = (outputJson as { attackFlow?: unknown }).attackFlow;
  if (!graphOk && Array.isArray(finalAttackFlow) && finalAttackFlow.length > 0) {
    outputJson = {
      ...outputJson,
      graph: deriveGraphFromAttackFlow({
        cveId,
        attackFlow: finalAttackFlow.map(String),
        summary: typeof (outputJson as any).summary === "string" ? (outputJson as any).summary : undefined,
        explanation: typeof (outputJson as any).explanation === "string" ? (outputJson as any).explanation : undefined
      })
    };
  }

  const { inTok, outTok } = readTokenUsage((data as { usage?: unknown }).usage);

  if (logLlm) {
    // eslint-disable-next-line no-console
    console.log(`[llm] ok cve=${cveId} tokensIn=${inTok ?? "?"} tokensOut=${outTok ?? "?"}`);
  }

  outputJson = augmentEnrichmentWithNvdFixes(
    outputJson as Record<string, unknown>,
    raw
  ) as LlmJson;
  outputJson = { ...outputJson, _display_source: "llm" };

  return {
    inputHash,
    outputJson,
    outputText: outputJson?.summary as string | undefined,
    tokensInput: inTok,
    tokensOutput: outTok,
    model: config.model,
    promptVersion: config.promptVersion
  };
}

/** ИИ-анализ записи БДУ ФСТЭК (тот же JSON-шаблон, что и для CVE). */
export async function runBduContextLlm(
  bduId: string,
  raw: Record<string, unknown>,
  config: VulnContextLlmConfig
): Promise<VulnContextLlmResult> {
  return runVulnContextLlm(`BDU:${bduId}`, raw, config, { kind: "bdu", entityId: bduId });
}

const FSTEC_BULLETIN_SCHEMA_HINT = {
  title: "string — заголовок отчёта",
  executiveSummary: "string — 3–5 предложений для руководства: суть письма ФСТЭК, масштаб, срочность",
  keyFindings: ["string — 4–7 маркеров «что важно знать»"],
  overallRiskRating: "'critical'|'high'|'medium'|'low'|'mixed'",
  bulletinContext: "string — контекст: кому адресовано, правовая база, цель бюллетеня",
  regulatoryObligations: ["string — обязательные действия для оператора КИИ"],
  itemSummaries: [
    {
      ordinal: "number",
      bduId: "YYYY-NNNNN",
      priority: "1–5 (1 = срочнее всего)",
      headline: "string",
      summary: "string — 2–4 предложения: суть, затронутое ПО, эффект",
      businessImpact: "string — влияние на КИИ/бизнес одним абзацем",
      cvssFromBulletin: "string",
      registryCvss: "number | null",
      exploitUrgency: "'immediate'|'soon'|'planned'|'monitor'",
      attackFlow: ["4–6 коротких шагов цепочки атаки"],
      remediation: ["конкретные шаги устранения"],
      compensatingIfAny: ["компенсирующие меры или []"],
      linkedCves: ["CVE-… только из analysisContext"]
    }
  ],
  crossCuttingThemes: ["string — общие паттерны: стек, вектор, тип уязвимости"],
  priorityOrder: ["BDU:YYYY-NNNNN — от срочных к отложенным"],
  combinedRemediationPlan: ["string — пошаговый план: 0–72ч, неделя, месяц"],
  timelinePhases: [
    {
      phase: "string — например «0–72 часа»",
      horizon: "string",
      actions: ["string"]
    }
  ],
  riskMatrix: {
    itemCount: "number",
    highOrCriticalCount: "number",
    withPublicExploit: "number",
    needsImmediatePatch: "number"
  },
  combinedGraph: {
    nodes: [{ id: "string", label: "string", type: "attacker|vector|asset|service|impact" }],
    edges: [{ from: "nodeId", to: "nodeId", label: "string" }]
  },
  managementBrief: "string — 1 абзац для CISO/руководства",
  technicalBrief: "string — 2–3 абзаца для инженеров ИБ",
  uncertainties: ["string — что проверить дополнительно"]
};

/**
 * Сводный ИИ-анализ официального бюллетеня ФСТЭК (несколько BDU в одном документе).
 */
export async function runFstecBulletinAnalysisLlm(
  bulletinId: string,
  raw: Record<string, unknown>,
  config: VulnContextLlmConfig
): Promise<VulnContextLlmResult> {
  const subjectId = `FSTEC-BULLETIN:${bulletinId}`;
  const payload = { bulletinId, raw, promptVersion: config.promptVersion };
  const inputHash = await sha256Hex(stableJsonStringify(payload));
  const logLlm = process.env.LLM_LOG_REQUESTS !== "false";

  if (!config.apiKey && requiresApiKey(config.endpoint)) {
    return {
      inputHash,
      model: config.model,
      promptVersion: config.promptVersion,
      outputJson: {
        title: "ИИ не настроен (LLM not configured)",
        executiveSummary: `${LLM_NOT_CONFIGURED_SUMMARY_PREFIX} (настройте LLM_API_KEY / XAI_API_KEY / DASHSCOPE_API_KEY).`,
        overallRiskRating: "mixed",
        bulletinContext: "",
        itemSummaries: [],
        crossCuttingThemes: [],
        priorityOrder: [],
        combinedRemediationPlan: [],
        riskMatrix: {
          itemCount: 0,
          highOrCriticalCount: 0,
          withPublicExploit: 0,
          needsImmediatePatch: 0
        },
        combinedGraph: { nodes: [], edges: [] },
        managementBrief: "",
        technicalBrief: "",
        uncertainties: []
      },
      outputText: LLM_NOT_CONFIGURED_OUTPUT_TEXT
    };
  }

  const userContent =
    `Ты — аналитик ИБ банка/оператора КИИ. Сформируй ЗРЕЛЫЙ СВОДНЫЙ ОТЧЁТ по официальному бюллетеню ФСТЭК (${subjectId}).\n\n` +
    `Вход: объект analysisContext (позиции BDU, CVSS, эксплуатация, CVE, urgencyScore, выдержки текста). ` +
    `Используй precomputedPriorityOrder как основу для priorityOrder, но можешь уточнить с обоснованием в summary.\n` +
    `ЗАПРЕЩЕНО: выдумывать CVE, BDU, версии ПО — только из analysisContext.items[].linkedCves и bduId.\n` +
    `Стиль: деловой русский, без воды, без markdown, без «как ИИ».\n` +
    `Верни ТОЛЬКО JSON (один объект), ключи строго как в схеме.\n\n` +
    `Схема:\n${JSON.stringify(FSTEC_BULLETIN_SCHEMA_HINT, null, 2)}\n\n` +
    `Качество (обязательно):\n` +
    `1) itemSummaries — РОВНО по одной записи на каждый элемент analysisContext.items (все ${(raw as { analysisContext?: { stats?: { totalItems?: number } } }).analysisContext?.stats?.totalItems ?? "?"} позиций).\n` +
    `2) attackFlow в каждой позиции — 4–6 шагов от входа до воздействия; не дублируй один шаблон для всех.\n` +
    `3) actionPlan сервер дополнит автоматически; сфокусируйся на itemSummaries.remediation и compensatingIfAny.\n` +
    `4) timelinePhases — опционально; не дублируй расплывчатый combinedRemediationPlan списком без BDU.\n` +
    `5) combinedGraph — 8–14 узлов, цепочка attacker→vector→asset/service→impact; label на русском.\n` +
    `6) keyFindings — отдельно от executiveSummary; короткие маркеры для слайда руководству.\n` +
    `7) regulatoryObligations — что оператор КИИ должен сделать по смыслу бюллетеня ФСТЭК.\n` +
    `8) uncertainties — 3–6 вопросов к инвентаризации (версии, экспозиция, сегменты сети).\n\n` +
    `analysisContext:\n${JSON.stringify((raw as { analysisContext?: unknown }).analysisContext ?? raw).slice(0, effectiveRawJsonMaxChars(config.endpoint))}`;

  const headers: Record<string, string> = { "content-type": "application/json" };
  if (config.apiKey.length > 0) headers.authorization = `Bearer ${config.apiKey}`;

  const useXaiResponses = isXaiResponsesEndpoint(config.endpoint);
  const ollama = isLikelyOllamaOpenAiEndpoint(config.endpoint);
  const requestBody = useXaiResponses
    ? {
        model: config.model,
        temperature: 0,
        max_output_tokens: 8192,
        store: false,
        input: [
          { role: "system" as const, content: DEFAULT_SYSTEM_POLICY },
          { role: "user" as const, content: userContent }
        ]
      }
    : {
        model: config.model,
        temperature: 0,
        messages: [
          { role: "system" as const, content: DEFAULT_SYSTEM_POLICY },
          { role: "user" as const, content: userContent }
        ],
        ...(ollama
          ? ({
              stream: false as const,
              max_tokens: Math.max(effectiveOllamaMaxOutputTokens(), 12_000)
            } as const)
          : {})
      };

  const timeoutMs = Math.max(effectiveLlmTimeoutMs(config.endpoint), 180_000);
  const maxAttempts = Math.max(1, Math.min(5, Number(process.env.LLM_HTTP_RETRIES ?? 2)));
  let res: Response | undefined;
  let lastErr: Error | null = null;
  const useOllamaUndici = ollama && process.env.LLM_OLLAMA_UNDICI !== "false";

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const init = {
        method: "POST" as const,
        headers,
        body: JSON.stringify(requestBody),
        signal: AbortSignal.timeout(timeoutMs)
      };
      const fetched: Response = useOllamaUndici
        ? ((await undiciFetch(config.endpoint, {
            ...init,
            dispatcher: getOllamaUndiciAgent(timeoutMs)
          })) as unknown as Response)
        : await fetch(config.endpoint, init);
      res = fetched;
      if (fetched.ok) break;
      const text = await fetched.text().catch(() => "");
      lastErr = new Error(`LLM request failed: ${fetched.status} ${text.slice(0, 2500)}`);
      const retryable = [500, 502, 503, 504, 429].includes(fetched.status);
      if (!retryable || attempt === maxAttempts) throw lastErr;
      await new Promise((r) => setTimeout(r, 2000));
    } catch (err) {
      lastErr = new Error(formatLlmTransportError(err));
      if (attempt === maxAttempts) throw lastErr;
      await new Promise((r) => setTimeout(r, 1500));
    }
  }
  if (!res?.ok) throw lastErr ?? new Error("LLM request failed");

  const data = (await res.json()) as unknown;
  const content = extractModelText(data, config.endpoint);
  if (!content?.length) throw new Error("LLM response missing assistant content");

  const parsed = tryParseLlmJson(content);
  let outputJson = normalizeOutputJson(parsed, content);
  const { inTok, outTok } = readTokenUsage((data as { usage?: unknown }).usage);

  const summary =
    typeof (outputJson as { executiveSummary?: unknown }).executiveSummary === "string"
      ? (outputJson as { executiveSummary: string }).executiveSummary
      : typeof (outputJson as { summary?: unknown }).summary === "string"
        ? (outputJson as { summary: string }).summary
        : undefined;

  return {
    inputHash,
    outputJson,
    outputText: summary,
    tokensInput: inTok,
    tokensOutput: outTok,
    model: config.model,
    promptVersion: config.promptVersion
  };
}

const VOC_TASK_BRIEF_SCHEMA = {
  taskTitle: "string (короткий заголовок задачи, до 120 символов)",
  contextSummary: "string (markdown, 4-8 предложений: что за сигнал, почему важен, на что смотреть)",
  verificationChecklist: ["string (конкретный шаг проверки на инфре, без эксплуатации)"],
  keyQuestions: ["string (2-4 вопроса к инвентаризации/экспозиции)"]
};

/**
 * ИИ-бриф для задачи из VOC-кейса: контекст + чеклист верификации.
 */
export async function runVocTaskBriefLlm(
  input: VocTaskBriefInput,
  config: VulnContextLlmConfig
): Promise<VocTaskBriefOutput> {
  const fallback = buildVocTaskBriefFallback(input);
  if (!config.apiKey && requiresApiKey(config.endpoint)) return fallback;

  const userContent =
    `Ты — аналитик ИБ в Vulnerability Operations Center банка/оператора КИИ.\n` +
    `Сформируй ЗРЕЛЫЙ бриф для задачи верификации уязвимости на инфраструктуре.\n` +
    `Платформа уже отранжировала сигнал — аналитик идёт проверять на инфре.\n` +
    `ЗАПРЕЩЕНО: выдумывать CVE, версии, факты эксплуатации — только из входа.\n` +
    `Стиль: деловой русский, без воды, без «как ИИ».\n` +
    `Верни ТОЛЬКО JSON по схеме.\n\n` +
    `Схема:\n${JSON.stringify(VOC_TASK_BRIEF_SCHEMA, null, 2)}\n\n` +
    `Вход:\n${JSON.stringify(input).slice(0, 12_000)}`;

  try {
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (config.apiKey.length > 0) headers.authorization = `Bearer ${config.apiKey}`;
    const ollama = isLikelyOllamaOpenAiEndpoint(config.endpoint);
    const requestBody = {
      model: config.model,
      temperature: 0,
      messages: [
        { role: "system" as const, content: DEFAULT_SYSTEM_POLICY },
        { role: "user" as const, content: userContent }
      ],
      ...(ollama ? { stream: false as const, max_tokens: 4096 } : {})
    };
    const timeoutMs = Math.max(effectiveLlmTimeoutMs(config.endpoint), 90_000);
    const res = await fetch(config.endpoint, {
      method: "POST",
      headers,
      body: JSON.stringify(requestBody),
      signal: AbortSignal.timeout(timeoutMs)
    });
    if (!res.ok) return fallback;
    const data = (await res.json()) as unknown;
    const content = extractModelText(data, config.endpoint);
    if (!content?.trim()) return fallback;
    const parsed = tryParseLlmJson(content) as Record<string, unknown> | null;
    if (!parsed) return fallback;

    const contextSummary =
      typeof parsed.contextSummary === "string" && parsed.contextSummary.trim()
        ? parsed.contextSummary.trim()
        : fallback.notesMd;
    const checklist = Array.isArray(parsed.verificationChecklist)
      ? parsed.verificationChecklist.map(String).filter((s) => s.trim()).slice(0, 10)
      : [];
    const questions = Array.isArray(parsed.keyQuestions)
      ? parsed.keyQuestions.map(String).filter((s) => s.trim()).slice(0, 6)
      : [];
    const taskTitle =
      typeof parsed.taskTitle === "string" && parsed.taskTitle.trim()
        ? parsed.taskTitle.trim().slice(0, 160)
        : fallback.taskTitle;

    const notesParts = [contextSummary];
    if (questions.length) {
      notesParts.push("", "### Вопросы к проверке", ...questions.map((q) => `- ${q}`));
    }
    notesParts.push("", `---`, `VOC case \`${input.caseId}\` · ${input.refKey}`);

    const evidence =
      checklist.length > 0
        ? checklist.map((step, i) => `${i + 1}. ${step}`).join("\n")
        : fallback.evidence;

    return {
      notesMd: notesParts.join("\n"),
      evidence,
      taskTitle,
      aiGenerated: true
    };
  } catch {
    return fallback;
  }
}

const VOC_PLAYBOOK_SCHEMA = {
  contextSummary: "string (2-3 предложения: специфика именно этой уязвимости и фокус проверки)",
  steps: [
    "string (уникальный шаг верификации на инфре: конкретный продукт/CVE/вектор из входа; без эксплуатации; 1 шаг = 1 действие)"
  ]
};

/**
 * ИИ-playbook верификации для VOC-кейса — шаги зависят от контекста уязвимости.
 */
export async function runVocPlaybookLlm(
  input: VocPlaybookContextInput,
  config: VulnContextLlmConfig
): Promise<VocPlaybook> {
  const fallback = buildVocPlaybookFromContext(input);
  if (!config.apiKey && requiresApiKey(config.endpoint)) return fallback;

  const stepCount =
    input.vocPriority === "p1" ? "7-10" : input.vocPriority === "p2" ? "6-9" : "5-7";

  const userContent =
    `Ты — старший аналитик Vulnerability Operations Center банка/оператора КИИ.\n` +
    `Сгенерируй ПЕРСОНАЛЬНЫЙ playbook верификации на инфраструктуре для КОНКРЕТНОГО сигнала.\n` +
    `Каждый шаг должен ссылаться на факты из входа (CVE, продукт, CVSS, EPSS, KEV, БДУ, TG, watchlist).\n` +
    `НЕ используй универсальные шаблоны вроде «проверить инвентарь» без привязки к продукту/CVE из входа.\n` +
    `ЗАПРЕЩЕНО: эксплуатация, сканирование с exploit, выдуманные CVE/версии.\n` +
    `Разрешено: инвентарь, версии, логи, конфиги, perimeter check, advisory, тикеты.\n` +
    `Стиль: деловой русский, императив, без воды.\n` +
    `Количество шагов: ${stepCount}. Последний шаг — зафиксировать evidence.\n` +
    `Верни ТОЛЬКО JSON по схеме.\n\n` +
    `Схема:\n${JSON.stringify(VOC_PLAYBOOK_SCHEMA, null, 2)}\n\n` +
    `Вход:\n${JSON.stringify(input).slice(0, 14_000)}`;

  try {
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (config.apiKey.length > 0) headers.authorization = `Bearer ${config.apiKey}`;
    const ollama = isLikelyOllamaOpenAiEndpoint(config.endpoint);
    const requestBody = {
      model: config.model,
      temperature: 0.2,
      messages: [
        { role: "system" as const, content: DEFAULT_SYSTEM_POLICY },
        { role: "user" as const, content: userContent }
      ],
      ...(ollama ? { stream: false as const, max_tokens: 4096 } : {})
    };
    const timeoutMs = Math.max(effectiveLlmTimeoutMs(config.endpoint), 90_000);
    const res = await fetch(config.endpoint, {
      method: "POST",
      headers,
      body: JSON.stringify(requestBody),
      signal: AbortSignal.timeout(timeoutMs)
    });
    if (!res.ok) return fallback;
    const data = (await res.json()) as unknown;
    const content = extractModelText(data, config.endpoint);
    if (!content?.trim()) return fallback;
    const parsed = tryParseLlmJson(content) as Record<string, unknown> | null;
    if (!parsed) return fallback;

    const rawSteps = Array.isArray(parsed.steps) ? parsed.steps.map(String).filter((s) => s.trim()) : [];
    if (rawSteps.length < 3) return fallback;

    const contextSummary =
      typeof parsed.contextSummary === "string" && parsed.contextSummary.trim()
        ? parsed.contextSummary.trim()
        : null;

    return playbookFromStepLabels(rawSteps, { aiGenerated: true, contextSummary });
  } catch {
    return fallback;
  }
}
