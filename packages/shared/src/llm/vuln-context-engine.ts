import { Agent, fetch as undiciFetch } from "undici";
import {
  LLM_NOT_CONFIGURED_OUTPUT_TEXT,
  LLM_NOT_CONFIGURED_SUMMARY_PREFIX
} from "../ai/enrichment-placeholder.js";
import { DEFAULT_SYSTEM_POLICY, sha256Hex, stableJsonStringify } from "../security/prompt-safety.js";

export type VulnContextLlmConfig = {
  endpoint: string;
  apiKey: string;
  model: string;
  promptVersion: string;
};

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

  if (hasV2Shape && (parsed.summary as string).trim().length > 0) return parsed;

  const vuln = (parsed.vulnerability as Record<string, unknown> | undefined) ?? undefined;
  const vulnTitle = vuln && typeof vuln.title === "string" ? vuln.title : null;
  const vulnDesc = vuln && typeof vuln.description === "string" ? vuln.description : null;
  const rootId = typeof parsed.id === "string" ? parsed.id : null;
  const rootDesc = typeof parsed.description === "string" ? parsed.description : null;

  const fallbackSummary =
    (vulnTitle ?? "").trim() ||
    (rootId && rootDesc ? `Кратко: ${rootId} — ${rootDesc}` : null) ||
    rawSnippet.slice(0, 4000);
  const fallbackDescription =
    (vulnDesc ?? "").trim() ||
    (rootDesc ? `Описание (как в источнике): ${rootDesc}` : null) ||
    rawSnippet.slice(0, 4000);

  // Some local models (e.g. smaller Qwen) can ignore schema instructions.
  // Normalize into the expected envelope so downstream UI/code has stable keys.
  return {
    title: rootId ? `Комплексный анализ ${rootId}` : "Комплексный анализ уязвимости",
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

/**
 * OpenAI-compatible chat completion → structured CVE context JSON.
 * Used by the `ai` worker and (for reliability) the API inline enrich path.
 */
export async function runVulnContextLlm(
  cveId: string,
  raw: Record<string, unknown>,
  config: VulnContextLlmConfig
): Promise<VulnContextLlmResult> {
  const payload = {
    cveId,
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
    `Сгенерируй КОМПЛЕКСНЫЙ АНАЛИЗ УЯЗВИМОСТИ для ${cveId} по шаблону банка.\n` +
    `Цель: человекочитаемый отчёт + структурированные поля для автоматизации.\n` +
    `Все текстовые поля пиши НА РУССКОМ. Верни ТОЛЬКО raw JSON (без markdown, без \`\`\`, без пояснений).\n` +
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
    `- remediation: конкретные шаги фикса/минимизации.\n` +
    `- nextSteps: что делать прямо сейчас (аудит/проверки/сбор фактов/создание заявки).\n` +
    `- questions: если не хватает данных (версия, модуль, конфигурация) — задай 3–8 вопросов.\n` +
    `- sources: заполни ссылками, которые нашёл в raw.references/источниках (если есть). Не выдумывай ссылки.\n\n` +
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
    `Неверифицированный CVE-ввод:\n${JSON.stringify(raw).slice(0, effectiveRawJsonMaxChars(config.endpoint))}`;

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
    const metrics = (raw as any)?.metrics;
    const av =
      metrics?.cvssMetricV31?.[0]?.cvssData?.attackVector ??
      metrics?.cvssMetricV30?.[0]?.cvssData?.attackVector ??
      metrics?.cvssMetricV2?.[0]?.cvssData?.accessVector ??
      null;
    const viaNetwork = String(av ?? "").toUpperCase().includes("NETWORK");
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
