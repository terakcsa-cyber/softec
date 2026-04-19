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

function extractAssistantContent(data: unknown): string | null {
  const choice = (data as { choices?: unknown[] })?.choices?.[0] as
    | { message?: Record<string, unknown>; delta?: Record<string, unknown> }
    | undefined;
  if (!choice) return null;
  const msg = (choice.message ?? choice.delta) as Record<string, unknown> | undefined;
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
      summary: "Модель вернула не-JSON. Использую текст как черновик.",
      explanation: rawSnippet.slice(0, 4000),
      attackFlow: [],
      exploitNarrative: null,
      consequences: [],
      remediation: [],
      graph: { nodes: [], edges: [] },
      uncertainties: [],
      raw_text: rawSnippet
    };
  }
  const hasExpectedShape =
    typeof parsed.summary === "string" &&
    typeof parsed.explanation === "string" &&
    Array.isArray(parsed.attackFlow) &&
    Array.isArray(parsed.consequences) &&
    Array.isArray(parsed.remediation) &&
    parsed.graph != null &&
    typeof parsed.graph === "object";

  if (hasExpectedShape && (parsed.summary as string).trim().length > 0) return parsed;

  const fromExplanation =
    typeof parsed.explanation === "string" && parsed.explanation.trim().length > 0
      ? parsed.explanation.trim()
      : null;
  if (hasExpectedShape && fromExplanation) return { ...parsed, summary: fromExplanation };

  const vuln = (parsed.vulnerability as Record<string, unknown> | undefined) ?? undefined;
  const vulnTitle = vuln && typeof vuln.title === "string" ? vuln.title : null;
  const vulnDesc = vuln && typeof vuln.description === "string" ? vuln.description : null;
  const rootId = typeof parsed.id === "string" ? parsed.id : null;
  const rootDesc = typeof parsed.description === "string" ? parsed.description : null;

  const fallbackSummary =
    (vulnTitle ?? "").trim() ||
    (rootId && rootDesc ? `Кратко: ${rootId} — ${rootDesc}` : null) ||
    rawSnippet.slice(0, 4000);
  const fallbackExplanation =
    (vulnDesc ?? "").trim() ||
    (rootDesc ? `Описание (как в источнике): ${rootDesc}` : null) ||
    rawSnippet.slice(0, 4000);

  // Some local models (e.g. smaller Qwen) can ignore schema instructions.
  // Normalize into the expected envelope so downstream UI/code has stable keys.
  return {
    summary: fallbackSummary,
    explanation: fallbackExplanation,
    attackFlow: [],
    exploitNarrative: null,
    consequences: [],
    remediation: [],
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
        summary: `${LLM_NOT_CONFIGURED_SUMMARY_PREFIX} (set LLM_API_KEY, XAI_API_KEY, or DASHSCOPE_API_KEY, or use local Ollama / LAN LLM and LLM_ENDPOINT).`,
        explanation: "Configure LLM_API_KEY (or XAI_API_KEY for x.ai) to enable AI context engine.",
        attackFlow: [],
        exploitNarrative: null,
        consequences: [],
        graph: { nodes: [], edges: [] }
      },
      outputText: LLM_NOT_CONFIGURED_OUTPUT_TEXT
    };
  }

  const schemaHint = {
    summary: "string",
    explanation: "string",
    attackFlow: ["step strings"],
    exploitNarrative: "string | null",
    consequences: ["string"],
    remediation: ["string"],
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
    `Сгенерируй "контекст уязвимости" для ${cveId}.\n` +
    `Все текстовые поля (summary, explanation, attackFlow, consequences, remediation, uncertainties, exploitNarrative) пиши НА РУССКОМ.\n` +
    `Поле attackFlow обязательно: 4–10 коротких шагов (строки), описывающих ход атаки от входной точки до воздействия.\n` +
    `Верни ТОЛЬКО raw JSON (без markdown, без \`\`\`, без пояснений).\n` +
    `Top-level объект ДОЛЖЕН совпадать с формой и ключами ниже:\n${JSON.stringify(schemaHint, null, 2)}\n\n` +
    `Пример МИНИМАЛЬНО корректного ответа (заполни конкретикой для ${cveId}):\n` +
    `{\n` +
    `  "summary": "Коротко (1–2 предложения): что это за уязвимость и где проявляется.",\n` +
    `  "explanation": "Чуть подробнее: в чём баг, какие условия эксплуатации, какие компоненты/версии.",\n` +
    `  "attackFlow": [\n` +
    `    "Шаг 1: точка входа (например, HTTP-запрос/параметр/заголовок).",\n` +
    `    "Шаг 2: обработка приложением и достижение уязвимого кода.",\n` +
    `    "Шаг 3: действие злоумышленника, которое приводит к эксплуатации.",\n` +
    `    "Шаг 4: результат (RCE/утечка/DoS) и пост-эксплуатация."\n` +
    `  ],\n` +
    `  "exploitNarrative": null,\n` +
    `  "consequences": ["К чему приводит эксплуатация (список)."],\n` +
    `  "remediation": ["Что сделать для устранения (список)."],\n` +
    `  "graph": { "nodes": [], "edges": [] },\n` +
    `  "uncertainties": []\n` +
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
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    const t0 = Date.now();
    try {
      res = await fetch(config.endpoint, {
        method: "POST",
        headers,
        body: JSON.stringify(requestBody),
        signal: AbortSignal.timeout(timeoutMs)
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      lastErr = new Error(`LLM fetch failed (endpoint=${config.endpoint} timeoutMs=${timeoutMs}): ${msg}`);
      if (attempt === maxAttempts) throw lastErr;
      const backoff = 1500 + Math.floor(Math.random() * 800);
      if (logLlm) {
        // eslint-disable-next-line no-console
        console.warn(`[llm] retry ${attempt}/${maxAttempts} after transport error in ${backoff}ms: ${msg}`);
      }
      await new Promise((r) => setTimeout(r, backoff));
      continue;
    }

    if (res.ok) {
      if (logLlm) {
        const ms = Date.now() - t0;
        // Ollama access logs show 200 per request — mirror status here so ai worker logs match server traffic.
        // eslint-disable-next-line no-console
        console.log(`[llm] HTTP ${res.status} cve=${cveId} attempt=${attempt} ms=${ms}`);
      }
      break;
    }

    const text = await res.text().catch(() => "");
    const errSnippet = text.length > 2500 ? `${text.slice(0, 2500)}…` : text;
    lastErr = new Error(`LLM request failed: ${res.status} ${res.statusText} ${errSnippet}`);

    const retryable =
      res.status === 500 ||
      res.status === 502 ||
      res.status === 503 ||
      res.status === 504 ||
      res.status === 429;
    if (!retryable || attempt === maxAttempts) {
      throw lastErr;
    }
    const backoff = 2000 + Math.floor(Math.random() * 1000);
    if (logLlm) {
      // eslint-disable-next-line no-console
      console.warn(
        `[llm] retry ${attempt}/${maxAttempts} after HTTP ${res.status} in ${backoff}ms cve=${cveId}`
      );
    }
    await new Promise((r) => setTimeout(r, backoff));
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
