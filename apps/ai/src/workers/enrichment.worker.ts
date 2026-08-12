import { Injectable, OnModuleInit } from "@nestjs/common";
import { v4 as uuidv4 } from "uuid";
import type { QueueEventEnvelope } from "@vuln-intel/shared";
import {
  EnrichCveRequestedEventSchema,
  isLikelyOllamaOpenAiEndpoint,
  isLlmNotConfiguredEnrichment,
  isMatureEnrichmentForTextEngine,
  llmEndpointRequiresApiKey,
  QueueEventEnvelopeSchema,
  QueueEventType,
  releaseEnrichInflight
} from "@vuln-intel/shared";
import { DbService } from "../services/db.service.js";
import { QueueService } from "../services/queue.service.js";
import { RedisService } from "../services/redis.service.js";
import { LlmService } from "../services/llm.service.js";

function coerceEnrichPayloadSource(payload: unknown): unknown {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return payload;
  const p = payload as Record<string, unknown>;
  const s = p.source;
  if (s === "nvd" || s === "mitre" || s === "other") return payload;
  return { ...p, source: "other" };
}

/** Сообщения из backlog / DLQ / ручного force не режем по окну published_at. */
function shouldApplyQueuePublishedWindow(idempotencyKey: string): boolean {
  if (idempotencyKey.includes(":dlq:")) return false;
  if (idempotencyKey.startsWith("enrich:backlog:")) return false;
  if (idempotencyKey.startsWith("enrich:manual:")) return false;
  // Digest preparation: may include older CVEs with fresh exploit signals; do not drop by published_at window.
  if (idempotencyKey.startsWith("enrich:digest:")) return false;
  return true;
}

/** Ограничивает одновременные HTTP к LLM (Ollama на одном GPU часто отвечает 500 при многих параллельных запросах). */
class LlmConcurrencyGate {
  private readonly max: number;
  private active = 0;
  private readonly waiters: Array<() => void> = [];

  constructor(max: number) {
    this.max = Math.max(1, max);
  }

  async use<T>(fn: () => Promise<T>): Promise<T> {
    await new Promise<void>((resolve) => {
      const enter = () => {
        if (this.active < this.max) {
          this.active++;
          resolve();
        } else {
          this.waiters.push(enter);
        }
      };
      enter();
    });
    try {
      return await fn();
    } finally {
      this.active--;
      const next = this.waiters.shift();
      if (next) next();
    }
  }
}

function parseRetryFromIdempotencyKey(key: string | null | undefined): number {
  if (!key) return 0;
  const m = key.match(/:retry:(\d+)$/);
  if (!m) return 0;
  const n = Number(m[1]);
  return Number.isFinite(n) ? Math.max(0, Math.min(50, Math.floor(n))) : 0;
}

function isTransientLlmTransportError(err: unknown): boolean {
  const s = err instanceof Error ? `${err.name}: ${err.message}` : String(err);
  return /ECONNREFUSED|ETIMEDOUT|ENOTFOUND|EAI_AGAIN|ECONNRESET|socket hang up|fetch failed/i.test(s);
}

@Injectable()
export class EnrichmentWorker implements OnModuleInit {
  constructor(
    private readonly db: DbService,
    private readonly queue: QueueService,
    private readonly redis: RedisService,
    private readonly llm: LlmService
  ) {}

  async onModuleInit() {
    await this.queue.ensureTopology();
    const ch = this.queue.channel!;
    const textEngineBoot = await this.llm.getTextEngineSettings();
    const isTextEngine = textEngineBoot.textEngine !== "llm";
    const llmCfgEarly = await this.llm.getEffectiveLlmConfig();
    const defaultLlmParallel = isLikelyOllamaOpenAiEndpoint(llmCfgEarly.endpoint) ? 3 : 12;
    // baseline: near-instant local templates — high parallelism. translate: keep low to avoid MyMemory 429.
    const defaultTextParallel =
      textEngineBoot.textEngine === "baseline" ? 48 : textEngineBoot.textEngine === "translate" ? 3 : defaultLlmParallel;
    const llmMaxParallelForGate = Math.max(
      1,
      Number(process.env.LLM_MAX_PARALLEL ?? (isTextEngine ? defaultTextParallel : defaultLlmParallel))
    );
    const llmGate = new LlmConcurrencyGate(llmMaxParallelForGate);

    const defaultPrefetch = isTextEngine
      ? textEngineBoot.textEngine === "baseline"
        ? 64
        : 6
      : 10;
    // Prefetch может быть > параллели к LLM: лишние сообщения ждут в gate (очередь не теряется).
    ch.prefetch(Math.max(1, Number(process.env.AI_ENRICH_PREFETCH ?? defaultPrefetch)));

    const persistEnrichment = async (
      cveId: string,
      res: {
        model: string;
        promptVersion: string;
        inputHash: string;
        outputJson: unknown;
        outputText?: string;
        tokensInput?: number;
        tokensOutput?: number;
        costUsd?: number;
      },
      opts?: { cacheKey?: string | null; useRedisCache?: boolean }
    ) => {
      await this.db.query(
        `INSERT INTO enrichment_ai(cve_id, model, prompt_version, input_hash, output_json, output_text, tokens_input, tokens_output, cost_usd)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
         ON CONFLICT (cve_id, model, prompt_version, input_hash) DO UPDATE SET
           output_json = EXCLUDED.output_json,
           output_text = EXCLUDED.output_text,
           tokens_input = EXCLUDED.tokens_input,
           tokens_output = EXCLUDED.tokens_output,
           cost_usd = EXCLUDED.cost_usd`,
        [
          cveId,
          res.model,
          res.promptVersion,
          res.inputHash,
          JSON.stringify(res.outputJson),
          res.outputText ?? null,
          res.tokensInput ?? null,
          res.tokensOutput ?? null,
          res.costUsd ?? null
        ]
      );

      const completed = {
        id: uuidv4(),
        type: QueueEventType.EnrichCveCompleted,
        ts: new Date().toISOString(),
        producer: { service: "ai", version: "0.0.1" },
        idempotencyKey: `enrich-completed:${cveId}:${res.inputHash}`,
        payload: {
          cveId,
          model: res.model,
          promptVersion: res.promptVersion,
          inputHash: res.inputHash,
          outputJson: res.outputJson,
          outputText: res.outputText,
          tokensInput: res.tokensInput,
          tokensOutput: res.tokensOutput,
          costUsd: res.costUsd
        }
      };

      if (
        opts?.useRedisCache &&
        opts.cacheKey &&
        !isLlmNotConfiguredEnrichment({
          output_json: res.outputJson,
          output_text: res.outputText ?? null
        })
      ) {
        const src =
          res.outputJson && typeof res.outputJson === "object" && !Array.isArray(res.outputJson)
            ? String((res.outputJson as Record<string, unknown>)._display_source ?? "")
            : "";
        // Only cache fully translated / baseline rows — not partial translate work-in-progress.
        if (src !== "baseline_ru" || textEngineBoot.textEngine === "baseline") {
          await this.redis.client.set(opts.cacheKey, JSON.stringify(completed), "EX", 60 * 60 * 24 * 30);
        }
      }
      if (process.env.AI_LOG_ENRICH_OK !== "false") {
        // eslint-disable-next-line no-console
        console.log(`[ai:enrich] ok cve=${cveId} model=${res.model}`);
      }
      this.queue.publish("vuln.events", "vuln.enrich.completed.v1", completed);
    };

    await ch.consume("ai.enrich", async (msg) => {
      if (!msg) return;
      let env: QueueEventEnvelope | undefined;
      let idempotencyInserted = false;
      let inflightCveId: string | null = null;
      let inflightTextEngine: string | null = null;
      let keepInflightForRetry = false;
      try {
        env = QueueEventEnvelopeSchema.parse(JSON.parse(msg.content.toString("utf8")));
        if (env.type !== QueueEventType.EnrichCveRequested) {
          this.queue.ack(msg);
          return;
        }

        // Defense in depth: dev sometimes runs stale @vuln-intel/shared/dist; legacy source must not block LLM.
        const payload = EnrichCveRequestedEventSchema.parse(coerceEnrichPayloadSource(env.payload));
        const scope = "ai.enrich";
        inflightCveId = payload.cveId;
        const textEngineEarly = await this.llm.getTextEngineSettings();
        inflightTextEngine = textEngineEarly.textEngine;

        const maxAgeRaw = process.env.AI_ENRICH_QUEUE_PUBLISHED_MAX_AGE_HOURS;
        const maxAgeHours =
          maxAgeRaw === undefined || maxAgeRaw === "" ? 24 : Number(maxAgeRaw);
        if (
          maxAgeHours > 0 &&
          shouldApplyQueuePublishedWindow(env.idempotencyKey)
        ) {
          const pub = await this.db.query<{ published_at: Date | null; raw: unknown }>(
            `SELECT published_at, raw FROM cve WHERE cve_id = $1`,
            [payload.cveId]
          );
          const row = pub.rows[0];
          const publishedAt =
            row?.published_at ??
            (row?.raw &&
            typeof row.raw === "object" &&
            !Array.isArray(row.raw) &&
            typeof (row.raw as Record<string, unknown>).published === "string"
              ? new Date(String((row.raw as Record<string, unknown>).published))
              : null);
          if (!publishedAt || Number.isNaN(publishedAt.getTime())) {
            // eslint-disable-next-line no-console
            console.log(
              `[ai:enrich] skip queue job (no published date) cve=${payload.cveId} key=${env.idempotencyKey}`
            );
            this.queue.ack(msg);
            return;
          }
          const ageMs = Date.now() - publishedAt.getTime();
          if (ageMs > maxAgeHours * 60 * 60 * 1000) {
            // eslint-disable-next-line no-console
            console.log(
              `[ai:enrich] skip queue job (published outside window) cve=${payload.cveId} published_at=${publishedAt.toISOString()} maxAgeHours=${maxAgeHours}`
            );
            this.queue.ack(msg);
            return;
          }
        }

        // If we already have a mature enrichment for the active text engine, skip.
        const existing = await this.db.query<{
          output_text: string | null;
          output_json: unknown;
          model: string | null;
          prompt_version: string | null;
        }>(
          `SELECT output_text, output_json, model, prompt_version
             FROM enrichment_ai
            WHERE cve_id = $1
         ORDER BY created_at DESC
            LIMIT 20`,
          [payload.cveId]
        );
        const mature = existing.rows.find((row) =>
          isMatureEnrichmentForTextEngine(row, textEngineEarly.textEngine)
        );
        if (mature) {
          if (process.env.AI_LOG_DEDUPE === "true") {
            // eslint-disable-next-line no-console
            console.log(`[ai:enrich] already enriched; ack cve=${payload.cveId} key=${env.idempotencyKey}`);
          }
          this.queue.ack(msg);
          return;
        }

        // Idempotency: if we've seen this key, ack and drop.
        const inserted = await this.db.query(
          `INSERT INTO idempotency_key(key, scope, expires_at, metadata)
           VALUES ($1, $2, now() + interval '7 days', $3)
           ON CONFLICT (key) DO NOTHING`,
          [env.idempotencyKey, scope, JSON.stringify({ cveId: payload.cveId })]
        );
        if (inserted.rowCount === 0) {
          // Another copy owns this work key / already finished — do not drop inflight.
          keepInflightForRetry = true;
          if (process.env.AI_LOG_DEDUPE === "true") {
            // eslint-disable-next-line no-console
            console.log(`[ai:enrich] dedupe skip key=${env.idempotencyKey} cve=${payload.cveId}`);
          }
          this.queue.ack(msg);
          return;
        }
        idempotencyInserted = true;

        const textEngine = textEngineEarly;
        const useRedisCache = process.env.AI_ENRICH_REDIS_CACHE !== "false";
        const cacheVersion = textEngine.textEngine === "llm" ? this.llm.getPromptVersion() : `${textEngine.textEngine}-v1`;
        const cacheKey = `ai:enrich:${payload.cveId}:${cacheVersion}`;
        const cached = useRedisCache ? await this.redis.client.get(cacheKey) : null;
        if (cached) {
          try {
            const evt = JSON.parse(cached) as {
              payload?: { outputJson?: unknown; outputText?: string | null; model?: string; promptVersion?: string };
            };
            const p = evt.payload;
            if (
              p &&
              isMatureEnrichmentForTextEngine(
                {
                  output_json: p.outputJson,
                  output_text: p.outputText ?? null,
                  model: p.model ?? null,
                  prompt_version: p.promptVersion ?? null
                },
                textEngine.textEngine
              )
            ) {
              if (process.env.AI_LOG_ENRICH_CACHE !== "false") {
                // eslint-disable-next-line no-console
                console.log(
                  `[ai:enrich] redis cache hit cve=${payload.cveId} (no HTTP to LLM; set AI_ENRICH_REDIS_CACHE=false to always call Ollama)`
                );
              }
              this.queue.publish("vuln.events", "vuln.enrich.completed.v1", evt);
              this.queue.ack(msg);
              return;
            }
            await this.redis.client.del(cacheKey);
          } catch {
            await this.redis.client.del(cacheKey);
          }
        }

        const res =
          textEngine.textEngine === "translate"
            ? await (async () => {
                // Phase 1: persist baseline_ru immediately so the card is mature.
                const quick = await llmGate.use(() =>
                  this.llm.generateVulnContext({
                    cveId: payload.cveId,
                    raw: payload.raw,
                    skipTranslate: true
                  })
                );
                await persistEnrichment(payload.cveId, quick, {
                  useRedisCache: false,
                  cacheKey: null
                });
                // Phase 2: rate-limited translate upgrade (may stay baseline_ru on 429/errors).
                return llmGate.use(() =>
                  this.llm.generateVulnContext({
                    cveId: payload.cveId,
                    raw: payload.raw,
                    skipTranslate: false
                  })
                );
              })()
            : await llmGate.use(() =>
                this.llm.generateVulnContext({
                  cveId: payload.cveId,
                  raw: payload.raw
                })
              );

        await persistEnrichment(payload.cveId, res, { useRedisCache, cacheKey });
        this.queue.ack(msg);
      } catch (err) {
        if (idempotencyInserted && env?.idempotencyKey) {
          await this.db
            .query(`DELETE FROM idempotency_key WHERE key = $1`, [env.idempotencyKey])
            .catch(() => {});
        }
        // eslint-disable-next-line no-console
        console.error("[ai:enrich] failed", err);
        // Transport errors to LLM are usually transient; retry with backoff instead of DLQ.
        if (env?.type === QueueEventType.EnrichCveRequested && isTransientLlmTransportError(err)) {
          const retry = parseRetryFromIdempotencyKey(env.idempotencyKey);
          const maxRetries = Math.max(0, Math.min(12, Number(process.env.AI_ENRICH_MAX_RETRIES ?? 8)));
          if (retry < maxRetries) {
            const delayMs = Math.min(300_000, 5_000 * Math.pow(2, retry)); // 5s,10s,20s,... max 5m
            // eslint-disable-next-line no-console
            console.warn(`[ai:enrich] transient LLM error; retrying in ${delayMs}ms key=${env.idempotencyKey} retry=${retry + 1}/${maxRetries}`);
            await new Promise((r) => setTimeout(r, delayMs));
            const nextEnv: QueueEventEnvelope = {
              ...env,
              id: uuidv4(),
              ts: new Date().toISOString(),
              producer: { service: "ai", version: "0.0.1" },
              idempotencyKey: `${env.idempotencyKey}:retry:${retry + 1}`
            };
            keepInflightForRetry = true;
            this.queue.publish("vuln.events", "vuln.enrich.requested.v1", nextEnv);
            this.queue.ack(msg);
            return;
          }
        }
        // Non-transient errors: reject to DLQ (no requeue) to avoid hot-looping.
        this.queue.nack(msg, false);
      } finally {
        if (inflightCveId && inflightTextEngine && !keepInflightForRetry) {
          await releaseEnrichInflight(this.db, inflightCveId, inflightTextEngine).catch(() => {});
        }
      }
    });

    const pref = Math.max(1, Number(process.env.AI_ENRICH_PREFETCH ?? defaultPrefetch));
    const cfg = await this.llm.getEffectiveLlmConfig();
    const needsKey = llmEndpointRequiresApiKey(cfg.endpoint);
    const keyOk = Boolean(cfg.apiKey?.length);
    // eslint-disable-next-line no-console
    const redisCache = process.env.AI_ENRICH_REDIS_CACHE !== "false";
    const maxAgeRaw = process.env.AI_ENRICH_QUEUE_PUBLISHED_MAX_AGE_HOURS;
    const queueMaxAgeHours =
      maxAgeRaw === undefined || maxAgeRaw === "" ? 24 : Number(maxAgeRaw);
    // eslint-disable-next-line no-console
    console.log(
      `[ai:enrich] worker ready queue=ai.enrich prefetch=${pref} llmMaxParallel=${llmMaxParallelForGate} textEngine=${textEngineBoot.textEngine} redisEnrichCache=${redisCache} queuePublishedMaxAgeHours=${queueMaxAgeHours <= 0 ? "off" : String(queueMaxAgeHours)} llmEndpoint=${cfg.endpoint} model=${cfg.model} needsApiKey=${needsKey} hasKey=${keyOk}`
    );
    if (needsKey && !keyOk) {
      // eslint-disable-next-line no-console
      console.error(
        "[ai:enrich] LLM: для выбранного endpoint нужен API-ключ (LLM_API_KEY / XAI_API_KEY / DASHSCOPE_API_KEY). " +
          "Иначе в БД попадёт только заглушка «LLM не настроен». Для Ollama: LLM_ENDPOINT=http://<host>:11434/v1/chat/completions (127.0.0.1 или LAN IP) и LLM_MODEL=… (ключ не нужен)."
      );
    }
  }
}

