import { Injectable, OnModuleInit } from "@nestjs/common";
import { v4 as uuidv4 } from "uuid";
import type { QueueEventEnvelope } from "@vuln-intel/shared";
import {
  EnrichCveRequestedEventSchema,
  getVulnContextLlmConfigFromEnv,
  isLikelyOllamaOpenAiEndpoint,
  isLlmNotConfiguredEnrichment,
  llmEndpointRequiresApiKey,
  QueueEventEnvelopeSchema,
  QueueEventType
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

/** Сообщения из backlog / повтор из DLQ не режем по окну published_at. */
function shouldApplyQueuePublishedWindow(idempotencyKey: string): boolean {
  if (idempotencyKey.includes(":dlq:")) return false;
  if (idempotencyKey.startsWith("enrich:backlog:")) return false;
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
    const llmCfgEarly = getVulnContextLlmConfigFromEnv();
    const defaultLlmParallel = isLikelyOllamaOpenAiEndpoint(llmCfgEarly.endpoint) ? 3 : 12;
    const llmMaxParallelForGate = Math.max(1, Number(process.env.LLM_MAX_PARALLEL ?? defaultLlmParallel));
    const llmGate = new LlmConcurrencyGate(llmMaxParallelForGate);

    // Prefetch может быть > параллели к LLM: лишние сообщения ждут в gate (очередь не теряется).
    ch.prefetch(Math.max(1, Number(process.env.AI_ENRICH_PREFETCH ?? 10)));

    await ch.consume("ai.enrich", async (msg) => {
      if (!msg) return;
      let env: QueueEventEnvelope | undefined;
      let idempotencyInserted = false;
      try {
        env = QueueEventEnvelopeSchema.parse(JSON.parse(msg.content.toString("utf8")));
        if (env.type !== QueueEventType.EnrichCveRequested) {
          this.queue.ack(msg);
          return;
        }

        // Defense in depth: dev sometimes runs stale @vuln-intel/shared/dist; legacy source must not block LLM.
        const payload = EnrichCveRequestedEventSchema.parse(coerceEnrichPayloadSource(env.payload));
        const scope = "ai.enrich";

        const maxAgeRaw = process.env.AI_ENRICH_QUEUE_PUBLISHED_MAX_AGE_HOURS;
        const maxAgeHours =
          maxAgeRaw === undefined || maxAgeRaw === "" ? 24 : Number(maxAgeRaw);
        if (
          maxAgeHours > 0 &&
          shouldApplyQueuePublishedWindow(env.idempotencyKey)
        ) {
          const pub = await this.db.query<{ published_at: Date | null }>(
            `SELECT published_at FROM cve WHERE cve_id = $1`,
            [payload.cveId]
          );
          const publishedAt = pub.rows[0]?.published_at ?? null;
          if (!publishedAt) {
            // eslint-disable-next-line no-console
            console.log(
              `[ai:enrich] skip queue job (no published_at in DB) cve=${payload.cveId} key=${env.idempotencyKey}`
            );
            this.queue.ack(msg);
            return;
          }
          const ageMs = Date.now() - new Date(publishedAt).getTime();
          if (ageMs > maxAgeHours * 60 * 60 * 1000) {
            // eslint-disable-next-line no-console
            console.log(
              `[ai:enrich] skip queue job (published outside window) cve=${payload.cveId} published_at=${publishedAt.toISOString()} maxAgeHours=${maxAgeHours}`
            );
            this.queue.ack(msg);
            return;
          }
        }

        // Idempotency: if we've seen this key, ack and drop.
        const inserted = await this.db.query(
          `INSERT INTO idempotency_key(key, scope, expires_at, metadata)
           VALUES ($1, $2, now() + interval '7 days', $3)
           ON CONFLICT (key) DO NOTHING`,
          [env.idempotencyKey, scope, JSON.stringify({ cveId: payload.cveId })]
        );
        if (inserted.rowCount === 0) {
          if (process.env.AI_LOG_DEDUPE === "true") {
            // eslint-disable-next-line no-console
            console.log(`[ai:enrich] dedupe skip key=${env.idempotencyKey} cve=${payload.cveId}`);
          }
          this.queue.ack(msg);
          return;
        }
        idempotencyInserted = true;

        const useRedisCache = process.env.AI_ENRICH_REDIS_CACHE !== "false";
        const cacheKey = `ai:enrich:${payload.cveId}:${this.llm.getPromptVersion()}`;
        const cached = useRedisCache ? await this.redis.client.get(cacheKey) : null;
        if (cached) {
          try {
            const evt = JSON.parse(cached) as {
              payload?: { outputJson?: unknown; outputText?: string | null };
            };
            const p = evt.payload;
            if (
              p &&
              !isLlmNotConfiguredEnrichment({
                output_json: p.outputJson,
                output_text: p.outputText ?? null
              })
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

        const res = await llmGate.use(() =>
          this.llm.generateVulnContext({
            cveId: payload.cveId,
            raw: payload.raw
          })
        );

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
            payload.cveId,
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
          idempotencyKey: `enrich-completed:${payload.cveId}:${res.inputHash}`,
          payload: {
            cveId: payload.cveId,
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
          useRedisCache &&
          !isLlmNotConfiguredEnrichment({
            output_json: res.outputJson,
            output_text: res.outputText ?? null
          })
        ) {
          await this.redis.client.set(cacheKey, JSON.stringify(completed), "EX", 60 * 60 * 24 * 30);
        }
        if (process.env.AI_LOG_ENRICH_OK !== "false") {
          // eslint-disable-next-line no-console
          console.log(`[ai:enrich] ok cve=${payload.cveId} model=${res.model}`);
        }
        this.queue.publish("vuln.events", "vuln.enrich.completed.v1", completed);
        this.queue.ack(msg);
      } catch (err) {
        if (idempotencyInserted && env?.idempotencyKey) {
          await this.db
            .query(`DELETE FROM idempotency_key WHERE key = $1`, [env.idempotencyKey])
            .catch(() => {});
        }
        // eslint-disable-next-line no-console
        console.error("[ai:enrich] failed", err);
        // On error: reject to DLQ (no requeue) to avoid hot-looping.
        this.queue.nack(msg, false);
      }
    });

    const pref = Math.max(1, Number(process.env.AI_ENRICH_PREFETCH ?? 10));
    const cfg = getVulnContextLlmConfigFromEnv();
    const needsKey = llmEndpointRequiresApiKey(cfg.endpoint);
    const keyOk = Boolean(cfg.apiKey?.length);
    // eslint-disable-next-line no-console
    const redisCache = process.env.AI_ENRICH_REDIS_CACHE !== "false";
    const maxAgeRaw = process.env.AI_ENRICH_QUEUE_PUBLISHED_MAX_AGE_HOURS;
    const queueMaxAgeHours =
      maxAgeRaw === undefined || maxAgeRaw === "" ? 24 : Number(maxAgeRaw);
    // eslint-disable-next-line no-console
    console.log(
      `[ai:enrich] worker ready queue=ai.enrich prefetch=${pref} llmMaxParallel=${llmMaxParallelForGate} redisEnrichCache=${redisCache} queuePublishedMaxAgeHours=${queueMaxAgeHours <= 0 ? "off" : String(queueMaxAgeHours)} llmEndpoint=${cfg.endpoint} model=${cfg.model} needsApiKey=${needsKey} hasKey=${keyOk}`
    );
  }
}

