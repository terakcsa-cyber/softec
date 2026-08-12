import { randomUUID } from "node:crypto";
import { QueueEventType } from "./events.js";

export const AI_ENRICH_QUEUE = "ai.enrich";
export const AI_ENRICH_IDEMPOTENCY_SCOPE = "ai.enrich";

export type EnrichEventProducer = { service: string; version: string };

export type EnrichRequestedEnvelope = {
  id: string;
  type: typeof QueueEventType.EnrichCveRequested;
  ts: string;
  producer: EnrichEventProducer;
  idempotencyKey: string;
  payload: {
    cveId: string;
    source: "nvd" | "mitre" | "other";
    raw: Record<string, unknown>;
    [key: string]: unknown;
  };
};

export type EnrichDbQueryable = {
  query(
    sql: string,
    params?: unknown[]
  ): Promise<{ rows: unknown[]; rowCount?: number | null }>;
};

/**
 * Soft cap on `ai.enrich` depth. Producers skip new publishes when at/above this.
 * `0` / negative = unlimited. Default 2000 (enterprise backpressure).
 */
export function getAiEnrichMaxDepth(env: NodeJS.ProcessEnv = process.env): number {
  const raw = (env.AI_ENRICH_MAX_DEPTH ?? "").trim();
  if (raw === "" || raw === undefined) return 2000;
  const n = Number(raw);
  if (!Number.isFinite(n)) return 2000;
  return Math.floor(n);
}

export function shouldSkipEnrichPublishForDepth(
  messageCount: number,
  maxDepth: number = getAiEnrichMaxDepth()
): boolean {
  if (maxDepth <= 0) return false;
  return messageCount >= maxDepth;
}

/** One outstanding enrich job per CVE + text-engine mode (stops hot24/fanout duplicate storms). */
export function enrichInflightIdempotencyKey(cveId: string, textEngine: string): string {
  return `enrich:inflight:${cveId.trim()}:${textEngine.trim() || "baseline"}`;
}

export function getEnrichInflightTtlHours(env: NodeJS.ProcessEnv = process.env): number {
  const n = Number(env.AI_ENRICH_INFLIGHT_TTL_HOURS ?? 6);
  if (!Number.isFinite(n) || n <= 0) return 6;
  return Math.min(168, Math.max(1, Math.floor(n)));
}

/**
 * Claim inflight slot before publish. Returns false if already in-flight.
 * Expired rows (expires_at < now()) are reclaimable so a crashed worker cannot wedge a CVE forever.
 */
export async function claimEnrichInflight(
  db: EnrichDbQueryable,
  cveId: string,
  textEngine: string,
  opts?: { ttlHours?: number; metadata?: Record<string, unknown> }
): Promise<boolean> {
  const key = enrichInflightIdempotencyKey(cveId, textEngine);
  const ttlHours = opts?.ttlHours ?? getEnrichInflightTtlHours();
  const claimed = await db.query(
    `INSERT INTO idempotency_key(key, scope, expires_at, metadata)
     VALUES ($1, $2, now() + ($3::text || ' hours')::interval, $4::jsonb)
     ON CONFLICT (key) DO UPDATE
        SET expires_at = EXCLUDED.expires_at,
            metadata = EXCLUDED.metadata,
            created_at = now()
      WHERE idempotency_key.expires_at IS NOT NULL
        AND idempotency_key.expires_at < now()
  RETURNING key`,
    [
      key,
      AI_ENRICH_IDEMPOTENCY_SCOPE,
      String(ttlHours),
      JSON.stringify({ cveId, textEngine, ...(opts?.metadata ?? {}) })
    ]
  );
  return (claimed.rowCount ?? 0) > 0;
}

/** Release inflight after worker finishes (success, skip, or terminal failure). */
export async function releaseEnrichInflight(
  db: EnrichDbQueryable,
  cveId: string,
  textEngine: string
): Promise<void> {
  const key = enrichInflightIdempotencyKey(cveId, textEngine);
  await db.query(`DELETE FROM idempotency_key WHERE scope = $1 AND key = $2`, [
    AI_ENRICH_IDEMPOTENCY_SCOPE,
    key
  ]);
}

export function buildEnrichRequestedEvent(opts: {
  cveId: string;
  producer: EnrichEventProducer;
  idempotencyKey: string;
  source?: "nvd" | "mitre" | "other";
  raw?: Record<string, unknown>;
  ts?: string;
  payloadExtra?: Record<string, unknown>;
}): EnrichRequestedEnvelope {
  return {
    id: randomUUID(),
    type: QueueEventType.EnrichCveRequested,
    ts: opts.ts ?? new Date().toISOString(),
    producer: opts.producer,
    idempotencyKey: opts.idempotencyKey,
    payload: {
      cveId: opts.cveId,
      source: opts.source ?? "other",
      raw: opts.raw ?? {},
      ...opts.payloadExtra
    }
  };
}

export type EnrichPublisher = (
  exchange: string,
  routingKey: string,
  payload: EnrichRequestedEnvelope,
  options?: { priority?: number }
) => void;

export function publishEnrichRequested(
  publish: EnrichPublisher,
  event: EnrichRequestedEnvelope,
  opts?: { priority?: number }
): void {
  publish("vuln.events", "vuln.enrich.requested.v1", event, {
    priority: opts?.priority
  });
}
