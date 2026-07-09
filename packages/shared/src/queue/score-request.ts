import { randomUUID } from "node:crypto";
import { QueueEventType } from "./events.js";
import { sha256Hex, stableJsonStringify } from "../security/prompt-safety.js";

export type ScoreEventProducer = { service: string; version: string };

export type ScoreRequestedEnvelope = {
  id: string;
  type: typeof QueueEventType.ScoreCveRequested;
  ts: string;
  producer: ScoreEventProducer;
  idempotencyKey: string;
  payload: { cveId: string; [key: string]: unknown };
};

export function buildScoreRequestedEvent(opts: {
  cveId: string;
  producer: ScoreEventProducer;
  idempotencyKey: string;
  ts?: string;
  payloadExtra?: Record<string, unknown>;
}): ScoreRequestedEnvelope {
  return {
    id: randomUUID(),
    type: QueueEventType.ScoreCveRequested,
    ts: opts.ts ?? new Date().toISOString(),
    producer: opts.producer,
    idempotencyKey: opts.idempotencyKey,
    payload: { cveId: opts.cveId, ...opts.payloadExtra }
  };
}

export async function buildHashedScoreIdempotencyKey(seed: {
  t: string;
  cveId: string;
  ts: string;
}): Promise<string> {
  const hash = await sha256Hex(stableJsonStringify(seed));
  return `score:${seed.t}:${hash}`;
}

/** Строит score-события для списка CVE с хешированным idempotency key (день или полный ts). */
export async function buildScoreEventsForCveIds(
  cveIds: string[],
  opts: {
    producer: ScoreEventProducer;
    tag: string;
    tsBucket?: "day" | "iso";
    idempotencyKeyFor?: (cveId: string) => string;
    payloadExtraFor?: (cveId: string) => Record<string, unknown>;
  }
): Promise<ScoreRequestedEnvelope[]> {
  if (!cveIds.length) return [];
  const nowIso = new Date().toISOString();
  const ts = opts.tsBucket === "day" ? nowIso.slice(0, 10) : nowIso;
  const out: ScoreRequestedEnvelope[] = [];
  for (const cveId of cveIds) {
    const idempotencyKey = opts.idempotencyKeyFor
      ? opts.idempotencyKeyFor(cveId)
      : await buildHashedScoreIdempotencyKey({ t: opts.tag, cveId, ts });
    out.push(
      buildScoreRequestedEvent({
        cveId,
        producer: opts.producer,
        idempotencyKey,
        ts: nowIso,
        payloadExtra: opts.payloadExtraFor?.(cveId)
      })
    );
  }
  return out;
}

export type ScorePublisher = (
  exchange: string,
  routingKey: string,
  payload: ScoreRequestedEnvelope
) => void;

export function publishScoreEvents(publish: ScorePublisher, events: ScoreRequestedEnvelope[]): number {
  for (const event of events) {
    publish("vuln.events", "vuln.score.requested.v1", event);
  }
  return events.length;
}
