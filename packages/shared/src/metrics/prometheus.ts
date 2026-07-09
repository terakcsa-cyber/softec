import { createServer, type Server } from "node:http";
import client from "prom-client";

const METRICS_PREFIX = "vuln_";

let registry: client.Registry | null = null;

export function getMetricsRegistry(): client.Registry {
  if (!registry) {
    registry = new client.Registry();
    client.collectDefaultMetrics({ register: registry, prefix: METRICS_PREFIX });
  }
  return registry;
}

export function counter(name: string, help: string, labelNames: string[] = []): client.Counter {
  const reg = getMetricsRegistry();
  const existing = reg.getSingleMetric(`${METRICS_PREFIX}${name}`);
  if (existing) return existing as client.Counter;
  return new client.Counter({
    name: `${METRICS_PREFIX}${name}`,
    help,
    labelNames,
    registers: [reg]
  });
}

export function gauge(name: string, help: string, labelNames: string[] = []): client.Gauge {
  const reg = getMetricsRegistry();
  const existing = reg.getSingleMetric(`${METRICS_PREFIX}${name}`);
  if (existing) return existing as client.Gauge;
  return new client.Gauge({
    name: `${METRICS_PREFIX}${name}`,
    help,
    labelNames,
    registers: [reg]
  });
}

export function histogram(
  name: string,
  help: string,
  labelNames: string[] = [],
  buckets?: number[]
): client.Histogram {
  const reg = getMetricsRegistry();
  const existing = reg.getSingleMetric(`${METRICS_PREFIX}${name}`);
  if (existing) return existing as client.Histogram;
  return new client.Histogram({
    name: `${METRICS_PREFIX}${name}`,
    help,
    labelNames,
    buckets: buckets ?? [0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300],
    registers: [reg]
  });
}

export async function renderMetrics(): Promise<string> {
  return getMetricsRegistry().metrics();
}

export function startMetricsServer(opts?: {
  port?: number;
  host?: string;
  bearer?: string;
}): Server {
  const port = opts?.port ?? Number(process.env.METRICS_PORT ?? "9090");
  const host = opts?.host ?? process.env.METRICS_HOST ?? "127.0.0.1";
  const bearer = opts?.bearer ?? process.env.METRICS_BEARER?.trim();

  const server = createServer(async (req, res) => {
    if (req.url !== "/metrics" && req.url !== "/metrics/") {
      res.statusCode = 404;
      res.end("not found");
      return;
    }
    if (bearer) {
      const auth = req.headers.authorization?.trim();
      if (auth !== `Bearer ${bearer}`) {
        res.statusCode = 401;
        res.end("unauthorized");
        return;
      }
    }
    const body = await renderMetrics();
    res.statusCode = 200;
    res.setHeader("Content-Type", getMetricsRegistry().contentType);
    res.end(body);
  });

  server.listen(port, host, () => {
    // eslint-disable-next-line no-console
    console.log(`[metrics] listening on http://${host}:${port}/metrics`);
  });
  return server;
}

/** Standard queue/worker metrics used across api, ingest, ai. */
export const queueMessagesTotal = counter(
  "queue_messages_total",
  "Queue messages processed",
  ["queue", "status"]
);

export const queueProcessingSeconds = histogram(
  "queue_processing_seconds",
  "Time from consume to ack/nack",
  ["queue"]
);

export const queueDepthGauge = gauge("queue_depth", "RabbitMQ queue depth", ["queue"]);

export const dlqReplayTotal = counter("dlq_replay_total", "DLQ replay outcomes", ["queue", "result"]);

export const scoreEventsPublishedTotal = counter(
  "score_events_published_total",
  "Score events published to vuln.events",
  ["tag"]
);

export const ingestCycleSeconds = histogram(
  "ingest_cycle_duration_seconds",
  "Ingest job cycle duration",
  ["job"]
);

export const llmRequestSeconds = histogram(
  "llm_request_duration_seconds",
  "LLM request duration",
  ["worker"]
);
