import { z } from "zod";

export const VulnerabilitySourceSchema = z.enum(["nvd", "mitre", "other"]);
export type VulnerabilitySource = z.infer<typeof VulnerabilitySourceSchema>;

export const QueueEventEnvelopeSchema = z.object({
  id: z.string().uuid(),
  type: z.string(),
  ts: z.string().datetime({ offset: true, local: true }),
  producer: z.object({
    service: z.string(),
    version: z.string().optional()
  }),
  trace: z
    .object({
      traceId: z.string().optional(),
      spanId: z.string().optional()
    })
    .optional(),
  idempotencyKey: z.string().min(10),
  payload: z.unknown()
});

export type QueueEventEnvelope = z.infer<typeof QueueEventEnvelopeSchema>;

export const IngestCveEventSchema = z.object({
  cveId: z.string().regex(/^CVE-\d{4}-\d+$/),
  source: VulnerabilitySourceSchema,
  raw: z.record(z.string(), z.any()),
  publishedAt: z.string().datetime({ offset: true, local: true }).optional(),
  modifiedAt: z.string().datetime({ offset: true, local: true }).optional()
});
export type IngestCveEvent = z.infer<typeof IngestCveEventSchema>;

export const EnrichCveRequestedEventSchema = z.object({
  cveId: z.string().regex(/^CVE-\d{4}-\d+$/),
  // Legacy producers (e.g. hot24h-sweep) map to other so DLQ replays do not fail Zod before LLM runs.
  source: z.preprocess(
    (v) => {
      if (v === "nvd" || v === "mitre" || v === "other") return v;
      return "other";
    },
    VulnerabilitySourceSchema
  ),
  raw: z.record(z.string(), z.any())
});
export type EnrichCveRequestedEvent = z.infer<typeof EnrichCveRequestedEventSchema>;

export const EnrichCveCompletedEventSchema = z.object({
  cveId: z.string().regex(/^CVE-\d{4}-\d+$/),
  model: z.string(),
  promptVersion: z.string(),
  inputHash: z.string(),
  outputJson: z.record(z.string(), z.any()),
  outputText: z.string().optional(),
  tokensInput: z.number().int().nonnegative().optional(),
  tokensOutput: z.number().int().nonnegative().optional(),
  costUsd: z.number().nonnegative().optional()
});
export type EnrichCveCompletedEvent = z.infer<typeof EnrichCveCompletedEventSchema>;

export const ScoreCveRequestedEventSchema = z.object({
  cveId: z.string().regex(/^CVE-\d{4}-\d+$/),
  cvss: z.number().min(0).max(10).optional(),
  epss: z.number().min(0).max(1).optional(),
  exploitKnown: z.boolean().optional(),
  publishedAt: z.string().datetime({ offset: true, local: true }).optional(),
  modifiedAt: z.string().datetime({ offset: true, local: true }).optional(),
  mentions: z.number().int().nonnegative().optional()
});
export type ScoreCveRequestedEvent = z.infer<typeof ScoreCveRequestedEventSchema>;

export const ScoreCveCompletedEventSchema = z.object({
  cveId: z.string().regex(/^CVE-\d{4}-\d+$/),
  score: z.number().int().min(0).max(100),
  modelVersion: z.string(),
  factors: z.record(z.string(), z.any())
});
export type ScoreCveCompletedEvent = z.infer<typeof ScoreCveCompletedEventSchema>;

export const QueueEventType = {
  IngestCve: "vuln.ingest.cve.v1",
  EnrichCveRequested: "vuln.enrich.requested.v1",
  EnrichCveCompleted: "vuln.enrich.completed.v1",
  ScoreCveRequested: "vuln.score.requested.v1",
  ScoreCveCompleted: "vuln.score.completed.v1"
} as const;

