import { Injectable, OnModuleInit } from "@nestjs/common";
import { v4 as uuidv4 } from "uuid";
import type { QueueEventEnvelope } from "@vuln-intel/shared";
import {
  QueueEventEnvelopeSchema,
  QueueEventType,
  ScoreCveRequestedEventSchema,
  computeUnifiedRiskScoreV1
} from "@vuln-intel/shared";
import { DbService } from "../services/db.service.js";
import { QueueService } from "../services/queue.service.js";

@Injectable()
export class ScoringWorker implements OnModuleInit {
  constructor(private readonly db: DbService, private readonly queue: QueueService) {}

  async onModuleInit() {
    await this.ensureSchema();
    await this.queue.ensureTopology();
    const ch = this.queue.channel!;
    // Keep <= PG_POOL_MAX: each message may use DB for several sequential queries.
    ch.prefetch(Number(process.env.AI_SCORE_PREFETCH ?? 4));

    await ch.consume("ai.score", async (msg) => {
      if (!msg) return;
      let env: QueueEventEnvelope | undefined;
      let idempotencyInserted = false;
      try {
        env = QueueEventEnvelopeSchema.parse(JSON.parse(msg.content.toString("utf8")));
        if (env.type !== QueueEventType.ScoreCveRequested) {
          this.queue.ack(msg);
          return;
        }

        const payload = ScoreCveRequestedEventSchema.parse(env.payload);
        const scope = "ai.score";

        const inserted = await this.db.query(
          `INSERT INTO idempotency_key(key, scope, expires_at, metadata)
           VALUES ($1, $2, now() + interval '7 days', $3)
           ON CONFLICT (key) DO NOTHING`,
          [env.idempotencyKey, scope, JSON.stringify({ cveId: payload.cveId })]
        );
        if ((inserted.rowCount ?? 0) === 0) {
          this.queue.ack(msg);
          return;
        }
        idempotencyInserted = true;

        const enriched = await this.enrichInputs(payload.cveId, {
          cvss: payload.cvss,
          epss: payload.epss,
          exploitKnown: payload.exploitKnown,
          publishedAt: payload.publishedAt
        });

        const publishedAt = enriched.publishedAt ? new Date(enriched.publishedAt) : undefined;
        const computed = computeUnifiedRiskScoreV1({
          cvss: enriched.cvss,
          epss: enriched.epss,
          exploitKnown: enriched.exploitKnown,
          mentions: payload.mentions,
          publishedAt
        });

        await this.db.query(
          `INSERT INTO risk_score(cve_id, score, factors, model_version, computed_at)
           VALUES ($1,$2,$3,$4,now())
           ON CONFLICT (cve_id)
           DO UPDATE SET score = EXCLUDED.score,
                         factors = EXCLUDED.factors,
                         model_version = EXCLUDED.model_version,
                         computed_at = now()`,
          [payload.cveId, computed.score, JSON.stringify(computed.factors), computed.modelVersion]
        );

        const completed = {
          id: uuidv4(),
          type: QueueEventType.ScoreCveCompleted,
          ts: new Date().toISOString(),
          producer: { service: "ai", version: "0.0.1" },
          idempotencyKey: `score-completed:${payload.cveId}:${computed.modelVersion}`,
          payload: {
            cveId: payload.cveId,
            score: computed.score,
            modelVersion: computed.modelVersion,
            factors: computed.factors
          }
        };

        this.queue.publish("vuln.events", "vuln.score.completed.v1", completed);
        this.queue.ack(msg);
      } catch (err) {
        if (idempotencyInserted && env?.idempotencyKey) {
          await this.db
            .query(`DELETE FROM idempotency_key WHERE key = $1`, [env.idempotencyKey])
            .catch(() => {});
        }
        // eslint-disable-next-line no-console
        console.error("[ai:score] failed", err);
        this.queue.nack(msg, false);
      }
    });
  }

  private async ensureSchema() {
    // Allow running against an already-initialized DB volume.
    await this.db.query(
      `CREATE TABLE IF NOT EXISTS idempotency_key (
        key TEXT PRIMARY KEY,
        scope TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        expires_at TIMESTAMPTZ,
        metadata JSONB NOT NULL DEFAULT '{}'::jsonb
      )`
    );
    await this.db.query(
      `CREATE TABLE IF NOT EXISTS risk_score (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        cve_id TEXT UNIQUE NOT NULL,
        score INT NOT NULL CHECK (score >= 0 AND score <= 100),
        factors JSONB NOT NULL DEFAULT '{}'::jsonb,
        model_version TEXT NOT NULL,
        computed_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )`
    );
    await this.db.query(`CREATE INDEX IF NOT EXISTS risk_score_computed_at_idx ON risk_score (computed_at DESC)`);

    await this.db.query(
      `CREATE TABLE IF NOT EXISTS epss_score (
        cve_id TEXT PRIMARY KEY,
        score DOUBLE PRECISION NOT NULL CHECK (score >= 0 AND score <= 1),
        percentile DOUBLE PRECISION CHECK (percentile >= 0 AND percentile <= 1),
        scored_at DATE,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )`
    );
    await this.db.query(
      `CREATE TABLE IF NOT EXISTS kev (
        cve_id TEXT PRIMARY KEY,
        vendor_project TEXT,
        product TEXT,
        vulnerability_name TEXT,
        date_added DATE,
        due_date DATE,
        required_action TEXT,
        ransomware_use TEXT,
        notes TEXT,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )`
    );
  }

  private async enrichInputs(
    cveId: string,
    input: { cvss?: number; epss?: number; exploitKnown?: boolean; publishedAt?: string }
  ): Promise<{ cvss?: number; epss?: number; exploitKnown?: boolean; publishedAt?: string }> {
    const out = { ...input };

    if (out.publishedAt == null || out.cvss == null) {
      const cve = await this.db.query<{ raw: any; published_at: Date | null }>(
        `SELECT raw, published_at FROM cve WHERE cve_id = $1 LIMIT 1`,
        [cveId]
      );
      if ((cve.rowCount ?? 0) > 0) {
        const published = cve.rows[0]?.published_at;
        if (out.publishedAt == null && published) out.publishedAt = published.toISOString();
        if (out.cvss == null) out.cvss = this.extractCvssBaseScore(cve.rows[0]?.raw);
      }
    }

    if (out.epss == null) {
      const epss = await this.db.query<{ score: number }>(
        `SELECT score FROM epss_score WHERE cve_id = $1 LIMIT 1`,
        [cveId]
      );
      if ((epss.rowCount ?? 0) > 0) out.epss = Number(epss.rows[0]!.score);
    }

    if (out.exploitKnown == null) {
      const kev = await this.db.query<{ cve_id: string }>(`SELECT cve_id FROM kev WHERE cve_id = $1 LIMIT 1`, [cveId]);
      if ((kev.rowCount ?? 0) > 0) out.exploitKnown = true;
    }

    return out;
  }

  private extractCvssBaseScore(raw: any): number | undefined {
    const metrics = raw?.metrics;
    if (!metrics || typeof metrics !== "object") return undefined;
    const candidates: unknown[] = [];
    for (const k of Object.keys(metrics)) {
      const v = (metrics as any)[k];
      if (Array.isArray(v)) candidates.push(...v);
    }
    for (const c of candidates) {
      const score = (c as any)?.cvssData?.baseScore;
      if (typeof score === "number" && score >= 0 && score <= 10) return score;
    }
    return undefined;
  }
}

