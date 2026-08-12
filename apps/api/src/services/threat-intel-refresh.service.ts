import { Inject, Injectable, Logger } from "@nestjs/common";
import {
  applyRiskScoresForCveIds,
  buildScoreEventsForCveIds,
  ensureExploitIntelSchema,
  ensureVulncheckKevSchema,
  ingestVulncheckKev,
  publishScoreEvents,
  refreshExploitIntelHot
} from "@vuln-intel/shared";
import { DbService } from "./db.service.js";
import { QueueService } from "./queue.service.js";

export type ThreatIntelRefreshResult = {
  ok: boolean;
  vulncheck: Awaited<ReturnType<typeof ingestVulncheckKev>>;
  exploitIntel: Awaited<ReturnType<typeof refreshExploitIntelHot>>;
  scored: number;
  refreshedAt: string;
};

@Injectable()
export class ThreatIntelRefreshService {
  private readonly logger = new Logger(ThreatIntelRefreshService.name);
  private running = false;
  private startedAt: string | null = null;
  private lastCompletedAt: string | null = null;

  constructor(
    @Inject(DbService) private readonly db: DbService,
    @Inject(QueueService) private readonly queue: QueueService
  ) {}

  getStatus() {
    return { running: this.running, startedAt: this.startedAt, lastCompletedAt: this.lastCompletedAt };
  }

  async refresh(opts?: { reason?: string; force?: boolean }): Promise<ThreatIntelRefreshResult> {
    if (this.running) {
      return this.waitForRunning();
    }

    const minIntervalMs = Number(process.env.THREAT_INTEL_REFRESH_MIN_MS ?? 120_000);
    if (!opts?.force && this.lastCompletedAt) {
      const age = Date.now() - new Date(this.lastCompletedAt).getTime();
      if (age < minIntervalMs) {
        return {
          ok: true,
          vulncheck: {
            ok: true,
            skipped: true,
            reason: "cooldown",
            items: 0,
            touched: 0,
            touchedCveIds: [],
            vckevOnly: 0,
            skippedUnknown: 0
          },
          exploitIntel: { refreshed: 0, cveIds: [] },
          scored: 0,
          refreshedAt: this.lastCompletedAt
        };
      }
    }

    this.running = true;
    this.startedAt = new Date().toISOString();
    const refreshedAt = this.startedAt;
    try {
      await ensureVulncheckKevSchema(this.db);
      await ensureExploitIntelSchema(this.db);
      await this.normalizePollutedLastSeenOnce();

      const vulncheck = await ingestVulncheckKev(this.db, {
        auditMeta: { reason: opts?.reason ?? "api", via: "api" }
      });
      const exploitIntel = await refreshExploitIntelHot(this.db);
      const scored = await this.enqueueScoring(vulncheck.touchedCveIds);

      this.lastCompletedAt = refreshedAt;
      this.logger.log(
        `refreshed reason=${opts?.reason ?? "api"} vc=${vulncheck.touched} intel=${exploitIntel.refreshed} scored=${scored}`
      );

      return { ok: true, vulncheck, exploitIntel, scored, refreshedAt };
    } finally {
      this.running = false;
      this.startedAt = null;
    }
  }

  /** Old TI upserts bumped last_seen_at on every sync; reset once so “updated” buckets stay real. */
  private async normalizePollutedLastSeenOnce() {
    try {
      const done = await this.db.query<{ n: string }>(
        `SELECT count(*)::text AS n FROM audit_log WHERE action = 'threat.normalize_last_seen' LIMIT 1`
      );
      if (Number(done.rows[0]?.n ?? 0) > 0) return;

      const upd = await this.db.query(
        `UPDATE cve_exploit_signal
            SET last_seen_at = first_seen_at
          WHERE signal_type IN ('vulncheck_kev', 'nvd_exploit_tag')
            AND last_seen_at > first_seen_at + interval '1 minute'`
      );
      await this.db.query(
        `INSERT INTO audit_log(actor_type, action, metadata) VALUES ('system', 'threat.normalize_last_seen', $1)`,
        [JSON.stringify({ resetRows: upd.rowCount ?? 0 })]
      );
      this.logger.log(`normalized polluted last_seen_at rows=${upd.rowCount ?? 0}`);
    } catch (e) {
      this.logger.warn(`normalize last_seen skipped: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  private async waitForRunning(): Promise<ThreatIntelRefreshResult> {
    for (let i = 0; i < 120; i++) {
      await new Promise((r) => setTimeout(r, 500));
      if (!this.running && this.lastCompletedAt) {
        return {
          ok: true,
          vulncheck: {
            ok: true,
            skipped: true,
            reason: "waited_for_parallel",
            items: 0,
            touched: 0,
            touchedCveIds: [],
            vckevOnly: 0,
            skippedUnknown: 0
          },
          exploitIntel: { refreshed: 0, cveIds: [] },
          scored: 0,
          refreshedAt: this.lastCompletedAt
        };
      }
    }
    throw new Error("Threat intel refresh timeout");
  }

  private async enqueueScoring(cveIds: string[]): Promise<number> {
    return applyRiskScoresForCveIds(this.db, cveIds, {
      concurrency: Number(process.env.AI_SCORE_INLINE_CONCURRENCY ?? 32),
      buildQueueEvents: () =>
        buildScoreEventsForCveIds(cveIds, {
          producer: { service: "api", version: "0.0.1" },
          tag: "vulncheck-kev",
          tsBucket: "day"
        }),
      publishViaQueue: (events) =>
        publishScoreEvents((ex, rk, payload) => this.queue.publish(ex, rk, payload), events)
    });
  }
}
