import { Inject, Injectable, OnModuleInit } from "@nestjs/common";
import {
  buildScoreEventsForCveIds,
  ingestEpssFeed,
  publishScoreEvents
} from "@vuln-intel/shared";
import { DbService } from "../services/db.service.js";
import { QueueService } from "../services/queue.service.js";

@Injectable()
export class EpssIngestJob implements OnModuleInit {
  constructor(
    @Inject(DbService) private readonly db: DbService,
    @Inject(QueueService) private readonly queue: QueueService
  ) {}

  async onModuleInit() {
    if (process.env.EPSS_INGEST_ENABLED === "false") return;
    // Default 6h — EPSS publishes ~daily; check often enough that overnight stale is rare.
    const intervalMs = Number(process.env.EPSS_POLL_INTERVAL_MS ?? 6 * 60 * 60 * 1000);
    const initialDelayMs = Number(process.env.EPSS_INITIAL_DELAY_MS ?? 3_000);
    setTimeout(() => {
      this.runForever(intervalMs).catch((e) => {
        // eslint-disable-next-line no-console
        console.error("[ingest:epss] runForever crashed", e);
      });
    }, initialDelayMs);
  }

  private async runForever(intervalMs: number) {
    const failureBackoffMs = Number(process.env.EPSS_FAIL_RETRY_MS ?? 2 * 60_000);
    let consecutiveFailures = 0;
    // eslint-disable-next-line no-constant-condition
    while (true) {
      const startedAt = Date.now();
      try {
        await this.runOnce();
        consecutiveFailures = 0;
      } catch (e) {
        consecutiveFailures += 1;
        const retryMs = Math.min(intervalMs, failureBackoffMs * Math.min(consecutiveFailures, 12));
        // eslint-disable-next-line no-console
        console.error(
          `[ingest:epss] cycle failed (attempt ${consecutiveFailures}), retry in ${Math.round(retryMs / 1000)}s`,
          e
        );
        await new Promise((r) => setTimeout(r, retryMs));
        continue;
      }
      const sleep = Math.max(60_000, intervalMs - (Date.now() - startedAt));
      await new Promise((r) => setTimeout(r, sleep));
    }
  }

  private async runOnce() {
    const force =
      process.env.EPSS_FORCE_FULL === "1" ||
      process.env.EPSS_FORCE_FULL === "true" ||
      (await this.isStale(36));
    const result = await ingestEpssFeed(this.db, { auditMeta: { via: "epss-job" }, force });
    const rescored = result.changedCveIds.slice(0, Number(process.env.EPSS_RESCORE_LIMIT ?? 20_000));
    if (rescored.length) {
      const events = await buildScoreEventsForCveIds(rescored, {
        producer: { service: "ingest", version: "0.0.1" },
        tag: "epss",
        tsBucket: "iso"
      });
      publishScoreEvents((ex, rk, payload) => this.queue.publish(ex, rk, payload), events);
    }

    // eslint-disable-next-line no-console
    console.log(
      `[ingest:epss] ok rows=${result.rows} upserted=${result.upserted} rescored=${rescored.length}` +
        ` skippedFresh=${Boolean(result.skippedFresh)} scoreDate=${result.scoreDate ?? "?"} ` +
        `exploitIntel=${result.exploitIntelRefreshed ?? 0} source=${result.sourceUrl}`
    );
  }

  /** Force full ingest if last watermark/ingest is older than `hours`. */
  private async isStale(hours: number): Promise<boolean> {
    try {
      const r = await this.db.query<{ ts: Date | null }>(
        `SELECT MAX(ts) AS ts
           FROM audit_log
          WHERE action IN ('epss.ingest', 'epss.watermark')`
      );
      const ts = r.rows[0]?.ts ? new Date(r.rows[0].ts).getTime() : 0;
      if (!ts) return true;
      return Date.now() - ts > hours * 3600_000;
    } catch {
      return true;
    }
  }
}
