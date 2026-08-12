import { Inject, Injectable, OnModuleInit } from "@nestjs/common";
import {
  applyRiskScoresForCveIds,
  buildScoreEventsForCveIds,
  ensureVulncheckKevSchema,
  ingestVulncheckKev,
  publishScoreEvents
} from "@vuln-intel/shared";
import { DbService } from "../services/db.service.js";
import { QueueService } from "../services/queue.service.js";

@Injectable()
export class VulncheckKevIngestJob implements OnModuleInit {
  constructor(
    @Inject(DbService) private readonly db: DbService,
    @Inject(QueueService) private readonly queue: QueueService
  ) {}

  async onModuleInit() {
    if (process.env.VULNCHECK_KEV_JOB === "false") return;
    const intervalMs = Number(process.env.VULNCHECK_POLL_INTERVAL_MS ?? 6 * 60 * 60 * 1000);
    const initialDelayMs = Number(process.env.VULNCHECK_INITIAL_DELAY_MS ?? 12_000);
    setTimeout(() => {
      this.runForever(intervalMs).catch((e) => {
        // eslint-disable-next-line no-console
        console.error("[ingest:vulncheck-kev] runForever crashed — restarting in 60s", e);
        setTimeout(() => {
          this.runForever(intervalMs).catch((err) => {
            // eslint-disable-next-line no-console
            console.error("[ingest:vulncheck-kev] runForever crashed again", err);
          });
        }, 60_000);
      });
    }, initialDelayMs);
  }

  private async runForever(intervalMs: number) {
    let noTokenSleepLogged = false;
    // eslint-disable-next-line no-constant-condition
    while (true) {
      const startedAt = Date.now();
      let emptyToken = false;
      try {
        await ensureVulncheckKevSchema(this.db);
        emptyToken = await this.runOnce();
      } catch (e) {
        // eslint-disable-next-line no-console
        console.error("[ingest:vulncheck-kev] failed", e);
      }
      // Without API token, don't burn cycles every few hours on a guaranteed skip.
      const sleep = emptyToken
        ? Math.max(intervalMs, 24 * 60 * 60 * 1000)
        : Math.max(60_000, intervalMs - (Date.now() - startedAt));
      if (emptyToken && !noTokenSleepLogged) {
        noTokenSleepLogged = true;
        // eslint-disable-next-line no-console
        console.log(
          `[ingest:vulncheck-kev] no token — sleeping ${Math.round(sleep / 3_600_000)}h until next check`
        );
      }
      await new Promise((r) => setTimeout(r, sleep));
    }
  }

  /** @returns true when skipped due to missing API token */
  async runOnce(): Promise<boolean> {
    const result = await ingestVulncheckKev(this.db, { auditMeta: { via: "ingest_poll" } });
    if (result.skipped) {
      // eslint-disable-next-line no-console
      console.log("[ingest:vulncheck-kev] skip: no API token (settings vulncheck or VULNCHECK_API_TOKEN)");
      return true;
    }
    await this.enqueueScoring(result.touchedCveIds);
    // eslint-disable-next-line no-console
    console.log(
      `[ingest:vulncheck-kev] items=${result.items} touched=${result.touched} vckev_only=${result.vckevOnly} skipped_unknown_cve=${result.skippedUnknown}`
    );
    return false;
  }

  private async enqueueScoring(cveIds: string[]) {
    await applyRiskScoresForCveIds(this.db, cveIds, {
      concurrency: Number(process.env.AI_SCORE_INLINE_CONCURRENCY ?? 32),
      buildQueueEvents: () =>
        buildScoreEventsForCveIds(cveIds, {
          producer: { service: "ingest", version: "0.0.1" },
          tag: "vulncheck-kev",
          tsBucket: "day"
        }),
      publishViaQueue: (events) =>
        publishScoreEvents((ex, rk, payload) => this.queue.publish(ex, rk, payload), events)
    });
  }
}
