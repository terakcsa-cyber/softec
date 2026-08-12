import { Inject, Injectable, OnModuleInit } from "@nestjs/common";
import {
  applyRiskScoresForCveIds,
  buildScoreEventsForCveIds,
  ensureExploitIntelSchema,
  ensureVulncheckKevSchema,
  ingestVulncheckKev,
  publishScoreEvents,
  refreshExploitIntelHot
} from "@vuln-intel/shared";
import { DbService } from "../services/db.service.js";
import { QueueService } from "../services/queue.service.js";

const INGEST_PRODUCER = { service: "ingest", version: "0.0.1" } as const;

/** Стартовый прогон VulnCheck + exploit intel сразу после поднятия ingest. */
@Injectable()
export class ThreatIntelBootJob implements OnModuleInit {
  constructor(
    @Inject(DbService) private readonly db: DbService,
    @Inject(QueueService) private readonly queue: QueueService
  ) {}

  async onModuleInit() {
    if (process.env.THREAT_INTEL_BOOT_REFRESH === "false") return;
    const delayMs = Number(process.env.THREAT_INTEL_BOOT_DELAY_MS ?? 45_000);
    setTimeout(() => {
      this.runBoot().catch((e) => {
        // eslint-disable-next-line no-console
        console.error("[ingest:threat-intel-boot] failed", e);
      });
    }, delayMs);
  }

  private async runBoot() {
    await ensureVulncheckKevSchema(this.db);
    await ensureExploitIntelSchema(this.db);

    if (process.env.VULNCHECK_KEV_JOB !== "false") {
      const vulncheck = await ingestVulncheckKev(this.db, { auditMeta: { reason: "boot", via: "ingest" } });
      if (!vulncheck.skipped) {
        // eslint-disable-next-line no-console
        console.log(
          `[ingest:threat-intel-boot] vulncheck items=${vulncheck.items} touched=${vulncheck.touched} vckev_only=${vulncheck.vckevOnly}`
        );
      }
      await this.enqueueScoring(vulncheck.touchedCveIds);
    }

    if (process.env.EXPLOIT_INTEL_REFRESH_JOB !== "false") {
      const intel = await refreshExploitIntelHot(this.db);
      // eslint-disable-next-line no-console
      console.log(`[ingest:threat-intel-boot] exploit-intel refreshed=${intel.refreshed}`);
    }
  }

  private async enqueueScoring(cveIds: string[]) {
    await applyRiskScoresForCveIds(this.db, cveIds, {
      concurrency: Number(process.env.AI_SCORE_INLINE_CONCURRENCY ?? 32),
      buildQueueEvents: () =>
        buildScoreEventsForCveIds(cveIds, {
          producer: INGEST_PRODUCER,
          tag: "vulncheck-kev",
          tsBucket: "day"
        }),
      publishViaQueue: (events) =>
        publishScoreEvents((ex, rk, payload) => this.queue.publish(ex, rk, payload), events)
    });
  }
}
