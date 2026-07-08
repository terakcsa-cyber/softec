import { Inject, Injectable, OnModuleInit } from "@nestjs/common";
import { v4 as uuidv4 } from "uuid";
import {
  ensureExploitIntelSchema,
  ensureVulncheckKevSchema,
  ingestVulncheckKev,
  QueueEventType,
  refreshExploitIntelHot,
  sha256Hex,
  stableJsonStringify
} from "@vuln-intel/shared";
import { DbService } from "../services/db.service.js";
import { QueueService } from "../services/queue.service.js";

/** Стартовый прогон VulnCheck + exploit intel сразу после поднятия ingest. */
@Injectable()
export class ThreatIntelBootJob implements OnModuleInit {
  constructor(
    @Inject(DbService) private readonly db: DbService,
    @Inject(QueueService) private readonly queue: QueueService
  ) {}

  async onModuleInit() {
    if (process.env.THREAT_INTEL_BOOT_REFRESH === "false") return;
    const delayMs = Number(process.env.THREAT_INTEL_BOOT_DELAY_MS ?? 4_000);
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
    if (!cveIds.length) return;
    const nowIso = new Date().toISOString();
    for (const cveId of cveIds) {
      const idempotencyKey = await sha256Hex(
        stableJsonStringify({ t: "vulncheck-kev", cveId, ts: nowIso.slice(0, 10) })
      );
      this.queue.publish("vuln.events", "vuln.score.requested.v1", {
        id: uuidv4(),
        type: QueueEventType.ScoreCveRequested,
        ts: nowIso,
        producer: { service: "ingest", version: "0.0.1" },
        idempotencyKey: `score:${idempotencyKey}`,
        payload: { cveId }
      });
    }
  }
}
