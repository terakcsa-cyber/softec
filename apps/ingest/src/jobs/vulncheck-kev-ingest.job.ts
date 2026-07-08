import { Inject, Injectable, OnModuleInit } from "@nestjs/common";
import { v4 as uuidv4 } from "uuid";
import {
  ensureVulncheckKevSchema,
  ingestVulncheckKev,
  QueueEventType,
  sha256Hex,
  stableJsonStringify
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
        console.error(e);
        process.exit(1);
      });
    }, initialDelayMs);
  }

  private async runForever(intervalMs: number) {
    // eslint-disable-next-line no-constant-condition
    while (true) {
      const startedAt = Date.now();
      try {
        await ensureVulncheckKevSchema(this.db);
        await this.runOnce();
      } catch (e) {
        // eslint-disable-next-line no-console
        console.error("[ingest:vulncheck-kev] failed", e);
      }
      const sleep = Math.max(60_000, intervalMs - (Date.now() - startedAt));
      await new Promise((r) => setTimeout(r, sleep));
    }
  }

  async runOnce() {
    const result = await ingestVulncheckKev(this.db, { auditMeta: { via: "ingest_poll" } });
    if (result.skipped) {
      // eslint-disable-next-line no-console
      console.log("[ingest:vulncheck-kev] skip: no API token (settings vulncheck or VULNCHECK_API_TOKEN)");
      return;
    }
    await this.enqueueScoring(result.touchedCveIds);
    // eslint-disable-next-line no-console
    console.log(
      `[ingest:vulncheck-kev] items=${result.items} touched=${result.touched} vckev_only=${result.vckevOnly} skipped_unknown_cve=${result.skippedUnknown}`
    );
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
