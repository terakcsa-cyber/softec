import { Inject, Injectable, Logger } from "@nestjs/common";
import { v4 as uuidv4 } from "uuid";
import {
  ensureExploitIntelSchema,
  ensureVulncheckKevSchema,
  ingestVulncheckKev,
  QueueEventType,
  refreshExploitIntelHot,
  stableJsonStringify,
  sha256Hex
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
  private lastCompletedAt: string | null = null;

  constructor(
    @Inject(DbService) private readonly db: DbService,
    @Inject(QueueService) private readonly queue: QueueService
  ) {}

  getStatus() {
    return { running: this.running, lastCompletedAt: this.lastCompletedAt };
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
    const refreshedAt = new Date().toISOString();
    try {
      await ensureVulncheckKevSchema(this.db);
      await ensureExploitIntelSchema(this.db);

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
    if (!cveIds.length) return 0;
    const nowIso = new Date().toISOString();
    let n = 0;
    for (const cveId of cveIds) {
      const idempotencyKey = await sha256Hex(
        stableJsonStringify({ t: "vulncheck-kev", cveId, ts: nowIso.slice(0, 10) })
      );
      this.queue.publish("vuln.events", "vuln.score.requested.v1", {
        id: uuidv4(),
        type: QueueEventType.ScoreCveRequested,
        ts: nowIso,
        producer: { service: "api", version: "0.0.1" },
        idempotencyKey: `score:${idempotencyKey}`,
        payload: { cveId }
      });
      n++;
    }
    return n;
  }
}
