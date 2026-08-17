import { Inject, Injectable, OnModuleInit } from "@nestjs/common";
import { epssUtcYmd, ingestEpssFeed } from "@vuln-intel/shared";
import { DbService } from "../services/db.service.js";

@Injectable()
export class EpssIngestJob implements OnModuleInit {
  constructor(@Inject(DbService) private readonly db: DbService) {}

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
      // While the corpus is a calendar day behind, retry at most every 6h even if poll is 24h.
      const catchUpMs = 6 * 60 * 60 * 1000;
      const behind = await this.isBehindUtcToday();
      const sleep = behind
        ? Math.min(Math.max(60_000, intervalMs), catchUpMs)
        : Math.max(60_000, intervalMs - (Date.now() - startedAt));
      await new Promise((r) => setTimeout(r, sleep));
    }
  }

  private async runOnce() {
    const force = process.env.EPSS_FORCE_FULL === "1" || process.env.EPSS_FORCE_FULL === "true";
    const result = await ingestEpssFeed(this.db, { auditMeta: { via: "epss-job" }, force });

    // eslint-disable-next-line no-console
    console.log(
      `[ingest:epss] ok rows=${result.rows} upserted=${result.upserted}` +
        ` riskScores=${result.riskScoresUpserted ?? 0} skippedFresh=${Boolean(result.skippedFresh)}` +
        ` scoreDate=${result.scoreDate ?? "?"} exploitIntel=${result.exploitIntelRefreshed ?? 0}` +
        ` source=${result.sourceUrl}`
    );
  }

  /** True when MAX(epss_score.scored_at) is before today's UTC date. */
  private async isBehindUtcToday(): Promise<boolean> {
    try {
      const r = await this.db.query<{ d: string | null }>(`SELECT MAX(scored_at)::text AS d FROM epss_score`);
      const d = r.rows[0]?.d?.slice(0, 10) ?? null;
      if (!d) return true;
      return d < epssUtcYmd();
    } catch {
      return true;
    }
  }
}
