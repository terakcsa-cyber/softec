import { Inject, Injectable, OnModuleInit } from "@nestjs/common";
import { ingestContextSources } from "@vuln-intel/shared";
import { DbService } from "../services/db.service.js";

/** Каталожный контекст: версии, SSVC и сигналы эксплойта без текста эксплойтов. */
@Injectable()
export class ContextSourcesJob implements OnModuleInit {
  constructor(@Inject(DbService) private readonly db: DbService) {}

  async onModuleInit() {
    if (process.env.CONTEXT_SOURCES_JOB === "false") return;
    const intervalMs = Math.max(60_000, Number(process.env.CONTEXT_SOURCES_INTERVAL_MS ?? 30 * 60 * 1000));
    const initialDelayMs = Number(process.env.CONTEXT_SOURCES_INITIAL_DELAY_MS ?? 90_000);
    setTimeout(() => {
      this.runForever(intervalMs).catch((error) => {
        // eslint-disable-next-line no-console
        console.error(error);
        process.exit(1);
      });
    }, initialDelayMs);
  }

  private async runForever(intervalMs: number) {
    // eslint-disable-next-line no-constant-condition
    while (true) {
      const startedAt = Date.now();
      try {
        const result = await ingestContextSources(this.db);
        // eslint-disable-next-line no-console
        console.log(`[ingest:context-sources] scanned=${result.scanned} enriched=${result.enriched}`);
      } catch (error) {
        // eslint-disable-next-line no-console
        console.error("[ingest:context-sources] failed", error);
      }
      const sleep = Math.max(60_000, intervalMs - (Date.now() - startedAt));
      await new Promise((resolve) => setTimeout(resolve, sleep));
    }
  }
}
