import { Inject, Injectable, OnModuleInit } from "@nestjs/common";
import {
  buildScoreEventsForCveIds,
  ensureEpssSchema,
  hot24ScoreHourBucket,
  hot24ScoreIdempotencyKey,
  ingestEpssFeed,
  listHot24CvesNeedingScore,
  publishScoreEvents,
  replayDlqMessages
} from "@vuln-intel/shared";
import { DbService } from "../services/db.service.js";
import { QueueService } from "../services/queue.service.js";

const INGEST_PRODUCER = { service: "ingest", version: "0.0.1" } as const;

/** Быстрый старт критичных интеграций после wipe/первого деплоя. */
@Injectable()
export class IntegrationsBootJob implements OnModuleInit {
  constructor(
    @Inject(DbService) private readonly db: DbService,
    @Inject(QueueService) private readonly queue: QueueService
  ) {}

  async onModuleInit() {
    if (process.env.INTEGRATIONS_BOOT === "false") return;
    const delayMs = Number(process.env.INTEGRATIONS_BOOT_DELAY_MS ?? 2_500);
    setTimeout(() => {
      this.runBoot().catch((e) => {
        // eslint-disable-next-line no-console
        console.error("[ingest:integrations-boot] failed", e);
      });
    }, delayMs);
  }

  private async runBoot() {
    if (process.env.DLQ_BOOT_RETRY !== "false") {
      await this.retryDlqIfNeeded();
    }
    if (process.env.EPSS_BOOT_ON_START !== "false") {
      await this.bootEpssIfNeeded();
    }
    if (process.env.HOT24_SCORE_BOOT !== "false") {
      await this.bootHot24ScoreSweep();
    }
  }

  private async retryDlqIfNeeded() {
    const ch = this.queue.channel;
    if (!ch) return;
    const limit = Math.max(1, Math.min(5000, Number(process.env.DLQ_BOOT_RETRY_LIMIT ?? 200)));
    const r = await replayDlqMessages(ch, { limitPerQueue: limit });
    if (r.replayed > 0 || r.skipped > 0) {
      // eslint-disable-next-line no-console
      console.log(`[ingest:integrations-boot] dlq replayed=${r.replayed} skipped=${r.skipped}`, r.byQueue);
    }
  }

  private async bootHot24ScoreSweep() {
    const limit = Math.max(1, Math.min(2000, Number(process.env.HOT24_SCORE_SWEEP_LIMIT ?? 500)));
    const staleHours = Math.max(0, Math.min(168, Number(process.env.HOT24_SCORE_STALE_HOURS ?? 6)));
    const bucket = hot24ScoreHourBucket();
    const rows = await listHot24CvesNeedingScore(this.db, { limit, staleHours, bucket });
    if (!rows.length) {
      // eslint-disable-next-line no-console
      console.log("[ingest:integrations-boot] hot24 score skip (nothing to enqueue)");
      return;
    }
    const events = await buildScoreEventsForCveIds(
      rows.map((r) => r.cve_id),
      {
        producer: INGEST_PRODUCER,
        tag: "hot24-boot",
        idempotencyKeyFor: (cveId) => hot24ScoreIdempotencyKey(cveId, bucket)
      }
    );
    const n = publishScoreEvents((ex, rk, payload) => this.queue.publish(ex, rk, payload), events);
    // eslint-disable-next-line no-console
    console.log(`[ingest:integrations-boot] hot24 score enqueued=${n} (limit=${limit}, bucket=${bucket})`);
  }

  private async bootEpssIfNeeded() {
    await ensureEpssSchema(this.db);
    const countR = await this.db.query<{ c: string }>(`SELECT COUNT(*)::text AS c FROM epss_score`);
    const count = Number(countR.rows[0]?.c ?? "0");
    const force = process.env.EPSS_BOOT_FORCE === "true";
    if (!force && count > 0) {
      // eslint-disable-next-line no-console
      console.log(`[ingest:integrations-boot] epss skip (rows=${count})`);
      return;
    }

    // eslint-disable-next-line no-console
    console.log(`[ingest:integrations-boot] epss import start (rows=${count}, force=${force})`);
    const result = await ingestEpssFeed(this.db, { auditMeta: { reason: "boot", via: "ingest" } });
    const rescored = result.changedCveIds.slice(0, Number(process.env.EPSS_BOOT_RESCORE_LIMIT ?? 5000));
    const events = await buildScoreEventsForCveIds(rescored, {
      producer: INGEST_PRODUCER,
      tag: "epss-boot",
      tsBucket: "day"
    });
    publishScoreEvents((ex, rk, payload) => this.queue.publish(ex, rk, payload), events);
    // eslint-disable-next-line no-console
    console.log(
      `[ingest:integrations-boot] epss ok rows=${result.rows} upserted=${result.upserted} rescored=${events.length}`
    );
  }
}
