import { Injectable, OnModuleDestroy, OnModuleInit } from "@nestjs/common";
import { sqlBduFstecAttentionWithinHours } from "@vuln-intel/shared";
import { BduEnrichRunnerService } from "./bdu-enrich-runner.service.js";
import { DbService } from "./db.service.js";
import { IntegrationSettingsService } from "./integration-settings.service.js";

/**
 * Background BDU card maturity for TEXT_ENGINE=baseline|translate.
 * BDU has no RabbitMQ enrich queue — schedule in-process via BduEnrichRunnerService.
 */
@Injectable()
export class TextEngineBgSweepService implements OnModuleInit, OnModuleDestroy {
  private timeouts: NodeJS.Timeout[] = [];
  private intervals: NodeJS.Timeout[] = [];

  constructor(
    private readonly db: DbService,
    private readonly integration: IntegrationSettingsService,
    private readonly bduEnrich: BduEnrichRunnerService
  ) {}

  onModuleInit() {
    if (process.env.TEXT_ENGINE_BG_ENRICH === "false") return;

    const onStartMs = Number(process.env.BDU_TEXT_SWEEP_ON_START_MS ?? 8_000);
    if (onStartMs > 0) {
      this.timeouts.push(
        setTimeout(() => {
          void this.sweepBduHotWindow().catch((e) => {
            // eslint-disable-next-line no-console
            console.error("[api:text-bg] bdu hot sweep on start failed", e);
          });
        }, onStartMs)
      );
    }

    // Aggressive default for baseline maturity (3m); override with BDU_TEXT_SWEEP_INTERVAL_MS.
    const intervalMs = Number(process.env.BDU_TEXT_SWEEP_INTERVAL_MS ?? 3 * 60_000);
    if (intervalMs > 0) {
      this.intervals.push(
        setInterval(() => {
          void this.sweepBduHotWindow().catch((e) => {
            // eslint-disable-next-line no-console
            console.error("[api:text-bg] bdu hot sweep interval failed", e);
          });
        }, intervalMs)
      );
    }
  }

  onModuleDestroy() {
    for (const t of this.timeouts) clearTimeout(t);
    for (const t of this.intervals) clearInterval(t);
    this.timeouts = [];
    this.intervals = [];
  }

  private async sweepBduHotWindow() {
    const textEngine = await this.integration.getTextEngineSettings();
    if (textEngine.textEngine === "llm") {
      // LLM mass fanout stays gated elsewhere; do not auto-schedule BDU LLM here.
      return;
    }

    const defaultLimit = textEngine.textEngine === "baseline" ? 200 : 60;
    const limit = Math.max(1, Math.min(500, Number(process.env.BDU_TEXT_SWEEP_LIMIT ?? defaultLimit)));
    const hotSql = sqlBduFstecAttentionWithinHours("b", 24);

    const r = await this.db.query<{ bdu_id: string }>(
      `SELECT b.bdu_id
         FROM bdu_vuln b
    LEFT JOIN LATERAL (
          SELECT output_text, output_json, model, prompt_version
            FROM enrichment_bdu
           WHERE bdu_id = b.bdu_id
        ORDER BY created_at DESC
           LIMIT 1
         ) latest ON true
        WHERE (${hotSql})
          AND (
            latest.output_text IS NULL
            OR latest.output_text = 'LLM not configured.'
            OR COALESCE(latest.output_json->>'summary', '') LIKE 'LLM not configured%'
            OR (latest.output_json @> '{"_enrich_error": true}'::jsonb)
            OR (
              $2::text = 'translate'
              AND NOT (
                latest.model = 'translate'
                OR latest.prompt_version = 'translate-v1'
                OR COALESCE(latest.output_json->>'_display_source', '') IN ('translated', 'baseline_ru')
              )
            )
          )
     ORDER BY b.publication_date DESC NULLS LAST, b.updated_at DESC
        LIMIT $1`,
      [limit, textEngine.textEngine]
    );

    let n = 0;
    for (const row of r.rows) {
      this.bduEnrich.scheduleEnrich(row.bdu_id, { force: false, allowOutsideHotWindow: true });
      n += 1;
    }
    if (n > 0) {
      // eslint-disable-next-line no-console
      console.log(
        `[api:text-bg] bdu hot sweep scheduled=${n} (limit=${limit}, engine=${textEngine.textEngine})`
      );
    }
  }
}
