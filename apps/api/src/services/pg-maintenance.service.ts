import { Injectable, Logger, OnModuleDestroy, OnModuleInit } from "@nestjs/common";
import { runPgMaintenance } from "@vuln-intel/shared";
import { DbService } from "./db.service.js";

/**
 * Periodic prune + VACUUM ANALYZE so disk does not grow unbounded from audit/idempotency/enrich history.
 * Disable with PG_MAINTENANCE=false.
 */
@Injectable()
export class PgMaintenanceService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(PgMaintenanceService.name);
  private timer: ReturnType<typeof setInterval> | null = null;
  private running = false;

  constructor(private readonly db: DbService) {}

  onModuleInit() {
    if (process.env.PG_MAINTENANCE === "false") return;
    const onStartMs = Math.max(0, Number(process.env.PG_MAINTENANCE_ON_START_MS ?? 120_000));
    const intervalMs = Math.max(
      60 * 60_000,
      Number(process.env.PG_MAINTENANCE_INTERVAL_MS ?? 24 * 60 * 60_000)
    );
    if (onStartMs > 0) {
      setTimeout(() => void this.tick(), onStartMs);
    }
    this.timer = setInterval(() => void this.tick(), intervalMs);
    this.logger.log(
      `scheduled (onStart=${onStartMs}ms interval=${Math.round(intervalMs / 3_600_000)}h)`
    );
  }

  onModuleDestroy() {
    if (this.timer) clearInterval(this.timer);
  }

  private async tick() {
    if (this.running) return;
    this.running = true;
    try {
      const result = await runPgMaintenance(this.db, {
        auditRetentionDays: Number(process.env.AUDIT_LOG_RETENTION_DAYS ?? 90),
        enrichmentKeepPerCve: Number(process.env.ENRICHMENT_AI_KEEP_PER_CVE ?? 2),
        refreshTokenRetentionDays: Number(process.env.REFRESH_TOKEN_RETENTION_DAYS ?? 14),
        vacuum: process.env.PG_MAINTENANCE_VACUUM !== "false",
        log: (msg) => this.logger.log(msg)
      });
      this.logger.log(
        `done pruned audit=${result.pruned.auditLog} idem=${result.pruned.idempotencyKey} ` +
          `refresh=${result.pruned.refreshToken} enrich=${result.pruned.enrichmentAi} ` +
          `vacuum=${result.vacuumed.length}`
      );
      try {
        await this.db.query(
          `INSERT INTO audit_log(actor_type, action, metadata) VALUES ('system', 'pg.maintenance', $1)`,
          [JSON.stringify(result)]
        );
      } catch {
        // ignore
      }
    } catch (e) {
      this.logger.warn(`failed: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      this.running = false;
    }
  }
}
