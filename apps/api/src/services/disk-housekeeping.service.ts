import { Injectable, Logger, OnModuleDestroy, OnModuleInit } from "@nestjs/common";
import { PlatformUpdateService } from "./platform-update.service.js";

/**
 * Daily Docker/git/staging prune (no volumes, no .env).
 * Disable with DISK_HOUSEKEEPING=false.
 */
@Injectable()
export class DiskHousekeepingService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(DiskHousekeepingService.name);
  private timer: ReturnType<typeof setInterval> | null = null;
  private running = false;

  constructor(private readonly updates: PlatformUpdateService) {}

  onModuleInit() {
    if (process.env.DISK_HOUSEKEEPING === "false") return;
    const onStartMs = Math.max(0, Number(process.env.DISK_HOUSEKEEPING_ON_START_MS ?? 300_000));
    const intervalMs = Math.max(
      60 * 60_000,
      Number(process.env.DISK_HOUSEKEEPING_INTERVAL_MS ?? 24 * 60 * 60_000)
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
      const result = await this.updates.housekeepDaily();
      this.logger.log(
        `done steps=${result.steps.filter((s) => s.ok).length}/${result.steps.length}`
      );
    } catch (e) {
      this.logger.warn(`failed: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      this.running = false;
    }
  }
}
