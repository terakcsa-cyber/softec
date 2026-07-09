import { Injectable, Logger, OnModuleDestroy, OnModuleInit } from "@nestjs/common";
import { queueDepthGauge } from "@vuln-intel/shared";
import { QueueService } from "./queue.service.js";

const POLL_QUEUES = [
  "ai.enrich",
  "ai.score",
  "dlq.ai.enrich",
  "dlq.ai.score",
  "asv.scan",
  "dlq.asv.scan"
] as const;

@Injectable()
export class MetricsPollerService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(MetricsPollerService.name);
  private timer: ReturnType<typeof setInterval> | null = null;

  constructor(private readonly queue: QueueService) {}

  onModuleInit() {
    const enabled = process.env.METRICS_POLL_QUEUES?.trim() !== "false";
    if (!enabled) return;
    void this.poll();
    this.timer = setInterval(() => void this.poll(), 30_000);
  }

  onModuleDestroy() {
    if (this.timer) clearInterval(this.timer);
  }

  private async poll() {
    for (const q of POLL_QUEUES) {
      try {
        const d = await this.queue.getQueueDepth(q);
        queueDepthGauge.set({ queue: q }, d.messages);
      } catch (e) {
        this.logger.debug(`queue depth poll failed for ${q}: ${String(e)}`);
      }
    }
  }
}
