import { Injectable } from "@nestjs/common";

/**
 * When both ai.score and ai.enrich are idle (inline defaults), exit so the
 * container does not hold idle connections. Compose should use restart: on-failure.
 * Keep alive: AI_KEEP_IDLE_PROCESS=true.
 */
@Injectable()
export class AiIdleExitService {
  private scoreReported = false;
  private enrichReported = false;
  private scoreIdle = false;
  private enrichIdle = false;
  private scheduled = false;

  reportScore(idle: boolean) {
    this.scoreReported = true;
    this.scoreIdle = idle;
    this.maybeScheduleExit();
  }

  reportEnrich(idle: boolean) {
    this.enrichReported = true;
    this.enrichIdle = idle;
    this.maybeScheduleExit();
  }

  private maybeScheduleExit() {
    if (this.scheduled) return;
    if (!this.scoreReported || !this.enrichReported) return;
    if (!(this.scoreIdle && this.enrichIdle)) return;
    if (process.env.AI_KEEP_IDLE_PROCESS === "true") {
      // eslint-disable-next-line no-console
      console.log("[ai] both workers idle — keeping process (AI_KEEP_IDLE_PROCESS=true)");
      return;
    }
    const delay = Math.max(0, Number(process.env.AI_IDLE_EXIT_MS ?? 8_000));
    this.scheduled = true;
    // eslint-disable-next-line no-console
    console.log(
      `[ai] both workers idle — exiting in ${delay}ms (set AI_KEEP_IDLE_PROCESS=true to keep)`
    );
    setTimeout(() => {
      process.exit(0);
    }, delay);
  }
}
