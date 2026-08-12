import { Module } from "@nestjs/common";
import { DbModule } from "./db.module.js";
import { QueueModule } from "./queue.module.js";
import { RedisModule } from "./redis.module.js";
import { LlmModule } from "./llm.module.js";
import { EnrichmentWorker } from "../workers/enrichment.worker.js";
import { ScoringWorker } from "../workers/scoring.worker.js";
import { AiIdleExitService } from "../services/ai-idle-exit.service.js";

@Module({
  imports: [DbModule, RedisModule, QueueModule, LlmModule],
  providers: [AiIdleExitService, EnrichmentWorker, ScoringWorker]
})
export class AppModule {}

