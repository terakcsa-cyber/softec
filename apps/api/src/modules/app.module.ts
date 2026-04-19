import { Module } from "@nestjs/common";
import { ThrottlerModule } from "@nestjs/throttler";
import { HealthController } from "../routes/health.controller.js";
import { CveController } from "../routes/cve.controller.js";
import { StatsController } from "../routes/stats.controller.js";
import { DbModule } from "./db.module.js";
import { QueueModule } from "./queue.module.js";
import { CveEnrichRunnerService } from "../services/cve-enrich-runner.service.js";
import { RedisEnrichCacheService } from "../services/redis-enrich-cache.service.js";
import { SchemaService } from "../services/schema.service.js";
import { CveVendorIndexService } from "../services/cve-vendor-index.service.js";

@Module({
  imports: [
    DbModule,
    QueueModule,
    ThrottlerModule.forRoot([
      {
        name: "default",
        ttl: 60_000,
        limit: 120
      }
    ])
  ],
  controllers: [HealthController, CveController, StatsController],
  providers: [SchemaService, RedisEnrichCacheService, CveEnrichRunnerService, CveVendorIndexService]
})
export class AppModule {}

