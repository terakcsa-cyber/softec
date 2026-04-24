import { Module } from "@nestjs/common";
import { APP_GUARD } from "@nestjs/core";
import { ThrottlerModule } from "@nestjs/throttler";
import { JwtAuthGuard } from "../auth/jwt-auth.guard.js";
import { AuthModule } from "../auth/auth.module.js";
import { HealthController } from "../routes/health.controller.js";
import { CveController } from "../routes/cve.controller.js";
import { StatsController } from "../routes/stats.controller.js";
import { VendorAdvisoryController } from "../routes/vendor-advisory.controller.js";
import { AsvController } from "../routes/asv.controller.js";
import { VulnTaskController } from "../routes/vuln-task.controller.js";
import { DbModule } from "./db.module.js";
import { QueueModule } from "./queue.module.js";
import { CveEnrichRunnerService } from "../services/cve-enrich-runner.service.js";
import { RedisEnrichCacheService } from "../services/redis-enrich-cache.service.js";
import { SchemaService } from "../services/schema.service.js";
import { CveVendorIndexService } from "../services/cve-vendor-index.service.js";
import { VulnTaskService } from "../services/vuln-task.service.js";

@Module({
  imports: [
    DbModule,
    AuthModule,
    QueueModule,
    ThrottlerModule.forRoot([
      {
        name: "default",
        ttl: 60_000,
        limit: 120
      }
    ])
  ],
  controllers: [HealthController, CveController, StatsController, VendorAdvisoryController, AsvController, VulnTaskController],
  providers: [
    SchemaService,
    RedisEnrichCacheService,
    CveEnrichRunnerService,
    CveVendorIndexService,
    VulnTaskService,
    { provide: APP_GUARD, useClass: JwtAuthGuard }
  ]
})
export class AppModule {}

