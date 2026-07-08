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
import { IntegrationSettingsController } from "../routes/integration-settings.controller.js";
import { BduController } from "../routes/bdu.controller.js";
import { FstecBulletinController } from "../routes/fstec-bulletin.controller.js";
import { TelegramController } from "../routes/telegram.controller.js";
import { FstecBulletinService } from "../services/fstec-bulletin.service.js";
import { MpvmSyncService } from "../services/mpvm-sync.service.js";
import { TelegramPostService } from "../services/telegram-post.service.js";
import { DbModule } from "./db.module.js";
import { QueueModule } from "./queue.module.js";
import { BduEnrichRunnerService } from "../services/bdu-enrich-runner.service.js";
import { CveEnrichRunnerService } from "../services/cve-enrich-runner.service.js";
import { RedisEnrichCacheService } from "../services/redis-enrich-cache.service.js";
import { SchemaService } from "../services/schema.service.js";
import { CveVendorIndexService } from "../services/cve-vendor-index.service.js";
import { CveNvdImportService } from "../services/cve-nvd-import.service.js";
import { VulnTaskService } from "../services/vuln-task.service.js";
import { VocCaseService } from "../services/voc-case.service.js";
import { VocShiftService } from "../services/voc-shift.service.js";
import { VocService } from "../services/voc.service.js";
import { ThreatFeedService } from "../services/threat-feed.service.js";
import { ThreatDigestPdfService } from "../services/threat-digest-pdf.service.js";
import { ThreatIntelRefreshService } from "../services/threat-intel-refresh.service.js";
import { VocController } from "../routes/voc.controller.js";
import { IntegrationSettingsService } from "../services/integration-settings.service.js";

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
  controllers: [
    HealthController,
    CveController,
    StatsController,
    VendorAdvisoryController,
    AsvController,
    VulnTaskController,
    IntegrationSettingsController,
    BduController,
    FstecBulletinController,
    TelegramController,
    VocController
  ],
  providers: [
    SchemaService,
    FstecBulletinService,
    MpvmSyncService,
    TelegramPostService,
    RedisEnrichCacheService,
    IntegrationSettingsService,
    CveEnrichRunnerService,
    BduEnrichRunnerService,
    CveVendorIndexService,
    CveNvdImportService,
    VulnTaskService,
    VocCaseService,
    VocShiftService,
    VocService,
    ThreatFeedService,
    ThreatDigestPdfService,
    ThreatIntelRefreshService,
    { provide: APP_GUARD, useClass: JwtAuthGuard }
  ]
})
export class AppModule {}

