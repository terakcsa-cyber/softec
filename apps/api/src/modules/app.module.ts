import { Module } from "@nestjs/common";
import { APP_GUARD } from "@nestjs/core";
import { ThrottlerGuard, ThrottlerModule } from "@nestjs/throttler";
import { JwtAuthGuard } from "../auth/jwt-auth.guard.js";
import { RolesGuard } from "../auth/roles.guard.js";
import { WriteRoleGuard } from "../auth/write-role.guard.js";
import { AuthModule } from "../auth/auth.module.js";
import { HealthController } from "../routes/health.controller.js";
import { MetricsController } from "../routes/metrics.controller.js";
import { CveController } from "../routes/cve.controller.js";
import { StatsController } from "../routes/stats.controller.js";
import { VendorAdvisoryController } from "../routes/vendor-advisory.controller.js";
import { VulnTaskController } from "../routes/vuln-task.controller.js";
import { IntegrationSettingsController } from "../routes/integration-settings.controller.js";
import { WebTlsController } from "../routes/web-tls.controller.js";
import { PlatformUpdateController } from "../routes/platform-update.controller.js";
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
import { ReconciliationService } from "../services/reconciliation.service.js";
import { OpsRepairService } from "../services/ops-repair.service.js";
import { TextEngineBgSweepService } from "../services/text-engine-bg-sweep.service.js";
import { VocController } from "../routes/voc.controller.js";
import { IntegrationSettingsService } from "../services/integration-settings.service.js";
import { WebTlsService } from "../services/web-tls.service.js";
import { LocalHttpsProxyService } from "../services/local-https-proxy.service.js";
import { LetsEncryptCertbotService } from "../services/letsencrypt-certbot.service.js";
import { PlatformUpdateService } from "../services/platform-update.service.js";
import { MigrationService } from "../services/migration.service.js";
import { MetricsPollerService } from "../services/metrics-poller.service.js";

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
    MetricsController,
    CveController,
    StatsController,
    VendorAdvisoryController,
    VulnTaskController,
    IntegrationSettingsController,
    WebTlsController,
    PlatformUpdateController,
    BduController,
    FstecBulletinController,
    TelegramController,
    VocController
  ],
  providers: [
    SchemaService,
    MigrationService,
    ReconciliationService,
    OpsRepairService,
    TextEngineBgSweepService,
    MetricsPollerService,
    FstecBulletinService,
    MpvmSyncService,
    TelegramPostService,
    RedisEnrichCacheService,
    IntegrationSettingsService,
    WebTlsService,
    LocalHttpsProxyService,
    LetsEncryptCertbotService,
    PlatformUpdateService,
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
    { provide: APP_GUARD, useClass: JwtAuthGuard },
    { provide: APP_GUARD, useClass: ThrottlerGuard },
    { provide: APP_GUARD, useClass: RolesGuard },
    { provide: APP_GUARD, useClass: WriteRoleGuard }
  ]
})
export class AppModule {}

