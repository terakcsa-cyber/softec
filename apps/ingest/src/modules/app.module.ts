import { Module } from "@nestjs/common";
import { DbModule } from "./db.module.js";
import { QueueModule } from "./queue.module.js";
import { NvdIngestJob } from "../jobs/nvd-ingest.job.js";
import { KevIngestJob } from "../jobs/kev-ingest.job.js";
import { EpssIngestJob } from "../jobs/epss-ingest.job.js";
import { VendorAdvisoryIngestJob } from "../jobs/vendor-advisory-ingest.job.js";
import { BduIngestJob } from "../jobs/bdu-ingest.job.js";
import { NvdExploitRefsJob } from "../jobs/nvd-exploit-refs.job.js";
import { VulncheckKevIngestJob } from "../jobs/vulncheck-kev-ingest.job.js";
import { ExploitIntelRefreshJob } from "../jobs/exploit-intel-refresh.job.js";
import { ThreatIntelBootJob } from "../jobs/threat-intel-boot.job.js";
import { IntegrationsBootJob } from "../jobs/integrations-boot.job.js";
import { AsvScanWorker } from "../workers/asv-scan.worker.js";
import { AsvMsfWorker } from "../workers/asv-msf.worker.js";

@Module({
  imports: [DbModule, QueueModule],
  providers: [
    NvdIngestJob,
    KevIngestJob,
    EpssIngestJob,
    VendorAdvisoryIngestJob,
    BduIngestJob,
    NvdExploitRefsJob,
    VulncheckKevIngestJob,
    ExploitIntelRefreshJob,
    ThreatIntelBootJob,
    IntegrationsBootJob,
    AsvScanWorker,
    AsvMsfWorker
  ]
})
export class AppModule {}

