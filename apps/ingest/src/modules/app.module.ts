import { Module } from "@nestjs/common";
import { DbModule } from "./db.module.js";
import { QueueModule } from "./queue.module.js";
import { NvdIngestJob } from "../jobs/nvd-ingest.job.js";
import { KevIngestJob } from "../jobs/kev-ingest.job.js";
import { EpssIngestJob } from "../jobs/epss-ingest.job.js";

@Module({
  imports: [DbModule, QueueModule],
  providers: [NvdIngestJob, KevIngestJob, EpssIngestJob]
})
export class AppModule {}

