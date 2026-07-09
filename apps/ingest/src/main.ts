import "reflect-metadata";
import { NestFactory } from "@nestjs/core";
import { AppModule } from "./modules/app.module.js";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { config as loadDotenv } from "dotenv";

async function bootstrap() {
  // Ensure ingest sees the same root .env as other services, even when started via turbo.
  const here = path.dirname(fileURLToPath(import.meta.url));
  const rootEnvPath = path.resolve(here, "../../..", ".env");
  loadDotenv({ path: rootEnvPath });

  await NestFactory.createApplicationContext(AppModule, { bufferLogs: true });
  const { startMetricsServer } = await import("@vuln-intel/shared");
  if (process.env.METRICS_ENABLED?.trim() !== "false") {
    startMetricsServer({
      port: Number(process.env.METRICS_PORT ?? "9091")
    });
  }
}

bootstrap().catch((err) => {
  // eslint-disable-next-line no-console
  console.error(err);
  process.exit(1);
});

