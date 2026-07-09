import "./load-env.js";
import "reflect-metadata";
import { NestFactory } from "@nestjs/core";
import { AppModule } from "./modules/app.module.js";

async function bootstrap() {
  // Worker-style app: no HTTP listener.
  await NestFactory.createApplicationContext(AppModule, { bufferLogs: true });
  const { startMetricsServer } = await import("@vuln-intel/shared");
  if (process.env.METRICS_ENABLED?.trim() !== "false") {
    startMetricsServer();
  }
}

bootstrap().catch((err) => {
  // eslint-disable-next-line no-console
  console.error(err);
  process.exit(1);
});

