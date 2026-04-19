import "./load-env.js";
import "reflect-metadata";
import helmet from "helmet";
import { NestFactory } from "@nestjs/core";
import { AppModule } from "./modules/app.module.js";

async function bootstrap() {
  const app = await NestFactory.create(AppModule, { bufferLogs: true });
  app.use(helmet());

  app.enableShutdownHooks();
  app.setGlobalPrefix("api");

  // Dev-friendly CORS for Next.js running on a different port.
  // (curl works either way; browsers will block without CORS headers.)
  app.enableCors({
    origin: [/^http:\/\/localhost:\d+$/, /^http:\/\/127\.0\.0\.1:\d+$/],
    methods: ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"],
    maxAge: 86400
  });

  const port = Number(process.env.PORT ?? 4001);
  const host = process.env.API_HOST ?? "127.0.0.1";
  await app.listen(port, host);
  // eslint-disable-next-line no-console
  console.log(`[api] listening on http://${host}:${port}/api`);
}

bootstrap().catch((err) => {
  // eslint-disable-next-line no-console
  console.error(err);
  process.exit(1);
});

