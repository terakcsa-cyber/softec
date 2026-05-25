import "./load-env.js";
import "reflect-metadata";
import helmet from "helmet";
import { NestFactory } from "@nestjs/core";
import { AppModule } from "./modules/app.module.js";

function resolveCorsOptions(): {
  origin: boolean | string | RegExp | Array<string | RegExp>;
  methods: string[];
  maxAge: number;
} {
  const isProd = process.env.NODE_ENV === "production";
  const raw = process.env.API_CORS_ORIGIN?.trim();
  if (isProd) {
    if (!raw) {
      return {
        origin: false,
        methods: ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"],
        maxAge: 86400
      };
    }
    const origins = raw.split(",").map((s) => s.trim()).filter(Boolean);
    return {
      origin: origins.length === 1 ? origins[0]! : origins,
      methods: ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"],
      maxAge: 86400
    };
  }
  return {
    origin: [/^http:\/\/localhost:\d+$/, /^http:\/\/127\.0\.0\.1:\d+$/],
    methods: ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"],
    maxAge: 86400
  };
}

async function bootstrap() {
  const app = await NestFactory.create(AppModule, { bufferLogs: true });
  const isProd = process.env.NODE_ENV === "production";
  app.use(
    helmet({
      contentSecurityPolicy: false,
      crossOriginEmbedderPolicy: false,
      crossOriginResourcePolicy: { policy: "cross-origin" },
      hsts: isProd ? { maxAge: 31536000, includeSubDomains: true, preload: false } : false,
      referrerPolicy: { policy: "strict-origin-when-cross-origin" }
    })
  );

  app.enableShutdownHooks();
  app.setGlobalPrefix("api");

  // Dev: localhost origins. Prod: только явный список в API_CORS_ORIGIN (без regex).
  app.enableCors(resolveCorsOptions());

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

