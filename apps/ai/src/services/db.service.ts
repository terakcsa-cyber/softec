import { Injectable, OnModuleDestroy } from "@nestjs/common";
import pg from "pg";

@Injectable()
export class DbService implements OnModuleDestroy {
  private readonly pool: pg.Pool;

  constructor() {
    const url =
      process.env.DATABASE_URL ?? "postgres://vuln:vuln@localhost:5432/vuln_intel";
    this.pool = new pg.Pool({
      connectionString: url,
      // Должен быть ≥ AI_ENRICH_PREFETCH, иначе воркер будет ждать соединения из пула при параллельных enrich.
      max: Number(process.env.PG_POOL_MAX ?? 20),
      idleTimeoutMillis: 20_000,
      connectionTimeoutMillis: 10_000
    });
  }

  query<T extends pg.QueryResultRow = pg.QueryResultRow>(
    text: string,
    params?: unknown[]
  ): Promise<pg.QueryResult<T>> {
    return this.pool.query<T>(text, params as any[] | undefined);
  }

  async onModuleDestroy() {
    await this.pool.end();
  }
}

