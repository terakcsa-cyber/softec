import { Injectable, Logger, OnModuleDestroy, OnModuleInit } from "@nestjs/common";
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { DbService } from "./db.service.js";

@Injectable()
export class MigrationService implements OnModuleInit {
  private readonly logger = new Logger(MigrationService.name);

  constructor(private readonly db: DbService) {}

  async onModuleInit() {
    await this.runPendingMigrations();
  }

  private migrationsDir(): string {
    const here = path.dirname(fileURLToPath(import.meta.url));
    return path.resolve(here, "../../../../infra/postgres/migrations");
  }

  async runPendingMigrations(): Promise<void> {
    await this.db.query(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        version TEXT PRIMARY KEY,
        applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )
    `);

    let files: string[];
    try {
      files = (await readdir(this.migrationsDir()))
        .filter((f) => f.endsWith(".sql"))
        .sort();
    } catch (e) {
      this.logger.warn(`Migrations dir not found, skipping: ${String(e)}`);
      return;
    }

    const applied = await this.db.query<{ version: string }>(
      `SELECT version FROM schema_migrations`
    );
    const done = new Set(applied.rows.map((r) => r.version));

    for (const file of files) {
      const version = file.replace(/\.sql$/, "");
      if (done.has(version)) continue;
      const sql = await readFile(path.join(this.migrationsDir(), file), "utf8");
      this.logger.log(`Applying migration ${file}`);
      await this.db.query("BEGIN");
      try {
        await this.db.query(sql);
        await this.db.query(`INSERT INTO schema_migrations (version) VALUES ($1)`, [version]);
        await this.db.query("COMMIT");
        this.logger.log(`Migration ${file} applied`);
      } catch (e) {
        await this.db.query("ROLLBACK");
        throw e;
      }
    }
  }
}
