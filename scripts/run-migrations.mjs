#!/usr/bin/env node
/**
 * Apply versioned SQL migrations from infra/postgres/migrations/.
 * Idempotent: tracks applied versions in schema_migrations.
 */
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import pg from "pg";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");
const migrationsDir = path.join(root, "infra/postgres/migrations");

function dbUrl() {
  return (
    process.env.DATABASE_URL?.trim() ||
    `postgresql://${process.env.POSTGRES_USER ?? "vuln"}:${process.env.POSTGRES_PASSWORD ?? "vuln"}@${process.env.POSTGRES_HOST ?? "127.0.0.1"}:${process.env.POSTGRES_PORT ?? "5432"}/${process.env.POSTGRES_DB ?? "vuln_intel"}`
  );
}

async function main() {
  const client = new pg.Client({ connectionString: dbUrl() });
  await client.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        version TEXT PRIMARY KEY,
        applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )
    `);

    const files = (await readdir(migrationsDir))
      .filter((f) => f.endsWith(".sql"))
      .sort();

    const applied = await client.query(`SELECT version FROM schema_migrations`);
    const done = new Set(applied.rows.map((r) => r.version));

    for (const file of files) {
      const version = file.replace(/\.sql$/, "");
      if (done.has(version)) {
        console.log(`skip ${file} (already applied)`);
        continue;
      }
      const sql = await readFile(path.join(migrationsDir, file), "utf8");
      console.log(`apply ${file}...`);
      await client.query("BEGIN");
      try {
        await client.query(sql);
        await client.query(`INSERT INTO schema_migrations (version) VALUES ($1)`, [version]);
        await client.query("COMMIT");
        console.log(`ok ${file}`);
      } catch (e) {
        await client.query("ROLLBACK");
        throw e;
      }
    }
    console.log("migrations complete");
  } finally {
    await client.end();
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
