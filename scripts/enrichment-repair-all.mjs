/**
 * Чинит enrichment_ai.output_json: сырой JSON в summary, пустые remediation/nextSteps.
 * Подмешивает NVD baseline и сигналы патчей для всех строк с raw в cve.
 */
import pg from "pg";
import {
  isGarbageEnrichSummary,
  resolveCveCardEnrichment,
  stableJsonStringify
} from "../packages/shared/dist/index.js";

const DATABASE_URL =
  process.env.DATABASE_URL ?? "postgres://vuln:vuln@localhost:5432/vuln_intel";

const BATCH = Math.max(50, Number(process.env.ENRICH_REPAIR_BATCH ?? 400));
const LIMIT = Number(process.env.ENRICH_REPAIR_LIMIT ?? 0);
const DRY_RUN = (process.env.ENRICH_REPAIR_DRY_RUN ?? "false") === "true";

function needsRepair(stored, resolved) {
  if (!stored || typeof stored !== "object") return true;
  const summary = stored.summary;
  if (isGarbageEnrichSummary(summary)) return true;
  if (typeof summary === "string" && summary.startsWith("LLM not configured")) return true;
  const oldText = stableJsonStringify(stored);
  const newText = stableJsonStringify(resolved);
  return oldText !== newText;
}

async function main() {
  const db = new pg.Pool({ connectionString: DATABASE_URL });
  let offset = 0;
  let scanned = 0;
  let updated = 0;
  let skipped = 0;

  console.log(`enrichment-repair-all: batch=${BATCH} dryRun=${DRY_RUN} limit=${LIMIT || "∞"}`);

  try {
    while (true) {
      if (LIMIT > 0 && scanned >= LIMIT) break;

      const take = LIMIT > 0 ? Math.min(BATCH, LIMIT - scanned) : BATCH;
      const r = await db.query(
        `SELECT ea.cve_id, ea.model, ea.prompt_version, ea.input_hash,
                ea.output_json, ea.output_text, c.raw
           FROM enrichment_ai ea
           JOIN cve c ON c.cve_id = ea.cve_id
          WHERE c.raw IS NOT NULL
          ORDER BY ea.created_at ASC
          LIMIT $1 OFFSET $2`,
        [take, offset]
      );

      if (r.rows.length === 0) break;

      for (const row of r.rows) {
        scanned += 1;
        const resolved = resolveCveCardEnrichment(row.output_json, row.cve_id, row.raw);
        if (!needsRepair(row.output_json, resolved)) {
          skipped += 1;
          continue;
        }

        const outputText =
          typeof resolved.summary === "string" && resolved.summary.trim()
            ? resolved.summary.trim()
            : row.output_text;

        if (!DRY_RUN) {
          await db.query(
            `UPDATE enrichment_ai
                SET output_json = $1::jsonb,
                    output_text = $2
              WHERE cve_id = $3
                AND model = $4
                AND prompt_version = $5
                AND input_hash = $6`,
            [
              JSON.stringify(resolved),
              outputText,
              row.cve_id,
              row.model,
              row.prompt_version,
              row.input_hash
            ]
          );
        }
        updated += 1;
        if (updated % 100 === 0) {
          console.log(`  updated ${updated} (scanned ${scanned})…`);
        }
      }

      offset += r.rows.length;
      if (r.rows.length < take) break;
    }

    console.log(`Done: scanned=${scanned} updated=${updated} skipped=${skipped} dryRun=${DRY_RUN}`);
  } finally {
    await db.end();
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
