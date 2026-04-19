import pg from "pg";
import {
  enrichFailureOutputJson,
  getVulnContextLlmConfigFromEnv,
  isLlmEnrichFailureRow,
  isLlmNotConfiguredEnrichment,
  runVulnContextLlm,
  sha256Hex,
  stableJsonStringify
} from "../packages/shared/dist/index.js";

const DATABASE_URL =
  process.env.DATABASE_URL ?? "postgres://vuln:vuln@localhost:5432/vuln_intel";

// Defaults are intentionally conservative for LAN Ollama.
const LIMIT = Number(process.env.AI_BULK_LIMIT ?? 200);
const BATCH = Number(process.env.AI_BULK_BATCH ?? 20);
const CONCURRENCY = Math.max(1, Number(process.env.AI_BULK_CONCURRENCY ?? 2));
const ONLY_MISSING = (process.env.AI_BULK_ONLY_MISSING ?? "true") !== "false";
const FORCE = (process.env.AI_BULK_FORCE ?? "false") === "true";

function formatEnrichFailure(err) {
  const msg = err instanceof Error ? err.message : String(err);
  return {
    summary: "AI enrichment failed (LLM or network error).",
    explanation: msg.slice(0, 4000)
  };
}

async function upsertResult(db, cveId, res) {
  await db.query(
    `INSERT INTO enrichment_ai(cve_id, model, prompt_version, input_hash, output_json, output_text, tokens_input, tokens_output, cost_usd)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
     ON CONFLICT (cve_id, model, prompt_version, input_hash) DO UPDATE SET
       output_json = EXCLUDED.output_json,
       output_text = EXCLUDED.output_text,
       tokens_input = EXCLUDED.tokens_input,
       tokens_output = EXCLUDED.tokens_output,
       cost_usd = EXCLUDED.cost_usd`,
    [
      cveId,
      res.model,
      res.promptVersion,
      res.inputHash,
      JSON.stringify(res.outputJson),
      res.outputText ?? null,
      res.tokensInput ?? null,
      res.tokensOutput ?? null,
      res.costUsd ?? null
    ]
  );
}

async function upsertFailure(db, cveId, cfg, err) {
  const { summary, explanation } = formatEnrichFailure(err);
  const failJson = enrichFailureOutputJson(summary, explanation);
  const inputHash = await sha256Hex(
    stableJsonStringify({ _fail: true, cveId, model: cfg.model, err: String(err).slice(0, 3000), t: Date.now() })
  );
  await db.query(
    `INSERT INTO enrichment_ai(cve_id, model, prompt_version, input_hash, output_json, output_text, tokens_input, tokens_output, cost_usd)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
     ON CONFLICT (cve_id, model, prompt_version, input_hash) DO UPDATE SET
       output_json = EXCLUDED.output_json,
       output_text = EXCLUDED.output_text,
       tokens_input = EXCLUDED.tokens_input,
       tokens_output = EXCLUDED.tokens_output,
       cost_usd = EXCLUDED.cost_usd`,
    [
      cveId,
      cfg.model,
      cfg.promptVersion,
      inputHash,
      JSON.stringify(failJson),
      failJson.summary ?? null,
      null,
      null,
      null
    ]
  );
}

async function shouldSkipBecauseAlreadyEnriched(db, cveId) {
  const latest = await db.query(
    `SELECT output_text, output_json
       FROM enrichment_ai
      WHERE cve_id = $1
   ORDER BY created_at DESC
      LIMIT 1`,
    [cveId]
  );
  const row = latest.rows[0] ?? null;
  if (!row) return false;
  if (isLlmNotConfiguredEnrichment(row)) return false;
  if (isLlmEnrichFailureRow(row)) return false;
  return true;
}

async function main() {
  const cfg = getVulnContextLlmConfigFromEnv();
  const db = new pg.Pool({ connectionString: DATABASE_URL });

  let processed = 0;
  let started = 0;
  let ok = 0;
  let failed = 0;

  try {
    // eslint-disable-next-line no-console
    console.log(
      `[ai-bulk-enrich] start limit=${LIMIT} batch=${BATCH} concurrency=${CONCURRENCY} onlyMissing=${ONLY_MISSING} force=${FORCE} endpoint=${cfg.endpoint} model=${cfg.model}`
    );

    let last = "";
    const inFlight = new Set();

    async function worker(cveId, raw) {
      try {
        const res = await runVulnContextLlm(cveId, raw, cfg);
        await upsertResult(db, cveId, res);
        ok++;
      } catch (e) {
        failed++;
        await upsertFailure(db, cveId, cfg, e);
      } finally {
        processed++;
        if (processed % 10 === 0) {
          // eslint-disable-next-line no-console
          console.log(`[ai-bulk-enrich] processed=${processed} ok=${ok} failed=${failed} last=${cveId}`);
        }
      }
    }

    // eslint-disable-next-line no-constant-condition
    while (true) {
      if (LIMIT > 0 && started >= LIMIT) break;

      // keyset pagination; optionally filter to rows without any ai record.
      // NOTE: prefer LEFT JOIN over NOT EXISTS for speed on some setups.
      // eslint-disable-next-line no-await-in-loop
      const q = ONLY_MISSING
        ? `SELECT c.cve_id, c.raw
             FROM cve c
        LEFT JOIN enrichment_ai ea ON ea.cve_id = c.cve_id
            WHERE c.cve_id > $1
              AND ea.cve_id IS NULL
         ORDER BY c.cve_id ASC
            LIMIT $2`
        : `SELECT cve_id, raw
             FROM cve
            WHERE cve_id > $1
         ORDER BY cve_id ASC
            LIMIT $2`;

      const tQ = Date.now();
      const r = await db.query(q, [last, BATCH]);
      // eslint-disable-next-line no-console
      console.log(`[ai-bulk-enrich] fetched rows=${r.rowCount} ms=${Date.now() - tQ}`);

      if (r.rowCount === 0) break;
      last = r.rows[r.rows.length - 1]?.cve_id ?? last;

      for (const row of r.rows) {
        if (LIMIT > 0 && started >= LIMIT) break;
        const cveId = row.cve_id;
        if (!FORCE && !ONLY_MISSING) {
          // eslint-disable-next-line no-await-in-loop
          const skip = await shouldSkipBecauseAlreadyEnriched(db, cveId);
          if (skip) continue;
        }

        while (inFlight.size >= CONCURRENCY) {
          // eslint-disable-next-line no-await-in-loop
          await Promise.race(inFlight);
        }
        const raw =
          row.raw != null && typeof row.raw === "object" && !Array.isArray(row.raw) ? row.raw : {};
        // eslint-disable-next-line no-console
        console.log(`[ai-bulk-enrich] start_one ${cveId}`);
        const p = worker(cveId, raw);
        inFlight.add(p);
        p.finally(() => inFlight.delete(p));
        started++;
      }

      // Avoid fetching unbounded work while the model is slow.
      // eslint-disable-next-line no-await-in-loop
      if (inFlight.size > 0) await Promise.race(inFlight);
    }

    await Promise.allSettled([...inFlight]);
    // eslint-disable-next-line no-console
    console.log(`[ai-bulk-enrich] done processed=${processed} ok=${ok} failed=${failed}`);
  } finally {
    await db.end().catch(() => {});
  }
}

await main();

