import { Injectable } from "@nestjs/common";
import {
  CVE_HOT_WINDOW_HOURS,
  enrichFailureOutputJson,
  isBduPublicationInLast24h,
  isLlmEnrichFailureRow,
  isLlmNotConfiguredEnrichment,
  runBduContextLlm,
  sha256Hex,
  stableJsonStringify
} from "@vuln-intel/shared";
import { DbService } from "./db.service.js";
import { RedisEnrichCacheService } from "./redis-enrich-cache.service.js";
import { IntegrationSettingsService } from "./integration-settings.service.js";

type EnrichmentBduRow = {
  output_text: string | null;
  output_json: unknown;
};

function normalizeEnrichmentRow(row: EnrichmentBduRow): EnrichmentBduRow {
  let oj = row.output_json;
  if (typeof oj === "string") {
    try {
      oj = JSON.parse(oj) as unknown;
    } catch {
      return row;
    }
  }
  return { ...row, output_json: oj };
}

function formatEnrichFailure(err: unknown): { summary: string; explanation: string } {
  const msg = err instanceof Error ? err.message : String(err);
  return {
    summary: "AI enrichment failed (LLM or network error).",
    explanation: msg.slice(0, 4000)
  };
}

@Injectable()
export class BduEnrichRunnerService {
  private readonly inFlight = new Set<string>();
  private readonly pendingForce = new Set<string>();

  constructor(
    private readonly db: DbService,
    private readonly enrichCache: RedisEnrichCacheService,
    private readonly integration: IntegrationSettingsService
  ) {}

  private async loadMpvmContext(cveIds: string[]): Promise<Record<string, unknown>> {
    const ids = [...new Set(cveIds.map((x) => String(x).trim().toUpperCase()))].filter((x) =>
      /^CVE-\d{4}-\d{4,}$/.test(x)
    );
    if (ids.length === 0) return { summary: { affectedAssets: 0 }, vulnerabilities: [], software: [] };
    const vulns = await this.db.query<{ asset_external_id: string } & Record<string, unknown>>(
      `SELECT v.cve_id,
              v.title,
              v.severity,
              v.cvss_score,
              v.status,
              v.fix_available,
              v.solution,
              v.affected_software_name,
              v.affected_software_version,
              a.external_id AS asset_external_id,
              a.display_name AS asset_display_name,
              a.hostname,
              a.ip_address,
              a.os_name,
              a.os_version
         FROM mpvm_asset_vulnerability v
         JOIN mpvm_asset a ON a.external_id = v.asset_external_id
        WHERE v.cve_id = ANY($1::text[])
     ORDER BY v.cvss_score DESC NULLS LAST, v.last_seen_at DESC
        LIMIT 100`,
      [ids]
    );
    const software = await this.db.query(
      `SELECT DISTINCT s.asset_external_id,
              a.display_name AS asset_display_name,
              s.kind,
              s.name,
              s.version,
              s.vendor,
              s.install_path
         FROM mpvm_asset_software s
         JOIN mpvm_asset a ON a.external_id = s.asset_external_id
         JOIN mpvm_asset_vulnerability v ON v.asset_external_id = s.asset_external_id
          AND (v.affected_software_key = s.software_key OR lower(v.affected_software_name) = lower(s.name))
        WHERE v.cve_id = ANY($1::text[])
     ORDER BY s.name ASC, s.version ASC
        LIMIT 100`,
      [ids]
    );
    const affectedAssets = new Set(vulns.rows.map((r) => String(r.asset_external_id))).size;
    return {
      summary: { affectedAssets, vulnerabilities: vulns.rows.length, software: software.rows.length },
      vulnerabilities: vulns.rows,
      software: software.rows
    };
  }

  scheduleEnrich(bduId: string, opts?: { force?: boolean; allowOutsideHotWindow?: boolean }): void {
    if (this.inFlight.has(bduId)) {
      if (opts?.force) this.pendingForce.add(bduId);
      return;
    }
    this.inFlight.add(bduId);
    void this.run(bduId, Boolean(opts?.force), Boolean(opts?.allowOutsideHotWindow)).finally(() => {
      this.inFlight.delete(bduId);
      if (this.pendingForce.has(bduId)) {
        this.pendingForce.delete(bduId);
        this.scheduleEnrich(bduId, { force: true });
      }
    });
  }

  private async run(bduId: string, force: boolean, allowOutsideHotWindow = false): Promise<void> {
    const cfg = await this.integration.getEffectiveLlmConfig();
    const logApi = process.env.LLM_LOG_REQUESTS !== "false";
    if (logApi) {
      // eslint-disable-next-line no-console
      console.log(`[api:enrich:bdu] start bdu=${bduId} force=${force}`);
    }
    try {
      const r = await this.db.query<{
        bdu_id: string;
        name: string;
        description: string | null;
        software_names: string | null;
        vendors: string | null;
        cve_ids: string[];
        severity: string | null;
        severity_level: number;
        cvss_score: number | null;
        cvss_vector: string | null;
        identify_date: string | null;
        publication_date: string | null;
        solution: string | null;
        status: string | null;
        exploit_status: string | null;
        fix_status: string | null;
        has_exploit: boolean;
        has_fix: boolean;
        sources: string | null;
        fstec_url: string;
      }>(
        `SELECT bdu_id, name, description, software_names, vendors, cve_ids,
                severity, severity_level, cvss_score, cvss_vector,
                identify_date, publication_date, solution, status,
                exploit_status, fix_status, has_exploit, has_fix, sources, fstec_url
           FROM bdu_vuln WHERE bdu_id = $1 LIMIT 1`,
        [bduId]
      );
      if ((r.rowCount ?? 0) === 0) return;
      const row = r.rows[0]!;

      const inHotWindow = isBduPublicationInLast24h(row.publication_date);
      if (!force && !allowOutsideHotWindow && !inHotWindow) {
        // eslint-disable-next-line no-console
        console.log(
          `[api:enrich:bdu] skip (publication outside ${CVE_HOT_WINDOW_HOURS}h) bdu=${bduId} publication=${row.publication_date ?? "none"}`
        );
        return;
      }

      if (!force) {
        const latestAi = await this.db.query<EnrichmentBduRow>(
          `SELECT output_text, output_json FROM enrichment_bdu
            WHERE bdu_id = $1 ORDER BY created_at DESC LIMIT 20`,
          [bduId]
        );
        const hit = latestAi.rows
          .map(normalizeEnrichmentRow)
          .find((x) => !isLlmNotConfiguredEnrichment(x) && !isLlmEnrichFailureRow(x));
        if (hit) return;
      }

      const linked = await this.db.query<{
        cve_id: string;
        cvss_base: number | null;
        epss: number | null;
        exploit_known: boolean;
        risk_score: number | null;
      }>(
        `SELECT c.cve_id, c.cvss_base, es.score AS epss, (k.cve_id IS NOT NULL) AS exploit_known, rs.score AS risk_score
           FROM cve_bdu_link l
           JOIN cve c ON c.cve_id = l.cve_id
           LEFT JOIN epss_score es ON es.cve_id = c.cve_id
           LEFT JOIN kev k ON k.cve_id = c.cve_id
           LEFT JOIN risk_score rs ON rs.cve_id = c.cve_id
          WHERE l.bdu_id = $1
          ORDER BY c.cve_id
          LIMIT 20`,
        [bduId]
      );

      const raw: Record<string, unknown> = {
        registry: "BDU_FSTEC",
        bduId: row.bdu_id,
        name: row.name,
        description: row.description,
        softwareNames: row.software_names,
        vendors: row.vendors,
        cveIds: row.cve_ids,
        severity: row.severity,
        severityLevel: row.severity_level,
        cvssScore: row.cvss_score,
        cvssVector: row.cvss_vector,
        identifyDate: row.identify_date,
        publicationDate: row.publication_date,
        solution: row.solution,
        status: row.status,
        exploitStatus: row.exploit_status,
        fixStatus: row.fix_status,
        hasExploit: row.has_exploit,
        hasFix: row.has_fix,
        sources: row.sources,
        fstecUrl: row.fstec_url,
        linkedCves: linked.rows.map((c) => ({
          cve_id: c.cve_id,
          cvss_base: c.cvss_base,
          epss: c.epss,
          exploit_known: c.exploit_known,
          risk_score: c.risk_score
        }))
      };
      const mpvmContext = await this.loadMpvmContext([
        ...row.cve_ids,
        ...linked.rows.map((c) => c.cve_id)
      ]);
      if ((mpvmContext.summary as { affectedAssets?: number }).affectedAssets || (mpvmContext.summary as { software?: number }).software) {
        raw.mpvmContext = mpvmContext;
      }

      const res = await runBduContextLlm(bduId, raw, cfg);
      await this.enrichCache?.invalidateForBdu(bduId, cfg.promptVersion);

      await this.db.query(
        `INSERT INTO enrichment_bdu(bdu_id, model, prompt_version, input_hash, output_json, output_text, tokens_input, tokens_output, cost_usd)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
         ON CONFLICT (bdu_id, model, prompt_version, input_hash) DO UPDATE SET
           output_json = EXCLUDED.output_json,
           output_text = EXCLUDED.output_text,
           tokens_input = EXCLUDED.tokens_input,
           tokens_output = EXCLUDED.tokens_output,
           cost_usd = EXCLUDED.cost_usd`,
        [
          bduId,
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
      // eslint-disable-next-line no-console
      console.log(`[api:enrich:bdu] ok ${bduId}`);
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error(`[api:enrich:bdu] failed ${bduId}`, err);
      const { summary, explanation } = formatEnrichFailure(err);
      const failJson = enrichFailureOutputJson(summary, explanation);
      const inputHash = await sha256Hex(
        stableJsonStringify({ _fail: true, bduId, err: String(err).slice(0, 3000), t: Date.now() })
      );
      try {
        await this.db.query(
          `INSERT INTO enrichment_bdu(bdu_id, model, prompt_version, input_hash, output_json, output_text, tokens_input, tokens_output, cost_usd)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
           ON CONFLICT (bdu_id, model, prompt_version, input_hash) DO UPDATE SET
             output_json = EXCLUDED.output_json,
             output_text = EXCLUDED.output_text`,
          [bduId, cfg.model, cfg.promptVersion, inputHash, JSON.stringify(failJson), summary, null, null, null]
        );
      } catch (dbErr) {
        // eslint-disable-next-line no-console
        console.error(`[api:enrich:bdu] could not persist failure ${bduId}`, dbErr);
      }
    }
  }
}
