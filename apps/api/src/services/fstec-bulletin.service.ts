import { Injectable, NotFoundException } from "@nestjs/common";
import {
  enrichFailureOutputJson,
  getVulnContextLlmConfigFromEnv,
  isLlmNotConfiguredEnrichment,
  mergeVulnContextLlmConfig,
  buildBulletinAnalysisContext,
  FSTEC_BULLETIN_PROMPT_VERSION,
  normalizeFstecBulletinAnalysis,
  parseFstecBulletinText,
  runFstecBulletinAnalysisLlm,
  stableJsonStringify,
  type FstecBulletinParsed
} from "@vuln-intel/shared";
import { DbService } from "./db.service.js";
import { BduEnrichRunnerService } from "./bdu-enrich-runner.service.js";
import { IntegrationSettingsService } from "./integration-settings.service.js";

const BDU_ENRICH_STAGGER_MS = 1500;

export type FstecBulletinRegistryItem = {
  bduId: string;
  found: boolean;
  name: string | null;
  cvssScore: number | null;
  severity: string | null;
  cveIds: string[];
  hasExploit: boolean;
  hasFix: boolean;
  publicationDate: string | null;
  linkedCves: {
    cveId: string;
    cvssBase: number | null;
    riskScore: number | null;
  }[];
};

@Injectable()
export class FstecBulletinService {
  private readonly analyzing = new Set<string>();

  constructor(
    private readonly db: DbService,
    private readonly integration: IntegrationSettingsService,
    private readonly bduEnrich: BduEnrichRunnerService
  ) {}

  private collectBduIds(parsed: FstecBulletinParsed): string[] {
    const ids = new Set<string>();
    for (const it of parsed.items ?? []) {
      const id = String(it.bduId ?? "")
        .replace(/^BDU:/i, "")
        .trim();
      if (id) ids.add(id);
    }
    for (const raw of parsed.orphanBduIds ?? []) {
      const id = String(raw)
        .replace(/^BDU:/i, "")
        .trim();
      if (id) ids.add(id);
    }
    return [...ids];
  }

  /** ИИ-обогащение каждой BDU из бюллетеня (вне окна 24ч — тоже). */
  private scheduleBduEnrichForParsed(parsed: FstecBulletinParsed): number {
    const ids = this.collectBduIds(parsed);
    ids.forEach((bduId, index) => {
      const run = () => {
        this.bduEnrich.scheduleEnrich(bduId, { allowOutsideHotWindow: true });
      };
      if (index === 0) run();
      else setTimeout(run, index * BDU_ENRICH_STAGGER_MS);
    });
    return ids.length;
  }

  async createFromPlainText(input: {
    plainText: string;
    title?: string | null;
    referenceNo?: string | null;
    sourceFilename?: string | null;
  }) {
    const parsed = parseFstecBulletinText(input.plainText, {
      referenceHint: input.referenceNo ?? null
    });
    const title =
      input.title?.trim() ||
      parsed.title ||
      parsed.subject ||
      input.sourceFilename ||
      "Бюллетень ФСТЭК";

    const ins = await this.db.query<{ id: string }>(
      `INSERT INTO fstec_bulletin (title, reference_no, source_filename, plain_text, parsed_json, status)
       VALUES ($1, $2, $3, $4, $5::jsonb, 'parsed')
       RETURNING id`,
      [
        title,
        input.referenceNo ?? parsed.referenceHint,
        input.sourceFilename ?? null,
        input.plainText,
        stableJsonStringify(parsed)
      ]
    );
    const id = ins.rows[0]!.id;
    this.scheduleBduEnrichForParsed(parsed);
    this.scheduleAnalyze(id);
    return this.getById(id);
  }

  async deleteById(id: string): Promise<{ ok: true }> {
    const r = await this.db.query<{ id: string }>(
      `DELETE FROM fstec_bulletin WHERE id = $1 RETURNING id`,
      [id]
    );
    if ((r.rowCount ?? 0) === 0) throw new NotFoundException("bulletin not found");
    this.analyzing.delete(id);
    return { ok: true };
  }

  async list(limit = 30, offset = 0) {
    const r = await this.db.query<{
      id: string;
      title: string | null;
      reference_no: string | null;
      source_filename: string | null;
      status: string;
      created_at: Date;
      item_count: number;
      has_analysis: boolean;
    }>(
      `SELECT b.id, b.title, b.reference_no, b.source_filename, b.status, b.created_at,
              COALESCE(jsonb_array_length(b.parsed_json->'items'), 0)::int AS item_count,
              (a.status = 'ready') AS has_analysis
         FROM fstec_bulletin b
         LEFT JOIN fstec_bulletin_analysis a ON a.bulletin_id = b.id
        ORDER BY b.created_at DESC
        LIMIT $1 OFFSET $2`,
      [limit, offset]
    );
    return { items: r.rows, limit, offset };
  }

  async getById(id: string) {
    const r = await this.db.query<{
      id: string;
      title: string | null;
      reference_no: string | null;
      source_filename: string | null;
      plain_text: string;
      parsed_json: unknown;
      status: string;
      created_at: Date;
      updated_at: Date;
    }>(`SELECT * FROM fstec_bulletin WHERE id = $1`, [id]);
    if ((r.rowCount ?? 0) === 0) throw new NotFoundException("bulletin not found");
    const row = r.rows[0]!;
    let parsed = row.parsed_json as FstecBulletinParsed;
    if (typeof parsed === "string") {
      try {
        parsed = JSON.parse(parsed) as FstecBulletinParsed;
      } catch {
        parsed = parseFstecBulletinText(row.plain_text, { referenceHint: row.reference_no });
      }
    }
    const registry = await this.loadRegistryForParsed(parsed);
    let analysis = await this.getAnalysisRow(id);
    if (analysis?.status === "ready" && analysis.outputJson && typeof analysis.outputJson === "object") {
      const oj = analysis.outputJson as Record<string, unknown>;
      const needsPlan =
        !oj.actionPlan ||
        (typeof oj.actionPlan === "object" &&
          !Array.isArray((oj.actionPlan as { phases?: unknown }).phases));
      if (needsPlan) {
        const analysisContext = buildBulletinAnalysisContext({
          bulletin: {
            title: row.title,
            referenceNo: row.reference_no
          },
          parsed,
          registry
        });
        analysis = {
          ...analysis,
          outputJson: normalizeFstecBulletinAnalysis(oj, analysisContext)
        };
      }
    }
    return {
      bulletin: {
        id: row.id,
        title: row.title,
        referenceNo: row.reference_no,
        sourceFilename: row.source_filename,
        status: row.status,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
        itemCount: parsed.items?.length ?? 0
      },
      parsed,
      registry,
      analysis
    };
  }

  scheduleAnalyze(id: string, opts?: { force?: boolean }): { scheduled: boolean } {
    if (this.analyzing.has(id) && !opts?.force) return { scheduled: false };
    this.analyzing.add(id);
    void this.runAnalyze(id, Boolean(opts?.force)).finally(() => this.analyzing.delete(id));
    return { scheduled: true };
  }

  private async getAnalysisRow(bulletinId: string) {
    const r = await this.db.query<{
      output_json: unknown;
      output_text: string | null;
      model: string | null;
      prompt_version: string | null;
      status: string;
      error_text: string | null;
      updated_at: Date;
    }>(
      `SELECT output_json, output_text, model, prompt_version, status, error_text, updated_at
         FROM fstec_bulletin_analysis WHERE bulletin_id = $1`,
      [bulletinId]
    );
    if ((r.rowCount ?? 0) === 0) return null;
    const row = r.rows[0]!;
    let oj = row.output_json;
    if (typeof oj === "string") {
      try {
        oj = JSON.parse(oj) as unknown;
      } catch {
        oj = null;
      }
    }
    return {
      status: row.status,
      outputJson: oj,
      outputText: row.output_text,
      model: row.model,
      promptVersion: row.prompt_version,
      errorText: row.error_text,
      updatedAt: row.updated_at
    };
  }

  private async loadRegistryForParsed(parsed: FstecBulletinParsed): Promise<FstecBulletinRegistryItem[]> {
    const ids = [
      ...new Set([
        ...(parsed.items ?? []).map((i) => i.bduId),
        ...(parsed.orphanBduIds ?? [])
      ])
    ];
    if (ids.length === 0) return [];

    const bduRows = await this.db.query<{
      bdu_id: string;
      name: string;
      cvss_score: number | null;
      severity: string | null;
      cve_ids: string[];
      has_exploit: boolean;
      has_fix: boolean;
      publication_date: string | null;
    }>(
      `SELECT bdu_id, name, cvss_score, severity, cve_ids, has_exploit, has_fix, publication_date
         FROM bdu_vuln WHERE bdu_id = ANY($1::text[])`,
      [ids]
    );
    const bduMap = new Map(bduRows.rows.map((r) => [r.bdu_id, r]));

    const allCves = [...new Set(bduRows.rows.flatMap((r) => r.cve_ids ?? []))];
    const cveMap = new Map<string, { cvss_base: number | null; risk_score: number | null }>();
    if (allCves.length > 0) {
      const cveR = await this.db.query<{
        cve_id: string;
        cvss_base: number | null;
        risk_score: number | null;
      }>(
        `SELECT c.cve_id, c.cvss_base, rs.score AS risk_score
           FROM cve c
           LEFT JOIN risk_score rs ON rs.cve_id = c.cve_id
          WHERE c.cve_id = ANY($1::text[])`,
        [allCves]
      );
      for (const c of cveR.rows) cveMap.set(c.cve_id, c);
    }

    return ids.map((bduId) => {
      const row = bduMap.get(bduId);
      if (!row) {
        return {
          bduId,
          found: false,
          name: null,
          cvssScore: null,
          severity: null,
          cveIds: [],
          hasExploit: false,
          hasFix: false,
          publicationDate: null,
          linkedCves: []
        };
      }
      return {
        bduId,
        found: true,
        name: row.name,
        cvssScore: row.cvss_score,
        severity: row.severity,
        cveIds: row.cve_ids ?? [],
        hasExploit: row.has_exploit,
        hasFix: row.has_fix,
        publicationDate: row.publication_date,
        linkedCves: (row.cve_ids ?? []).map((cveId) => {
          const c = cveMap.get(cveId);
          return {
            cveId,
            cvssBase: c?.cvss_base ?? null,
            riskScore: c?.risk_score ?? null
          };
        })
      };
    });
  }

  private async runAnalyze(bulletinId: string, force: boolean): Promise<void> {
    const detail = await this.getById(bulletinId);
    if (!force && detail.analysis?.status === "ready") return;

    this.scheduleBduEnrichForParsed(detail.parsed);

    await this.db.query(
      `INSERT INTO fstec_bulletin_analysis (bulletin_id, status)
       VALUES ($1, 'running')
       ON CONFLICT (bulletin_id) DO UPDATE SET status = 'running', error_text = NULL, updated_at = now()`,
      [bulletinId]
    );
    await this.db.query(`UPDATE fstec_bulletin SET status = 'analyzing', updated_at = now() WHERE id = $1`, [
      bulletinId
    ]);

    const envBase = getVulnContextLlmConfigFromEnv();
    const effective = mergeVulnContextLlmConfig(envBase, await this.integration.getEffectiveLlmConfig());

    const analysisContext = buildBulletinAnalysisContext({
      bulletin: {
        title: detail.bulletin.title,
        referenceNo: detail.bulletin.referenceNo
      },
      parsed: detail.parsed,
      registry: detail.registry
    });

    const llmConfig = {
      ...effective,
      promptVersion: FSTEC_BULLETIN_PROMPT_VERSION
    };

    try {
      const result = await runFstecBulletinAnalysisLlm(bulletinId, { analysisContext }, llmConfig);
      const outputJson = normalizeFstecBulletinAnalysis(
        result.outputJson as Record<string, unknown>,
        analysisContext
      );
      const normalized = { ...result, outputJson };
      const notConfigured = isLlmNotConfiguredEnrichment({
        output_text: normalized.outputText ?? null,
        output_json: normalized.outputJson
      });

      const summaryText =
        typeof (outputJson as { executiveSummary?: unknown }).executiveSummary === "string"
          ? (outputJson as { executiveSummary: string }).executiveSummary
          : normalized.outputText ?? null;

      await this.db.query(
        `UPDATE fstec_bulletin_analysis SET
           output_json = $2::jsonb,
           output_text = $3,
           model = $4,
           prompt_version = $5,
           input_hash = $6,
           tokens_input = $7,
           tokens_output = $8,
           status = $9,
           error_text = NULL,
           updated_at = now()
         WHERE bulletin_id = $1`,
        [
          bulletinId,
          stableJsonStringify(outputJson),
          summaryText,
          normalized.model,
          normalized.promptVersion,
          normalized.inputHash,
          normalized.tokensInput ?? null,
          normalized.tokensOutput ?? null,
          notConfigured ? "skipped" : "ready"
        ]
      );
      await this.db.query(
        `UPDATE fstec_bulletin SET status = $2, updated_at = now() WHERE id = $1`,
        [bulletinId, notConfigured ? "parsed" : "ready"]
      );
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      const failJson = enrichFailureOutputJson("AI bulletin analysis failed", msg.slice(0, 4000));
      await this.db.query(
        `UPDATE fstec_bulletin_analysis SET
           status = 'failed',
           error_text = $2,
           output_json = $3::jsonb,
           output_text = $4,
           updated_at = now()
         WHERE bulletin_id = $1`,
        [
          bulletinId,
          msg.slice(0, 4000),
          stableJsonStringify(failJson),
          typeof failJson.summary === "string" ? failJson.summary : null
        ]
      );
      await this.db.query(`UPDATE fstec_bulletin SET status = 'failed', updated_at = now() WHERE id = $1`, [
        bulletinId
      ]);
    }
  }
}
