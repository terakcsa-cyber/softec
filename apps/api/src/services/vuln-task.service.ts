import { BadRequestException, Injectable, NotFoundException } from "@nestjs/common";
import {
  runVocTaskBriefLlm,
  type VocPriority,
  type VocSource,
  type VocTaskBriefInput
} from "@vuln-intel/shared";
import { escapePgLikePattern } from "../pg-like.util.js";
import { DbService } from "./db.service.js";
import { IntegrationSettingsService } from "./integration-settings.service.js";

export type VulnTaskStatus = "new" | "in_progress" | "closed";

export type VulnTaskPriorityLocal = "low" | "medium" | "high" | "critical";

type CveScoreRow = {
  cve_id: string;
  risk_score: number | null;
  epss: number | null;
  cvss_base: number | null;
  exploit_known: boolean;
  cvss_av_network: boolean;
  cvss_pr_none: boolean;
  cvss_ui_none: boolean;
  cvss_ac_low: boolean;
  perimeter_product: boolean;
};

function clamp(n: number, lo: number, hi: number) {
  return Math.max(lo, Math.min(hi, n));
}

function scorePerimeter(c: CveScoreRow): { score: number; reasons: string[] } {
  let s = 0;
  const reasons: string[] = [];
  const add = (n: number, r: string) => {
    s += n;
    reasons.push(r);
  };

  if (c.perimeter_product) add(22, "edge/web/VPN продукт (CPE)");
  if (c.cvss_av_network) add(25, "CVSS AV:N");
  if (c.cvss_av_network && c.cvss_pr_none) add(18, "CVSS PR:N");
  if (c.cvss_av_network && c.cvss_ui_none) add(12, "CVSS UI:N");
  if (c.cvss_av_network && c.cvss_ac_low) add(8, "CVSS AC:L");
  if (c.exploit_known) add(15, "KEV");
  if (typeof c.epss === "number" && Number.isFinite(c.epss) && c.epss >= 0.6) add(10, "EPSS ≥ 0.60");
  else if (typeof c.epss === "number" && Number.isFinite(c.epss) && c.epss >= 0.3) add(6, "EPSS ≥ 0.30");

  return { score: clamp(Math.round(s), 0, 100), reasons };
}

function scorePriorityBankish(c: CveScoreRow): { score: number; reasons: string[] } {
  // Keep this consistent with the web computeCvePriority, but server-side and lightweight.
  // The goal is stable sorting for tasks, not pixel-perfect parity.
  let s = 0;
  const reasons: string[] = [];
  const add = (n: number, r: string) => {
    s += n;
    reasons.push(r);
  };
  if (c.exploit_known) add(25, "KEV");
  if (typeof c.epss === "number" && Number.isFinite(c.epss)) {
    if (c.epss >= 0.6) add(20, "EPSS высокий");
    else if (c.epss >= 0.3) add(12, "EPSS средний");
    else if (c.epss >= 0.1) add(6, "EPSS заметный");
  }
  if (typeof c.cvss_base === "number" && Number.isFinite(c.cvss_base)) {
    if (c.cvss_base >= 9.0) add(18, "CVSS критический");
    else if (c.cvss_base >= 8.0) add(12, "CVSS высокий");
    else if (c.cvss_base >= 7.0) add(6, "CVSS заметный");
  }
  if (typeof c.risk_score === "number" && Number.isFinite(c.risk_score)) {
    if (c.risk_score >= 85) add(12, "risk score критичный");
    else if (c.risk_score >= 70) add(8, "risk score высокий");
    else if (c.risk_score >= 40) add(4, "risk score средний");
  }
  // Network vector is a bank-perimeter amplifier.
  if (c.cvss_av_network) add(8, "сетевой вектор");
  return { score: clamp(Math.round(s), 0, 100), reasons };
}

function scoreUrgency(c: CveScoreRow): { urgency: number; reasons: string[]; maxReason: string } {
  const pr = scorePriorityBankish(c);
  const per = scorePerimeter(c);
  const risk = typeof c.risk_score === "number" && Number.isFinite(c.risk_score) ? c.risk_score : 0;
  const epssScaled = typeof c.epss === "number" && Number.isFinite(c.epss) ? c.epss * 100 : 0;
  const kevBonus = c.exploit_known ? 10 : 0;

  const raw =
    0.45 * pr.score +
    0.35 * per.score +
    0.15 * risk +
    0.05 * epssScaled +
    kevBonus;
  const urgency = clamp(Math.round(raw), 0, 100);
  const reasons = [
    `priority=${pr.score}`,
    `perimeter=${per.score}`,
    risk ? `risk=${Math.round(risk)}` : null,
    epssScaled ? `epss=${Math.round(epssScaled)}` : null,
    c.exploit_known ? "KEV" : null
  ].filter(Boolean) as string[];
  const maxReason = c.exploit_known
    ? "KEV"
    : per.score >= 75
      ? "perimeter high"
      : pr.score >= 75
        ? "priority high"
        : "mixed";
  return { urgency, reasons, maxReason };
}

function aggregateTaskScore(urgencies: Array<{ cveId: string; urgency: number; reasons: string[] }>) {
  const us = [...urgencies].sort((a, b) => b.urgency - a.urgency);
  const max = us[0]?.urgency ?? 0;
  const avg = (xs: number[]) => (xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : 0);
  const top3 = avg(us.slice(0, 3).map((x) => x.urgency));
  const top10 = avg(us.slice(0, 10).map((x) => x.urgency));
  const raw = clamp(Math.round(0.65 * max + 0.25 * top3 + 0.1 * top10), 0, 100);
  return { raw, max, top3: Math.round(top3), top10: Math.round(top10), top: us[0] ?? null };
}

function normalizeTaskStatus(raw: unknown, fallback: VulnTaskStatus = "new"): VulnTaskStatus {
  const s = String(raw ?? "").trim();
  if (s === "new" || s === "in_progress" || s === "closed") return s;
  if (s === "needs_info" || s === "fixing" || s === "mitigated") return "in_progress";
  if (s === "risk_accepted" || s === "not_applicable") return "closed";
  return fallback;
}

function normalizeCveIds(cveIds: unknown): string[] {
  if (!Array.isArray(cveIds)) return [];
  return [...new Set(cveIds.map((x) => String(x).trim().toUpperCase()))].filter((x) =>
    /^CVE-\d{4}-\d{4,}$/.test(x)
  );
}

function statusMultiplier(st: VulnTaskStatus): number {
  if (st === "new" || st === "in_progress") return 1.0;
  return 0.0;
}

@Injectable()
export class VulnTaskService {
  constructor(
    private readonly db: DbService,
    private readonly integration: IntegrationSettingsService
  ) {}

  private validatePatch(input: Partial<{
    title: string;
    status: VulnTaskStatus | string;
    priorityLocal: VulnTaskPriorityLocal;
    owner: string | null;
    dueDate: string | null;
    reviewDate: string | null;
    notesMd: string;
    decision: string | null;
    decisionNotes: string | null;
    evidence: string | null;
  }>): Partial<{
    title: string;
    status: VulnTaskStatus;
    priorityLocal: VulnTaskPriorityLocal;
    owner: string | null;
    dueDate: string | null;
    reviewDate: string | null;
    notesMd: string;
    decision: string | null;
    decisionNotes: string | null;
    evidence: string | null;
  }> {
    if (input.status === undefined) {
      const patch = { ...input } as Partial<{
        title: string;
        status: VulnTaskStatus;
        priorityLocal: VulnTaskPriorityLocal;
        owner: string | null;
        dueDate: string | null;
        reviewDate: string | null;
        notesMd: string;
        decision: string | null;
        decisionNotes: string | null;
        evidence: string | null;
      }>;
      delete patch.status;
      return patch;
    }
    return { ...input, status: normalizeTaskStatus(input.status, "new") };
  }

  private async loadCveSignals(cveIds: string[]): Promise<CveScoreRow[]> {
    if (cveIds.length === 0) return [];
    const ids = normalizeCveIds(cveIds);
    if (ids.length === 0) return [];

    const r = await this.db.query<CveScoreRow>(
      `SELECT c.cve_id,
              rs.score AS risk_score,
              es.score AS epss,
              c.cvss_base AS cvss_base,
              (k.cve_id IS NOT NULL) AS exploit_known,
              (COALESCE(
                c.raw->'metrics'->'cvssMetricV31'->0->'cvssData'->>'attackVector',
                c.raw->'metrics'->'cvssMetricV30'->0->'cvssData'->>'attackVector',
                c.raw->'impact'->'baseMetricV3'->'cvssV3'->>'attackVector'
              ) = 'NETWORK') AS cvss_av_network,
              (COALESCE(
                c.raw->'metrics'->'cvssMetricV31'->0->'cvssData'->>'privilegesRequired',
                c.raw->'metrics'->'cvssMetricV30'->0->'cvssData'->>'privilegesRequired',
                c.raw->'impact'->'baseMetricV3'->'cvssV3'->>'privilegesRequired'
              ) = 'NONE') AS cvss_pr_none,
              (COALESCE(
                c.raw->'metrics'->'cvssMetricV31'->0->'cvssData'->>'userInteraction',
                c.raw->'metrics'->'cvssMetricV30'->0->'cvssData'->>'userInteraction',
                c.raw->'impact'->'baseMetricV3'->'cvssV3'->>'userInteraction'
              ) = 'NONE') AS cvss_ui_none,
              (COALESCE(
                c.raw->'metrics'->'cvssMetricV31'->0->'cvssData'->>'attackComplexity',
                c.raw->'metrics'->'cvssMetricV30'->0->'cvssData'->>'attackComplexity',
                c.raw->'impact'->'baseMetricV3'->'cvssV3'->>'attackComplexity'
              ) = 'LOW') AS cvss_ac_low,
              EXISTS (
                SELECT 1 FROM cve_vendor_product vp_p
                WHERE vp_p.cve_id = c.cve_id
                  AND (
                    vp_p.vendor_key IN (
                      'microsoft','apache','nginx','openssl','openbsd','openssh','citrix','f5','paloaltonetworks',
                      'fortinet','checkpoint','juniper','cisco','vmware','okta','redhat','oracle','ibm','sap'
                    )
                    OR vp_p.product_key_norm IN (
                      'iis','http_server','nginx','openssl','openssh','netscaler','adc','big-ip','pan-os','fortios',
                      'fortigate','pulse_connect_secure','globalprotect','vpn','sslvpn','gateway','reverse_proxy',
                      'load_balancer','waf','firewall','identity','sso','keycloak','tomcat','jetty','spring'
                    )
                    OR lower(vp_p.product_key_norm) LIKE '%vpn%'
                    OR lower(vp_p.product_key_norm) LIKE '%proxy%'
                    OR lower(vp_p.product_key_norm) LIKE '%gateway%'
                  )
              ) AS perimeter_product
         FROM cve c
    LEFT JOIN risk_score rs ON rs.cve_id = c.cve_id
    LEFT JOIN epss_score es ON es.cve_id = c.cve_id
    LEFT JOIN kev k ON k.cve_id = c.cve_id
        WHERE c.cve_id = ANY($1::text[])`,
      [ids]
    );
    return r.rows;
  }

  private async buildAutoEvidence(input: {
    vendorDisplay: string;
    productDisplay?: string | null;
    cveIds?: string[];
    notesMd?: string | null;
  }): Promise<string> {
    const cveIds = normalizeCveIds(input.cveIds ?? []);
    const product = input.productDisplay ? `${input.vendorDisplay} / ${input.productDisplay}` : input.vendorDisplay;
    const cveText = cveIds.length > 0 ? cveIds.slice(0, 5).join(", ") : "связанные CVE";
    const lines = [
      `Проверить применимость ${cveText} к ${product}.`,
      "Проверить наличие уязвимой версии в инвентаре/на периметре.",
      "Проверить наличие патча, workaround или vendor advisory.",
      "Проверить признаки эксплуатации и необходимость срочной реакции.",
      "Зафиксировать результат проверки: версия, ссылка на тикет/advisory или причина неприменимости."
    ];
    if (cveIds.length > 5) lines[0] = `Проверить применимость ${cveText} и ещё ${cveIds.length - 5} CVE к ${product}.`;
    return lines.join("\n");
  }

  private async ensureCvesExist(
    cveIds: string[],
    opts?: {
      vendorDisplay?: string;
      vendorKey?: string;
      productDisplay?: string | null;
      productKeyNorm?: string | null;
      source?: string;
    }
  ): Promise<void> {
    const ids = normalizeCveIds(cveIds);
    if (ids.length === 0) return;
    const source = opts?.source ?? "task";
    await this.db.query(
      `INSERT INTO cve (cve_id, source, raw)
       SELECT x.cve_id,
              $2::text,
              jsonb_build_object(
                'source', $2::text,
                'placeholder', true,
                'cve', jsonb_build_object('id', x.cve_id),
                'descriptions', jsonb_build_array(
                  jsonb_build_object('lang', 'en', 'value', 'Placeholder CVE row created from vulnerability task source.')
                )
              )
         FROM unnest($1::text[]) AS x(cve_id)
       ON CONFLICT (cve_id) DO NOTHING`,
      [ids, source]
    );

    const vendorDisplay = opts?.vendorDisplay?.trim();
    const vendorKey = opts?.vendorKey?.trim().toLowerCase();
    if (!vendorDisplay || !vendorKey) return;
    const productDisplay = opts?.productDisplay?.trim() || null;
    const productKeyNorm = opts?.productKeyNorm?.trim().toLowerCase() ?? "";
    await this.db.query(
      `INSERT INTO cve_vendor_product (cve_id, vendor, product, vendor_key, product_key, product_key_norm, source)
       SELECT x.cve_id, $2::text, $3::text, $4::text, $5::text, $6::text, $7::text
         FROM unnest($1::text[]) AS x(cve_id)
       ON CONFLICT (cve_id, vendor_key, product_key_norm) DO UPDATE
         SET vendor = EXCLUDED.vendor,
             product = EXCLUDED.product,
             product_key = EXCLUDED.product_key,
             source = EXCLUDED.source,
             updated_at = now()`,
      [ids, vendorDisplay, productDisplay, vendorKey, productDisplay, productKeyNorm, source]
    );
  }

  private async recomputeTask(taskId: string): Promise<void> {
    const links = await this.db.query<{ cve_id: string }>(
      `SELECT cve_id FROM vuln_task_cve WHERE task_id = $1 ORDER BY added_at ASC`,
      [taskId]
    );
    const cveIds = links.rows.map((r) => r.cve_id);
    const rows = await this.loadCveSignals(cveIds);

    const urgencies = rows.map((c) => {
      const u = scoreUrgency(c);
      return { cveId: c.cve_id, urgency: u.urgency, reasons: u.reasons };
    });
    const agg = aggregateTaskScore(urgencies);

    const t = await this.db.query<{ status: VulnTaskStatus }>(
      `SELECT status FROM vuln_task WHERE id = $1 LIMIT 1`,
      [taskId]
    );
    if ((t.rowCount ?? 0) === 0) throw new NotFoundException("Task not found");
    const st = normalizeTaskStatus(t.rows[0]!.status, "new");
    const final = clamp(Math.round(agg.raw * statusMultiplier(st)), 0, 100);

    const kevCount = rows.filter((r) => r.exploit_known).length;
    const perimeterHighCount = rows.filter((r) => scorePerimeter(r).score >= 70).length;
    const maxPerimeter = rows.reduce((m, r) => Math.max(m, scorePerimeter(r).score), 0);
    const maxPriority = rows.reduce((m, r) => Math.max(m, scorePriorityBankish(r).score), 0);

    const reasons = [
      { k: "max", v: agg.max },
      { k: "top3", v: agg.top3 },
      { k: "kevCount", v: kevCount },
      { k: "perimeterHigh", v: perimeterHighCount },
      agg.top ? { k: "topCve", v: agg.top.cveId, urgency: agg.top.urgency } : null
    ].filter(Boolean);

    const stats = {
      cveCount: cveIds.length,
      kevCount,
      perimeterHighCount,
      maxPerimeter,
      maxPriority
    };

    await this.db.query(
      `UPDATE vuln_task
          SET score_raw = $2,
              score_final = $3,
              score_reasons = $4::jsonb,
              stats = $5::jsonb,
              updated_at = now()
        WHERE id = $1`,
      [taskId, agg.raw, final, JSON.stringify(reasons), JSON.stringify(stats)]
    );
  }

  async list(opts: { q?: string; status?: string; limit?: number; sort?: string }) {
    const limit = clamp(Number(opts.limit ?? 50), 1, 200);
    const params: any[] = [];
    const filters: string[] = [];
    const add = (cond: string, v?: any) => {
      if (v === undefined) return;
      params.push(v);
      filters.push(cond.replace(/\$(\d+)/g, () => `$${params.length}`));
    };
    const q = opts.q?.trim() ? opts.q.trim().toLowerCase() : null;
    if (q) {
      const needle = escapePgLikePattern(q);
      params.push(needle);
      const ni = params.length;
      const like = `'%' || $${ni}::text || '%' ESCAPE E'\\\\'`;
      filters.push(
        `(lower(title) LIKE ${like} OR lower(vendor_display) LIKE ${like} OR lower(product_display) LIKE ${like})`
      );
    }
    const rawStatus = opts.status?.trim() ?? "";
    const st =
      rawStatus && /^(new|in_progress|closed|needs_info|fixing|mitigated|risk_accepted|not_applicable)$/.test(rawStatus)
        ? normalizeTaskStatus(rawStatus, "new")
        : null;
    if (st) add(`status = $1`, st);
    const where = filters.length ? `WHERE ${filters.join(" AND ")}` : `WHERE TRUE`;
    const sort = (opts.sort ?? "score").toLowerCase();
    const orderBy =
      sort === "updated" ? `ORDER BY updated_at DESC` : `ORDER BY score_final DESC, updated_at DESC`;

    params.push(limit);
    const limIdx = params.length;
    const r = await this.db.query(
      `SELECT id, title, status, priority_local, owner, due_date, review_date,
              vendor_key, vendor_display, product_key_norm, product_display,
              score_raw, score_final, score_reasons, stats,
              created_at, updated_at, closed_at
         FROM vuln_task
         ${where}
         ${orderBy}
         LIMIT $${limIdx}`,
      params
    );
    return { items: r.rows };
  }

  async get(taskId: string) {
    const r = await this.db.query(
      `SELECT *
         FROM vuln_task
        WHERE id = $1
        LIMIT 1`,
      [taskId]
    );
    if ((r.rowCount ?? 0) === 0) throw new NotFoundException("Task not found");

    const cves = await this.db.query(
      `SELECT l.cve_id, l.added_at, l.note,
              rs.score AS risk_score,
              es.score AS epss,
              c.cvss_base AS cvss_base,
              (k.cve_id IS NOT NULL) AS exploit_known
         FROM vuln_task_cve l
         JOIN cve c ON c.cve_id = l.cve_id
    LEFT JOIN risk_score rs ON rs.cve_id = c.cve_id
    LEFT JOIN epss_score es ON es.cve_id = c.cve_id
    LEFT JOIN kev k ON k.cve_id = c.cve_id
        WHERE l.task_id = $1
     ORDER BY l.added_at DESC`,
      [taskId]
    );

    const events = await this.db.query(
      `SELECT id, ts, actor, action, before, after, meta
         FROM vuln_task_event
        WHERE task_id = $1
     ORDER BY ts DESC
        LIMIT 100`,
      [taskId]
    );

    return { task: r.rows[0], cves: cves.rows, events: events.rows };
  }

  async create(input: {
    title?: string;
    vendorKey: string;
    vendorDisplay: string;
    productKeyNorm?: string | null;
    productDisplay?: string | null;
    owner?: string | null;
    dueDate?: string | null;
    priorityLocal?: VulnTaskPriorityLocal;
    cveIds?: string[];
    notesMd?: string | null;
    evidence?: string | null;
  }) {
    const vendorKey = String(input.vendorKey ?? "").trim().toLowerCase();
    const vendorDisplay = String(input.vendorDisplay ?? "").trim();
    if (!vendorKey || !vendorDisplay) throw new BadRequestException("vendorKey/vendorDisplay required");
    const productKeyNorm = String(input.productKeyNorm ?? "").trim().toLowerCase();
    const productDisplay = String(input.productDisplay ?? "").trim();
    const title =
      (input.title?.trim() || null) ??
      `${vendorDisplay}${productDisplay ? ` / ${productDisplay}` : ""} — кампания по уязвимостям`;
    const normalizedCveIds = normalizeCveIds(input.cveIds ?? []);
    await this.ensureCvesExist(normalizedCveIds, {
      vendorDisplay,
      vendorKey,
      productDisplay,
      productKeyNorm,
      source: "task.create"
    });
    const evidence = input.evidence?.trim() || (await this.buildAutoEvidence({
      vendorDisplay,
      productDisplay,
      cveIds: normalizedCveIds,
      notesMd: input.notesMd
    }));

    const r = await this.db.query<{ id: string }>(
      `INSERT INTO vuln_task (title, vendor_key, vendor_display, product_key_norm, product_display, owner, due_date, priority_local, notes_md, evidence)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
       RETURNING id`,
      [
        title,
        vendorKey,
        vendorDisplay,
        productKeyNorm,
        productDisplay,
        input.owner?.trim() || null,
        input.dueDate ? new Date(input.dueDate) : null,
        input.priorityLocal ?? "medium",
        input.notesMd ?? "",
        evidence
      ]
    );
    const id = r.rows[0]!.id;

    let linkedCveCount = 0;
    let ignoredCveCount = 0;
    if (normalizedCveIds.length > 0) {
      const inserted = await this.db.query(
        `INSERT INTO vuln_task_cve (task_id, cve_id)
         SELECT $1, x.cve_id
           FROM unnest($2::text[]) AS x(cve_id)
         ON CONFLICT DO NOTHING`,
        [id, normalizedCveIds]
      );
      linkedCveCount = inserted.rowCount ?? 0;
      ignoredCveCount = Math.max(0, normalizedCveIds.length - linkedCveCount);
    }

    await this.db.query(
      `INSERT INTO vuln_task_event (task_id, action, after)
       VALUES ($1, 'task.created', $2::jsonb)`,
      [id, JSON.stringify({ title, vendorKey, productKeyNorm, cveCount: linkedCveCount, ignoredCveCount, evidenceAuto: true })]
    );

    await this.recomputeTask(id);
    return { ok: true, id };
  }

  async createFromVocCase(input: {
    caseId: string;
    refKey: string;
    source: VocSource;
    refId: string;
    title: string;
    subtitle?: string | null;
    vocPriority: VocPriority;
    vocReasons?: string[];
    cveIds?: string[];
    vendorKey?: string;
    vendorDisplay?: string;
    productKeyNorm?: string | null;
    productDisplay?: string | null;
    bduName?: string | null;
    tgChannel?: string | null;
    dueDate?: string | null;
    priorityLocal?: VulnTaskPriorityLocal;
  }) {
    const vendorKey = String(input.vendorKey ?? input.vendorDisplay ?? "voc").trim().toLowerCase() || "voc";
    const vendorDisplay = String(input.vendorDisplay ?? vendorKey).trim() || vendorKey;
    const productKeyNorm = String(input.productKeyNorm ?? "").trim().toLowerCase();
    const productDisplay = String(input.productDisplay ?? "").trim();
    const normalizedCveIds = normalizeCveIds(input.cveIds ?? []);

    await this.ensureCvesExist(normalizedCveIds, {
      vendorDisplay,
      vendorKey,
      productDisplay,
      productKeyNorm,
      source: "voc.case"
    });

    const llmCfg = await this.integration.getEffectiveLlmConfig();
    const briefInput: VocTaskBriefInput = {
      caseId: input.caseId,
      refKey: input.refKey,
      source: input.source,
      refId: input.refId,
      title: input.title,
      subtitle: input.subtitle,
      vocPriority: input.vocPriority,
      vocReasons: input.vocReasons,
      cveIds: normalizedCveIds,
      vendorDisplay,
      productDisplay: productDisplay || null,
      bduName: input.bduName,
      tgChannel: input.tgChannel
    };
    const brief = await runVocTaskBriefLlm(briefInput, llmCfg);
    const taskTitle = brief.taskTitle?.trim() || `VOC: ${input.title}`;

    const r = await this.db.query<{ id: string }>(
      `INSERT INTO vuln_task (
         title, status, vendor_key, vendor_display, product_key_norm, product_display,
         owner, due_date, priority_local, notes_md, evidence
       ) VALUES ($1,'new',$2,$3,$4,$5,NULL,$6,$7,$8,$9)
       RETURNING id`,
      [
        taskTitle,
        vendorKey,
        vendorDisplay,
        productKeyNorm,
        productDisplay,
        input.dueDate ? new Date(input.dueDate) : null,
        input.priorityLocal ?? "medium",
        brief.notesMd,
        brief.evidence
      ]
    );
    const id = r.rows[0]!.id;

    if (normalizedCveIds.length > 0) {
      await this.db.query(
        `INSERT INTO vuln_task_cve (task_id, cve_id)
         SELECT $1, x.cve_id
           FROM unnest($2::text[]) AS x(cve_id)
         ON CONFLICT DO NOTHING`,
        [id, normalizedCveIds]
      );
    }

    await this.db.query(
      `INSERT INTO vuln_task_event (task_id, action, after)
       VALUES ($1, 'task.created', $2::jsonb)`,
      [
        id,
        JSON.stringify({
          source: "voc.case",
          caseId: input.caseId,
          refKey: input.refKey,
          cveCount: normalizedCveIds.length,
          aiGenerated: brief.aiGenerated,
          status: "new"
        })
      ]
    );

    await this.recomputeTask(id);
    return { ok: true, id, aiGenerated: brief.aiGenerated };
  }

  async patch(taskId: string, input: Partial<{
    title: string;
    status: VulnTaskStatus | string;
    priorityLocal: VulnTaskPriorityLocal;
    owner: string | null;
    dueDate: string | null;
    reviewDate: string | null;
    notesMd: string;
    decision: string | null;
    decisionNotes: string | null;
    evidence: string | null;
  }>) {
    const patch = this.validatePatch(input);
    const before = await this.db.query(`SELECT * FROM vuln_task WHERE id = $1 LIMIT 1`, [taskId]);
    if ((before.rowCount ?? 0) === 0) throw new NotFoundException("Task not found");

    const upd: Record<string, any> = {};
    const set = (k: string, v: any) => {
      if (v === undefined) return;
      upd[k] = v;
    };
    set("title", patch.title?.trim());
    set("status", patch.status);
    set("priority_local", patch.priorityLocal);
    set("owner", patch.owner === undefined ? undefined : patch.owner?.trim() || null);
    set("due_date", patch.dueDate === undefined ? undefined : patch.dueDate ? new Date(patch.dueDate) : null);
    set("review_date", patch.reviewDate === undefined ? undefined : patch.reviewDate ? new Date(patch.reviewDate) : null);
    set("notes_md", patch.notesMd);
    set("decision", patch.decision === undefined ? undefined : patch.decision);
    set("decision_notes", patch.decisionNotes === undefined ? undefined : patch.decisionNotes);
    set("evidence", patch.evidence === undefined ? undefined : patch.evidence);

    const keys = Object.keys(upd);
    if (keys.length === 0) return { ok: true };

    const params: any[] = [taskId];
    const sets: string[] = [];
    for (const k of keys) {
      params.push(upd[k]);
      sets.push(`${k} = $${params.length}`);
    }
    sets.push(`updated_at = now()`);

    // auto closed_at
    if (patch.status === "closed") {
      sets.push(`closed_at = COALESCE(closed_at, now())`);
    }
    if (patch.status && patch.status !== "closed") {
      sets.push(`closed_at = NULL`);
    }

    await this.db.query(`UPDATE vuln_task SET ${sets.join(", ")} WHERE id = $1`, params);

    await this.db.query(
      `INSERT INTO vuln_task_event (task_id, action, before, after)
       VALUES ($1, 'task.updated', $2::jsonb, $3::jsonb)`,
      [taskId, JSON.stringify(before.rows[0]), JSON.stringify({ ...before.rows[0], ...upd })]
    );

    await this.recomputeTask(taskId);
    return { ok: true };
  }

  async addCves(taskId: string, cveIds: string[]) {
    const normalized = normalizeCveIds(cveIds ?? []);
    if (normalized.length === 0) throw new BadRequestException("No CVEs");

    const task = await this.db.query<{
      vendor_display: string;
      product_display: string | null;
      notes_md: string | null;
      evidence: string | null;
    }>(`SELECT vendor_display, product_display, notes_md, evidence FROM vuln_task WHERE id = $1 LIMIT 1`, [taskId]);
    if ((task.rowCount ?? 0) === 0) throw new NotFoundException("Task not found");
    await this.ensureCvesExist(normalized, {
      vendorDisplay: task.rows[0]?.vendor_display ?? "vendor",
      vendorKey: String(task.rows[0]?.vendor_display ?? "vendor").toLowerCase(),
      productDisplay: task.rows[0]?.product_display ?? "",
      productKeyNorm: String(task.rows[0]?.product_display ?? "").toLowerCase().replace(/\s+/g, "_"),
      source: "task.add_cves"
    });

    await this.db.query(
      `INSERT INTO vuln_task_cve (task_id, cve_id)
       SELECT $1, x.cve_id
         FROM unnest($2::text[]) AS x(cve_id)
       ON CONFLICT DO NOTHING`,
      [taskId, normalized]
    );

    if (!String(task.rows[0]?.evidence ?? "").trim()) {
      const evidence = await this.buildAutoEvidence({
        vendorDisplay: task.rows[0]?.vendor_display ?? "vendor",
        productDisplay: task.rows[0]?.product_display ?? "",
        cveIds: normalized,
        notesMd: task.rows[0]?.notes_md ?? ""
      });
      await this.db.query(`UPDATE vuln_task SET evidence = $2, updated_at = now() WHERE id = $1`, [taskId, evidence]);
    }

    await this.db.query(
      `INSERT INTO vuln_task_event (task_id, action, after)
       VALUES ($1, 'task.cves.added', $2::jsonb)`,
      [taskId, JSON.stringify({ cveIds: normalized })]
    );

    await this.recomputeTask(taskId);
    return { ok: true };
  }

  async removeCve(taskId: string, cveId: string) {
    const id = String(cveId ?? "").trim().toUpperCase();
    if (!/^CVE-\d{4}-\d{4,}$/.test(id)) throw new BadRequestException("Bad CVE id");
    await this.db.query(`DELETE FROM vuln_task_cve WHERE task_id = $1 AND cve_id = $2`, [taskId, id]);
    await this.db.query(
      `INSERT INTO vuln_task_event (task_id, action, after)
       VALUES ($1, 'task.cves.removed', $2::jsonb)`,
      [taskId, JSON.stringify({ cveId: id })]
    );
    await this.recomputeTask(taskId);
    return { ok: true };
  }

  async tasksByCve(cveId: string) {
    const id = String(cveId ?? "").trim().toUpperCase();
    if (!/^CVE-\d{4}-\d{4,}$/.test(id)) throw new BadRequestException("Bad CVE id");
    const r = await this.db.query(
      `SELECT t.id, t.title, t.status, t.priority_local, t.vendor_display, t.product_display, t.score_final, t.updated_at
         FROM vuln_task_cve l
         JOIN vuln_task t ON t.id = l.task_id
        WHERE l.cve_id = $1
     ORDER BY t.score_final DESC, t.updated_at DESC
        LIMIT 50`,
      [id]
    );
    return { items: r.rows };
  }
}

