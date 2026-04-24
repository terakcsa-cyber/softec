import { BadRequestException, Injectable, NotFoundException } from "@nestjs/common";
import { DbService } from "./db.service.js";

export type VulnTaskStatus =
  | "new"
  | "in_progress"
  | "needs_info"
  | "fixing"
  | "mitigated"
  | "closed"
  | "not_applicable"
  | "risk_accepted";

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

function statusMultiplier(st: VulnTaskStatus): number {
  if (st === "new" || st === "in_progress") return 1.0;
  if (st === "needs_info") return 0.9;
  if (st === "fixing") return 0.8;
  if (st === "mitigated") return 0.7;
  if (st === "risk_accepted") return 0.3;
  return 0.0; // closed / not_applicable
}

@Injectable()
export class VulnTaskService {
  constructor(private readonly db: DbService) {}

  private validatePatch(input: Partial<{
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
  }>) {
    const status = input.status;
    const hasText = (s: unknown) => typeof s === "string" && s.trim().length > 0;
    const evidenceOk = hasText(input.evidence) || hasText(input.decisionNotes);
    const reviewOk = input.reviewDate != null && String(input.reviewDate).trim().length > 0;

    if (status === "closed") {
      if (!evidenceOk) {
        throw new BadRequestException(
          "For status=closed you must provide evidence or decisionNotes (patch proof / verification)."
        );
      }
    }
    if (status === "not_applicable") {
      if (!hasText(input.decision) && !hasText(input.decisionNotes)) {
        throw new BadRequestException(
          "For status=not_applicable you must provide decision and/or decisionNotes (reason)."
        );
      }
      if (!evidenceOk) {
        throw new BadRequestException("For status=not_applicable you must provide evidence (how we know).");
      }
    }
    if (status === "risk_accepted") {
      if (!hasText(input.decision) && !hasText(input.decisionNotes)) {
        throw new BadRequestException(
          "For status=risk_accepted you must provide decision and/or decisionNotes (why accepted)."
        );
      }
      if (!reviewOk) {
        throw new BadRequestException("For status=risk_accepted you must provide reviewDate (when to revisit).");
      }
    }
    if (status === "needs_info") {
      if (!reviewOk) {
        throw new BadRequestException("For status=needs_info you must provide reviewDate (avoid stuck tasks).");
      }
    }
  }

  private async loadCveSignals(cveIds: string[]): Promise<CveScoreRow[]> {
    if (cveIds.length === 0) return [];
    const ids = [...new Set(cveIds.map((x) => String(x).trim().toUpperCase()))].filter((x) =>
      /^CVE-\d{4}-\d{4,}$/.test(x)
    );
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
    const st = t.rows[0]!.status;
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
    if (q) add(`(lower(title) LIKE '%' || $1 || '%' OR lower(vendor_display) LIKE '%' || $1 || '%' OR lower(product_display) LIKE '%' || $1 || '%')`, q);
    const st = opts.status?.trim() ? opts.status.trim() : null;
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
  }) {
    const vendorKey = String(input.vendorKey ?? "").trim().toLowerCase();
    const vendorDisplay = String(input.vendorDisplay ?? "").trim();
    if (!vendorKey || !vendorDisplay) throw new BadRequestException("vendorKey/vendorDisplay required");
    const productKeyNorm = String(input.productKeyNorm ?? "").trim().toLowerCase();
    const productDisplay = String(input.productDisplay ?? "").trim();
    const title =
      (input.title?.trim() || null) ??
      `${vendorDisplay}${productDisplay ? ` / ${productDisplay}` : ""} — кампания по уязвимостям`;

    const r = await this.db.query<{ id: string }>(
      `INSERT INTO vuln_task (title, vendor_key, vendor_display, product_key_norm, product_display, owner, due_date, priority_local, notes_md)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
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
        input.notesMd ?? ""
      ]
    );
    const id = r.rows[0]!.id;

    const cveIds = Array.isArray(input.cveIds) ? input.cveIds : [];
    if (cveIds.length > 0) {
      const normalized = [...new Set(cveIds.map((x) => String(x).trim().toUpperCase()))].filter((x) =>
        /^CVE-\d{4}-\d{4,}$/.test(x)
      );
      if (normalized.length > 0) {
        await this.db.query(
          `INSERT INTO vuln_task_cve (task_id, cve_id)
           SELECT $1, x.cve_id
             FROM unnest($2::text[]) AS x(cve_id)
           ON CONFLICT DO NOTHING`,
          [id, normalized]
        );
      }
    }

    await this.db.query(
      `INSERT INTO vuln_task_event (task_id, action, after)
       VALUES ($1, 'task.created', $2::jsonb)`,
      [id, JSON.stringify({ title, vendorKey, productKeyNorm, cveCount: cveIds.length })]
    );

    await this.recomputeTask(id);
    return { ok: true, id };
  }

  async patch(taskId: string, input: Partial<{
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
  }>) {
    this.validatePatch(input);
    const before = await this.db.query(`SELECT * FROM vuln_task WHERE id = $1 LIMIT 1`, [taskId]);
    if ((before.rowCount ?? 0) === 0) throw new NotFoundException("Task not found");

    const upd: Record<string, any> = {};
    const set = (k: string, v: any) => {
      if (v === undefined) return;
      upd[k] = v;
    };
    set("title", input.title?.trim());
    set("status", input.status);
    set("priority_local", input.priorityLocal);
    set("owner", input.owner === undefined ? undefined : input.owner?.trim() || null);
    set("due_date", input.dueDate === undefined ? undefined : input.dueDate ? new Date(input.dueDate) : null);
    set("review_date", input.reviewDate === undefined ? undefined : input.reviewDate ? new Date(input.reviewDate) : null);
    set("notes_md", input.notesMd);
    set("decision", input.decision === undefined ? undefined : input.decision);
    set("decision_notes", input.decisionNotes === undefined ? undefined : input.decisionNotes);
    set("evidence", input.evidence === undefined ? undefined : input.evidence);

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
    if (input.status === "closed" || input.status === "not_applicable") {
      sets.push(`closed_at = COALESCE(closed_at, now())`);
    }
    if (input.status && input.status !== "closed" && input.status !== "not_applicable") {
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
    const normalized = [...new Set((cveIds ?? []).map((x) => String(x).trim().toUpperCase()))].filter((x) =>
      /^CVE-\d{4}-\d{4,}$/.test(x)
    );
    if (normalized.length === 0) throw new BadRequestException("No CVEs");

    await this.db.query(
      `INSERT INTO vuln_task_cve (task_id, cve_id)
       SELECT $1, x.cve_id
         FROM unnest($2::text[]) AS x(cve_id)
       ON CONFLICT DO NOTHING`,
      [taskId, normalized]
    );

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

