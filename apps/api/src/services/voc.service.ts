import { BadRequestException, Injectable } from "@nestjs/common";
import {
  applyWatchlistBoost,
  CVE_HOT_WINDOW_HOURS,
  SQL_EFFECTIVE_PUBLISHED_AT,
  isSlaBreached,
  resolveBduHasExploit,
  resolveBduHasFix,
  scoreBduForVoc,
  scoreCveForVoc,
  sqlBduVocWindowWithinHours,
  sqlVulnClassGuessExpr,
  vocRefKey,
  type VocPriority,
  type VocSource,
  type VocTriageStatus,
  type VocWatchlistKind,
  type VocWatchlistRule
} from "@vuln-intel/shared";
import type { AuthUser } from "../auth/jwt.strategy.js";
import { DbService } from "./db.service.js";

export type VocQueueItem = {
  refKey: string;
  source: VocSource;
  refId: string;
  vocScore: number;
  vocPriority: VocPriority;
  vocReasons: string[];
  title: string;
  subtitle: string;
  publishedAt: string | null;
  status: VocTriageStatus;
  claimedByEmail: string | null;
  updatedAt: string | null;
  payload: Record<string, unknown>;
  caseId?: string | null;
  caseStatus?: string | null;
  assigneeEmail?: string | null;
  slaDueAt?: string | null;
  slaBreached?: boolean;
  linkedRefsCount?: number;
  taskId?: string | null;
};

type VocCaseRefHit = {
  ref_key: string;
  case_id: string;
  status: string;
  assignee_email: string | null;
  sla_due_at: Date | null;
  task_id: string | null;
  ref_count: number;
};

@Injectable()
export class VocService {
  constructor(private readonly db: DbService) {}

  async queue(opts: {
    source?: string;
    status?: string;
    limit?: number;
  }): Promise<{ items: VocQueueItem[]; stats: Record<string, number> }> {
    const sourceFilter = (opts.source ?? "all").toLowerCase();
    const statusFilter = (opts.status ?? "active").toLowerCase();
    const limit = Math.max(1, Math.min(300, opts.limit ?? 120));
    const watchlist = await this.loadWatchlist();

    const items: VocQueueItem[] = [];

    if (sourceFilter === "watchlist") {
      const active = watchlist.filter((r) => r.active && r.value.trim());
      if (active.length > 0) {
        items.push(...(await this.fetchWatchlistCves(limit, watchlist)));
        items.push(...(await this.fetchWatchlistBdu(limit, watchlist)));
      }
    } else {
      if (sourceFilter === "all" || sourceFilter === "cve") {
        items.push(...(await this.fetchHotCves(limit, watchlist)));
      }
      if (sourceFilter === "all" || sourceFilter === "bdu") {
        items.push(...(await this.fetchHotBdu(limit, watchlist)));
      }
    }

    items.sort((a, b) => {
      if (b.vocScore !== a.vocScore) return b.vocScore - a.vocScore;
      return String(b.publishedAt ?? "").localeCompare(String(a.publishedAt ?? ""));
    });

    const triageMap = await this.loadTriageMap(items.map((i) => i.refKey));
    const caseMap = await this.loadCaseMapByRefKeys(items.map((i) => i.refKey));

    const merged = items.map((item) => {
      const triage = triageMap.get(item.refKey);
      const caseHit = caseMap.get(item.refKey);
      const base = triage
        ? {
            ...item,
            status: triage.status,
            claimedByEmail: triage.claimed_by_email,
            updatedAt: triage.updated_at?.toISOString?.() ?? null
          }
        : item;
      if (!caseHit) return base;
      const slaIso = caseHit.sla_due_at?.toISOString?.() ?? null;
      return {
        ...base,
        caseId: caseHit.case_id,
        caseStatus: caseHit.status,
        assigneeEmail: caseHit.assignee_email,
        slaDueAt: slaIso,
        slaBreached: isSlaBreached(slaIso),
        linkedRefsCount: caseHit.ref_count,
        taskId: caseHit.task_id
      };
    });

    const filtered = merged.filter((item) => {
      if (statusFilter === "all") return true;
      if (statusFilter === "active") return item.status === "open" || item.status === "claimed";
      if (statusFilter === "open") return item.status === "open";
      if (statusFilter === "claimed") return item.status === "claimed";
      if (statusFilter === "done") return item.status === "done";
      if (statusFilter === "dismissed") return item.status === "dismissed";
      return true;
    });

    const stats = {
      total: merged.length,
      open: merged.filter((i) => i.status === "open").length,
      claimed: merged.filter((i) => i.status === "claimed").length,
      done: merged.filter((i) => i.status === "done").length,
      dismissed: merged.filter((i) => i.status === "dismissed").length,
      p1: merged.filter((i) => i.vocPriority === "p1").length,
      p2: merged.filter((i) => i.vocPriority === "p2").length,
      watchlist_hits: merged.filter((i) => i.vocReasons.some((r) => r.startsWith("watchlist:"))).length,
      open_cases: merged.filter((i) => i.caseId).length
    };

    return { items: this.capQueue(filtered, limit, sourceFilter), stats };
  }

  /** В общей ленте CVE с высоким скором не должны вытеснять БДУ ФСТЭК. */
  private capQueue(items: VocQueueItem[], limit: number, sourceFilter: string): VocQueueItem[] {
    if (items.length <= limit) return items;
    if (sourceFilter !== "all") return items.slice(0, limit);
    const bdu = items.filter((i) => i.source === "bdu");
    const rest = items.filter((i) => i.source !== "bdu");
    const bduKeep = bdu.slice(0, Math.min(bdu.length, Math.max(24, Math.floor(limit * 0.3))));
    return [...bduKeep, ...rest.slice(0, Math.max(0, limit - bduKeep.length))].sort((a, b) => {
      if (b.vocScore !== a.vocScore) return b.vocScore - a.vocScore;
      return String(b.publishedAt ?? "").localeCompare(String(a.publishedAt ?? ""));
    });
  }

  async upsertTriage(
    user: AuthUser,
    body: {
      refKey: string;
      source: VocSource;
      refId: string;
      status: VocTriageStatus;
      title?: string;
      vocScore?: number;
      vocPriority?: VocPriority;
      vocReasons?: string[];
      meta?: Record<string, unknown>;
    }
  ) {
    const refKey = body.refKey.trim();
    if (!refKey) throw new BadRequestException("refKey required");
    const status = body.status;
    if (!["open", "claimed", "done", "dismissed"].includes(status)) {
      throw new BadRequestException("invalid status");
    }

    const actorId = user.userId === "internal" ? null : user.userId;
    const claimedByUserId = status === "claimed" ? actorId : null;
    const claimedByEmail = status === "claimed" ? user.email : null;

    await this.db.query(
      `INSERT INTO voc_triage (
         ref_key, source, ref_id, status,
         claimed_by_user_id, claimed_by_email,
         updated_by_user_id, updated_by_email,
         voc_score, voc_priority, voc_reasons, title, meta, updated_at
       ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12,$13::jsonb,now())
       ON CONFLICT (ref_key) DO UPDATE SET
         status = EXCLUDED.status,
         claimed_by_user_id = CASE
           WHEN EXCLUDED.status = 'claimed' THEN EXCLUDED.claimed_by_user_id
           WHEN EXCLUDED.status = 'open' THEN NULL
           ELSE voc_triage.claimed_by_user_id
         END,
         claimed_by_email = CASE
           WHEN EXCLUDED.status = 'claimed' THEN EXCLUDED.claimed_by_email
           WHEN EXCLUDED.status = 'open' THEN NULL
           ELSE voc_triage.claimed_by_email
         END,
         updated_by_user_id = EXCLUDED.updated_by_user_id,
         updated_by_email = EXCLUDED.updated_by_email,
         voc_score = GREATEST(voc_triage.voc_score, EXCLUDED.voc_score),
         voc_priority = EXCLUDED.voc_priority,
         voc_reasons = EXCLUDED.voc_reasons,
         title = CASE WHEN EXCLUDED.title <> '' THEN EXCLUDED.title ELSE voc_triage.title END,
         meta = voc_triage.meta || EXCLUDED.meta,
         updated_at = now()`,
      [
        refKey,
        body.source,
        body.refId,
        status,
        claimedByUserId,
        claimedByEmail,
        actorId,
        user.email,
        body.vocScore ?? 0,
        body.vocPriority ?? "p4",
        JSON.stringify(body.vocReasons ?? []),
        body.title ?? "",
        JSON.stringify(body.meta ?? {})
      ]
    );

    return { ok: true, refKey, status };
  }

  async listTriage(opts: { source?: string; limit?: number }) {
    const source = (opts.source ?? "all").toLowerCase();
    const limit = Math.max(1, Math.min(500, opts.limit ?? 200));
    const params: unknown[] = [];
    let where = "";
    if (source !== "all") {
      params.push(source);
      where = `WHERE source = $1`;
    }
    params.push(limit);
    const limitIdx = params.length;
    const r = await this.db.query<{
      ref_key: string;
      status: VocTriageStatus;
      claimed_by_email: string | null;
      updated_at: Date;
    }>(
      `SELECT ref_key, status, claimed_by_email, updated_at
         FROM voc_triage
         ${where}
        ORDER BY updated_at DESC
        LIMIT $${limitIdx}`,
      params
    );
    return r.rows.map((row) => ({
      refKey: row.ref_key,
      status: row.status,
      claimedByEmail: row.claimed_by_email,
      updatedAt: row.updated_at?.toISOString?.() ?? null
    }));
  }

  async listWatchlist(): Promise<VocWatchlistRule[]> {
    const r = await this.db.query<{
      id: string;
      kind: VocWatchlistKind;
      value: string;
      label: string;
      active: boolean;
    }>(
      `SELECT id::text, kind, value, label, active
         FROM voc_watchlist
        ORDER BY active DESC, updated_at DESC`
    );
    return r.rows.map((row) => ({
      id: row.id,
      kind: row.kind,
      value: row.value,
      label: row.label || row.value,
      active: row.active
    }));
  }

  async addWatchlist(
    user: AuthUser,
    body: { kind?: VocWatchlistKind; value?: string; label?: string }
  ): Promise<VocWatchlistRule> {
    const kind = body.kind;
    if (!kind || !["vendor", "product", "keyword"].includes(kind)) {
      throw new BadRequestException("invalid kind");
    }
    const value = String(body.value ?? "").trim().toLowerCase();
    if (!value) throw new BadRequestException("value required");
    const label = String(body.label ?? body.value ?? value).trim() || value;
    const actorId = user?.userId === "internal" ? null : user?.userId ?? null;

    try {
      const existing = await this.db.query<{ id: string }>(
        `SELECT id::text FROM voc_watchlist WHERE kind = $1 AND value = $2 LIMIT 1`,
        [kind, value]
      );

      if (existing.rows[0]) {
        const r = await this.db.query<{
          id: string;
          kind: VocWatchlistKind;
          value: string;
          label: string;
          active: boolean;
        }>(
          `UPDATE voc_watchlist
              SET label = CASE WHEN $2 <> '' THEN $2 ELSE label END,
                  active = true,
                  updated_at = now()
            WHERE id = $1::uuid
            RETURNING id::text, kind, value, label, active`,
          [existing.rows[0].id, label]
        );
        const row = r.rows[0];
        if (!row) throw new BadRequestException("watchlist update failed");
        return { id: row.id, kind: row.kind, value: row.value, label: row.label, active: row.active };
      }

      const r = await this.db.query<{
        id: string;
        kind: VocWatchlistKind;
        value: string;
        label: string;
        active: boolean;
      }>(
        `INSERT INTO voc_watchlist (kind, value, label, created_by_user_id, created_by_email, updated_at)
         VALUES ($1, $2, $3, $4, $5, now())
         RETURNING id::text, kind, value, label, active`,
        [kind, value, label, actorId, user?.email ?? null]
      );
      const row = r.rows[0];
      if (!row) throw new BadRequestException("watchlist insert failed");
      return { id: row.id, kind: row.kind, value: row.value, label: row.label, active: row.active };
    } catch (err) {
      if (err instanceof BadRequestException) throw err;
      const msg = err instanceof Error ? err.message : "watchlist failed";
      throw new BadRequestException(msg);
    }
  }

  async updateWatchlist(
    id: string,
    body: { active?: boolean; label?: string }
  ): Promise<VocWatchlistRule | null> {
    const sets: string[] = ["updated_at = now()"];
    const params: unknown[] = [];
    if (typeof body.active === "boolean") {
      params.push(body.active);
      sets.push(`active = $${params.length}`);
    }
    if (body.label !== undefined) {
      params.push(String(body.label).trim());
      sets.push(`label = $${params.length}`);
    }
    if (params.length === 0) throw new BadRequestException("nothing to update");
    params.push(id);
    const r = await this.db.query<{
      id: string;
      kind: VocWatchlistKind;
      value: string;
      label: string;
      active: boolean;
    }>(
      `UPDATE voc_watchlist SET ${sets.join(", ")}
        WHERE id = $${params.length}::uuid
        RETURNING id::text, kind, value, label, active`,
      params
    );
    const row = r.rows[0];
    if (!row) return null;
    return { id: row.id, kind: row.kind, value: row.value, label: row.label, active: row.active };
  }

  async removeWatchlist(id: string): Promise<{ ok: boolean }> {
    await this.db.query(`DELETE FROM voc_watchlist WHERE id = $1::uuid`, [id]);
    return { ok: true };
  }

  private async loadWatchlist(): Promise<VocWatchlistRule[]> {
    return this.listWatchlist();
  }

  private async loadTriageMap(refKeys: string[]) {
    const map = new Map<
      string,
      { status: VocTriageStatus; claimed_by_email: string | null; updated_at: Date }
    >();
    if (refKeys.length === 0) return map;
    const r = await this.db.query<{
      ref_key: string;
      status: VocTriageStatus;
      claimed_by_email: string | null;
      updated_at: Date;
    }>(`SELECT ref_key, status, claimed_by_email, updated_at FROM voc_triage WHERE ref_key = ANY($1::text[])`, [
      refKeys
    ]);
    for (const row of r.rows) {
      map.set(row.ref_key, row);
    }
    return map;
  }

  private async loadCaseMapByRefKeys(refKeys: string[]): Promise<Map<string, VocCaseRefHit>> {
    const keys = [...new Set(refKeys.map((k) => k.trim()).filter(Boolean))];
    if (!keys.length) return new Map();

    const r = await this.db.query<VocCaseRefHit & { ref_count: string }>(
      `SELECT r.ref_key,
              c.id AS case_id,
              c.status,
              c.assignee_email,
              c.sla_due_at,
              c.task_id,
              (SELECT count(*)::text FROM voc_case_ref r2 WHERE r2.case_id = c.id) AS ref_count
         FROM voc_case_ref r
         JOIN voc_case c ON c.id = r.case_id
        WHERE r.ref_key = ANY($1::text[])
          AND c.status IN ('open','in_progress')`,
      [keys]
    );

    const map = new Map<string, VocCaseRefHit>();
    for (const row of r.rows) {
      map.set(row.ref_key, {
        ref_key: row.ref_key,
        case_id: row.case_id,
        status: row.status,
        assignee_email: row.assignee_email,
        sla_due_at: row.sla_due_at,
        task_id: row.task_id,
        ref_count: Number(row.ref_count) || 1
      });
    }
    return map;
  }

  private async fetchHotCves(limit: number, watchlist: VocWatchlistRule[]): Promise<VocQueueItem[]> {
    const vulnClassGuessSql = sqlVulnClassGuessExpr();
    const r = await this.db.query<{
      cve_id: string;
      published_at: string | null;
      risk_score: number | null;
      epss: number | null;
      cvss_base: number | null;
      exploit_known: boolean;
      epss_spike: boolean;
      vckev_only: boolean;
      vulncheck_kev: boolean;
      has_poc: boolean;
      has_public_exploit: boolean;
      vp_vendor: string | null;
      vp_product: string | null;
      short_description: string | null;
      enrich_summary: string | null;
      enrich_title: string | null;
      vuln_class: string | null;
    }>(
      `WITH recent_cve AS MATERIALIZED (
        SELECT c.cve_id, c.published_at, c.cvss_base, c.raw
          FROM cve c
         WHERE ${SQL_EFFECTIVE_PUBLISHED_AT} IS NOT NULL
           AND ${SQL_EFFECTIVE_PUBLISHED_AT} >= now() - interval '${CVE_HOT_WINDOW_HOURS} hours'
         ORDER BY ${SQL_EFFECTIVE_PUBLISHED_AT} DESC NULLS LAST
         LIMIT 5000
      )
       SELECT c.cve_id, c.published_at,
              rs.score AS risk_score, es.score AS epss, c.cvss_base,
              (k.cve_id IS NOT NULL) AS exploit_known,
              COALESCE(ei.epss_spike, false) AS epss_spike,
              COALESCE(ei.vckev_only, false) AS vckev_only,
              COALESCE(ei.vulncheck_kev, false) AS vulncheck_kev,
              COALESCE(ei.has_poc, false) AS has_poc,
              COALESCE(ei.has_public_exploit, false) AS has_public_exploit,
              vp1.vendor AS vp_vendor, vp1.product AS vp_product,
              NULLIF(substring(COALESCE(
                c.raw->'descriptions'->0->>'value',
                c.raw->'cve'->'descriptions'->0->>'value',
                ''
              ) for 800), '') AS short_description,
              NULLIF(substring(
                CASE
                  WHEN COALESCE(ea1.output_json->>'summary', '') LIKE 'LLM not configured%' THEN ''
                  ELSE COALESCE(ea1.output_json->>'summary', '')
                END
                for 800
              ), '') AS enrich_summary,
              NULLIF(btrim(ea1.output_json->>'title'), '') AS enrich_title,
              ${vulnClassGuessSql} AS vuln_class
         FROM recent_cve c
    LEFT JOIN LATERAL (
      SELECT vp.vendor, vp.product FROM cve_vendor_product vp
       WHERE vp.cve_id = c.cve_id
       ORDER BY vp.vendor_key ASC LIMIT 1
    ) vp1 ON TRUE
    LEFT JOIN risk_score rs ON rs.cve_id = c.cve_id
    LEFT JOIN epss_score es ON es.cve_id = c.cve_id
    LEFT JOIN kev k ON k.cve_id = c.cve_id
    LEFT JOIN cve_exploit_intel ei ON ei.cve_id = c.cve_id
    LEFT JOIN LATERAL (
      SELECT ea.output_json FROM enrichment_ai ea
       WHERE ea.cve_id = c.cve_id
       ORDER BY ea.created_at DESC LIMIT 1
    ) ea1 ON TRUE
        WHERE (
            k.cve_id IS NOT NULL
            OR es.score >= 0.5
            OR c.cvss_base >= 9
          )
        ORDER BY es.score DESC NULLS LAST, c.cvss_base DESC NULLS LAST, c.published_at DESC NULLS LAST
        LIMIT $1`,
      [limit]
    );

    return r.rows.map((row) => {
      const scored = scoreCveForVoc({
        cve_id: row.cve_id,
        published_at: row.published_at,
        risk_score: row.risk_score,
        epss: row.epss,
        cvss_base: row.cvss_base,
        exploit_known: row.exploit_known,
        vuln_class: row.vuln_class,
        epss_spike: row.epss_spike,
        vckev_only: row.vckev_only,
        vulncheck_kev: row.vulncheck_kev,
        has_poc: row.has_poc,
        has_public_exploit: row.has_public_exploit
      });
      const subtitle = [row.vp_vendor, row.vp_product].filter(Boolean).join(" / ") || row.short_description || "";
      const boosted = applyWatchlistBoost(
        scored,
        {
          vendor: row.vp_vendor,
          product: row.vp_product,
          text: `${row.cve_id} ${subtitle} ${row.short_description ?? ""}`
        },
        watchlist
      );
      return {
        refKey: vocRefKey("cve", row.cve_id),
        source: "cve" as const,
        refId: row.cve_id,
        vocScore: boosted.score,
        vocPriority: boosted.priority,
        vocReasons: boosted.reasons,
        title: row.cve_id,
        subtitle,
        publishedAt: row.published_at,
        status: "open" as const,
        claimedByEmail: null,
        updatedAt: null,
        payload: {
          risk_score: row.risk_score,
          epss: row.epss,
          cvss_base: row.cvss_base,
          exploit_known: row.exploit_known,
          epss_spike: row.epss_spike,
          vckev_only: row.vckev_only,
          vulncheck_kev: row.vulncheck_kev,
          has_poc: row.has_poc,
          has_public_exploit: row.has_public_exploit,
          vuln_class: row.vuln_class,
          vp_vendor: row.vp_vendor,
          vp_product: row.vp_product,
          short_description: row.short_description,
          enrich_summary: row.enrich_summary,
          enrich_title: row.enrich_title
        }
      };
    });
  }

  private async fetchHotBdu(limit: number, watchlist: VocWatchlistRule[]): Promise<VocQueueItem[]> {
    const windowHours = Math.max(24, Math.min(168, Number(process.env.VOC_BDU_WINDOW_HOURS ?? 168)));
    const minEpss = 0.5;
    const minCvss = 9.0;
    const hotLinkedSql = `EXISTS (
      SELECT 1
        FROM cve_bdu_link l
        JOIN cve c ON c.cve_id = l.cve_id
   LEFT JOIN kev k ON k.cve_id = c.cve_id
   LEFT JOIN epss_score es ON es.cve_id = c.cve_id
       WHERE l.bdu_id = b.bdu_id
         AND (k.cve_id IS NOT NULL OR es.score >= ${minEpss} OR c.cvss_base >= ${minCvss})
    )`;

    const candidates = await this.db.query<{
      bdu_id: string;
      name: string;
      publication_date: string | null;
      cvss_score: number | null;
      has_exploit: boolean;
      has_fix: boolean;
      fix_status: string | null;
      exploit_status: string | null;
      severity_level: number;
      cve_ids: string[] | null;
    }>(
      `SELECT b.bdu_id, b.name, b.publication_date, b.cvss_score, b.has_exploit, b.has_fix,
              b.fix_status, b.exploit_status, b.severity_level, b.cve_ids
         FROM bdu_vuln b
        WHERE ${sqlBduVocWindowWithinHours("b", windowHours)}
          AND (
            b.has_exploit
            OR COALESCE(b.cvss_score, 0) >= 7
            OR b.severity_level >= 3
            OR ${hotLinkedSql}
          )
        ORDER BY to_timestamp(b.publication_date, 'DD.MM.YYYY') DESC NULLS LAST, b.severity_level DESC, b.has_exploit DESC, b.cvss_score DESC NULLS LAST
        LIMIT $1`,
      [Math.max(limit, 80)]
    );

    if (candidates.rows.length === 0) return [];

    const bduIds = candidates.rows.map((row) => row.bdu_id);
    const linkRows = await this.db.query<{ bdu_id: string; cve_id: string }>(
      `SELECT bdu_id, cve_id
         FROM cve_bdu_link
        WHERE bdu_id = ANY($1::text[])`,
      [bduIds]
    );

    const linkedByBdu = new Map<string, Set<string>>();
    const allCveIds = new Set<string>();
    for (const row of candidates.rows) {
      const linked = new Set((row.cve_ids ?? []).map((id) => id.trim().toUpperCase()).filter(Boolean));
      linkedByBdu.set(row.bdu_id, linked);
      for (const cveId of linked) allCveIds.add(cveId);
    }

    const linkCountByBdu = new Map<string, number>();
    for (const row of linkRows.rows) {
      const cveId = row.cve_id.trim().toUpperCase();
      if (!cveId) continue;
      let linked = linkedByBdu.get(row.bdu_id);
      if (!linked) {
        linked = new Set<string>();
        linkedByBdu.set(row.bdu_id, linked);
      }
      linked.add(cveId);
      allCveIds.add(cveId);
      linkCountByBdu.set(row.bdu_id, (linkCountByBdu.get(row.bdu_id) ?? 0) + 1);
    }

    const hotCves = new Set<string>();
    if (allCveIds.size > 0) {
      const hotRows = await this.db.query<{ cve_id: string }>(
        `SELECT c.cve_id
           FROM cve c
      LEFT JOIN epss_score es ON es.cve_id = c.cve_id
      LEFT JOIN kev k ON k.cve_id = c.cve_id
          WHERE c.cve_id = ANY($1::text[])
            AND (k.cve_id IS NOT NULL OR es.score >= $2 OR c.cvss_base >= $3)`,
        [[...allCveIds], minEpss, minCvss]
      );
      for (const row of hotRows.rows) hotCves.add(row.cve_id.toUpperCase());
    }

    return candidates.rows
      .map((row) => {
        const linked = linkedByBdu.get(row.bdu_id) ?? new Set<string>();
        const linkedHot = [...linked].some((cveId) => hotCves.has(cveId));
        const linkedCount = Math.max(linkCountByBdu.get(row.bdu_id) ?? 0, linked.size);
        return this.toBduQueueItem(
          {
            bdu_id: row.bdu_id,
            name: row.name,
            publication_date: row.publication_date,
            cvss_score: row.cvss_score,
            has_exploit: row.has_exploit,
            has_fix: row.has_fix,
            fix_status: row.fix_status,
            exploit_status: row.exploit_status,
            severity_level: row.severity_level,
            linked_hot: linkedHot,
            linked_count: linkedCount,
            cve_ids: [...linked].slice(0, 4)
          },
          watchlist
        );
      })
      .slice(0, limit);
  }

  private toBduQueueItem(
    row: {
      bdu_id: string;
      name: string;
      publication_date: string | null;
      cvss_score: number | null;
      has_exploit: boolean;
      has_fix?: boolean | null;
      fix_status?: string | null;
      exploit_status?: string | null;
      severity_level?: number | null;
      linked_hot: boolean;
      linked_count: number;
      cve_ids?: string[];
      watchlist_match?: boolean;
    },
    watchlist: VocWatchlistRule[]
  ): VocQueueItem {
    const hasFix = resolveBduHasFix({ fixStatus: row.fix_status, hasFix: row.has_fix });
    const hasExploit = resolveBduHasExploit({
      exploitStatus: row.exploit_status,
      hasExploit: row.has_exploit
    });
    const scored = scoreBduForVoc({
      bduId: row.bdu_id,
      hasExploit: hasExploit ?? false,
      cvssScore: row.cvss_score,
      linkedCveCount: row.linked_count,
      hasHotLinkedCve: row.linked_hot,
      severityLevel: row.severity_level,
      hasFix,
      fixStatus: row.fix_status,
      exploitStatus: row.exploit_status
    });
    const boosted = applyWatchlistBoost(scored, { text: `${row.bdu_id} ${row.name}` }, watchlist);
    return {
      refKey: vocRefKey("bdu", row.bdu_id),
      source: "bdu" as const,
      refId: row.bdu_id,
      vocScore: boosted.score,
      vocPriority: boosted.priority,
      vocReasons: boosted.reasons,
      title: `BDU:${row.bdu_id}`,
      subtitle: row.name || "",
      publishedAt: row.publication_date,
      status: "open" as const,
      claimedByEmail: null,
      updatedAt: null,
      payload: {
        name: row.name,
        cvss_score: row.cvss_score,
        has_exploit: hasExploit ?? false,
        has_fix: hasFix,
        fix_status: row.fix_status ?? null,
        exploit_status: row.exploit_status ?? null,
        severity_level: row.severity_level ?? 0,
        linked_hot: row.linked_hot,
        linked_count: row.linked_count,
        publication_date: row.publication_date,
        cve_ids: row.cve_ids ?? [],
        ...(row.watchlist_match ? { watchlist_match: true } : {})
      }
    };
  }

  private buildCveWatchlistWhere(
    rules: VocWatchlistRule[]
  ): { clause: string; params: string[] } | null {
    const active = rules.filter((r) => r.active && r.value.trim());
    if (!active.length) return null;
    const parts: string[] = [];
    const params: string[] = [];
    for (const rule of active) {
      const needle = `%${rule.value.trim().toLowerCase()}%`;
      params.push(needle);
      const n = params.length;
      if (rule.kind === "vendor") {
        parts.push(`lower(coalesce(vp1.vendor, '')) LIKE $${n}`);
      } else if (rule.kind === "product") {
        parts.push(
          `(lower(coalesce(vp1.product, '')) LIKE $${n} OR lower(concat(coalesce(vp1.vendor, ''), '/', coalesce(vp1.product, ''))) LIKE $${n})`
        );
      } else {
        parts.push(
          `lower(concat(c.cve_id, ' ', coalesce(vp1.vendor, ''), ' ', coalesce(vp1.product, ''), ' ', coalesce(
            substring(COALESCE(c.raw->'descriptions'->0->>'value', c.raw->'cve'->'descriptions'->0->>'value', '') for 400),
            ''
          ))) LIKE $${n}`
        );
      }
    }
    return { clause: `(${parts.join(" OR ")})`, params };
  }

  private buildBduWatchlistWhere(
    rules: VocWatchlistRule[]
  ): { clause: string; params: string[] } | null {
    const active = rules.filter((r) => r.active && r.value.trim());
    if (!active.length) return null;
    const parts: string[] = [];
    const params: string[] = [];
    for (const rule of active) {
      const needle = `%${rule.value.trim().toLowerCase()}%`;
      params.push(needle);
      const n = params.length;
      parts.push(`lower(concat(b.bdu_id, ' ', coalesce(b.name, ''))) LIKE $${n}`);
    }
    return { clause: `(${parts.join(" OR ")})`, params };
  }

  private async fetchWatchlistCves(limit: number, watchlist: VocWatchlistRule[]): Promise<VocQueueItem[]> {
    const match = this.buildCveWatchlistWhere(watchlist);
    if (!match) return [];
    const vulnClassGuessSql = sqlVulnClassGuessExpr();
    const windowHours = Math.max(24, Math.min(336, Number(process.env.VOC_WATCHLIST_WINDOW_HOURS ?? 168)));
    const params = [...match.params, limit];
    const limitIdx = params.length;

    const r = await this.db.query<{
      cve_id: string;
      published_at: string | null;
      risk_score: number | null;
      epss: number | null;
      cvss_base: number | null;
      exploit_known: boolean;
      epss_spike: boolean;
      vckev_only: boolean;
      vulncheck_kev: boolean;
      has_poc: boolean;
      has_public_exploit: boolean;
      vp_vendor: string | null;
      vp_product: string | null;
      short_description: string | null;
      enrich_summary: string | null;
      enrich_title: string | null;
      vuln_class: string | null;
    }>(
      `SELECT c.cve_id, c.published_at,
              rs.score AS risk_score, es.score AS epss, c.cvss_base,
              (k.cve_id IS NOT NULL) AS exploit_known,
              COALESCE(ei.epss_spike, false) AS epss_spike,
              COALESCE(ei.vckev_only, false) AS vckev_only,
              COALESCE(ei.vulncheck_kev, false) AS vulncheck_kev,
              COALESCE(ei.has_poc, false) AS has_poc,
              COALESCE(ei.has_public_exploit, false) AS has_public_exploit,
              vp1.vendor AS vp_vendor, vp1.product AS vp_product,
              NULLIF(substring(COALESCE(
                c.raw->'descriptions'->0->>'value',
                c.raw->'cve'->'descriptions'->0->>'value',
                ''
              ) for 800), '') AS short_description,
              NULLIF(substring(
                CASE
                  WHEN COALESCE(ea1.output_json->>'summary', '') LIKE 'LLM not configured%' THEN ''
                  ELSE COALESCE(ea1.output_json->>'summary', '')
                END
                for 800
              ), '') AS enrich_summary,
              NULLIF(btrim(ea1.output_json->>'title'), '') AS enrich_title,
              ${vulnClassGuessSql} AS vuln_class
         FROM cve c
    LEFT JOIN LATERAL (
      SELECT vp.vendor, vp.product FROM cve_vendor_product vp
       WHERE vp.cve_id = c.cve_id
       ORDER BY vp.vendor_key ASC LIMIT 1
    ) vp1 ON TRUE
    LEFT JOIN LATERAL (
      SELECT ea.output_json FROM enrichment_ai ea
       WHERE ea.cve_id = c.cve_id
       ORDER BY ea.created_at DESC LIMIT 1
    ) ea1 ON TRUE
    LEFT JOIN risk_score rs ON rs.cve_id = c.cve_id
    LEFT JOIN epss_score es ON es.cve_id = c.cve_id
    LEFT JOIN kev k ON k.cve_id = c.cve_id
    LEFT JOIN cve_exploit_intel ei ON ei.cve_id = c.cve_id
        WHERE ${SQL_EFFECTIVE_PUBLISHED_AT} IS NOT NULL
          AND ${SQL_EFFECTIVE_PUBLISHED_AT} >= now() - interval '${windowHours} hours'
          AND ${match.clause}
        ORDER BY es.score DESC NULLS LAST, c.cvss_base DESC NULLS LAST, c.published_at DESC NULLS LAST
        LIMIT $${limitIdx}`,
      params
    );

    return r.rows.map((row) => {
      const scored = scoreCveForVoc({
        cve_id: row.cve_id,
        published_at: row.published_at,
        risk_score: row.risk_score,
        epss: row.epss,
        cvss_base: row.cvss_base,
        exploit_known: row.exploit_known,
        vuln_class: row.vuln_class,
        epss_spike: row.epss_spike,
        vckev_only: row.vckev_only,
        vulncheck_kev: row.vulncheck_kev,
        has_poc: row.has_poc,
        has_public_exploit: row.has_public_exploit
      });
      const subtitle = [row.vp_vendor, row.vp_product].filter(Boolean).join(" / ") || row.short_description || "";
      const boosted = applyWatchlistBoost(
        scored,
        {
          vendor: row.vp_vendor,
          product: row.vp_product,
          text: `${row.cve_id} ${subtitle} ${row.short_description ?? ""}`
        },
        watchlist
      );
      return {
        refKey: vocRefKey("cve", row.cve_id),
        source: "cve" as const,
        refId: row.cve_id,
        vocScore: boosted.score,
        vocPriority: boosted.priority,
        vocReasons: boosted.reasons,
        title: row.cve_id,
        subtitle,
        publishedAt: row.published_at,
        status: "open" as const,
        claimedByEmail: null,
        updatedAt: null,
        payload: {
          risk_score: row.risk_score,
          epss: row.epss,
          cvss_base: row.cvss_base,
          exploit_known: row.exploit_known,
          epss_spike: row.epss_spike,
          vckev_only: row.vckev_only,
          vulncheck_kev: row.vulncheck_kev,
          has_poc: row.has_poc,
          has_public_exploit: row.has_public_exploit,
          vuln_class: row.vuln_class,
          vp_vendor: row.vp_vendor,
          vp_product: row.vp_product,
          short_description: row.short_description,
          enrich_summary: row.enrich_summary,
          enrich_title: row.enrich_title,
          watchlist_match: true
        }
      };
    });
  }

  private async fetchWatchlistBdu(limit: number, watchlist: VocWatchlistRule[]): Promise<VocQueueItem[]> {
    const match = this.buildBduWatchlistWhere(watchlist);
    if (!match) return [];
    const windowHours = Math.max(24, Math.min(168, Number(process.env.VOC_BDU_WINDOW_HOURS ?? 168)));
    const params = [...match.params, limit];
    const limitIdx = params.length;

    const r = await this.db.query<{
      bdu_id: string;
      name: string;
      publication_date: string | null;
      cvss_score: number | null;
      has_exploit: boolean;
      has_fix: boolean;
      fix_status: string | null;
      exploit_status: string | null;
      severity_level: number;
      linked_hot: boolean;
      linked_count: number;
    }>(
      `SELECT b.bdu_id, b.name, b.publication_date, b.cvss_score, b.has_exploit, b.has_fix,
              b.fix_status, b.exploit_status, b.severity_level,
              EXISTS (
                SELECT 1
                  FROM cve_bdu_link l
                  JOIN cve c ON c.cve_id = l.cve_id
             LEFT JOIN kev k ON k.cve_id = c.cve_id
             LEFT JOIN epss_score es ON es.cve_id = c.cve_id
                 WHERE l.bdu_id = b.bdu_id
                   AND (k.cve_id IS NOT NULL OR es.score >= 0.5 OR c.cvss_base >= 9)
              ) AS linked_hot,
              (SELECT count(DISTINCT l.cve_id)::int FROM cve_bdu_link l WHERE l.bdu_id = b.bdu_id) AS linked_count
        FROM bdu_vuln b
        WHERE ${sqlBduVocWindowWithinHours("b", windowHours)}
          AND ${match.clause}
        ORDER BY to_timestamp(b.publication_date, 'DD.MM.YYYY') DESC NULLS LAST, b.severity_level DESC, b.cvss_score DESC NULLS LAST
        LIMIT $${limitIdx}`,
      params
    );

    return r.rows.map((row) =>
      this.toBduQueueItem(
        {
          ...row,
          cve_ids: [],
          watchlist_match: true
        },
        watchlist
      )
    );
  }
}
