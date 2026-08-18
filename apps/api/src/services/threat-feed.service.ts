import { Injectable } from "@nestjs/common";
import {
  formatThreatDailyDigestMessages,
  NVD_REFS_SCANNED_SIGNAL_TYPE,
  type ThreatDigestHotCve,
  type ThreatDigestCriticalEvent,
  type ThreatDigestPayload
} from "@vuln-intel/shared";
import { DbService } from "./db.service.js";

export const THREAT_SCORE_SQL = `(
  CASE s.signal_type
    WHEN 'vulncheck_kev' THEN 40
    WHEN 'metasploit' THEN 35
    WHEN 'exploit_db' THEN 32
    WHEN 'nvd_exploit_tag' THEN 28
    WHEN 'poc_github' THEN 18
    WHEN 'poc_public' THEN 16
    WHEN 'nuclei' THEN 12
    ELSE 8
  END
  + CASE WHEN COALESCE(ei.vckev_only, false) THEN 25 ELSE 0 END
  + CASE WHEN COALESCE(ei.epss_spike, false) THEN 20 ELSE 0 END
  + CASE WHEN k.cve_id IS NOT NULL THEN 15 ELSE 0 END
  + COALESCE(rs.score, 0) * 0.2
  + COALESCE(es.score, 0) * 30
)::int`;

type FeedQuery = {
  limit: number;
  offset: number;
  windowHours: number | null;
  signalType: string | null;
  sort: "threat" | "recent";
  newOnly: boolean;
  since: Date | null;
  vendorKeys: string[];
  watchlistOnly: boolean;
};

@Injectable()
export class ThreatFeedService {
  constructor(private readonly db: DbService) {}

  private pickPriority(row: {
    threat_score: number;
    cisa_kev: boolean;
    vckev_only: boolean;
    epss_spike: boolean;
    has_public_exploit: boolean;
    has_poc: boolean;
    epss: number | null;
    cvss_base: number | null;
  }): "P0" | "P1" | "P2" {
    const epss = typeof row.epss === "number" ? row.epss : 0;
    const cvss = typeof row.cvss_base === "number" ? row.cvss_base : 0;
    const score = row.threat_score ?? 0;
    const isExploitReady = row.cisa_kev || row.vckev_only || row.has_public_exploit || row.epss_spike;
    if (row.cisa_kev) return "P0";
    if (row.vckev_only && (row.has_public_exploit || epss >= 0.4 || cvss >= 9 || score >= 75)) return "P0";
    if (row.has_public_exploit && (epss >= 0.2 || cvss >= 8 || score >= 55)) return "P0";
    if (isExploitReady && (epss >= 0.2 || cvss >= 8 || score >= 55)) return "P1";
    if (row.has_poc && (epss >= 0.2 || cvss >= 8 || score >= 35)) return "P1";
    return "P2";
  }

  private buildWhyRu(row: {
    cisa_kev: boolean;
    vckev_only: boolean;
    epss_spike: boolean;
    has_public_exploit: boolean;
    has_poc: boolean;
    epss: number | null;
    cvss_base: number | null;
  }): { tags: string[]; why: string } {
    const tags: string[] = [];
    if (row.cisa_kev) tags.push("CISA KEV");
    if (row.vckev_only) tags.push("VCK-only");
    if (row.epss_spike) tags.push("EPSS spike");
    if (row.has_public_exploit) tags.push("Публичный эксплойт");
    else if (row.has_poc) tags.push("PoC");
    const epss = typeof row.epss === "number" ? `${(row.epss * 100).toFixed(1)}%` : "—";
    const cvss = row.cvss_base ?? "—";
    const why = `CVSS ${cvss} · EPSS ${epss}${tags.length ? ` · ${tags.join(", ")}` : ""}`;
    return { tags, why };
  }

  private summarizeTrendsRu(
    hot: Array<Pick<ThreatDigestHotCve, "cvss_av" | "cvss_pr" | "cvss_ui">>
  ): ThreatDigestPayload["trends"] {
    const norm = (v: string | null | undefined) => (v ? String(v).trim().toUpperCase() : "UNKNOWN");
    const labelAv: Record<string, string> = {
      NETWORK: "Сеть (Network)",
      ADJACENT: "Соседняя сеть (Adjacent)",
      LOCAL: "Локально (Local)",
      PHYSICAL: "Физический доступ (Physical)",
      UNKNOWN: "Не определено"
    };
    const labelPr: Record<string, string> = {
      NONE: "Без привилегий (PR:NONE)",
      LOW: "Низкие привилегии (PR:LOW)",
      HIGH: "Высокие привилегии (PR:HIGH)",
      UNKNOWN: "Не определено"
    };
    const labelUi: Record<string, string> = {
      NONE: "Без участия пользователя (UI:NONE)",
      REQUIRED: "Требуется участие пользователя (UI:REQUIRED)",
      UNKNOWN: "Не определено"
    };

    const count = (keyFn: (r: any) => string, labels: Record<string, string>) => {
      const m = new Map<string, number>();
      for (const r of hot) {
        const k = keyFn(r);
        m.set(k, (m.get(k) ?? 0) + 1);
      }
      return [...m.entries()]
        .map(([key, c]) => ({ key, label: labels[key] ?? key, count: c }))
        .sort((a, b) => b.count - a.count);
    };

    return {
      attackVector: count((r) => norm(r.cvss_av), labelAv),
      privilegesRequired: count((r) => norm(r.cvss_pr), labelPr),
      userInteraction: count((r) => norm(r.cvss_ui), labelUi)
    };
  }

  private async buildFilters(q: FeedQuery) {
    const filters: string[] = [];
    const params: unknown[] = [];
    const add = (cond: string, value?: unknown) => {
      if (value === undefined) return;
      params.push(value);
      filters.push(cond.replace(/\$(\d+)/g, () => `$${params.length}`));
    };

    // `nvd_refs_scanned` is a scan watermark inserted during NVD raw processing.
    // It is not a real external “mention/source”, so it should not dominate “new/updated 24h”.
    if (!q.signalType || q.signalType !== NVD_REFS_SCANNED_SIGNAL_TYPE) {
      add(`s.signal_type <> $1`, NVD_REFS_SCANNED_SIGNAL_TYPE);
    }

    // Window is applied after CVE aggregation (see getFeed) so we keep the best signal score.
    if (q.signalType) add(`s.signal_type = $1`, q.signalType);
    // `since` используется только для summary.sinceCount, не сужает ленту.

    if (q.vendorKeys.length > 0) {
      add(
        `EXISTS (SELECT 1 FROM cve_vendor_product vpw WHERE vpw.cve_id = c.cve_id AND vpw.vendor_key = ANY($1::text[]))`,
        q.vendorKeys.map((v) => v.trim().toLowerCase()).filter(Boolean)
      );
    }

    if (q.watchlistOnly) {
      const rules = await this.db.query<{ kind: string; value: string }>(
        `SELECT kind, value FROM voc_watchlist WHERE active = true AND trim(value) <> ''`
      );
      const wlParts: string[] = [];
      const vendors = rules.rows.filter((r) => r.kind === "vendor").map((r) => r.value.trim().toLowerCase());
      const products = rules.rows.filter((r) => r.kind === "product").map((r) => r.value.trim().toLowerCase());
      const keywords = rules.rows.filter((r) => r.kind === "keyword").map((r) => r.value.trim().toLowerCase());
      if (vendors.length) {
        params.push(vendors);
        wlParts.push(
          `EXISTS (SELECT 1 FROM cve_vendor_product vpw WHERE vpw.cve_id = c.cve_id AND vpw.vendor_key = ANY($${params.length}::text[]))`
        );
      }
      if (products.length) {
        params.push(products);
        wlParts.push(
          `EXISTS (SELECT 1 FROM cve_vendor_product vpw WHERE vpw.cve_id = c.cve_id AND vpw.product_key_norm = ANY($${params.length}::text[]))`
        );
      }
      for (const kw of keywords) {
        params.push(`%${kw}%`);
        wlParts.push(`(lower(c.cve_id) LIKE $${params.length} OR lower(COALESCE(c.raw::text, '')) LIKE $${params.length})`);
      }
      filters.push(wlParts.length ? `(${wlParts.join(" OR ")})` : "false");
    }

    const whereSql = filters.length ? `WHERE ${filters.join(" AND ")}` : "";
    return { whereSql, params };
  }

  /** CVE-level activity window on aggregated first/last seen (not sync heartbeats). */
  private appendCveWindowFilter(
    q: FeedQuery,
    params: unknown[]
  ): { sql: string; params: unknown[] } {
    const out = [...params];
    const parts: string[] = [];
    if (q.windowHours != null) {
      out.push(String(q.windowHours));
      parts.push(
        `(
          cve_newest_first_seen >= now() - ($${out.length}::text || ' hours')::interval
          OR (
            cve_last_seen >= now() - interval '24 hours'
            AND cve_radar_first_seen < now() - interval '24 hours'
            AND cve_last_seen > cve_radar_first_seen + interval '1 hour'
          )
        )`
      );
    }
    if (q.newOnly) {
      parts.push(`cve_newest_first_seen >= now() - interval '24 hours'`);
    }
    return { sql: parts.length ? parts.join(" AND ") : "true", params: out };
  }

  async getFeed(q: FeedQuery) {
    const { whereSql, params: baseParams } = await this.buildFilters(q);
    const { sql: cveWindowSql, params } = this.appendCveWindowFilter(q, baseParams);
    // Prefer real discovery time (first_seen). last_seen is only for genuine payload updates.
    const orderByInner =
      q.sort === "recent"
        ? `cve_newest_first_seen DESC NULLS LAST, threat_score DESC, cve_id ASC`
        : `threat_score DESC, cve_newest_first_seen DESC NULLS LAST, cve_id ASC`;

    const summaryR = await this.db.query<{
      total: string;
      signals24h: string;
      signals7d: string;
      new_signals24h: string;
      updated_signals24h: string;
      hot_cves: string;
      bucket_new_24h: string;
      bucket_new_7d: string;
      bucket_updated_24h: string;
      bucket_older: string;
    }>(
      `WITH scored AS (
         SELECT s.cve_id,
                max(s.first_seen_at) AS cve_newest_first_seen,
                min(s.first_seen_at) AS cve_radar_first_seen,
                max(s.last_seen_at) AS cve_last_seen,
                max(${THREAT_SCORE_SQL}) AS threat_score
           FROM cve_exploit_signal s
           JOIN cve c ON c.cve_id = s.cve_id
      LEFT JOIN cve_exploit_intel ei ON ei.cve_id = c.cve_id
      LEFT JOIN epss_score es ON es.cve_id = c.cve_id
      LEFT JOIN kev k ON k.cve_id = c.cve_id
      LEFT JOIN risk_score rs ON rs.cve_id = c.cve_id
           ${whereSql}
       GROUP BY s.cve_id
       ),
       scoped AS (
         SELECT * FROM scored WHERE ${cveWindowSql}
       ),
       bucketed AS (
         SELECT *,
                CASE
                  WHEN cve_newest_first_seen >= now() - interval '24 hours' THEN 'new_24h'
                  WHEN cve_newest_first_seen >= now() - interval '7 days' THEN 'new_7d'
                  WHEN cve_last_seen >= now() - interval '24 hours'
                       AND cve_radar_first_seen < now() - interval '24 hours'
                       AND cve_last_seen > cve_radar_first_seen + interval '1 hour'
                    THEN 'updated_24h'
                  ELSE 'older'
                END AS time_bucket
           FROM scoped
       )
       SELECT
         (SELECT count(*)::text FROM bucketed) AS total,
         (SELECT count(*)::text FROM cve_exploit_signal s WHERE s.first_seen_at >= now() - interval '24 hours') AS signals24h,
         (SELECT count(*)::text FROM cve_exploit_signal s WHERE s.first_seen_at >= now() - interval '7 days') AS signals7d,
         (SELECT count(*)::text FROM cve_exploit_signal s WHERE s.first_seen_at >= now() - interval '24 hours') AS new_signals24h,
         (SELECT count(*)::text FROM cve_exploit_signal s
           WHERE s.last_seen_at >= now() - interval '24 hours'
             AND s.first_seen_at < now() - interval '24 hours'
             AND s.last_seen_at > s.first_seen_at + interval '1 hour') AS updated_signals24h,
         (SELECT count(*)::text FROM bucketed WHERE threat_score >= 55) AS hot_cves,
         (SELECT count(*)::text FROM bucketed WHERE time_bucket = 'new_24h') AS bucket_new_24h,
         (SELECT count(*)::text FROM bucketed WHERE time_bucket = 'new_7d') AS bucket_new_7d,
         (SELECT count(*)::text FROM bucketed WHERE time_bucket = 'updated_24h') AS bucket_updated_24h,
         (SELECT count(*)::text FROM bucketed WHERE time_bucket = 'older') AS bucket_older`,
      params
    );

    let sinceCount = 0;
    if (q.since) {
      const sinceOnlyR = await this.db.query<{ n: string }>(
        `SELECT count(DISTINCT s.cve_id)::text AS n
           FROM cve_exploit_signal s
           JOIN cve c ON c.cve_id = s.cve_id
          WHERE s.first_seen_at >= $1::timestamptz`,
        [q.since.toISOString()]
      );
      sinceCount = Number(sinceOnlyR.rows[0]?.n ?? 0);
    }

    const byTypeR = await this.db.query<{ signal_type: string; count: string }>(
      `WITH scored AS (
         SELECT s.cve_id, s.signal_type,
                max(s.first_seen_at) OVER (PARTITION BY s.cve_id) AS cve_newest_first_seen,
                min(s.first_seen_at) OVER (PARTITION BY s.cve_id) AS cve_radar_first_seen,
                max(s.last_seen_at) OVER (PARTITION BY s.cve_id) AS cve_last_seen
           FROM cve_exploit_signal s JOIN cve c ON c.cve_id = s.cve_id
           ${whereSql}
       )
       SELECT signal_type, count(DISTINCT cve_id)::text AS count
         FROM scored
        WHERE ${cveWindowSql}
     GROUP BY signal_type ORDER BY count(DISTINCT cve_id) DESC LIMIT 12`,
      params
    );

    const timelineR = await this.db.query<{ day: string; count: string }>(
      `SELECT to_char(date_trunc('day', s.first_seen_at AT TIME ZONE 'UTC'), 'YYYY-MM-DD') AS day,
              count(DISTINCT s.cve_id)::text AS count
         FROM cve_exploit_signal s JOIN cve c ON c.cve_id = s.cve_id
        WHERE s.first_seen_at >= now() - interval '7 days'
          AND s.signal_type <> '${NVD_REFS_SCANNED_SIGNAL_TYPE}'
     GROUP BY 1 ORDER BY 1 ASC`
    );

    const vendorMapR = await this.db.query<{
      vendor_key: string;
      vendor: string;
      signal_count: number;
      cve_count: number;
      hot_count: number;
    }>(
      `SELECT vp.vendor_key,
              max(vp.vendor) AS vendor,
              count(*)::int AS signal_count,
              count(DISTINCT s.cve_id)::int AS cve_count,
              count(DISTINCT CASE WHEN COALESCE(ei.vckev_only, false) OR COALESCE(ei.epss_spike, false) THEN s.cve_id END)::int AS hot_count
         FROM cve_exploit_signal s
         JOIN cve c ON c.cve_id = s.cve_id
         JOIN cve_vendor_product vp ON vp.cve_id = c.cve_id
    LEFT JOIN cve_exploit_intel ei ON ei.cve_id = c.cve_id
        WHERE s.first_seen_at >= now() - interval '7 days'
     GROUP BY vp.vendor_key
     ORDER BY signal_count DESC
        LIMIT 18`,
      []
    );

    const hotR = await this.db.query(
      `WITH scored AS (
         SELECT s.cve_id, max(${THREAT_SCORE_SQL}) AS threat_score,
                count(*)::int AS signal_count,
                max(s.first_seen_at) AS cve_newest_first_seen,
                min(s.first_seen_at) AS cve_radar_first_seen,
                max(s.last_seen_at) AS cve_last_seen
           FROM cve_exploit_signal s JOIN cve c ON c.cve_id = s.cve_id
      LEFT JOIN cve_exploit_intel ei ON ei.cve_id = c.cve_id
      LEFT JOIN epss_score es ON es.cve_id = c.cve_id
      LEFT JOIN kev k ON k.cve_id = c.cve_id
      LEFT JOIN risk_score rs ON rs.cve_id = c.cve_id
           ${whereSql}
       GROUP BY s.cve_id
       ),
       scoped AS (
         SELECT * FROM scored WHERE ${cveWindowSql}
       )
       SELECT agg.cve_id, agg.threat_score, agg.signal_count,
              es.score AS epss, c.cvss_base, rs.score AS risk_score,
              COALESCE(ei.vckev_only, false) AS vckev_only,
              COALESCE(ei.epss_spike, false) AS epss_spike,
              COALESCE(ei.has_poc, false) AS has_poc,
              COALESCE(ei.has_public_exploit, false) AS has_public_exploit,
              (k.cve_id IS NOT NULL) AS cisa_kev,
              vp.vendor, vp.product,
              to_char(agg.cve_newest_first_seen AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS latest_signal_at
         FROM (
           SELECT * FROM scoped
            ORDER BY threat_score DESC, cve_newest_first_seen DESC
            LIMIT 8
         ) agg
         JOIN cve c ON c.cve_id = agg.cve_id
    LEFT JOIN cve_exploit_intel ei ON ei.cve_id = agg.cve_id
    LEFT JOIN epss_score es ON es.cve_id = agg.cve_id
    LEFT JOIN kev k ON k.cve_id = agg.cve_id
    LEFT JOIN risk_score rs ON rs.cve_id = agg.cve_id
    LEFT JOIN LATERAL (
          SELECT vp.vendor, vp.product FROM cve_vendor_product vp
           WHERE vp.cve_id = agg.cve_id ORDER BY vp.vendor_key ASC LIMIT 1
         ) vp ON true
     ORDER BY agg.threat_score DESC`,
      params
    );

    const itemParams = [...params, q.limit, q.offset];
    const limitIdx = itemParams.length - 1;
    const offsetIdx = itemParams.length;

    // One card per CVE: best signal by threat score; bucket by newest first_seen (real discovery).
    const rowsR = await this.db.query(
      `WITH scored AS (
         SELECT s.id, s.cve_id, s.signal_type, s.source, s.url, s.title, s.confidence,
                s.first_seen_at, s.last_seen_at,
                c.cvss_base, es.score AS epss, rs.score AS risk_score,
                COALESCE(ei.vckev_only, false) AS vckev_only,
                COALESCE(ei.epss_spike, false) AS epss_spike,
                COALESCE(ei.has_poc, false) AS has_poc,
                COALESCE(ei.has_public_exploit, false) AS has_public_exploit,
                (k.cve_id IS NOT NULL) AS cisa_kev,
                ei.epss_delta_7d,
                ${THREAT_SCORE_SQL} AS threat_score,
                vp.vendor, vp.product, vp.vendor_key,
                max(s.first_seen_at) OVER (PARTITION BY s.cve_id) AS cve_newest_first_seen,
                min(s.first_seen_at) OVER (PARTITION BY s.cve_id) AS cve_radar_first_seen,
                max(s.last_seen_at) OVER (PARTITION BY s.cve_id) AS cve_last_seen,
                count(*) OVER (PARTITION BY s.cve_id) AS signal_count,
                row_number() OVER (
                  PARTITION BY s.cve_id
                  ORDER BY ${THREAT_SCORE_SQL} DESC, s.first_seen_at DESC, s.id DESC
                ) AS rn
           FROM cve_exploit_signal s
           JOIN cve c ON c.cve_id = s.cve_id
      LEFT JOIN cve_exploit_intel ei ON ei.cve_id = c.cve_id
      LEFT JOIN epss_score es ON es.cve_id = c.cve_id
      LEFT JOIN kev k ON k.cve_id = c.cve_id
      LEFT JOIN risk_score rs ON rs.cve_id = c.cve_id
      LEFT JOIN LATERAL (
            SELECT vp.vendor, vp.product, vp.vendor_key FROM cve_vendor_product vp
             WHERE vp.cve_id = c.cve_id ORDER BY vp.vendor_key ASC LIMIT 1
           ) vp ON true
           ${whereSql}
       ),
       best AS (
         SELECT *
           FROM scored
          WHERE rn = 1
            AND ${cveWindowSql}
       ),
       labeled AS (
         SELECT *,
                CASE
                  WHEN cve_newest_first_seen >= now() - interval '24 hours' THEN 'new_24h'
                  WHEN cve_newest_first_seen >= now() - interval '7 days' THEN 'new_7d'
                  WHEN cve_last_seen >= now() - interval '24 hours'
                       AND cve_radar_first_seen < now() - interval '24 hours'
                       AND cve_last_seen > cve_radar_first_seen + interval '1 hour'
                    THEN 'updated_24h'
                  ELSE 'older'
                END AS time_bucket,
                (cve_newest_first_seen >= now() - interval '24 hours') AS is_new,
                (
                  cve_newest_first_seen < now() - interval '24 hours'
                  AND cve_last_seen >= now() - interval '24 hours'
                  AND cve_radar_first_seen < now() - interval '24 hours'
                  AND cve_last_seen > cve_radar_first_seen + interval '1 hour'
                ) AS is_updated
           FROM best
       )
       SELECT cve_id, signal_type, source, url, title, confidence,
              to_char(cve_radar_first_seen AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS first_seen_at,
              to_char(cve_newest_first_seen AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS newest_signal_at,
              to_char(cve_last_seen AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS last_seen_at,
              cvss_base, epss, risk_score, vckev_only, epss_spike, has_poc, has_public_exploit,
              cisa_kev, epss_delta_7d, threat_score, is_new, is_updated, time_bucket,
              signal_count, vendor, product, vendor_key
         FROM labeled
        ORDER BY
          CASE time_bucket
            WHEN 'new_24h' THEN 0
            WHEN 'updated_24h' THEN 1
            WHEN 'new_7d' THEN 2
            ELSE 3
          END,
          ${orderByInner}
        LIMIT $${limitIdx} OFFSET $${offsetIdx}`,
      itemParams
    );

    const cveIds = [...new Set(rowsR.rows.map((r) => String((r as { cve_id: string }).cve_id)))];
    const sparkMap: Record<string, number[]> = {};
    if (cveIds.length > 0) {
      const sparkR = await this.db.query<{ cve_id: string; score: number; scored_at: Date }>(
        `SELECT cve_id, score, scored_at FROM (
           SELECT cve_id, score, scored_at,
                  row_number() OVER (PARTITION BY cve_id ORDER BY scored_at DESC) AS rn
             FROM epss_score_history WHERE cve_id = ANY($1::text[])
         ) t WHERE rn <= 7 ORDER BY cve_id, scored_at ASC`,
        [cveIds]
      );
      for (const row of sparkR.rows) {
        const list = sparkMap[row.cve_id] ?? [];
        list.push(Number(row.score));
        sparkMap[row.cve_id] = list;
      }
    }

    const summaryRow = summaryR.rows[0];
    const items = rowsR.rows.map((row: Record<string, unknown>) => ({
      ...row,
      epss_sparkline: sparkMap[String(row.cve_id)] ?? []
    }));

    const groupKeys = ["new_24h", "updated_24h", "new_7d", "older"] as const;
    const groups = Object.fromEntries(
      groupKeys.map((key) => [
        key,
        {
          total:
            key === "new_24h"
              ? Number(summaryRow?.bucket_new_24h ?? 0)
              : key === "new_7d"
                ? Number(summaryRow?.bucket_new_7d ?? 0)
                : key === "updated_24h"
                  ? Number(summaryRow?.bucket_updated_24h ?? 0)
                  : Number(summaryRow?.bucket_older ?? 0),
          items: items.filter((it) => String((it as { time_bucket?: string }).time_bucket) === key)
        }
      ])
    );

    return {
      summary: {
        total: Number(summaryRow?.total ?? 0),
        windowHours: q.windowHours,
        signals24h: Number(summaryRow?.signals24h ?? 0),
        signals7d: Number(summaryRow?.signals7d ?? 0),
        newSignals24h: Number(summaryRow?.new_signals24h ?? 0),
        updatedSignals24h: Number(summaryRow?.updated_signals24h ?? 0),
        hotCves: Number(summaryRow?.hot_cves ?? 0),
        sinceCount,
        byType: byTypeR.rows.map((r) => ({ signal_type: r.signal_type, count: Number(r.count) })),
        buckets: {
          new_24h: Number(summaryRow?.bucket_new_24h ?? 0),
          new_7d: Number(summaryRow?.bucket_new_7d ?? 0),
          updated_24h: Number(summaryRow?.bucket_updated_24h ?? 0),
          older: Number(summaryRow?.bucket_older ?? 0)
        }
      },
      timeline: timelineR.rows.map((r) => ({ day: r.day, count: Number(r.count) })),
      vendorHeatmap: vendorMapR.rows,
      hotCves: hotR.rows,
      groups,
      total: Number(summaryRow?.total ?? 0),
      limit: q.limit,
      offset: q.offset,
      items
    };
  }

  async buildDigestText(limit = 8): Promise<string> {
    const messages = await this.buildDailyDigestMessages(Math.max(limit, 20));
    return messages.join("\n\n━━━━━━━━━━━━━━━━━━━━\n\n");
  }

  async buildDailyDigestMessages(hotLimit = 20): Promise<string[]> {
    const payload = await this.collectDailyDigestPayload(hotLimit);
    return formatThreatDailyDigestMessages(payload);
  }

  async collectDailyDigestPayload(hotLimit = 20): Promise<ThreatDigestPayload> {
    const pulseR = await this.db.query<{
      signals: string;
      new_signals: string;
      updated_signals: string;
      distinct_cves: string;
      hot_cves: string;
      vckev_only: string;
      epss_spikes: string;
      cisa_kev: string;
      with_poc: string;
      with_public_exploit: string;
      new_vckev_24h: string;
      cves_published_24h: string;
    }>(
      `SELECT
         (SELECT count(*)::text FROM cve_exploit_signal WHERE last_seen_at >= now() - interval '24 hours') AS signals,
         (SELECT count(*)::text FROM cve_exploit_signal WHERE first_seen_at >= now() - interval '24 hours') AS new_signals,
         (SELECT count(*)::text FROM cve_exploit_signal
           WHERE last_seen_at >= now() - interval '24 hours'
             AND first_seen_at < now() - interval '24 hours') AS updated_signals,
         (SELECT count(DISTINCT cve_id)::text FROM cve_exploit_signal WHERE last_seen_at >= now() - interval '24 hours') AS distinct_cves,
         (SELECT count(*)::text FROM (
            SELECT s.cve_id FROM cve_exploit_signal s
              JOIN cve c ON c.cve_id = s.cve_id
         LEFT JOIN cve_exploit_intel ei ON ei.cve_id = c.cve_id
         LEFT JOIN epss_score es ON es.cve_id = c.cve_id
         LEFT JOIN kev k ON k.cve_id = c.cve_id
         LEFT JOIN risk_score rs ON rs.cve_id = c.cve_id
            WHERE s.last_seen_at >= now() - interval '24 hours'
         GROUP BY s.cve_id HAVING max(${THREAT_SCORE_SQL}) >= 55
          ) x) AS hot_cves,
         (SELECT count(DISTINCT s.cve_id)::text
            FROM cve_exploit_signal s
            JOIN cve_exploit_intel ei ON ei.cve_id = s.cve_id
           WHERE s.last_seen_at >= now() - interval '24 hours' AND ei.vckev_only) AS vckev_only,
         (SELECT count(DISTINCT s.cve_id)::text
            FROM cve_exploit_signal s
            JOIN cve_exploit_intel ei ON ei.cve_id = s.cve_id
           WHERE s.last_seen_at >= now() - interval '24 hours' AND ei.epss_spike) AS epss_spikes,
         (SELECT count(DISTINCT s.cve_id)::text
            FROM cve_exploit_signal s
            JOIN kev k ON k.cve_id = s.cve_id
           WHERE s.last_seen_at >= now() - interval '24 hours') AS cisa_kev,
         (SELECT count(DISTINCT s.cve_id)::text
            FROM cve_exploit_signal s
            JOIN cve_exploit_intel ei ON ei.cve_id = s.cve_id
           WHERE s.last_seen_at >= now() - interval '24 hours' AND ei.has_poc) AS with_poc,
         (SELECT count(DISTINCT s.cve_id)::text
            FROM cve_exploit_signal s
            JOIN cve_exploit_intel ei ON ei.cve_id = s.cve_id
           WHERE s.last_seen_at >= now() - interval '24 hours' AND ei.has_public_exploit) AS with_public_exploit,
         (SELECT count(*)::text FROM vulncheck_kev WHERE date_added >= CURRENT_DATE - 1) AS new_vckev_24h,
         (SELECT count(*)::text FROM cve WHERE published_at >= now() - interval '24 hours') AS cves_published_24h`
    );

    const byTypeR = await this.db.query<{ signal_type: string; count: string }>(
      `SELECT signal_type, count(*)::text AS count
         FROM cve_exploit_signal
        WHERE last_seen_at >= now() - interval '24 hours'
     GROUP BY signal_type
     ORDER BY count(*) DESC`
    );

    const vendorR = await this.db.query<{
      vendor: string;
      signal_count: number;
      cve_count: number;
      hot_count: number;
    }>(
      `SELECT max(vp.vendor) AS vendor,
              count(*)::int AS signal_count,
              count(DISTINCT s.cve_id)::int AS cve_count,
              count(DISTINCT CASE WHEN COALESCE(ei.vckev_only, false) OR COALESCE(ei.epss_spike, false) THEN s.cve_id END)::int AS hot_count
         FROM cve_exploit_signal s
         JOIN cve_vendor_product vp ON vp.cve_id = s.cve_id
    LEFT JOIN cve_exploit_intel ei ON ei.cve_id = s.cve_id
        WHERE s.last_seen_at >= now() - interval '24 hours'
     GROUP BY vp.vendor_key
     ORDER BY count(*) DESC
        LIMIT 12`
    );

    const hourlyR = await this.db.query<{ hour: string; count: string }>(
      `SELECT to_char(date_trunc('hour', last_seen_at AT TIME ZONE 'UTC'), 'HH24:00') AS hour,
              count(*)::text AS count
         FROM cve_exploit_signal
        WHERE last_seen_at >= now() - interval '24 hours'
     GROUP BY 1
     ORDER BY min(last_seen_at) ASC`
    );

    const hotRowsR = await this.db.query<{
      cve_id: string;
      threat_score: number;
      signal_count: number;
      epss: number | null;
      cvss_base: number | null;
      risk_score: number | null;
      vckev_only: boolean;
      epss_spike: boolean;
      has_poc: boolean;
      has_public_exploit: boolean;
      cisa_kev: boolean;
      epss_delta_7d: number | null;
      vendor: string | null;
      product: string | null;
      signal_types: string[];
      latest_signal_at: string | null;
      summary_ru: string | null;
      description: string | null;
      cvss_av: string | null;
      cvss_pr: string | null;
      cvss_ui: string | null;
      cvss_ac: string | null;
      remediation_json: unknown;
      next_steps_json: unknown;
      vuln_class: string | null;
    }>(
      `SELECT agg.*,
              es.score AS epss,
              c.cvss_base,
              rs.score AS risk_score,
              COALESCE(ei.vckev_only, false) AS vckev_only,
              COALESCE(ei.epss_spike, false) AS epss_spike,
              COALESCE(ei.has_poc, false) AS has_poc,
              COALESCE(ei.has_public_exploit, false) AS has_public_exploit,
              (k.cve_id IS NOT NULL) AS cisa_kev,
              ei.epss_delta_7d,
              vp.vendor,
              vp.product,
              sigs.types AS signal_types,
              to_char(agg.latest_signal_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS latest_signal_at,
              NULLIF(substring(regexp_replace(COALESCE(
                CASE
                  WHEN ea1.output_json->>'summary' IS NOT NULL
                    AND ea1.output_json->>'summary' NOT LIKE '{%'
                    AND length(ea1.output_json->>'summary') < 1800
                    THEN ea1.output_json->>'summary'
                END,
                ea1.output_json->'raw_model_json'->>'summary',
                CASE
                  WHEN ea1.output_json->>'title' IS NOT NULL
                    AND ea1.output_json->>'title' <> 'Комплексный анализ уязвимости'
                    THEN ea1.output_json->>'title'
                END,
                ea1.output_json->'raw_model_json'->>'title',
                ''
              ), E'\\s+', ' ', 'g') for 420), '') AS summary_ru,
              NULLIF(substring(regexp_replace(COALESCE(
                c.raw->'descriptions'->0->>'value',
                c.raw->'cve'->'descriptions'->0->>'value',
                c.raw->'cve'->'description'->'description_data'->0->>'value',
                c.raw->'description'->'description_data'->0->>'value',
                ''
              ), E'\\s+', ' ', 'g') for 520), '') AS description,
              COALESCE(
                c.raw->'metrics'->'cvssMetricV31'->0->'cvssData'->>'attackVector',
                c.raw->'metrics'->'cvssMetricV30'->0->'cvssData'->>'attackVector',
                c.raw->'impact'->'baseMetricV3'->'cvssV3'->>'attackVector'
              ) AS cvss_av,
              COALESCE(
                c.raw->'metrics'->'cvssMetricV31'->0->'cvssData'->>'privilegesRequired',
                c.raw->'metrics'->'cvssMetricV30'->0->'cvssData'->>'privilegesRequired',
                c.raw->'impact'->'baseMetricV3'->'cvssV3'->>'privilegesRequired'
              ) AS cvss_pr,
              COALESCE(
                c.raw->'metrics'->'cvssMetricV31'->0->'cvssData'->>'userInteraction',
                c.raw->'metrics'->'cvssMetricV30'->0->'cvssData'->>'userInteraction',
                c.raw->'impact'->'baseMetricV3'->'cvssV3'->>'userInteraction'
              ) AS cvss_ui,
              COALESCE(
                c.raw->'metrics'->'cvssMetricV31'->0->'cvssData'->>'attackComplexity',
                c.raw->'metrics'->'cvssMetricV30'->0->'cvssData'->>'attackComplexity',
                c.raw->'impact'->'baseMetricV3'->'cvssV3'->>'attackComplexity'
              ) AS cvss_ac,
              ea1.output_json->'remediation' AS remediation_json,
              COALESCE(ea1.output_json->'nextSteps', ea1.output_json->'next_steps') AS next_steps_json,
              COALESCE(ea1.output_json->>'vulnerabilityClass', ea1.output_json->>'vulnClass') AS vuln_class
         FROM (
           SELECT s.cve_id,
                  max(${THREAT_SCORE_SQL}) AS threat_score,
                  count(*)::int AS signal_count,
                  max(s.last_seen_at) AS latest_signal_at
             FROM cve_exploit_signal s
             JOIN cve c ON c.cve_id = s.cve_id
        LEFT JOIN cve_exploit_intel ei ON ei.cve_id = c.cve_id
        LEFT JOIN epss_score es ON es.cve_id = c.cve_id
        LEFT JOIN kev k ON k.cve_id = c.cve_id
        LEFT JOIN risk_score rs ON rs.cve_id = c.cve_id
            WHERE s.last_seen_at >= now() - interval '24 hours'
         GROUP BY s.cve_id
         ORDER BY max(${THREAT_SCORE_SQL}) DESC
            LIMIT $1
         ) agg
         JOIN cve c ON c.cve_id = agg.cve_id
    LEFT JOIN cve_exploit_intel ei ON ei.cve_id = agg.cve_id
    LEFT JOIN epss_score es ON es.cve_id = agg.cve_id
    LEFT JOIN kev k ON k.cve_id = agg.cve_id
    LEFT JOIN risk_score rs ON rs.cve_id = agg.cve_id
    LEFT JOIN LATERAL (
          SELECT ea.output_json
            FROM enrichment_ai ea
           WHERE ea.cve_id = agg.cve_id
             AND (ea.output_json->>'_enrich_error') IS DISTINCT FROM 'true'
             AND NOT (
               COALESCE(ea.output_text, '') = 'LLM not configured.'
               OR COALESCE(ea.output_json->>'summary', '') LIKE 'LLM not configured%'
             )
        ORDER BY ea.created_at DESC
           LIMIT 1
         ) ea1 ON true
    LEFT JOIN LATERAL (
          SELECT array_agg(DISTINCT s2.signal_type ORDER BY s2.signal_type) AS types
            FROM cve_exploit_signal s2
           WHERE s2.cve_id = agg.cve_id
             AND s2.last_seen_at >= now() - interval '24 hours'
         ) sigs ON true
    LEFT JOIN LATERAL (
          SELECT vp.vendor, vp.product FROM cve_vendor_product vp
           WHERE vp.cve_id = agg.cve_id ORDER BY vp.vendor_key ASC LIMIT 1
         ) vp ON true
     ORDER BY agg.threat_score DESC`,
      [hotLimit]
    );

    const hotIds = hotRowsR.rows.map((r) => r.cve_id);
    const sourcesByCve = new Map<
      string,
      Array<{ signal_type: string; source: string; title: string | null; url: string | null; last_seen_at: string | null }>
    >();
    if (hotIds.length > 0) {
      const srcR = await this.db.query<{
        cve_id: string;
        signal_type: string;
        source: string;
        title: string | null;
        url: string | null;
        last_seen_at: string | null;
      }>(
        `SELECT cve_id, signal_type, source, title, url,
                to_char(last_seen_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS last_seen_at
           FROM (
             SELECT s.*,
                    row_number() OVER (PARTITION BY s.cve_id ORDER BY s.last_seen_at DESC NULLS LAST) AS rn
               FROM cve_exploit_signal s
              WHERE s.cve_id = ANY($1::text[])
                AND s.last_seen_at >= now() - interval '24 hours'
           ) t
          WHERE rn <= 6
          ORDER BY cve_id, last_seen_at DESC NULLS LAST`,
        [hotIds]
      );
      for (const r of srcR.rows) {
        const cur = sourcesByCve.get(r.cve_id) ?? [];
        cur.push({
          signal_type: r.signal_type,
          source: r.source,
          title: r.title,
          url: r.url,
          last_seen_at: r.last_seen_at
        });
        sourcesByCve.set(r.cve_id, cur);
      }
    }

    const newVckR = await this.db.query<{
      cve_id: string;
      cvss_base: number | null;
      epss: number | null;
      vckev_only: boolean;
    }>(
      `SELECT vk.cve_id, c.cvss_base, es.score AS epss, COALESCE(ei.vckev_only, false) AS vckev_only
         FROM vulncheck_kev vk
         JOIN cve c ON c.cve_id = vk.cve_id
    LEFT JOIN epss_score es ON es.cve_id = vk.cve_id
    LEFT JOIN cve_exploit_intel ei ON ei.cve_id = vk.cve_id
        WHERE vk.date_added >= CURRENT_DATE - 1
     ORDER BY vk.date_added DESC, vk.cve_id ASC
        LIMIT 15`
    );

    const epssR = await this.db.query<{
      cve_id: string;
      epss: number | null;
      epss_delta_7d: number | null;
      cvss_base: number | null;
    }>(
      `SELECT c.cve_id, es.score AS epss, ei.epss_delta_7d, c.cvss_base
         FROM cve_exploit_intel ei
         JOIN cve c ON c.cve_id = ei.cve_id
    LEFT JOIN epss_score es ON es.cve_id = c.cve_id
        WHERE ei.epss_spike = true
          AND EXISTS (
            SELECT 1 FROM cve_exploit_signal s
             WHERE s.cve_id = c.cve_id
               AND s.last_seen_at >= now() - interval '24 hours'
          )
     ORDER BY COALESCE(ei.epss_delta_7d, 0) DESC, COALESCE(es.score, 0) DESC
        LIMIT 10`
    );

    const watchlistR = await this.db.query<{
      cve_id: string;
      threat_score: number;
      vendor: string | null;
      label: string;
    }>(
      `WITH hits AS (
         SELECT s.cve_id,
                max(${THREAT_SCORE_SQL}) AS threat_score,
                max(w.label) AS label
           FROM cve_exploit_signal s
           JOIN cve c ON c.cve_id = s.cve_id
      LEFT JOIN cve_exploit_intel ei ON ei.cve_id = c.cve_id
      LEFT JOIN epss_score es ON es.cve_id = c.cve_id
      LEFT JOIN kev k ON k.cve_id = c.cve_id
      LEFT JOIN risk_score rs ON rs.cve_id = c.cve_id
           JOIN voc_watchlist w ON w.active = true
          WHERE s.last_seen_at >= now() - interval '24 hours'
            AND (
              (w.kind = 'vendor' AND EXISTS (
                SELECT 1 FROM cve_vendor_product vpw
                 WHERE vpw.cve_id = c.cve_id AND vpw.vendor_key = w.value
              ))
              OR (w.kind = 'product' AND EXISTS (
                SELECT 1 FROM cve_vendor_product vpw
                 WHERE vpw.cve_id = c.cve_id AND vpw.product_key_norm = w.value
              ))
              OR (w.kind = 'keyword' AND (
                lower(c.cve_id) LIKE '%' || w.value || '%'
                OR lower(COALESCE(c.raw::text, '')) LIKE '%' || w.value || '%'
              ))
            )
       GROUP BY s.cve_id
       ORDER BY max(${THREAT_SCORE_SQL}) DESC
          LIMIT 12
       )
       SELECT h.cve_id, h.threat_score, h.label,
              (SELECT vp.vendor FROM cve_vendor_product vp WHERE vp.cve_id = h.cve_id LIMIT 1) AS vendor
         FROM hits h`
    );

    let watchlistHits = 0;
    try {
      const wh = await this.db.query<{ n: string }>(
        `SELECT count(DISTINCT s.cve_id)::text AS n
           FROM cve_exploit_signal s
           JOIN cve c ON c.cve_id = s.cve_id
          WHERE s.last_seen_at >= now() - interval '24 hours'
            AND EXISTS (
              SELECT 1 FROM voc_watchlist w WHERE w.active = true AND (
                (w.kind = 'vendor' AND EXISTS (SELECT 1 FROM cve_vendor_product vpw WHERE vpw.cve_id = c.cve_id AND vpw.vendor_key = w.value))
                OR (w.kind = 'product' AND EXISTS (SELECT 1 FROM cve_vendor_product vpw WHERE vpw.cve_id = c.cve_id AND vpw.product_key_norm = w.value))
                OR (w.kind = 'keyword' AND (lower(c.cve_id) LIKE '%' || w.value || '%' OR lower(COALESCE(c.raw::text, '')) LIKE '%' || w.value || '%'))
              )
            )`
      );
      watchlistHits = Number(wh.rows[0]?.n ?? 0);
    } catch {
      watchlistHits = watchlistR.rowCount ?? 0;
    }

    const p = pulseR.rows[0];
    const asStrArray = (v: unknown): string[] => {
      if (!Array.isArray(v)) return [];
      return v.map((x) => String(x)).map((s) => s.trim()).filter(Boolean).slice(0, 8);
    };

    const hotCves: ThreatDigestHotCve[] = hotRowsR.rows.map((r) => ({
      cve_id: r.cve_id,
      threat_score: r.threat_score,
      signal_count: r.signal_count,
      epss: r.epss,
      cvss_base: r.cvss_base,
      risk_score: r.risk_score,
      vckev_only: r.vckev_only,
      epss_spike: r.epss_spike,
      has_poc: r.has_poc,
      has_public_exploit: r.has_public_exploit,
      cisa_kev: r.cisa_kev,
      epss_delta_7d: r.epss_delta_7d,
      vendor: r.vendor,
      product: r.product,
      signal_types: Array.isArray(r.signal_types) ? r.signal_types : [],
      latest_signal_at: r.latest_signal_at,
      summary_ru: r.summary_ru,
      description: r.description,
      cvss_av: r.cvss_av,
      cvss_pr: r.cvss_pr,
      cvss_ui: r.cvss_ui,
      cvss_ac: r.cvss_ac,
      sources: sourcesByCve.get(r.cve_id) ?? []
      ,
      remediation: asStrArray(r.remediation_json),
      next_steps: asStrArray(r.next_steps_json),
      vuln_class: r.vuln_class
    }));

    const criticalEvents: ThreatDigestCriticalEvent[] = hotCves
      .map((h) => {
        const priority = this.pickPriority({
          threat_score: h.threat_score,
          cisa_kev: h.cisa_kev,
          vckev_only: h.vckev_only,
          epss_spike: h.epss_spike,
          has_public_exploit: h.has_public_exploit,
          has_poc: h.has_poc,
          epss: h.epss,
          cvss_base: h.cvss_base
        });
        const { tags, why } = this.buildWhyRu({
          cisa_kev: h.cisa_kev,
          vckev_only: h.vckev_only,
          epss_spike: h.epss_spike,
          has_public_exploit: h.has_public_exploit,
          has_poc: h.has_poc,
          epss: h.epss,
          cvss_base: h.cvss_base
        });
        return {
          cve_id: h.cve_id,
          priority,
          threat_score: h.threat_score,
          epss: h.epss,
          cvss_base: h.cvss_base,
          vendor: h.vendor,
          product: h.product,
          tags,
          why,
          summary_ru: (h.summary_ru ?? null) || (h.description ?? null)
        };
      })
      .sort((a, b) => {
        const p = (x: ThreatDigestCriticalEvent) => (x.priority === "P0" ? 0 : x.priority === "P1" ? 1 : 2);
        return p(a) - p(b) || (b.threat_score - a.threat_score) || a.cve_id.localeCompare(b.cve_id);
      })
      .slice(0, 12);

    const trends = this.summarizeTrendsRu(hotCves);

    return {
      generatedAt: new Date().toISOString(),
      windowHours: 24,
      pulse: {
        signals: Number(p?.signals ?? 0),
        newSignals: Number(p?.new_signals ?? 0),
        updatedSignals: Number(p?.updated_signals ?? 0),
        distinctCves: Number(p?.distinct_cves ?? 0),
        hotCves: Number(p?.hot_cves ?? 0),
        vckevOnly: Number(p?.vckev_only ?? 0),
        epssSpikes: Number(p?.epss_spikes ?? 0),
        cisaKev: Number(p?.cisa_kev ?? 0),
        withPoc: Number(p?.with_poc ?? 0),
        withPublicExploit: Number(p?.with_public_exploit ?? 0),
        watchlistHits,
        newVckev24h: Number(p?.new_vckev_24h ?? 0),
        cvesPublished24h: Number(p?.cves_published_24h ?? 0)
      },
      byType: byTypeR.rows.map((r) => ({ signal_type: r.signal_type, count: Number(r.count) })),
      vendors: vendorR.rows,
      hourly: hourlyR.rows.map((r) => ({ hour: r.hour, count: Number(r.count) })),
      hotCves,
      criticalEvents,
      trends,
      newVckev: newVckR.rows,
      epssSpikeLeaders: epssR.rows,
      watchlistCves: watchlistR.rows
    };
  }
}
