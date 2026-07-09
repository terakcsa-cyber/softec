import { Injectable, Logger, OnModuleDestroy, OnModuleInit } from "@nestjs/common";
import { gauge } from "@vuln-intel/shared";
import { DbService } from "./db.service.js";

const reconcileLagGauge = gauge(
  "reconcile_lag_hours",
  "Hours since last ingest activity",
  ["source"]
);

@Injectable()
export class ReconciliationService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(ReconciliationService.name);
  private timer: ReturnType<typeof setInterval> | null = null;

  constructor(private readonly db: DbService) {}

  onModuleInit() {
    if (process.env.RECONCILE_ENABLED?.trim() === "false") return;
    const hours = Math.max(1, Number(process.env.RECONCILE_INTERVAL_HOURS ?? "6"));
    void this.reconcile();
    this.timer = setInterval(() => void this.reconcile(), hours * 3_600_000);
  }

  onModuleDestroy() {
    if (this.timer) clearInterval(this.timer);
  }

  async reconcile() {
    const rows = await this.db.query<{
      source: string;
      watermark: Date | null;
      count: string;
    }>(`
      SELECT 'nvd' AS source,
             (SELECT MAX(ts) FROM audit_log
               WHERE action IN ('nvd.watermark', 'nvd.pub_sync', 'nvd.pub_catchup')) AS watermark,
             (SELECT COUNT(*)::text FROM cve) AS count
      UNION ALL
      SELECT 'epss',
             (SELECT MAX(ts) FROM audit_log WHERE action = 'epss.ingest'),
             (SELECT COUNT(*)::text FROM epss_score)
      UNION ALL
      SELECT 'kev',
             (SELECT MAX(ts) FROM audit_log WHERE action IN ('kev.ingest', 'vulncheck.kev.ingest')),
             (SELECT COUNT(*)::text FROM vulncheck_kev)
      UNION ALL
      SELECT 'bdu',
             (SELECT MAX(ts) FROM audit_log WHERE action = 'bdu.ingest'),
             (SELECT COUNT(*)::text FROM bdu_vuln)
    `);

    const now = Date.now();
    const staleH = Number(process.env.RECONCILE_STALE_HOURS ?? "12");
    const issues: string[] = [];

    for (const row of rows.rows) {
      const count = Number(row.count ?? "0");
      const wm = row.watermark;
      const lagH = wm ? (now - wm.getTime()) / 3_600_000 : null;
      if (lagH != null) {
        reconcileLagGauge.set({ source: row.source }, lagH);
        if (lagH > staleH) {
          issues.push(`${row.source}: last activity ${lagH.toFixed(1)}h ago (>${staleH}h)`);
        }
      } else if (row.source !== "bdu") {
        issues.push(`${row.source}: no ingest activity recorded`);
      }
      if (row.source === "nvd" && count < 1000) {
        issues.push(`nvd: low CVE count (${count})`);
      }
    }

    if (issues.length) {
      this.logger.warn(`Reconciliation: ${issues.join("; ")}`);
    }

    return {
      ok: issues.length === 0,
      checkedAt: new Date().toISOString(),
      sources: rows.rows.map((r) => ({
        source: r.source,
        count: Number(r.count ?? "0"),
        lastActivity: r.watermark?.toISOString() ?? null,
        lagHours: r.watermark ? (now - r.watermark.getTime()) / 3_600_000 : null
      })),
      issues
    };
  }
}
