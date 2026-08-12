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
               WHERE action IN (
                 'nvd.watermark', 'nvd.pub_sync', 'nvd.pub_catchup',
                 'nvd.catalog_backfill', 'nvd.catalog_complete'
               )) AS watermark,
             (SELECT COUNT(*)::text FROM cve) AS count
      UNION ALL
      SELECT 'epss',
             (SELECT MAX(ts) FROM audit_log WHERE action IN ('epss.ingest', 'epss.watermark')),
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
      staleHours: staleH,
      sources: rows.rows.map((r) => ({
        source: r.source,
        count: Number(r.count ?? "0"),
        lastActivity: r.watermark?.toISOString() ?? null,
        lagHours: r.watermark ? (now - r.watermark.getTime()) / 3_600_000 : null,
        ok:
          r.watermark != null &&
          (now - r.watermark.getTime()) / 3_600_000 <= staleH &&
          !(r.source === "nvd" && Number(r.count ?? "0") < 1000)
      })),
      issues
    };
  }

  /**
   * Product readiness: when is it safe to use the system after downtime/sync.
   * Visible to all authenticated users.
   */
  async readiness(opts?: {
    queueDepths?: { enrich?: number; score?: number; dlqEnrich?: number; dlqScore?: number };
    jobsRunning?: boolean;
    runningJobs?: Array<{
      kind: string;
      startedAt: string | null;
      expectedSeconds?: number;
    }>;
  }) {
    const recon = await this.reconcile();
    const stale = recon.sources.filter((s) => !s.ok);
    const syncing = Boolean(opts?.jobsRunning);
    // AI queues (ai.enrich / ai.score) are optional — readiness is about NVD/EPSS/BDU/KEV ingest only.
    const dlq =
      (opts?.queueDepths?.dlqEnrich ?? 0) + (opts?.queueDepths?.dlqScore ?? 0);

    let status: "ready" | "syncing" | "stale" | "degraded" = "ready";
    const warnings: string[] = [];
    const blocking: string[] = [...recon.issues];

    if (syncing) {
      status = "syncing";
      warnings.push("Идёт ручная синхронизация / ремонт");
    } else if (stale.length > 0) {
      status = "stale";
    } else if (dlq > 50) {
      status = "degraded";
      warnings.push(`DLQ depth=${dlq}`);
    }

    const ready = status === "ready" || status === "degraded";
    const lagging = stale.map((s) => s.source.toUpperCase()).join("/");
    const progress = this.computeProgress({
      sources: recon.sources,
      staleHours: recon.staleHours ?? 12,
      status,
      runningJobs: opts?.runningJobs ?? []
    });

    const headline =
      status === "ready"
        ? "Можно пользоваться — данные свежие"
        : status === "syncing"
          ? lagging
            ? `Подождите: ${lagging} ещё догоняют · ≈ ${progress.etaLabel}`
            : `Подождите: система ещё догоняет · ≈ ${progress.etaLabel}`
          : status === "stale"
            ? lagging
              ? `Устарело: ${lagging} — запустите ремонт (≈ ${progress.etaLabel} после старта)`
              : `Данные устарели — запустите ремонт (≈ ${progress.etaLabel} после старта)`
            : "Можно работать, но есть деградация (проверьте DLQ)";

    return {
      ready,
      status,
      headline,
      checkedAt: recon.checkedAt,
      staleHours: recon.staleHours,
      sources: recon.sources.map((s) => ({
        ...s,
        progressPercent: progress.bySource[s.source] ?? (s.ok ? 100 : 0)
      })),
      blockingIssues: blocking,
      warnings,
      queues: opts?.queueDepths ?? null,
      jobsRunning: syncing,
      progressPercent: progress.percent,
      etaSeconds: progress.etaSeconds,
      etaLabel: progress.etaLabel,
      etaAt: progress.etaAt,
      phase: progress.phase
    };
  }

  private computeProgress(input: {
    sources: Array<{ source: string; ok: boolean; lagHours: number | null; count: number }>;
    staleHours: number;
    status: "ready" | "syncing" | "stale" | "degraded";
    runningJobs: Array<{ kind: string; startedAt: string | null; expectedSeconds?: number }>;
  }) {
    const weights: Record<string, number> = { nvd: 30, epss: 25, bdu: 25, kev: 20 };
    const expectedByKind: Record<string, number> = {
      epss: 180,
      bdu: 420,
      nvd_hot: 120,
      hot24_score: 90,
      threat_intel: 150
    };
    const expectedBySource: Record<string, number> = {
      nvd: 120,
      epss: 180,
      bdu: 420,
      kev: 150
    };

    const bySource: Record<string, number> = {};
    let weighted = 0;
    let weightSum = 0;

    for (const s of input.sources) {
      const w = weights[s.source] ?? 20;
      weightSum += w;
      let p = 0;
      if (s.ok) {
        p = 100;
      } else if (s.lagHours == null) {
        p = Math.min(40, Math.round((s.count > 0 ? 25 : 5) + Math.min(15, s.count / 10_000)));
      } else {
        // Fresher lag → closer to done; very stale after AFK → low but not zero if data exists
        const ratio = Math.max(0, 1 - s.lagHours / Math.max(input.staleHours * 6, 24));
        p = Math.round(12 + ratio * 70);
        if (s.count > 0) p = Math.max(p, 18);
      }
      bySource[s.source] = Math.max(0, Math.min(100, p));
      weighted += (p / 100) * w;
    }

    let percent = weightSum > 0 ? Math.round((weighted / weightSum) * 100) : 0;

    let etaSeconds = 0;
    const running = input.runningJobs.filter((j) => j.startedAt);
    if (running.length > 0) {
      for (const j of running) {
        const expected = j.expectedSeconds ?? expectedByKind[j.kind] ?? 180;
        const elapsed = Math.max(0, (Date.now() - new Date(j.startedAt!).getTime()) / 1000);
        const rem = Math.max(15, expected - elapsed);
        // If already past expected, assume ~25% of expected still remaining
        etaSeconds += elapsed >= expected ? Math.max(30, expected * 0.25) : rem;
      }
      // Blend source incompleteness into ETA
      for (const s of input.sources) {
        if (!s.ok) etaSeconds += Math.round((expectedBySource[s.source] ?? 120) * 0.35);
      }
      percent = Math.min(96, Math.max(percent, 35));
    } else if (input.status === "stale" || input.status === "syncing") {
      for (const s of input.sources) {
        if (!s.ok) etaSeconds += expectedBySource[s.source] ?? 120;
      }
      if (input.status === "syncing" && etaSeconds === 0) {
        etaSeconds = 60;
      }
      percent = Math.min(input.status === "stale" ? 72 : 94, percent);
    }

    if (input.status === "ready") {
      percent = 100;
      etaSeconds = 0;
    } else if (input.status === "degraded") {
      percent = Math.max(percent, 92);
      etaSeconds = Math.min(etaSeconds || 120, 300);
    } else {
      percent = Math.min(99, Math.max(8, percent));
    }

    const phase =
      input.status === "ready"
        ? "complete"
        : running.length > 0
          ? `job:${running.map((j) => j.kind).join("+")}`
          : input.status === "stale"
            ? "awaiting_repair"
            : "catchup";

    return {
      percent,
      bySource,
      etaSeconds: Math.round(etaSeconds),
      etaLabel: formatEta(etaSeconds, input.status === "ready"),
      etaAt:
        etaSeconds > 0
          ? new Date(Date.now() + etaSeconds * 1000).toISOString()
          : null,
      phase
    };
  }
}

function formatEta(seconds: number, ready: boolean): string {
  if (ready || seconds <= 0) return "готово";
  if (seconds < 60) return `~${Math.max(15, Math.round(seconds))} с`;
  if (seconds < 3600) {
    const m = Math.max(1, Math.round(seconds / 60));
    return `~${m} мин`;
  }
  const h = Math.floor(seconds / 3600);
  const m = Math.round((seconds % 3600) / 60);
  return m > 0 ? `~${h} ч ${m} мин` : `~${h} ч`;
}
