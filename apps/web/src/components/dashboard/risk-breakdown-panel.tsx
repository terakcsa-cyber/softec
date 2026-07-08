"use client";

import { useMemo, useState } from "react";
import { cn } from "../ui/cn";

function fmtPct(p?: number | null) {
  if (typeof p !== "number" || !Number.isFinite(p)) return "—";
  return `${(p * 100).toFixed(2)}%`;
}

function fmtNum(n?: number | null, digits = 1) {
  if (typeof n !== "number" || !Number.isFinite(n)) return "—";
  return n.toFixed(digits);
}

function pill(cls: string) {
  return cn("rounded-full border px-2 py-0.5 text-[10px] font-medium", cls);
}

function clamp(n: number, min: number, max: number) {
  return Math.max(min, Math.min(max, n));
}

function exploitExposureN(input: {
  exploitKnown?: boolean;
  vckevOnly?: boolean;
  vulncheckKev?: boolean;
  hasPublicExploit?: boolean;
  hasPoc?: boolean;
}): number {
  if (input.exploitKnown) return 1;
  if (input.vckevOnly) return 0.92;
  if (input.hasPublicExploit) return 0.88;
  if (input.vulncheckKev) return 0.8;
  if (input.hasPoc) return 0.55;
  return 0;
}

function computeApproxContribV2(input: {
  cvss?: number | null;
  epss?: number | null;
  exploitKnown?: boolean;
  vckevOnly?: boolean;
  vulncheckKev?: boolean;
  epssSpike?: boolean;
  hasPoc?: boolean;
  hasPublicExploit?: boolean;
  mentions?: number | null;
  freshnessDays?: number | null;
}) {
  const cvss = typeof input.cvss === "number" ? input.cvss : undefined;
  const epss = typeof input.epss === "number" ? input.epss : undefined;
  const mentions = typeof input.mentions === "number" ? input.mentions : 0;
  const freshnessDays = typeof input.freshnessDays === "number" ? input.freshnessDays : undefined;

  const cvssN = cvss == null ? 0.35 : clamp(cvss / 10, 0, 1);
  const epssN = epss == null ? 0.15 : clamp(epss, 0, 1);
  const exploitN = exploitExposureN({
    exploitKnown: Boolean(input.exploitKnown),
    vckevOnly: Boolean(input.vckevOnly),
    vulncheckKev: Boolean(input.vulncheckKev),
    hasPublicExploit: Boolean(input.hasPublicExploit),
    hasPoc: Boolean(input.hasPoc)
  });
  const spikeN = input.epssSpike ? 1 : 0;
  const mentionsN = clamp(Math.log10(mentions + 1) / 4, 0, 1);
  const freshnessN = freshnessDays == null ? 0.2 : clamp(Math.exp(-freshnessDays / 180), 0, 1);

  const w = { cvss: 0.36, epss: 0.22, exploit: 0.18, spike: 0.06, freshness: 0.08, mentions: 0.1 };
  const parts = {
    cvss: w.cvss * cvssN,
    epss: w.epss * epssN,
    exploit: w.exploit * exploitN,
    spike: w.spike * spikeN,
    freshness: w.freshness * freshnessN,
    mentions: w.mentions * mentionsN
  };
  const boost =
    (input.exploitKnown || input.vckevOnly) && cvss != null && cvss >= 9
      ? 0.08
      : input.epssSpike && exploitN >= 0.55
        ? 0.05
        : 0;
  const combined = parts.cvss + parts.epss + parts.exploit + parts.spike + parts.freshness + parts.mentions + boost;
  const scoreApprox = Math.round(clamp(combined * 100, 0, 100));

  const items: Array<{
    key: string;
    value01: number;
    label: string;
    cls: string;
    detail: { raw: string; normalized01: number; weight: number; contribution01: number; source: string };
  }> = [
    {
      key: "CVSS",
      value01: parts.cvss,
      label: `${fmtNum(cvss, 1)} → ${(parts.cvss * 100).toFixed(1)}`,
      cls: "bg-emerald-500/70",
      detail: { raw: fmtNum(cvss, 1), normalized01: cvssN, weight: w.cvss, contribution01: parts.cvss, source: "cve.cvss_base" }
    },
    {
      key: "EPSS",
      value01: parts.epss,
      label: `${fmtPct(epss)} → ${(parts.epss * 100).toFixed(1)}`,
      cls: "bg-amber-500/80",
      detail: { raw: fmtPct(epss), normalized01: epssN, weight: w.epss, contribution01: parts.epss, source: "cve.epss" }
    },
    {
      key: "Exploit",
      value01: parts.exploit,
      label: `${exploitN.toFixed(2)} → ${(parts.exploit * 100).toFixed(1)}`,
      cls: "bg-rose-500/80",
      detail: {
        raw: `kev=${Boolean(input.exploitKnown)} vck=${Boolean(input.vckevOnly)} poc=${Boolean(input.hasPoc)}`,
        normalized01: exploitN,
        weight: w.exploit,
        contribution01: parts.exploit,
        source: "cve_exploit_intel"
      }
    },
    {
      key: "Spike",
      value01: parts.spike,
      label: `${input.epssSpike ? "yes" : "no"} → ${(parts.spike * 100).toFixed(1)}`,
      cls: "bg-orange-500/80",
      detail: {
        raw: input.epssSpike ? "true" : "false",
        normalized01: spikeN,
        weight: w.spike,
        contribution01: parts.spike,
        source: "cve_exploit_intel.epss_spike"
      }
    },
    {
      key: "Fresh",
      value01: parts.freshness,
      label: `${freshnessDays == null ? "—" : `${Math.round(freshnessDays)}d`} → ${(parts.freshness * 100).toFixed(1)}`,
      cls: "bg-indigo-500/70",
      detail: {
        raw: freshnessDays == null ? "—" : `${Math.round(freshnessDays)}d`,
        normalized01: freshnessN,
        weight: w.freshness,
        contribution01: parts.freshness,
        source: "cve.risk_factors.freshnessDays"
      }
    },
    {
      key: "Mentions",
      value01: parts.mentions,
      label: `${mentions ? Math.round(mentions) : "—"} → ${(parts.mentions * 100).toFixed(1)}`,
      cls: "bg-slate-400/70",
      detail: {
        raw: mentions ? String(Math.round(mentions)) : "—",
        normalized01: mentionsN,
        weight: w.mentions,
        contribution01: parts.mentions,
        source: "cve.risk_factors.mentions"
      }
    }
  ];
  if (boost > 0) {
    items.push({
      key: "Boost",
      value01: boost,
      label: `+${(boost * 100).toFixed(1)}`,
      cls: "bg-fuchsia-500/70",
      detail: { raw: "rule_v2 boost", normalized01: 1, weight: 1, contribution01: boost, source: "rule_v2 boost" }
    });
  }

  const max = Math.max(...items.map((x) => x.value01), 0.0001);
  return { items, scoreApprox, max };
}

function computeApproxContrib(input: {
  cvss?: number | null;
  epss?: number | null;
  exploitKnown?: boolean;
  mentions?: number | null;
  freshnessDays?: number | null;
}) {
  // Mirrors `computeUnifiedRiskScoreV1` in `@vuln-intel/shared` (rule_v1).
  const cvss = typeof input.cvss === "number" ? input.cvss : undefined;
  const epss = typeof input.epss === "number" ? input.epss : undefined;
  const exploitKnown = Boolean(input.exploitKnown);
  const mentions = typeof input.mentions === "number" ? input.mentions : 0;
  const freshnessDays = typeof input.freshnessDays === "number" ? input.freshnessDays : undefined;

  const cvssN = cvss == null ? 0.35 : clamp(cvss / 10, 0, 1);
  const epssN = epss == null ? 0.15 : clamp(epss, 0, 1);
  const exploitN = exploitKnown ? 1 : 0;
  const mentionsN = clamp(Math.log10(mentions + 1) / 4, 0, 1);
  const freshnessN = freshnessDays == null ? 0.2 : clamp(Math.exp(-freshnessDays / 180), 0, 1);

  const w = { cvss: 0.45, epss: 0.25, exploit: 0.15, freshness: 0.08, mentions: 0.07 };
  const parts = {
    cvss: w.cvss * cvssN,
    epss: w.epss * epssN,
    exploit: w.exploit * exploitN,
    freshness: w.freshness * freshnessN,
    mentions: w.mentions * mentionsN
  };
  const boost = exploitKnown && cvss != null && cvss >= 9 ? 0.08 : 0;
  const combined = parts.cvss + parts.epss + parts.exploit + parts.freshness + parts.mentions + boost;
  const scoreApprox = Math.round(clamp(combined * 100, 0, 100));

  const items: Array<{
    key: "CVSS" | "EPSS" | "KEV" | "Fresh" | "Mentions" | "Boost";
    value01: number;
    label: string;
    cls: string;
    detail: { raw: string; normalized01: number; weight: number; contribution01: number; source: string };
  }> = [
    {
      key: "CVSS",
      value01: parts.cvss,
      label: `${fmtNum(cvss, 1)} → ${(parts.cvss * 100).toFixed(1)}`,
      cls: "bg-emerald-500/70",
      detail: {
        raw: fmtNum(cvss, 1),
        normalized01: cvssN,
        weight: w.cvss,
        contribution01: parts.cvss,
        source: "cve.cvss_base"
      }
    },
    {
      key: "EPSS",
      value01: parts.epss,
      label: `${fmtPct(epss)} → ${(parts.epss * 100).toFixed(1)}`,
      cls: "bg-amber-500/80",
      detail: {
        raw: fmtPct(epss),
        normalized01: epssN,
        weight: w.epss,
        contribution01: parts.epss,
        source: "cve.epss"
      }
    },
    {
      key: "KEV",
      value01: parts.exploit,
      label: `${exploitKnown ? "yes" : "no"} → ${(parts.exploit * 100).toFixed(1)}`,
      cls: "bg-rose-500/80",
      detail: {
        raw: exploitKnown ? "true" : "false",
        normalized01: exploitN,
        weight: w.exploit,
        contribution01: parts.exploit,
        source: "cve.exploit_known"
      }
    },
    {
      key: "Fresh",
      value01: parts.freshness,
      label: `${freshnessDays == null ? "—" : `${Math.round(freshnessDays)}d`} → ${(parts.freshness * 100).toFixed(1)}`,
      cls: "bg-indigo-500/70"
      ,
      detail: {
        raw: freshnessDays == null ? "—" : `${Math.round(freshnessDays)}d`,
        normalized01: freshnessN,
        weight: w.freshness,
        contribution01: parts.freshness,
        source: "cve.risk_factors.freshnessDays"
      }
    },
    {
      key: "Mentions",
      value01: parts.mentions,
      label: `${mentions ? Math.round(mentions) : "—"} → ${(parts.mentions * 100).toFixed(1)}`,
      cls: "bg-slate-400/70"
      ,
      detail: {
        raw: mentions ? String(Math.round(mentions)) : "—",
        normalized01: mentionsN,
        weight: w.mentions,
        contribution01: parts.mentions,
        source: "cve.risk_factors.mentions"
      }
    }
  ];
  if (boost > 0) {
    items.push({
      key: "Boost",
      value01: boost,
      label: `+${(boost * 100).toFixed(1)}`,
      cls: "bg-fuchsia-500/70",
      detail: {
        raw: "exploitKnown && cvss>=9",
        normalized01: 1,
        weight: 1,
        contribution01: boost,
        source: "rule_v1 boost"
      }
    });
  }

  const max = Math.max(...items.map((x) => x.value01), 0.0001);
  return { items, scoreApprox, max };
}

export function RiskBreakdownPanel({ data }: { data: unknown | null }) {
  const d = (data ?? null) as null | { cve?: Record<string, unknown> | null; ai?: unknown };
  const cve = d?.cve ?? null;
  const score = cve?.risk_score as number | null | undefined;
  const factors = cve?.risk_factors ?? null;
  const modelVersion = cve?.model_version ?? null;
  const modelVersionText = modelVersion == null ? "—" : String(modelVersion);

  const epss = cve?.epss as number | null | undefined;
  const cvss = cve?.cvss_base as number | null | undefined;
  const kev = Boolean(cve?.exploit_known);
  const aiReady = Boolean(d?.ai);
  const f = factors && typeof factors === "object" ? (factors as Record<string, unknown>) : null;
  const isV2 = modelVersionText === "rule_v2";
  const contrib = useMemo(() => {
    if (isV2) {
      return computeApproxContribV2({
        cvss,
        epss,
        exploitKnown: kev || Boolean(f?.exploitKnown),
        vckevOnly: Boolean(f?.vckevOnly),
        vulncheckKev: Boolean(f?.vulncheckKev),
        epssSpike: Boolean(f?.epssSpike),
        hasPoc: Boolean(f?.hasPoc),
        hasPublicExploit: Boolean(f?.hasPublicExploit),
        mentions: typeof f?.mentions === "number" ? f.mentions : null,
        freshnessDays: typeof f?.freshnessDays === "number" ? f.freshnessDays : null
      });
    }
    return computeApproxContrib({
      cvss,
      epss,
      exploitKnown: kev,
      mentions: typeof f?.mentions === "number" ? f.mentions : null,
      freshnessDays: typeof f?.freshnessDays === "number" ? f.freshnessDays : null
    });
  }, [cvss, epss, kev, f, isV2]);
  const [openKey, setOpenKey] = useState<string | null>(null);

  const explain = (() => {
    const out: { title: string; detail: string; cls: string }[] = [];
    if (kev) out.push({ title: "KEV", detail: "Known exploited", cls: "border-danger/30 bg-danger/15 text-danger" });
    if (typeof epss === "number" && Number.isFinite(epss)) {
      if (epss >= 0.5) out.push({ title: "EPSS≥0.50", detail: fmtPct(epss), cls: "border-warn/30 bg-warn/15 text-warn" });
      else if (epss >= 0.2)
        out.push({ title: "EPSS≥0.20", detail: fmtPct(epss), cls: "border-accent/30 bg-accent/10 text-fg/80" });
    }
    if (typeof cvss === "number" && Number.isFinite(cvss)) {
      if (cvss >= 9) out.push({ title: "CVSS≥9.0", detail: fmtNum(cvss, 1), cls: "border-warn/30 bg-warn/15 text-warn" });
      else if (cvss >= 8)
        out.push({ title: "CVSS≥8.0", detail: fmtNum(cvss, 1), cls: "border-accent/30 bg-accent/10 text-fg/80" });
    }
    if (aiReady)
      out.push({
        title: "AI",
        detail: "Enriched",
        cls: "border-slate-200 bg-slate-50 text-fg/80 dark:border-white/10 dark:bg-white/5"
      });

    if (f) {
      if (f.vckevOnly) out.push({ title: "VCK-only", detail: "VulnCheck KEV", cls: "border-danger/30 bg-danger/15 text-danger" });
      if (f.epssSpike) out.push({ title: "EPSS spike", detail: "7d", cls: "border-warn/30 bg-warn/15 text-warn" });
      if (f.hasPublicExploit) out.push({ title: "Exploit", detail: "public", cls: "border-rose-500/30 bg-rose-500/15 text-rose-600 dark:text-rose-300" });
      if (f.hasPoc) out.push({ title: "PoC", detail: "public", cls: "border-accent/30 bg-accent/10 text-fg/80" });
      if (typeof f.tgMentions24h === "number" && f.tgMentions24h > 0)
        out.push({ title: "TG 24h", detail: String(Math.round(f.tgMentions24h)), cls: "border-slate-200 bg-slate-50 text-fg/80 dark:border-white/10 dark:bg-white/5" });
      if (typeof f.freshnessDays === "number")
        out.push({
          title: "Freshness",
          detail: `${Math.round(f.freshnessDays)}d`,
          cls: "border-slate-200 bg-slate-50 text-fg/80 dark:border-white/10 dark:bg-white/5"
        });
      if (typeof f.mentions === "number" && f.mentions > 0)
        out.push({
          title: "Mentions",
          detail: String(Math.round(f.mentions)),
          cls: "border-slate-200 bg-slate-50 text-fg/80 dark:border-white/10 dark:bg-white/5"
        });
    }
    return out;
  })();

  return (
    <div className="glass rounded-2xl p-5">
      <div className="flex items-center justify-between">
        <div className="text-sm font-medium">Risk</div>
        <div className="text-xs text-muted">{cve ? "Ready" : "Select a CVE"}</div>
      </div>

      <div className="mt-4 grid grid-cols-12 gap-4">
        <div className="col-span-12 xl:col-span-7">
          <div
            className={cn(
              "rounded-xl border border-border bg-white p-4 shadow-sm dark:bg-black/20 dark:shadow-none",
              score == null && "opacity-70"
            )}
          >
            <div className="text-xs text-muted">Unified risk score (0–100)</div>
            <div className="mt-2 flex items-end justify-between gap-4">
              <div className="text-3xl font-semibold tracking-tight">{score ?? "—"}</div>
              <div className="text-[11px] text-muted">
                Model <span className="text-fg/90">{modelVersionText}</span>
              </div>
            </div>
            <div className="mt-4 grid grid-cols-3 gap-2 text-xs">
              <div className="rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 dark:border-white/10 dark:bg-white/5">
                <div className="text-[11px] text-muted">CVSS</div>
                <div className="mt-0.5 font-medium text-fg/90">{fmtNum(cvss, 1)}</div>
              </div>
              <div className="rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 dark:border-white/10 dark:bg-white/5">
                <div className="text-[11px] text-muted">EPSS</div>
                <div className="mt-0.5 font-medium text-fg/90">{fmtPct(epss)}</div>
              </div>
              <div className="rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 dark:border-white/10 dark:bg-white/5">
                <div className="text-[11px] text-muted">KEV</div>
                <div className="mt-0.5 font-medium text-fg/90">{kev ? "Known exploited" : "—"}</div>
              </div>
            </div>

            <div className="mt-4 rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 dark:border-white/10 dark:bg-black/20">
              <div className="text-[11px] text-muted">Why this score</div>
              <div className="mt-2 flex flex-wrap gap-2">
                {explain.length ? (
                  explain.map((x) => (
                    <span key={`${x.title}:${x.detail}`} className={pill(x.cls)} title={x.detail}>
                      {x.title}
                      <span className="ml-1 opacity-80">{x.detail}</span>
                    </span>
                  ))
                ) : (
                  <span className="text-[11px] text-muted">—</span>
                )}
              </div>
            </div>

            <div className="mt-3 rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 dark:border-white/10 dark:bg-black/20">
              <div className="flex items-center justify-between gap-2">
                <div className="text-[11px] text-muted">Factor contributions (approx)</div>
                <div className="text-[11px] text-muted">
                  approx <span className="font-mono text-fg/80">{contrib.scoreApprox}</span>
                  {typeof score === "number" ? (
                    <span className="ml-2 text-muted/80">
                      (actual <span className="font-mono text-fg/80">{score}</span>)
                    </span>
                  ) : null}
                </div>
              </div>
              <div className="mt-2 space-y-2">
                {contrib.items.map((it) => {
                  const pct = Math.round((it.value01 / contrib.max) * 100);
                  return (
                    <div key={it.key} className="rounded-lg border border-slate-200 bg-white px-2.5 py-2 dark:border-white/10 dark:bg-black/20">
                      <button
                        className="grid w-full grid-cols-[70px_1fr_74px] items-center gap-2 text-left text-[11px]"
                        onClick={() => setOpenKey((k) => (k === it.key ? null : it.key))}
                        title="Click to expand calculation details"
                      >
                        <div className="text-muted">{it.key}</div>
                        <div className="h-2.5 overflow-hidden rounded-full bg-slate-200/80 ring-1 ring-slate-200 dark:bg-white/[0.06] dark:ring-white/[0.06]">
                          <div className={cn("h-full rounded-full", it.cls)} style={{ width: `${pct}%` }} />
                        </div>
                        <div className="truncate text-right font-mono text-[10px] text-fg/80" title={it.label}>
                          {it.label}
                        </div>
                      </button>
                      {openKey === it.key ? (
                        <div className="mt-2 grid gap-1 text-[10px] text-muted">
                          <div>
                            raw: <span className="font-mono text-fg/80">{it.detail.raw}</span> · normalized:{" "}
                            <span className="font-mono text-fg/80">{it.detail.normalized01.toFixed(3)}</span>
                          </div>
                          <div>
                            weight: <span className="font-mono text-fg/80">{it.detail.weight}</span> · contribution:{" "}
                            <span className="font-mono text-fg/80">{(it.detail.contribution01 * 100).toFixed(2)}</span>
                          </div>
                          <div>
                            source: <span className="font-mono text-fg/80">{it.detail.source}</span>
                          </div>
                        </div>
                      ) : null}
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>

        <div className="col-span-12 xl:col-span-5">
          <div className={cn("rounded-xl border border-border bg-white p-4 shadow-sm dark:bg-black/20 dark:shadow-none", !factors && "opacity-70")}>
            <div className="text-xs text-muted">Factors (as stored)</div>
            <pre className="mt-2 max-h-[220px] overflow-auto whitespace-pre-wrap break-words rounded-lg border border-slate-200 bg-slate-50 p-3 text-[11px] text-fg/85 dark:border-white/10 dark:bg-black/30">
              {factors ? JSON.stringify(factors, null, 2) : "—"}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
}

