"use client";

import { cn } from "../ui/cn";
import { computeBduPriority, bduRiskScore } from "@/lib/bdu-priority";

export type BduListItem = {
  bduId: string;
  name: string;
  cveIds?: string[];
  linkedCveIds?: string[];
  severity?: string | null;
  severityLevel?: number;
  cvssScore?: number | null;
  identifyDate?: string | null;
  publicationDate?: string | null;
  hasExploit?: boolean;
  hasFix?: boolean;
  fstecUrl?: string;
};

function riskPill(score: number | null) {
  if (score == null)
    return { label: "—", cls: "bg-slate-50 text-muted border-slate-200 dark:bg-white/5 dark:border-white/10" };
  if (score >= 85) return { label: `Критично ${score}`, cls: "bg-danger/15 text-danger border-danger/30" };
  if (score >= 70) return { label: `Высокий ${score}`, cls: "bg-warn/15 text-warn border-warn/30" };
  if (score >= 40) return { label: `Средний ${score}`, cls: "bg-accent/15 text-accent border-accent/30" };
  return { label: `Низкий ${score}`, cls: "bg-ok/15 text-ok border-ok/30" };
}

export function BduCard({
  item,
  selected,
  onSelect,
  triage,
  showCheckbox,
  checked,
  onToggleChecked
}: {
  item: BduListItem;
  selected: boolean;
  onSelect: () => void;
  triage?: "new" | "review" | "done";
  showCheckbox?: boolean;
  checked?: boolean;
  onToggleChecked?: (next: boolean) => void;
}) {
  const risk = bduRiskScore(item);
  const pill = riskPill(risk);
  const pr = computeBduPriority(item);
  const prPill =
    pr.level === "critical"
      ? { label: `Приоритет: крит ${pr.score}`, cls: "border-danger/30 bg-danger/15 text-danger" }
      : pr.level === "high"
        ? { label: `Приоритет: высокий ${pr.score}`, cls: "border-warn/30 bg-warn/15 text-warn" }
        : pr.level === "medium"
          ? { label: `Приоритет: средний ${pr.score}`, cls: "border-accent/30 bg-accent/10 text-fg/80" }
          : { label: `Приоритет: низкий ${pr.score}`, cls: "border-ok/30 bg-ok/10 text-ok" };

  const date = item.publicationDate ?? item.identifyDate;
  const cvss =
    typeof item.cvssScore === "number" && Number.isFinite(item.cvssScore) ? item.cvssScore.toFixed(1) : null;
  const linked = item.linkedCveIds ?? [];
  const registryCves = item.cveIds ?? [];

  const triagePill =
    triage === "done"
      ? { label: "Готово", cls: "border-ok/30 bg-ok/15 text-ok" }
      : triage === "review"
        ? { label: "На разборе", cls: "border-accent/30 bg-accent/10 text-fg/80" }
        : triage === "new"
          ? {
              label: "Новый",
              cls: "border-slate-200 bg-slate-50 text-fg/80 dark:border-white/10 dark:bg-white/5"
            }
          : null;

  const criticalReasons: string[] = [];
  if (item.hasExploit) criticalReasons.push("эксплойт");
  if (item.severityLevel != null && item.severityLevel >= 4) criticalReasons.push("критический (ФСТЭК)");
  if (typeof item.cvssScore === "number" && item.cvssScore >= 9) criticalReasons.push("CVSS≥9.0");

  return (
    <button
      type="button"
      onClick={onSelect}
      className={cn(
        "group w-full rounded-xl border px-4 py-3 text-left transition",
        "bg-gradient-to-br from-slate-50 to-white hover:from-slate-100 hover:to-slate-50/90",
        "dark:from-white/5 dark:to-white/[0.02] dark:hover:from-white/7 dark:hover:to-white/[0.04]",
        selected ? "border-accent/40 shadow-glass" : "border-border"
      )}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <div className="flex min-w-0 flex-wrap items-baseline gap-x-2 gap-y-0.5">
              <span className="text-sm font-semibold tracking-tight">BDU:{item.bduId}</span>
              {linked.length > 0 ? (
                <span className="text-[11px] font-normal text-muted">
                  {linked.map((cve) => (
                    <span key={cve} className="mr-2 inline font-mono text-fg/75 last:mr-0">
                      {cve}
                    </span>
                  ))}
                </span>
              ) : registryCves.length > 0 ? (
                <span className="text-[11px] font-normal text-muted">
                  {registryCves.slice(0, 2).map((cve) => (
                    <span key={cve} className="mr-2 inline font-mono text-fg/75 last:mr-0">
                      {cve}
                    </span>
                  ))}
                  {registryCves.length > 2 ? <span className="text-muted">…</span> : null}
                </span>
              ) : null}
            </div>
            {triagePill ? (
              <span className={cn("rounded-full border px-2 py-0.5 text-[10px]", triagePill.cls)}>{triagePill.label}</span>
            ) : null}
            <span className="rounded-full border border-slate-200 bg-white px-2 py-0.5 text-[10px] text-fg/80 shadow-sm dark:border-white/10 dark:bg-white/5 dark:shadow-none">
              ФСТЭК
            </span>
          </div>
          <div className="mt-0.5 line-clamp-1 text-xs text-fg/80">{item.name}</div>
          <div className="mt-1 text-xs text-muted">
            {date ? (date.includes(".") ? date : new Date(date).toLocaleString()) : "нет даты"}
          </div>
          <div className="mt-2 flex flex-wrap items-center gap-2 text-[11px] text-muted">
            <span className={cn("rounded-full border px-2 py-0.5 tabular-nums", prPill.cls)} title={pr.reasons.join(" • ")}>
              {prPill.label}
            </span>
            <span className="rounded-full border border-slate-200 bg-slate-50 px-2 py-0.5 tabular-nums dark:border-white/10 dark:bg-white/5">
              EPSS <span className="text-fg/80">—</span>
            </span>
            <span className="rounded-full border border-slate-200 bg-slate-50 px-2 py-0.5 tabular-nums dark:border-white/10 dark:bg-white/5">
              CVSS <span className="text-fg/80">{cvss ?? "—"}</span>
            </span>
            {item.hasExploit ? (
              <span className="rounded-full border border-danger/30 bg-danger/15 px-2 py-0.5 text-danger">
                известная эксплуатация
              </span>
            ) : null}
            {item.hasFix ? (
              <span className="rounded-full border border-ok/30 bg-ok/10 px-2 py-0.5 text-ok">есть исправление</span>
            ) : null}
            {criticalReasons.map((r) => (
              <span key={r} className="rounded-full border border-accent/30 bg-accent/10 px-2 py-0.5 text-fg/80">
                {r}
              </span>
            ))}
          </div>
        </div>
        <div
          className={cn(
            "shrink-0 rounded-full border px-2 py-1 text-[11px] font-medium transition group-hover:translate-y-[-1px]",
            pill.cls
          )}
        >
          <div className="flex items-center gap-2">
            {showCheckbox ? (
              <input
                type="checkbox"
                checked={Boolean(checked)}
                onChange={(e) => onToggleChecked?.(e.target.checked)}
                onClick={(e) => e.stopPropagation()}
              />
            ) : null}
            <span>{pill.label}</span>
          </div>
        </div>
      </div>
    </button>
  );
}
