"use client";

import { cn } from "../ui/cn";
import { deskDecisionLabel, deskResearch, type DeskRow } from "@/lib/voc-desk";
import { vocChipClass, type VocContextChip } from "@/lib/voc-queue-context";
import { ArrowUpRight } from "lucide-react";

function chipTone(label: string): VocContextChip["tone"] {
  if (/KEV|Exploit|крит/i.test(label)) return "danger";
  if (/PoC|EPSS|CVSS [89]|высокий|нет исправления/i.test(label)) return "warn";
  if (/есть исправление/i.test(label)) return "ok";
  return "muted";
}

export function VocQueueRow({
  row,
  active,
  onSelect,
  onOpenCve,
  onOpenBdu,
  onOpenTg
}: {
  row: DeskRow;
  active: boolean;
  onSelect: () => void;
  onOpenCve?: (cveId: string) => void;
  onOpenBdu?: (bduId: string) => void;
  onOpenTg?: (link: string) => void;
}) {
  const research = deskResearch(row);
  const decision = deskDecisionLabel(row.primary.deskDecision);
  const openPrimary = () => {
    if (research.cveId && onOpenCve) onOpenCve(research.cveId);
    else if (research.bduId && onOpenBdu) onOpenBdu(research.bduId);
    else if (research.tgLink && onOpenTg) onOpenTg(research.tgLink);
  };
  const canOpen = Boolean(
    (research.cveId && onOpenCve) || (research.bduId && onOpenBdu) || (research.tgLink && onOpenTg)
  );

  return (
    <div
      role="button"
      tabIndex={0}
      onClick={onSelect}
      onDoubleClick={(event) => {
        event.preventDefault();
        openPrimary();
      }}
      onKeyDown={(event) => {
        if (event.key === "Enter") {
          event.preventDefault();
          event.stopPropagation();
          openPrimary();
        }
      }}
      className={cn(
        "group relative w-full overflow-hidden rounded-lg border text-left transition",
        "before:absolute before:inset-y-0 before:left-0 before:w-[3px] before:content-['']",
        row.burning ? "before:bg-danger" : row.ours ? "before:bg-warn" : "before:bg-border",
        active
          ? "border-accent/40 bg-accent/[0.06]"
          : "border-border bg-white hover:border-fg/15 hover:bg-slate-50/80 dark:bg-black/20 dark:hover:bg-white/[0.03]"
      )}
    >
      <div className="px-3.5 py-3 pl-4">
        <div className="flex items-start justify-between gap-3">
          <div className="flex min-w-0 flex-wrap items-center gap-1.5">
            {research.cveId ? (
              <IdButton label={research.cveId} onClick={() => onOpenCve?.(research.cveId!)} />
            ) : null}
            {research.bduId ? (
              <IdButton label={research.bduId.startsWith("BDU") ? research.bduId : `BDU:${research.bduId}`} onClick={() => onOpenBdu?.(research.bduId!)} />
            ) : null}
            {!research.cveId && !research.bduId ? (
              <span className="font-mono text-[11px] text-fg/70">{row.ident}</span>
            ) : null}
          </div>
          <span
            className={cn(
              "shrink-0 rounded border px-1.5 py-0.5 text-[10px] font-medium tabular-nums",
              row.when === "просрочен"
                ? "border-danger/30 bg-danger/10 text-danger"
                : decision
                  ? "border-accent/30 bg-accent/10 text-fg/80"
                  : "border-transparent text-muted"
            )}
          >
            {decision || row.when || (row.ours ? "контур" : "очередь")}
          </span>
        </div>

        <div className="mt-1.5 text-[13px] font-semibold leading-snug tracking-tight text-fg/95">{row.product}</div>
        <div className="mt-0.5 text-[11px] font-medium text-fg/70">{row.phrase}</div>
        {row.summary ? (
          <p className="mt-1.5 line-clamp-2 text-[12px] leading-relaxed text-fg/75">{row.summary}</p>
        ) : (
          <p className="mt-1.5 text-[12px] leading-relaxed text-muted">Короткого описания в ленте нет. Откройте карточку.</p>
        )}

        <div className="mt-2 flex items-end justify-between gap-3">
          <div className="flex min-w-0 flex-wrap gap-1">
            {row.evidence.map((chip) => (
              <span key={chip} className={cn("rounded border px-1.5 py-0.5 text-[10px] font-medium", vocChipClass(chipTone(chip)))}>
                {chip}
              </span>
            ))}
          </div>
          {canOpen ? (
            <button
              type="button"
              onClick={(event) => {
                event.stopPropagation();
                openPrimary();
              }}
              className="inline-flex shrink-0 items-center gap-1 rounded-md border border-border bg-white px-2 py-1 text-[11px] font-medium text-fg/85 hover:border-accent/40 hover:text-fg dark:bg-black/30"
            >
              Карточка
              <ArrowUpRight className="h-3 w-3" />
            </button>
          ) : null}
        </div>
      </div>
    </div>
  );
}

function IdButton({ label, onClick }: { label: string; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={(event) => {
        event.stopPropagation();
        onClick();
      }}
      className="rounded border border-border bg-slate-50 px-1.5 py-0.5 font-mono text-[11px] font-medium text-fg/80 hover:border-accent/40 hover:text-accent dark:bg-white/[0.04]"
    >
      {label}
    </button>
  );
}
