"use client";

import { cn } from "../ui/cn";
import type { VocQueueItem, VocTriageStatus } from "@/lib/voc-api";
import { hasWatchlistHit } from "@/lib/voc-watchlist-client";
import { vocPriorityMeta } from "@/lib/voc-labels";
import { Check, Circle, Clock, Loader2, Target } from "lucide-react";
import { isSlaBreached, slaRemainingLabel, slaTone } from "@/lib/voc-case-client";
import { AssigneeCell, MetaRow } from "./vuln-task-ui";
import { vocChipClass, vocIntelContext } from "@/lib/voc-queue-context";

function sourceTone(s: string) {
  if (s === "bdu") return "border-teal-400/35 bg-teal-500/10 text-teal-800 dark:text-teal-300";
  if (s === "tg") return "border-sky-400/35 bg-sky-500/10 text-sky-800 dark:text-sky-300";
  return "border-indigo-400/30 bg-indigo-500/10 text-indigo-800 dark:text-indigo-300";
}

function sourceLabel(s: string) {
  if (s === "bdu") return "БДУ";
  if (s === "tg") return "TG";
  return "CVE";
}

function statusLabel(s: VocTriageStatus) {
  if (s === "claimed") return "В работе";
  if (s === "done") return "Готово";
  if (s === "dismissed") return "Снято";
  return "Очередь";
}

function statusTone(s: VocTriageStatus) {
  if (s === "claimed") return "border-accent/40 bg-accent/15 text-fg/90";
  if (s === "done") return "border-ok/40 bg-ok/15 text-ok";
  if (s === "dismissed") return "border-border bg-slate-100 text-muted dark:bg-white/10";
  return "border-border bg-slate-100 text-fg/80 dark:bg-white/10";
}

function queueRail(item: VocQueueItem, slaBreached: boolean, watchlistHit: boolean) {
  if (slaBreached) return "before:bg-danger";
  if (item.vocPriority === "p1") return "before:bg-danger";
  if (item.vocPriority === "p2") return "before:bg-warn";
  if (watchlistHit) return "before:bg-warn";
  if (item.status === "claimed") return "before:bg-accent";
  return vocPriorityMeta(item.vocPriority).rail;
}

export function VocQueueRow({
  item,
  active,
  currentUserEmail,
  onSelect,
  onClaim,
  onRelease,
  onDone,
  onReopen,
  pending
}: {
  item: VocQueueItem;
  active: boolean;
  currentUserEmail?: string | null;
  onSelect: () => void;
  onClaim: () => void;
  onRelease: () => void;
  onDone: () => void;
  onReopen: () => void;
  pending?: boolean;
}) {
  const done = item.status === "done" || item.status === "dismissed";
  const claimed = item.status === "claimed";
  const watchlistHit = hasWatchlistHit(item);
  const mine =
    claimed && currentUserEmail && item.claimedByEmail
      ? item.claimedByEmail.toLowerCase() === currentUserEmail.toLowerCase()
      : claimed && !item.claimedByEmail;
  const foreignClaim = claimed && item.claimedByEmail && !mine;
  const hasCase = Boolean(item.caseId);
  const slaBreached = item.slaBreached ?? isSlaBreached(item.slaDueAt);
  const prio = vocPriorityMeta(item.vocPriority);
  const intel = vocIntelContext(item);

  return (
    <div
      role="button"
      tabIndex={0}
      onClick={onSelect}
      onKeyDown={(e) => {
        if (e.key === "Enter") onSelect();
      }}
      className={cn(
        "group relative w-full overflow-hidden rounded-lg border text-left transition",
        "before:absolute before:inset-y-0 before:left-0 before:w-[3px] before:content-['']",
        "bg-white dark:bg-[#0d1524]",
        queueRail(item, slaBreached, watchlistHit),
        active
          ? "border-accent/45 bg-accent/[0.06] shadow-sm ring-1 ring-accent/20"
          : "border-border/90 hover:border-border hover:bg-slate-50/80 dark:hover:bg-white/[0.03]",
        done && "opacity-70",
        pending && "pointer-events-none opacity-90"
      )}
    >
      <div className="flex items-stretch gap-2 px-3 py-2.5 pl-4">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className={cn("rounded-md border px-1.5 py-0.5 text-[10px] font-semibold", prio.badge)}>
              {prio.short}
            </span>
            <span className="font-mono text-[11px] font-semibold tabular-nums text-fg/70">{item.vocScore}</span>
            <span className={cn("rounded border px-1.5 py-0.5 text-[9px] font-semibold uppercase", sourceTone(item.source))}>
              {sourceLabel(item.source)}
            </span>
            {watchlistHit ? (
              <span className="inline-flex items-center gap-0.5 rounded border border-warn/40 bg-warn/10 px-1.5 py-0.5 text-[9px] font-semibold text-warn">
                <Target className="h-3 w-3" />
                WL
              </span>
            ) : null}
            <span className={cn("ml-auto rounded border px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wide", statusTone(item.status))}>
              {pending ? "…" : statusLabel(item.status)}
            </span>
          </div>

          <div className="mt-1.5 line-clamp-2 text-[13px] font-semibold leading-snug tracking-tight text-fg/95">
            {item.title}
          </div>
          {intel ? (
            <>
              <MetaRow vendor={intel.vendor} product={intel.product} className="mt-0.5 text-[11px]" />
              {intel.description ? (
                <div className="mt-1 line-clamp-2 text-[11px] leading-snug text-fg/75">{intel.description}</div>
              ) : null}
            </>
          ) : item.subtitle ? (
            <div className="mt-0.5 line-clamp-2 text-[11px] leading-snug text-muted">{item.subtitle}</div>
          ) : null}

          <div className="mt-2 flex min-w-0 flex-wrap items-center gap-1.5">
            {intel
              ? intel.chips.slice(0, 5).map((chip) => (
                  <span
                    key={chip.key}
                    className={cn("rounded border px-1.5 py-0.5 text-[10px] font-medium", vocChipClass(chip.tone))}
                  >
                    {chip.label}
                  </span>
                ))
              : null}
            {hasCase ? (
              <span
                className={cn(
                  "inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[10px] font-medium tabular-nums",
                  slaTone(item.slaDueAt, slaBreached)
                )}
              >
                <Clock className="h-3 w-3" />
                {slaBreached ? "SLA" : slaRemainingLabel(item.slaDueAt)}
                {(item.linkedRefsCount ?? 0) > 1 ? ` · ${item.linkedRefsCount}` : ""}
              </span>
            ) : (
              <span className="rounded border border-dashed border-border px-1.5 py-0.5 text-[10px] text-muted">
                без кейса
              </span>
            )}
            {intel ? null : item.vocReasons.slice(0, 2).map((r) => (
              <span key={r} className="max-w-[10rem] truncate rounded border border-border/80 px-1.5 py-0.5 text-[10px] text-muted">
                {r}
              </span>
            ))}
          </div>

          <div className="mt-2 flex items-center gap-2 border-t border-border/70 pt-2">
            <AssigneeCell
              name={item.assigneeEmail || item.claimedByEmail}
              emptyLabel={mine ? "Вы" : "Unassigned"}
            />
            {mine ? <span className="text-[10px] font-medium text-accent">ваша</span> : null}
          </div>
        </div>

        <div className="flex shrink-0 flex-col justify-center gap-1">
          {pending ? (
            <Loader2 className="mx-auto h-4 w-4 animate-spin text-muted" />
          ) : !done ? (
            <>
              {item.status === "open" ? (
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    onClaim();
                  }}
                  className="rounded-md border border-accent/40 bg-accent/12 px-2 py-1 text-[10px] font-semibold hover:bg-accent/18"
                >
                  Взять
                </button>
              ) : null}
              {claimed && mine ? (
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    onRelease();
                  }}
                  className="rounded-md border border-border px-2 py-1 text-[10px] text-muted hover:text-fg"
                >
                  Отпустить
                </button>
              ) : null}
              {foreignClaim ? (
                <span className="max-w-[4.5rem] text-center text-[9px] leading-tight text-muted">занято</span>
              ) : (
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    onDone();
                  }}
                  className="inline-flex items-center justify-center gap-0.5 rounded-md border border-ok/35 bg-ok/10 px-2 py-1 text-[10px] text-ok hover:bg-ok/15"
                >
                  <Check className="h-3 w-3" />
                  Готово
                </button>
              )}
            </>
          ) : (
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                onReopen();
              }}
              className="inline-flex items-center gap-0.5 rounded-md border border-border px-2 py-1 text-[10px] text-muted"
            >
              <Circle className="h-3 w-3" />
              Вернуть
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
