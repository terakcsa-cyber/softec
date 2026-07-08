"use client";

import { cn } from "../ui/cn";
import type { VocQueueItem, VocTriageStatus } from "@/lib/voc-api";
import { hasWatchlistHit } from "@/lib/voc-watchlist-client";
import { Check, Circle, Clock, Loader2, Target, UserRound } from "lucide-react";
import { isSlaBreached, slaRemainingLabel, slaTone } from "@/lib/voc-case-client";

function priorityTone(p: string): string {
  if (p === "p1") return "border-danger/45 bg-danger/15 text-danger shadow-[0_0_12px_rgba(239,68,68,0.2)]";
  if (p === "p2") return "border-warn/40 bg-warn/12 text-warn";
  if (p === "p3") return "border-accent/35 bg-accent/10 text-fg/90";
  return "border-slate-200/90 bg-slate-50 text-muted dark:border-white/10 dark:bg-white/5";
}

function sourceTone(s: string): string {
  if (s === "bdu") return "border-teal-400/35 bg-teal-500/10 text-teal-700 dark:text-teal-300";
  if (s === "tg") return "border-sky-400/35 bg-sky-500/10 text-sky-700 dark:text-sky-300";
  return "border-indigo-400/30 bg-indigo-500/10 text-indigo-700 dark:text-indigo-300";
}

function sourceLabel(s: string): string {
  if (s === "bdu") return "БДУ";
  if (s === "tg") return "Telegram";
  return "CVE";
}

function statusLabel(s: VocTriageStatus): string {
  if (s === "claimed") return "В работе";
  if (s === "done") return "Готово";
  if (s === "dismissed") return "Снято";
  return "В очереди";
}

function statusTone(s: VocTriageStatus): string {
  if (s === "claimed") return "border-indigo-400/35 bg-indigo-500/12 text-indigo-700 dark:text-indigo-300";
  if (s === "done") return "border-ok/35 bg-ok/12 text-ok";
  if (s === "dismissed") return "border-slate-300 bg-slate-100 text-muted";
  return "border-slate-200/90 text-muted dark:border-white/10";
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

  return (
    <div
      role="button"
      tabIndex={0}
      onClick={onSelect}
      onKeyDown={(e) => {
        if (e.key === "Enter") onSelect();
      }}
      className={cn(
        "group w-full rounded-2xl border p-3 text-left transition",
        "bg-gradient-to-br from-white to-slate-50/80 dark:from-white/[0.05] dark:to-black/25",
        active ? "border-accent/40 ring-2 ring-accent/20 shadow-md" : "border-slate-200/90 dark:border-white/10",
        watchlistHit && "border-amber-400/35 bg-amber-50/50 dark:bg-amber-950/15",
        claimed && !done && "border-indigo-400/30 bg-indigo-50/40 dark:bg-indigo-950/20",
        mine && "ring-1 ring-indigo-400/25",
        done && "opacity-65 saturate-[0.9]",
        done && item.status === "done" && "border-ok/25",
        pending && "pointer-events-none opacity-90"
      )}
    >
      <div className="flex items-start gap-3">
        <span
          className={cn(
            "mt-0.5 shrink-0 rounded-lg border px-2 py-1 font-mono text-[10px] font-bold uppercase tracking-wider",
            priorityTone(item.vocPriority)
          )}
        >
          {item.vocPriority}
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-sm font-semibold tracking-tight text-fg/95">{item.title}</span>
            <span className={cn("rounded-full border px-2 py-0.5 text-[9px] font-semibold uppercase", sourceTone(item.source))}>
              {sourceLabel(item.source)}
            </span>
            {watchlistHit ? (
              <span className="inline-flex items-center gap-0.5 rounded-full border border-amber-400/40 bg-amber-500/12 px-2 py-0.5 text-[9px] font-medium text-amber-800 dark:text-amber-200">
                <Target className="h-3 w-3" />
                WL
              </span>
            ) : null}
            {hasCase ? (
              <span
                className={cn(
                  "inline-flex items-center gap-0.5 rounded-full border px-2 py-0.5 text-[9px] font-medium",
                  slaTone(item.slaDueAt, slaBreached)
                )}
              >
                <Clock className="h-3 w-3" />
                {slaBreached ? "SLA" : slaRemainingLabel(item.slaDueAt)}
                {(item.linkedRefsCount ?? 0) > 1 ? ` · ${item.linkedRefsCount}` : ""}
              </span>
            ) : null}
            <span className={cn("rounded-full border px-2 py-0.5 text-[9px] font-medium", statusTone(item.status))}>
              {pending ? "Сохранение…" : statusLabel(item.status)}
            </span>
            <span className="tabular-nums text-[10px] font-semibold text-fg/75">{item.vocScore}</span>
          </div>
          <div className="mt-1 line-clamp-2 text-[11px] leading-snug text-fg/80">{item.subtitle || "—"}</div>
          <div className="mt-2 flex flex-wrap gap-1">
            {item.vocReasons.slice(0, 4).map((r) => (
              <span
                key={r}
                className="rounded-md border border-accent/20 bg-accent/8 px-1.5 py-0.5 text-[9px] text-fg/80"
              >
                {r}
              </span>
            ))}
          </div>
          {item.claimedByEmail || item.assigneeEmail ? (
            <div className="mt-1.5 flex items-center gap-1 text-[10px] text-muted">
              <UserRound className="h-3 w-3" />
              {mine ? "Вы в работе" : item.assigneeEmail || item.claimedByEmail}
            </div>
          ) : null}
        </div>
        <div className="flex shrink-0 flex-col gap-1">
          {pending ? (
            <div className="flex h-14 items-center justify-center px-2">
              <Loader2 className="h-4 w-4 animate-spin text-indigo-500" />
            </div>
          ) : !done ? (
            <>
              {item.status === "open" ? (
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    onClaim();
                  }}
                  className="rounded-lg border border-indigo-400/40 bg-indigo-500/15 px-2 py-1 text-[10px] font-medium text-indigo-800 hover:bg-indigo-500/25 dark:text-indigo-200"
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
                  className="rounded-lg border border-slate-200 bg-white px-2 py-1 text-[10px] text-muted hover:bg-slate-50 dark:border-white/10 dark:bg-black/30"
                >
                  Отпустить
                </button>
              ) : null}
              {foreignClaim ? (
                <span className="max-w-[5.5rem] rounded-lg border border-slate-200 bg-slate-50 px-2 py-1 text-center text-[9px] leading-tight text-muted dark:border-white/10 dark:bg-black/20">
                  Занято
                </span>
              ) : null}
              {!foreignClaim ? (
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    onDone();
                  }}
                  className="inline-flex items-center gap-1 rounded-lg border border-ok/35 bg-ok/10 px-2 py-1 text-[10px] text-ok hover:bg-ok/15"
                >
                  <Check className="h-3 w-3" />
                  Готово
                </button>
              ) : null}
            </>
          ) : (
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                onReopen();
              }}
              className="inline-flex items-center gap-1 rounded-lg border border-slate-200 bg-white px-2 py-1 text-[10px] text-muted dark:border-white/10 dark:bg-black/30"
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
