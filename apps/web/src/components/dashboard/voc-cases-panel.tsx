"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  Briefcase,
  Clock,
  ExternalLink,
  Link2,
  Loader2,
  X
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { cn } from "../ui/cn";
import {
  fetchVocCases,
  patchVocCase,
  backfillVocCaseTasks,
  type VocCaseRow,
  type VocCaseStatus
} from "@/lib/voc-case-api";
import { useLiveQueryOptions } from "@/lib/live-refresh";
import {
  caseIssueKey,
  isSlaBreached,
  slaRemainingLabel,
  slaTone,
  vocCaseStatusMeta
} from "@/lib/voc-case-client";
import { vocPriorityMeta } from "@/lib/voc-labels";
import { parseVocRefKey } from "@/lib/voc-ref-keys";
import { VocVerificationPanel } from "./voc-verification-panel";
import { AssigneeCell } from "./vuln-task-ui";

type CaseFilter = "all" | "mine" | "sla";

export type VocCaseFilter = CaseFilter;

function sourceLabel(source: string) {
  if (source === "bdu") return "БДУ";
  if (source === "tg") return "TG";
  return "CVE";
}

function sourceTone(source: string) {
  if (source === "bdu") return "border-teal-400/35 bg-teal-500/10 text-teal-800 dark:text-teal-300";
  if (source === "tg") return "border-sky-400/35 bg-sky-500/10 text-sky-800 dark:text-sky-300";
  return "border-indigo-400/30 bg-indigo-500/10 text-indigo-800 dark:text-indigo-300";
}

function caseRail(row: VocCaseRow) {
  if (isSlaBreached(row.slaDueAt)) return "before:bg-danger";
  if (row.vocPriority === "p1") return "before:bg-danger";
  if (row.vocPriority === "p2") return "before:bg-warn";
  if (row.status === "in_progress") return "before:bg-accent";
  return vocPriorityMeta(row.vocPriority).rail;
}

function CaseStatusChip({ status, compact }: { status: VocCaseStatus; compact?: boolean }) {
  const m = vocCaseStatusMeta(status);
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 border font-semibold uppercase tracking-wide",
        compact ? "rounded px-1.5 py-0.5 text-[9px]" : "rounded px-2 py-0.5 text-[10px]",
        m.chip
      )}
    >
      <span className={cn("h-1.5 w-1.5 shrink-0 rounded-full", m.dot)} />
      {m.label}
    </span>
  );
}

function PriorityChip({ priority }: { priority: VocCaseRow["vocPriority"] }) {
  const m = vocPriorityMeta(priority);
  return (
    <span className={cn("inline-flex items-center rounded-md border px-1.5 py-0.5 text-[10px] font-semibold", m.badge)}>
      {m.short}
    </span>
  );
}

export function VocCasesPanel({
  className,
  currentUserEmail,
  onSelectRefKey,
  onOpenCve,
  onOpenBdu,
  openCaseId: openCaseIdProp,
  onOpenCaseIdChange,
  initialFilter
}: {
  className?: string;
  currentUserEmail?: string | null;
  onSelectRefKey?: (refKey: string) => void;
  onOpenCve?: (cveId: string) => void;
  onOpenBdu?: (bduId: string) => void;
  openCaseId?: string | null;
  onOpenCaseIdChange?: (id: string | null) => void;
  initialFilter?: CaseFilter;
}) {
  const queryClient = useQueryClient();
  const liveOpts = useLiveQueryOptions();
  const [filter, setFilter] = useState<CaseFilter>(initialFilter ?? "all");
  const [openCaseIdLocal, setOpenCaseIdLocal] = useState<string | null>(null);
  const openCaseId = openCaseIdProp !== undefined ? openCaseIdProp : openCaseIdLocal;
  const setOpenCaseId = (id: string | null) => {
    if (onOpenCaseIdChange) onOpenCaseIdChange(id);
    else setOpenCaseIdLocal(id);
  };

  useEffect(() => {
    if (initialFilter) setFilter(initialFilter);
  }, [initialFilter]);

  const casesQuery = useQuery({
    queryKey: ["voc", "cases", "active"],
    queryFn: () => fetchVocCases({ status: "active", limit: 80 }),
    ...liveOpts
  });

  const patchMut = useMutation({
    mutationFn: ({
      id,
      body
    }: {
      id: string;
      body: { assigneeEmail?: string | null; status?: VocCaseStatus };
    }) => patchVocCase(id, body),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["voc", "cases"] });
      void queryClient.invalidateQueries({ queryKey: ["voc", "queue"] });
    }
  });

  const backfillMut = useMutation({
    mutationFn: () => backfillVocCaseTasks(200),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["voc", "cases"] });
      void queryClient.invalidateQueries({ queryKey: ["voc", "queue"] });
      void queryClient.invalidateQueries({ queryKey: ["vuln-tasks"] });
    }
  });

  const cases = casesQuery.data ?? [];
  const mineCount = cases.filter(
    (c) =>
      Boolean(currentUserEmail) &&
      c.assigneeEmail?.toLowerCase() === currentUserEmail?.toLowerCase()
  ).length;
  const breached = cases.filter((c) => isSlaBreached(c.slaDueAt)).length;
  const missingTasks = cases.filter((c) => !c.taskId).length;

  const visible = useMemo(() => {
    const email = currentUserEmail?.toLowerCase();
    return cases.filter((c) => {
      if (filter === "sla") return isSlaBreached(c.slaDueAt);
      if (filter === "mine") return Boolean(email) && c.assigneeEmail?.toLowerCase() === email;
      return true;
    });
  }, [cases, filter, currentUserEmail]);

  const openRow = cases.find((c) => c.id === openCaseId) ?? null;

  const openRef = (refKey: string) => {
    const parsed = parseVocRefKey(refKey);
    if (parsed?.source === "cve" && onOpenCve) {
      onOpenCve(parsed.refId);
      return;
    }
    if (parsed?.source === "bdu" && onOpenBdu) {
      onOpenBdu(parsed.refId);
      return;
    }
    onSelectRefKey?.(refKey);
  };

  return (
    <div className={cn("min-w-0", className)}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2 text-sm font-semibold tracking-tight text-fg/95">
            <Briefcase className="h-4 w-4 text-accent" />
            Кейсы смены
          </div>
          <p className="mt-1 max-w-2xl text-[11px] leading-relaxed text-muted">
            Рабочая очередь кейсов. Клик открывает карточку: сигналы, SLA, playbook и закрытие.
            Дедуп по CVE/БДУ · SLA P1 4ч · P2 24ч · P3 72ч · P4 7д.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {missingTasks > 0 ? (
            <button
              type="button"
              disabled={backfillMut.isPending}
              onClick={() => backfillMut.mutate()}
              className="inline-flex items-center gap-1 rounded-lg border border-amber-400/50 bg-amber-500/15 px-2.5 py-1.5 text-[11px] font-medium text-amber-900 dark:text-amber-200"
            >
              {backfillMut.isPending ? <Loader2 className="h-3 w-3 animate-spin" /> : null}
              Догнать задачи ({missingTasks})
            </button>
          ) : null}
        </div>
      </div>

      {backfillMut.isSuccess ? (
        <p className="mt-2 text-[11px] text-emerald-700 dark:text-emerald-300">
          Догон: создано {backfillMut.data.created} из {backfillMut.data.scanned}
          {backfillMut.data.failed ? ` · ошибок ${backfillMut.data.failed}` : ""}
        </p>
      ) : null}
      {backfillMut.isError ? (
        <p className="mt-2 text-[11px] text-danger">
          {backfillMut.error instanceof Error ? backfillMut.error.message : "Ошибка догона задач"}
        </p>
      ) : null}

      <div className="mt-3 flex flex-wrap items-center gap-2">
        {(
          [
            ["all", `Все ${cases.length}`],
            ["mine", `Мои ${mineCount}`],
            ["sla", `SLA ${breached}`]
          ] as const
        ).map(([key, label]) => (
          <button
            key={key}
            type="button"
            onClick={() => setFilter(key)}
            className={cn(
              "rounded-full border px-3 py-1 text-[11px] font-medium transition",
              filter === key
                ? key === "sla" && breached > 0
                  ? "border-danger/40 bg-danger/12 text-danger"
                  : "border-accent/40 bg-accent/12 text-fg/95"
                : "border-slate-200 bg-white text-muted hover:text-fg/85 dark:border-white/10 dark:bg-black/25",
              key === "sla" && breached > 0 && filter !== "sla" && "text-danger"
            )}
          >
            {key === "sla" && breached > 0 ? (
              <span className="inline-flex items-center gap-1">
                <AlertTriangle className="h-3 w-3" />
                {label}
              </span>
            ) : (
              label
            )}
          </button>
        ))}
      </div>

      {casesQuery.isLoading ? (
        <div className="mt-4 space-y-2">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="h-[92px] animate-pulse rounded-lg bg-slate-200/60 dark:bg-white/[0.06]" />
          ))}
        </div>
      ) : visible.length === 0 ? (
        <div className="mt-4 rounded-2xl border border-dashed border-slate-300 px-4 py-12 text-center text-sm text-muted dark:border-white/10">
          {cases.length === 0
            ? "Нет открытых кейсов. Создайте из превью события в очереди."
            : "Нет кейсов по выбранному фильтру."}
        </div>
      ) : (
        <div className="mt-4 grid gap-2.5 sm:grid-cols-2 xl:grid-cols-3">
          {visible.map((c) => (
            <CaseCard
              key={c.id}
              row={c}
              active={openCaseId === c.id}
              onOpen={() => setOpenCaseId(c.id)}
            />
          ))}
        </div>
      )}

      {openCaseId && openRow ? (
        <CaseDrawer
          row={openRow}
          currentUserEmail={currentUserEmail}
          pending={patchMut.isPending && patchMut.variables?.id === openRow.id}
          onClose={() => setOpenCaseId(null)}
          onAssignMe={() => {
            if (!currentUserEmail) return;
            patchMut.mutate({ id: openRow.id, body: { assigneeEmail: currentUserEmail, status: "in_progress" } });
          }}
          onUnassign={() => patchMut.mutate({ id: openRow.id, body: { assigneeEmail: null } })}
          onStatus={(status) => patchMut.mutate({ id: openRow.id, body: { status } })}
          onOpenRef={openRef}
          onOpenInQueue={() => {
            onSelectRefKey?.(openRow.primaryRefKey);
            setOpenCaseId(null);
          }}
          onResolved={() => {
            setOpenCaseId(null);
            void queryClient.invalidateQueries({ queryKey: ["voc", "cases"] });
            void queryClient.invalidateQueries({ queryKey: ["voc", "queue"] });
          }}
        />
      ) : null}
    </div>
  );
}

function CaseCard({
  row,
  active,
  onOpen
}: {
  row: VocCaseRow;
  active?: boolean;
  onOpen: () => void;
}) {
  const breached = isSlaBreached(row.slaDueAt);
  const sources = Array.from(new Set(row.refs.map((r) => r.source)));

  return (
    <button
      type="button"
      onClick={onOpen}
      className={cn(
        "relative w-full overflow-hidden rounded-lg border text-left transition",
        "before:absolute before:inset-y-0 before:left-0 before:w-[3px] before:content-['']",
        "bg-white dark:bg-[#0d1524]",
        caseRail(row),
        active
          ? "border-accent/45 bg-accent/[0.06] shadow-sm ring-1 ring-accent/20"
          : "border-border/90 hover:border-border hover:bg-slate-50/80 dark:hover:bg-white/[0.03]"
      )}
    >
      <div className="px-3 py-2.5 pl-4">
        <div className="flex items-center gap-2">
          <span className="font-mono text-[11px] font-semibold tracking-wide text-accent/90">
            {caseIssueKey(row.id)}
          </span>
          <CaseStatusChip status={row.status} compact />
          <div className="ml-auto flex items-center gap-1.5">
            <PriorityChip priority={row.vocPriority} />
          </div>
        </div>
        <div className="mt-2 line-clamp-2 text-[13.5px] font-semibold leading-snug tracking-tight text-fg/95">
          {row.title}
        </div>
        <div className="mt-2 flex flex-wrap items-center gap-1.5">
          {sources.map((s) => (
            <span
              key={s}
              className={cn("rounded border px-1.5 py-0.5 text-[9px] font-semibold uppercase", sourceTone(s))}
            >
              {sourceLabel(s)}
            </span>
          ))}
          {row.refCount > 1 ? (
            <span className="rounded border border-border bg-slate-50 px-1.5 py-0.5 text-[10px] font-medium tabular-nums text-fg/70 dark:bg-white/[0.04]">
              {row.refCount} сигн.
            </span>
          ) : null}
          {row.taskId ? (
            <span className="rounded border border-border px-1.5 py-0.5 text-[10px] text-muted">задача</span>
          ) : null}
        </div>
        <div className="mt-2.5 flex min-w-0 items-center gap-2 border-t border-border/70 pt-2">
          <AssigneeCell name={row.assigneeEmail} emptyLabel="Unassigned" />
          <span
            className={cn(
              "ml-auto inline-flex shrink-0 items-center gap-1 rounded-md border px-1.5 py-0.5 text-[10px] font-medium tabular-nums",
              slaTone(row.slaDueAt, breached)
            )}
          >
            <Clock className="h-3 w-3" />
            {slaRemainingLabel(row.slaDueAt)}
          </span>
        </div>
      </div>
    </button>
  );
}

function CaseDrawer({
  row,
  currentUserEmail,
  pending,
  onClose,
  onAssignMe,
  onUnassign,
  onStatus,
  onOpenRef,
  onOpenInQueue,
  onResolved
}: {
  row: VocCaseRow;
  currentUserEmail?: string | null;
  pending?: boolean;
  onClose: () => void;
  onAssignMe: () => void;
  onUnassign: () => void;
  onStatus: (status: VocCaseStatus) => void;
  onOpenRef: (refKey: string) => void;
  onOpenInQueue: () => void;
  onResolved: () => void;
}) {
  const breached = isSlaBreached(row.slaDueAt);
  const mine =
    Boolean(row.assigneeEmail) &&
    Boolean(currentUserEmail) &&
    row.assigneeEmail!.toLowerCase() === currentUserEmail!.toLowerCase();
  const closed = row.status === "resolved" || row.status === "cancelled";
  const prio = vocPriorityMeta(row.vocPriority);

  return (
    <div className="fixed inset-0 z-[8000]">
      <button type="button" onClick={onClose} className="absolute inset-0 bg-black/25 backdrop-blur-[1px]" title="Закрыть" />
      <aside className="absolute right-0 top-0 flex h-dvh w-[min(580px,96vw)] flex-col border-l border-border bg-white shadow-2xl dark:bg-[#0b1220]">
        <div className="relative flex min-h-0 flex-1 flex-col overflow-y-auto">
          <div className="absolute inset-y-0 left-0 w-[3px] bg-accent/70" aria-hidden />
          <div className="sticky top-0 z-10 border-b border-border bg-white/95 pl-5 pr-4 py-3.5 backdrop-blur dark:bg-[#0b1220]/95">
            <div className="flex items-start gap-3">
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-[12px] font-semibold tracking-wide text-accent">
                    {caseIssueKey(row.id)}
                  </span>
                  <CaseStatusChip status={row.status} compact />
                  <span className={cn("rounded-md border px-1.5 py-0.5 text-[10px] font-semibold", prio.badge)}>
                    {prio.label}
                  </span>
                  <span
                    className={cn(
                      "ml-auto inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[10px] font-medium tabular-nums",
                      slaTone(row.slaDueAt, breached)
                    )}
                  >
                    <Clock className="h-3 w-3" />
                    SLA {slaRemainingLabel(row.slaDueAt)}
                  </span>
                </div>
                <h2 className="mt-2 text-[16px] font-semibold leading-snug tracking-tight text-fg/95">{row.title}</h2>
                <div className="mt-1 text-[12px] text-muted">
                  {row.createdByEmail ? `создал ${row.createdByEmail}` : "кейс смены"}
                  {row.createdAt
                    ? ` · ${new Date(row.createdAt).toLocaleString("ru-RU", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" })}`
                    : ""}
                </div>
              </div>
              <button
                type="button"
                onClick={onClose}
                className="rounded-md border border-border p-1.5 text-muted hover:bg-slate-50 hover:text-fg dark:hover:bg-white/5"
                title="Закрыть"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            </div>

            {!closed ? (
              <div className="mt-3 flex rounded-md border border-border bg-slate-50/80 p-0.5 dark:bg-black/30">
                {(
                  [
                    ["open", "Открыт"],
                    ["in_progress", "В работе"]
                  ] as const
                ).map(([key, label]) => {
                  const activeSeg = row.status === key;
                  return (
                    <button
                      key={key}
                      type="button"
                      disabled={pending || activeSeg}
                      onClick={() => onStatus(key)}
                      className={cn(
                        "min-w-0 flex-1 rounded px-2.5 py-1.5 text-[11px] font-semibold uppercase tracking-wide transition",
                        activeSeg
                          ? vocCaseStatusMeta(key).segmentActive
                          : "border-transparent text-muted hover:bg-white hover:text-fg/85 dark:hover:bg-white/5",
                        pending || activeSeg ? "cursor-default opacity-90" : ""
                      )}
                    >
                      {label}
                    </button>
                  );
                })}
              </div>
            ) : null}
          </div>

          <div className="space-y-4 px-5 py-4 pl-6">
            <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-border/80 bg-slate-50/70 px-3 py-2.5 dark:bg-black/25">
              <AssigneeCell name={row.assigneeEmail} emptyLabel="Unassigned" />
              <div className="flex items-center gap-2">
                {!row.assigneeEmail && currentUserEmail ? (
                  <button
                    type="button"
                    disabled={pending}
                    onClick={onAssignMe}
                    className="rounded-md border border-accent/35 bg-accent/10 px-2.5 py-1 text-[11px] font-medium hover:bg-accent/15 disabled:opacity-50"
                  >
                    {pending ? "…" : "На меня"}
                  </button>
                ) : null}
                {mine ? (
                  <button
                    type="button"
                    disabled={pending}
                    onClick={onUnassign}
                    className="rounded-md border border-border px-2.5 py-1 text-[11px] text-muted hover:text-fg disabled:opacity-50"
                  >
                    Снять
                  </button>
                ) : null}
              </div>
            </div>

            <section>
              <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-wide text-fg/70">Сигналы</div>
              <div className="space-y-1.5">
                {row.refs.map((ref) => {
                  const parsed = parseVocRefKey(ref.refKey);
                  const primary = ref.refKey === row.primaryRefKey;
                  return (
                    <button
                      key={ref.refKey}
                      type="button"
                      onClick={() => onOpenRef(ref.refKey)}
                      className={cn(
                        "flex w-full items-center gap-2 rounded-lg border px-2.5 py-2 text-left transition hover:bg-slate-50 dark:hover:bg-white/[0.04]",
                        primary ? "border-accent/35 bg-accent/[0.06]" : "border-border/80"
                      )}
                    >
                      <span className={cn("rounded border px-1.5 py-0.5 text-[9px] font-semibold uppercase", sourceTone(ref.source))}>
                        {sourceLabel(ref.source)}
                      </span>
                      <span className="min-w-0 truncate font-mono text-[12px] font-medium">{parsed?.refId ?? ref.refId}</span>
                      {primary ? <span className="text-[9px] uppercase tracking-wide text-muted">primary</span> : null}
                      <ExternalLink className="ml-auto h-3.5 w-3.5 shrink-0 text-muted" />
                    </button>
                  );
                })}
              </div>
              <button
                type="button"
                onClick={onOpenInQueue}
                className="mt-2 inline-flex items-center gap-1 text-[11px] text-muted hover:text-fg"
              >
                <Link2 className="h-3 w-3" />
                Найти в очереди VOC
              </button>
            </section>

            {row.taskId ? (
              <div className="rounded-lg border border-border/80 px-3 py-2 text-[11px] text-muted">
                Связанная задача{" "}
                <span className="font-mono font-medium text-fg/85">{row.taskId.slice(0, 8).toUpperCase()}</span>
              </div>
            ) : (
              <div className="rounded-lg border border-dashed border-border px-3 py-2 text-[11px] text-muted">
                Задача ещё не создана — догон из шапки вкладки или из очереди.
              </div>
            )}

            <VocVerificationPanel caseId={row.id} variant="plain" onResolved={onResolved} />
          </div>
        </div>
      </aside>
    </div>
  );
}
