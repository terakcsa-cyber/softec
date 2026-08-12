"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, Briefcase, Clock, Loader2, UserRound } from "lucide-react";
import * as Dialog from "@radix-ui/react-dialog";
import { useState } from "react";
import { cn } from "../ui/cn";
import { fetchVocCases, patchVocCase, backfillVocCaseTasks, type VocCaseRow } from "@/lib/voc-case-api";
import { useLiveQueryOptions } from "@/lib/live-refresh";
import { isSlaBreached, slaRemainingLabel, slaTone, vocCaseStatusLabel } from "@/lib/voc-case-client";
import { vocPriorityLabel } from "@/lib/voc-labels";
import { VocVerificationPanel } from "./voc-verification-panel";

export function VocCasesPanel({
  className,
  currentUserEmail,
  onSelectRefKey
}: {
  className?: string;
  currentUserEmail?: string | null;
  onSelectRefKey?: (refKey: string) => void;
}) {
  const queryClient = useQueryClient();
  const liveOpts = useLiveQueryOptions();
  const casesQuery = useQuery({
    queryKey: ["voc", "cases", "active"],
    queryFn: () => fetchVocCases({ status: "active", limit: 80 }),
    ...liveOpts
  });

  const patchMut = useMutation({
    mutationFn: ({ id, assigneeEmail }: { id: string; assigneeEmail: string | null }) =>
      patchVocCase(id, { assigneeEmail }),
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
  const breached = cases.filter((c) => isSlaBreached(c.slaDueAt)).length;
  const missingTasks = cases.filter((c) => !c.taskId).length;
  const [resolveCaseId, setResolveCaseId] = useState<string | null>(null);

  return (
    <div className={cn("rounded-2xl border border-violet-200/70 bg-violet-50/40 p-4 dark:border-violet-900/40 dark:bg-violet-950/20", className)}>
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 text-sm font-semibold text-fg/95">
          <Briefcase className="h-4 w-4 text-violet-500" />
          Кейсы смены
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {missingTasks > 0 ? (
            <button
              type="button"
              disabled={backfillMut.isPending}
              onClick={() => backfillMut.mutate()}
              className="inline-flex items-center gap-1 rounded-lg border border-amber-400/50 bg-amber-500/15 px-2 py-1 text-[10px] font-medium text-amber-900 dark:text-amber-200"
            >
              {backfillMut.isPending ? <Loader2 className="h-3 w-3 animate-spin" /> : null}
              Догнать задачи ({missingTasks})
            </button>
          ) : null}
          <div className="flex items-center gap-2 text-[10px] text-muted">
            <span className="tabular-nums">{cases.length} активных</span>
            {breached > 0 ? (
              <span className="inline-flex items-center gap-0.5 rounded-full border border-danger/35 bg-danger/10 px-2 py-0.5 text-danger">
                <AlertTriangle className="h-3 w-3" />
                {breached} SLA
              </span>
            ) : null}
          </div>
        </div>
      </div>
      {backfillMut.isSuccess ? (
        <p className="mt-1 text-[10px] text-emerald-700 dark:text-emerald-300">
          Догон: создано {backfillMut.data.created} из {backfillMut.data.scanned}
          {backfillMut.data.failed ? ` · ошибок ${backfillMut.data.failed}` : ""}
        </p>
      ) : null}
      {backfillMut.isError ? (
        <p className="mt-1 text-[10px] text-danger">
          {backfillMut.error instanceof Error ? backfillMut.error.message : "Ошибка догона задач"}
        </p>
      ) : null}
      <p className="mt-1 text-[11px] leading-relaxed text-muted">
        Дедуп по CVE/БДУ: повторные сигналы попадают в тот же кейс. SLA: P1 4ч · P2 24ч · P3 72ч · P4 7д.
      </p>

      {casesQuery.isLoading ? (
        <div className="mt-3 flex items-center gap-2 text-[11px] text-muted">
          <Loader2 className="h-3.5 w-3.5 animate-spin" />
          Загрузка кейсов…
        </div>
      ) : cases.length === 0 ? (
        <div className="mt-3 rounded-xl border border-dashed border-violet-300/50 px-3 py-6 text-center text-[11px] text-muted dark:border-violet-800/40">
          Нет открытых кейсов. Создайте из превью события в очереди.
        </div>
      ) : (
        <div className="mt-3 max-h-52 space-y-2 overflow-y-auto pr-1 [scrollbar-width:thin]">
          {cases.map((c) => (
            <CaseRow
              key={c.id}
              row={c}
              currentUserEmail={currentUserEmail}
              pending={patchMut.isPending && patchMut.variables?.id === c.id}
              onAssignMe={() => {
                if (!currentUserEmail) return;
                patchMut.mutate({ id: c.id, assigneeEmail: currentUserEmail });
              }}
              onSelectPrimary={() => onSelectRefKey?.(c.primaryRefKey)}
              onResolve={() => setResolveCaseId(c.id)}
            />
          ))}
        </div>
      )}

      <Dialog.Root open={Boolean(resolveCaseId)} onOpenChange={(v) => (!v ? setResolveCaseId(null) : null)}>
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 z-50 bg-black/40 backdrop-blur-sm" />
          <Dialog.Content className="fixed left-1/2 top-1/2 z-50 w-[min(720px,calc(100vw-24px))] -translate-x-1/2 -translate-y-1/2 rounded-2xl border border-border bg-white p-4 shadow-xl dark:bg-slate-950">
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <Dialog.Title className="text-sm font-semibold">Закрыть кейс</Dialog.Title>
                <Dialog.Description className="mt-0.5 text-[11px] text-muted">
                  Выбери исход и добавь заметки — кейс будет закрыт, а связанная задача (если есть) перейдёт в closed.
                </Dialog.Description>
              </div>
              <Dialog.Close asChild>
                <button
                  type="button"
                  className="rounded-lg border border-slate-200 px-2 py-1 text-[11px] text-muted hover:bg-slate-50 dark:border-white/10 dark:hover:bg-white/5"
                >
                  Закрыть
                </button>
              </Dialog.Close>
            </div>

            {resolveCaseId ? (
              <div className="mt-3">
                <VocVerificationPanel
                  caseId={resolveCaseId}
                  onResolved={() => {
                    setResolveCaseId(null);
                    void queryClient.invalidateQueries({ queryKey: ["voc", "cases"] });
                    void queryClient.invalidateQueries({ queryKey: ["voc", "queue"] });
                  }}
                />
              </div>
            ) : null}
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>
    </div>
  );
}

function CaseRow({
  row,
  currentUserEmail,
  pending,
  onAssignMe,
  onSelectPrimary,
  onResolve
}: {
  row: VocCaseRow;
  currentUserEmail?: string | null;
  pending?: boolean;
  onAssignMe: () => void;
  onSelectPrimary: () => void;
  onResolve: () => void;
}) {
  const breached = isSlaBreached(row.slaDueAt);
  const mine =
    row.assigneeEmail && currentUserEmail
      ? row.assigneeEmail.toLowerCase() === currentUserEmail.toLowerCase()
      : false;

  return (
    <button
      type="button"
      onClick={onSelectPrimary}
      className={cn(
        "w-full rounded-xl border px-3 py-2 text-left transition hover:bg-white/70 dark:hover:bg-black/25",
        breached ? "border-danger/35 bg-danger/5" : "border-violet-200/60 bg-white/60 dark:border-white/10 dark:bg-black/20"
      )}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="truncate font-mono text-[11px] font-semibold">{row.title}</div>
          <div className="mt-1 flex flex-wrap items-center gap-1.5 text-[9px] text-muted">
            <span className="rounded border border-violet-300/40 px-1.5 py-0.5 dark:border-violet-700/40">
              {vocCaseStatusLabel(row.status)}
            </span>
            <span>{vocPriorityLabel(row.vocPriority)}</span>
            {row.refCount > 1 ? <span>· {row.refCount} сигн.</span> : null}
            {row.taskId ? <span>· задача</span> : null}
          </div>
        </div>
        <span className={cn("shrink-0 rounded-lg border px-2 py-0.5 text-[9px] font-medium tabular-nums", slaTone(row.slaDueAt, breached))}>
          <Clock className="mr-0.5 inline h-3 w-3" />
          {slaRemainingLabel(row.slaDueAt)}
        </span>
      </div>
      <div className="mt-1.5 flex items-center justify-between gap-2">
        <div className="flex min-w-0 items-center gap-1 text-[10px] text-muted">
          <UserRound className="h-3 w-3 shrink-0" />
          <span className="truncate">{row.assigneeEmail || "без исполнителя"}</span>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <span
            role="button"
            tabIndex={0}
            onClick={(e) => {
              e.stopPropagation();
              onResolve();
            }}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.stopPropagation();
                onResolve();
              }
            }}
            className="rounded border border-teal-400/35 bg-teal-500/10 px-1.5 py-0.5 text-[9px] text-teal-800 hover:bg-teal-500/15 dark:text-teal-200"
            title="Закрыть кейс"
          >
            Закрыть
          </span>
          {!row.assigneeEmail && currentUserEmail ? (
            <span
              role="button"
              tabIndex={0}
              onClick={(e) => {
                e.stopPropagation();
                if (!pending) onAssignMe();
              }}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.stopPropagation();
                  if (!pending) onAssignMe();
                }
              }}
              className="rounded border border-violet-400/35 px-1.5 py-0.5 text-[9px] text-violet-700 hover:bg-violet-500/10 dark:text-violet-300"
            >
              {pending ? "…" : "На меня"}
            </span>
          ) : mine ? (
            <span className="text-[9px] text-violet-600 dark:text-violet-300">вы</span>
          ) : null}
        </div>
      </div>
    </button>
  );
}
