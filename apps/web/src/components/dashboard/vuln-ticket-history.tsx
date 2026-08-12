"use client";

import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "@/lib/api-fetch";
import { fetchVocCasesByRef, type VocCaseRow } from "@/lib/voc-case-api";
import { vocCaseStatusLabel } from "@/lib/voc-case-client";
import { cn } from "../ui/cn";

export type VulnTaskHistoryItem = {
  id: string;
  title?: string | null;
  status?: string | null;
  priority_local?: string | null;
  vendor_display?: string | null;
  product_display?: string | null;
  score_final?: number | null;
  created_at?: string | null;
  updated_at?: string | null;
  added_at?: string | null;
};

function fmtDateShort(s?: string | null) {
  if (!s) return "—";
  const d = new Date(s);
  return Number.isFinite(d.getTime()) ? d.toLocaleDateString() : String(s);
}

function taskStatusLabel(status?: string | null): string {
  const s = String(status ?? "").toLowerCase();
  if (s === "in_progress") return "В работе";
  if (s === "closed") return "Закрыта";
  if (s === "new") return "Новая";
  return status ? String(status) : "—";
}

function taskStatusCls(status?: string | null): string {
  const s = String(status ?? "").toLowerCase();
  if (s === "in_progress") return "border-accent/30 bg-accent/10 text-fg/80";
  if (s === "closed") return "border-ok/30 bg-ok/10 text-ok";
  return "border-slate-200 bg-slate-50 text-fg/75 dark:border-white/10 dark:bg-white/5";
}

function caseStatusCls(status: VocCaseRow["status"]): string {
  if (status === "in_progress") return "border-accent/30 bg-accent/10 text-fg/80";
  if (status === "resolved") return "border-ok/30 bg-ok/10 text-ok";
  if (status === "cancelled") return "border-slate-200 bg-slate-50 text-muted dark:border-white/10 dark:bg-white/5";
  return "border-warn/30 bg-warn/10 text-warn";
}

function shortId(id: string): string {
  return id.length > 10 ? `${id.slice(0, 8)}…` : id;
}

export function VulnTicketHistory({
  cveId,
  bduId,
  publishedAt,
  modifiedAt,
  onOpenTask
}: {
  cveId?: string | null;
  bduId?: string | null;
  publishedAt?: string | null;
  modifiedAt?: string | null;
  onOpenTask?: (taskId: string) => void;
}) {
  const taskCveId = cveId?.trim() || null;
  const bduRef = bduId?.trim() || null;

  const tasksQuery = useQuery({
    queryKey: ["vuln-tasks", "by-cve", "history", taskCveId],
    enabled: Boolean(taskCveId),
    queryFn: async () => {
      const res = await apiFetch(`/api/vuln-tasks/by-cve/${encodeURIComponent(String(taskCveId))}`, {
        cache: "no-store"
      });
      if (!res.ok) throw new Error("failed to fetch tasks");
      return (await res.json()) as { items: VulnTaskHistoryItem[] };
    },
    staleTime: 15_000
  });

  const bduCasesQuery = useQuery({
    queryKey: ["voc", "cases", "by-ref", "bdu", bduRef],
    enabled: Boolean(bduRef),
    queryFn: () => fetchVocCasesByRef({ source: "bdu", refId: String(bduRef), limit: 50 }),
    staleTime: 15_000
  });

  const cveCasesQuery = useQuery({
    queryKey: ["voc", "cases", "by-ref", "cve", taskCveId],
    enabled: Boolean(taskCveId),
    queryFn: () => fetchVocCasesByRef({ source: "cve", refId: String(taskCveId), limit: 50 }),
    staleTime: 15_000
  });

  const tasks = tasksQuery.data?.items ?? [];
  const cases = (() => {
    const map = new Map<string, VocCaseRow>();
    for (const c of bduCasesQuery.data ?? []) map.set(c.id, c);
    for (const c of cveCasesQuery.data ?? []) map.set(c.id, c);
    return [...map.values()].sort((a, b) => {
      const ta = new Date(a.updatedAt).getTime();
      const tb = new Date(b.updatedAt).getTime();
      return (Number.isFinite(tb) ? tb : 0) - (Number.isFinite(ta) ? ta : 0);
    });
  })();
  const casesLoading = bduCasesQuery.isLoading || cveCasesQuery.isLoading;
  const casesError = bduCasesQuery.isError || cveCasesQuery.isError;
  const casesEnabled = Boolean(bduRef || taskCveId);

  return (
    <div className="mt-4 space-y-4">
      <div className="rounded-xl border border-border bg-white p-4 shadow-sm dark:bg-black/20 dark:shadow-none">
        <div className="text-sm font-medium">История</div>
        <div className="mt-3 grid grid-cols-1 gap-2 text-sm sm:grid-cols-2">
          <div className="rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 dark:border-white/10 dark:bg-white/5">
            <div className="text-[11px] text-muted">Опубликовано</div>
            <div className="mt-0.5 text-fg/85">{fmtDateShort(publishedAt)}</div>
          </div>
          <div className="rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 dark:border-white/10 dark:bg-white/5">
            <div className="text-[11px] text-muted">Изменено</div>
            <div className="mt-0.5 text-fg/85">{fmtDateShort(modifiedAt)}</div>
          </div>
        </div>
      </div>

      <div className="rounded-xl border border-border bg-white p-4 shadow-sm dark:bg-black/20 dark:shadow-none">
        <div className="flex items-center justify-between gap-3">
          <div className="text-sm font-medium">Тикеты (задачи)</div>
          <div className="text-xs text-muted">
            {!taskCveId
              ? "нужен CVE"
              : tasksQuery.isLoading
                ? "Загрузка…"
                : tasks.length
                  ? `${tasks.length}`
                  : "нет"}
          </div>
        </div>
        {!taskCveId ? (
          <div className="mt-2 text-sm text-muted">
            Задачник привязан к CVE. Для этой записи нет связанного CVE — участие в тикетах недоступно.
          </div>
        ) : tasksQuery.isError ? (
          <div className="mt-2 text-sm text-danger">Не удалось загрузить тикеты.</div>
        ) : tasks.length === 0 && !tasksQuery.isLoading ? (
          <div className="mt-2 text-sm text-muted">Эта уязвимость пока не участвовала в тикетах.</div>
        ) : (
          <div className="mt-3 space-y-2">
            {tasks.map((t) => (
              <div
                key={String(t.id)}
                className="rounded-lg border border-slate-200 bg-slate-50 p-3 text-[12px] dark:border-white/10 dark:bg-white/5"
              >
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <div className="min-w-0">
                    <div className="font-medium text-fg/90">{String(t.title ?? t.id)}</div>
                    <div className="mt-0.5 font-mono text-[10px] text-muted">{shortId(String(t.id))}</div>
                  </div>
                  <span className={cn("inline-flex items-center rounded-full border px-2 py-0.5 text-[11px]", taskStatusCls(t.status))}>
                    {taskStatusLabel(t.status)}
                  </span>
                </div>
                <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1 text-[11px] text-muted">
                  {t.priority_local ? <span>приоритет: {String(t.priority_local)}</span> : null}
                  {typeof t.score_final === "number" ? <span>score: {t.score_final}</span> : null}
                  <span>добавлен: {fmtDateShort(t.added_at ?? t.created_at)}</span>
                  <span>обновлён: {fmtDateShort(t.updated_at)}</span>
                </div>
                {(t.vendor_display || t.product_display) && (
                  <div className="mt-1 text-[11px] text-muted">
                    {[t.vendor_display, t.product_display].filter(Boolean).join(" / ")}
                  </div>
                )}
                {onOpenTask ? (
                  <button
                    type="button"
                    onClick={() => onOpenTask(String(t.id))}
                    className="mt-2 rounded-lg border border-slate-200 bg-white px-2.5 py-1 text-[11px] text-fg/80 hover:bg-slate-50 dark:border-white/10 dark:bg-black/20 dark:hover:bg-black/30"
                  >
                    Открыть тикет →
                  </button>
                ) : null}
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="rounded-xl border border-border bg-white p-4 shadow-sm dark:bg-black/20 dark:shadow-none">
        <div className="flex items-center justify-between gap-3">
          <div className="text-sm font-medium">VOC кейсы</div>
          <div className="text-xs text-muted">
            {!casesEnabled
              ? "—"
              : casesLoading
                ? "Загрузка…"
                : cases.length
                  ? `${cases.length}`
                  : "нет"}
          </div>
        </div>
        {casesError ? (
          <div className="mt-2 text-sm text-danger">Не удалось загрузить кейсы.</div>
        ) : cases.length === 0 && !casesLoading ? (
          <div className="mt-2 text-sm text-muted">Нет VOC кейсов с участием этой уязвимости.</div>
        ) : (
          <div className="mt-3 space-y-2">
            {cases.map((c) => (
              <div
                key={c.id}
                className="rounded-lg border border-slate-200 bg-slate-50 p-3 text-[12px] dark:border-white/10 dark:bg-white/5"
              >
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <div className="min-w-0">
                    <div className="font-medium text-fg/90">{c.title}</div>
                    <div className="mt-0.5 font-mono text-[10px] text-muted">{shortId(c.id)}</div>
                  </div>
                  <span className={cn("inline-flex items-center rounded-full border px-2 py-0.5 text-[11px]", caseStatusCls(c.status))}>
                    {vocCaseStatusLabel(c.status)}
                  </span>
                </div>
                <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1 text-[11px] text-muted">
                  <span>приоритет: {c.vocPriority.toUpperCase()}</span>
                  <span>создан: {fmtDateShort(c.createdAt)}</span>
                  <span>обновлён: {fmtDateShort(c.updatedAt)}</span>
                  {c.assigneeEmail ? <span>исполнитель: {c.assigneeEmail}</span> : null}
                </div>
                {c.taskId && onOpenTask ? (
                  <button
                    type="button"
                    onClick={() => onOpenTask(c.taskId!)}
                    className="mt-2 rounded-lg border border-slate-200 bg-white px-2.5 py-1 text-[11px] text-fg/80 hover:bg-slate-50 dark:border-white/10 dark:bg-black/20 dark:hover:bg-black/30"
                  >
                    Открыть связанный тикет →
                  </button>
                ) : null}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
