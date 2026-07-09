"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "@/lib/api-fetch";
import { cn } from "../ui/cn";
import { Loader2, Plus, RefreshCw, Search, Trash2 } from "lucide-react";
import {
  DndContext,
  PointerSensor,
  DragOverlay,
  closestCenter,
  useSensor,
  useSensors,
  type DragEndEvent,
  type DragStartEvent
} from "@dnd-kit/core";
import { useDroppable } from "@dnd-kit/core";
import { SortableContext, useSortable, arrayMove, verticalListSortingStrategy } from "@dnd-kit/sortable";
import { CSS } from "@dnd-kit/utilities";

type TaskListRow = {
  id: string;
  title: string;
  status: string;
  priority_local: string;
  owner: string | null;
  due_date: string | null;
  review_date: string | null;
  vendor_display: string;
  product_display: string;
  score_raw: number;
  score_final: number;
  stats?: { cveCount?: number; kevCount?: number; perimeterHighCount?: number } | null;
  updated_at: string;
};

type TaskDetail = {
  task: (TaskListRow & { evidence?: string | null; decision_notes?: string | null; [k: string]: unknown }) | null;
  cves: Array<{
    cve_id: string;
    exploit_known?: boolean;
    epss?: number;
    cvss_base?: number;
    [k: string]: unknown;
  }>;
  events: Array<{ id?: string; action?: string; actor?: string; ts?: string; meta?: unknown; [k: string]: unknown }>;
};

type TaskStatus = "new" | "in_progress" | "closed";

const TASK_STATUS_COLUMNS: Array<{ key: TaskStatus; title: string }> = [
  { key: "new", title: "Новая" },
  { key: "in_progress", title: "В работе" },
  { key: "closed", title: "Закрыта" }
];

function normalizeUiTaskStatus(st: unknown): TaskStatus {
  const s = String(st || "");
  if (s === "new" || s === "in_progress" || s === "closed") return s;
  if (s === "risk_accepted" || s === "not_applicable") return "closed";
  return s === "needs_info" || s === "fixing" || s === "mitigated" ? "in_progress" : "new";
}

function TaskCardDraggable({
  task,
  active,
  containerId,
  onClick
}: {
  task: TaskListRow;
  active: boolean;
  containerId: string;
  onClick: () => void;
}) {
  const id = `task:${task.id}`;
  const normalizedStatus = normalizeUiTaskStatus(task.status);
  const { attributes, listeners, setNodeRef, transform, transition, isDragging } = useSortable({
    id,
    data: { taskId: task.id, fromStatus: normalizedStatus, containerId }
  });
  const st = statusPill(task.status);
  const cveCount = task.stats?.cveCount ?? null;
  const kevCount = task.stats?.kevCount ?? null;
  const reviewIso = task.review_date ? String(task.review_date) : null;
  const reviewDate = reviewIso ? new Date(reviewIso) : null;
  const reviewOverdue = reviewDate && !Number.isNaN(reviewDate.getTime()) ? reviewDate.getTime() < Date.now() : false;

  const style: React.CSSProperties = {
    transform: CSS.Translate.toString(transform),
    transition,
    opacity: isDragging ? 0.65 : 1
  };

  return (
    <button
      ref={setNodeRef}
      type="button"
      onClick={onClick}
      style={style}
      className={cn(
        "w-full select-none rounded-lg border px-3 py-2 text-left transition",
        active ? "border-accent/40 shadow-glass" : "border-border",
        "bg-white/85 hover:bg-white dark:bg-black/20 dark:hover:bg-black/30",
        isDragging ? "cursor-grabbing" : "cursor-grab"
      )}
      {...attributes}
      {...listeners}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="line-clamp-1 text-[12px] font-semibold leading-4 text-fg/90">{task.title}</div>
          <div className="mt-1 line-clamp-1 text-[11px] leading-4 text-muted">
            {task.vendor_display}
            {task.product_display ? ` / ${task.product_display}` : ""}
          </div>
          <div className="mt-1 flex flex-wrap items-center gap-1 text-[10px] text-muted">
            <span className={cn("rounded-full border px-2 py-0.5", st.cls)}>{st.label}</span>
            <span className={cn("rounded-full border px-2 py-0.5 tabular-nums", scoreCls(task.score_final))}>{task.score_final}</span>
            {cveCount != null ? (
              <span className="rounded-full border border-slate-200 bg-slate-50 px-2 py-0.5 tabular-nums dark:border-white/10 dark:bg-white/5">
                CVE {cveCount}
              </span>
            ) : null}
            {kevCount != null && kevCount > 0 ? (
              <span className="rounded-full border border-danger/30 bg-danger/10 px-2 py-0.5 text-danger">
                KEV {kevCount}
              </span>
            ) : null}
            {task.review_date ? (
              <span className={cn("rounded-full border px-2 py-0.5 tabular-nums", reviewOverdue ? "border-danger/30 bg-danger/10 text-danger" : "border-slate-200 bg-slate-50 dark:border-white/10 dark:bg-white/5")}>
                review {String(task.review_date).slice(0, 10)}
              </span>
            ) : null}
          </div>
        </div>
        <div className="shrink-0 text-[10px] text-muted">{task.updated_at ? new Date(task.updated_at).toLocaleDateString() : "—"}</div>
      </div>
    </button>
  );
}

function TaskCardGhost({ task }: { task: TaskListRow }) {
  const st = statusPill(task.status);
  return (
    <div className="w-[320px] rounded-xl border border-accent/25 bg-white/95 p-3 shadow-xl dark:border-accent/25 dark:bg-black/80">
      <div className="line-clamp-1 text-[12px] font-semibold leading-4 text-fg/90">{task.title}</div>
      <div className="mt-1 line-clamp-1 text-[11px] leading-4 text-muted">
        {task.vendor_display}
        {task.product_display ? ` / ${task.product_display}` : ""}
      </div>
      <div className="mt-2 flex flex-wrap items-center gap-1 text-[10px] text-muted">
        <span className={cn("rounded-full border px-2 py-0.5", st.cls)}>{st.label}</span>
        <span className={cn("rounded-full border px-2 py-0.5 tabular-nums", scoreCls(task.score_final))}>{task.score_final}</span>
      </div>
    </div>
  );
}

function BoardColumn({
  colKey,
  title,
  count,
  wip,
  items,
  dragging,
  children
}: {
  colKey: string;
  title: string;
  count: number;
  wip?: number | null;
  items: string[];
  dragging?: boolean;
  children: React.ReactNode;
}) {
  const id = `col:${colKey}`;
  const { setNodeRef, isOver } = useDroppable({ id, data: { status: colKey } });
  return (
    <div
      ref={setNodeRef}
      className={cn(
        "w-[320px] shrink-0 rounded-xl border",
        "border-slate-200 bg-slate-50 dark:border-white/10 dark:bg-white/5",
        "flex max-h-[620px] flex-col overflow-hidden",
        isOver ? "ring-2 ring-accent/30" : "",
        dragging ? "transition-[box-shadow,transform] duration-150" : ""
      )}
    >
      <div
        className={cn(
          "sticky top-0 z-10 flex items-center justify-between gap-2 border-b px-3 py-2 backdrop-blur",
          "border-slate-200/70 bg-slate-50/85 dark:border-white/10 dark:bg-black/30"
        )}
      >
        <div className="text-[11px] font-medium text-fg/85">{title}</div>
        <div className="flex items-center gap-2 text-[11px] tabular-nums">
          {typeof wip === "number" ? (
            <span
              className={cn(
                "rounded-full border px-2 py-0.5 text-[10px]",
                count > wip ? "border-danger/30 bg-danger/10 text-danger" : "border-slate-200 bg-white text-muted dark:border-white/10 dark:bg-black/20"
              )}
              title="WIP limit"
            >
              {count}/{wip}
            </span>
          ) : null}
          <span className="text-muted">{count}</span>
        </div>
      </div>
      <div className={cn("flex-1 overflow-auto px-3 py-2 pr-2", isOver ? "bg-accent/5" : "")}>
        <SortableContext items={items} strategy={verticalListSortingStrategy}>
          <div className="space-y-2">
            {count === 0 ? (
              <div className={cn("rounded-xl border border-dashed px-3 py-6 text-center text-[11px] text-muted", isOver ? "border-accent/40 bg-accent/10" : "border-slate-200 bg-white/50 dark:border-white/10 dark:bg-black/10")}>
                {dragging ? "Перетащи карточку сюда" : "Пусто"}
              </div>
            ) : null}
            {children}
          </div>
        </SortableContext>
      </div>
    </div>
  );
}

function statusPill(st: string) {
  const s = normalizeUiTaskStatus(st);
  if (s === "in_progress") return { label: "В работе", cls: "border-accent/30 bg-accent/10 text-fg/80" };
  if (s === "closed") return { label: "Закрыта", cls: "border-ok/30 bg-ok/10 text-ok" };
  return { label: "Новая", cls: "border-slate-200 bg-slate-50 text-fg/75 dark:border-white/10 dark:bg-white/5" };
}

function scoreCls(n: number) {
  if (n >= 85) return "border-danger/30 bg-danger/10 text-danger";
  if (n >= 70) return "border-warn/30 bg-warn/10 text-warn";
  if (n >= 40) return "border-accent/30 bg-accent/10 text-fg/80";
  return "border-ok/30 bg-ok/10 text-ok";
}

export function VulnTaskPanel({
  vendorsHint,
  onOpenCve,
  selectedTaskId,
  onSelectTaskId
}: {
  vendorsHint?: { vendors: { vendor: string; count: number }[]; products: { vendor: string; product: string; count: number }[] } | null;
  onOpenCve?: (cveId: string) => void;
  selectedTaskId?: string | null;
  onSelectTaskId?: (taskId: string | null) => void;
}) {
  type DragTaskData = { taskId?: string; fromStatus?: string; containerId?: string };
  const [q, setQ] = useState("");
  const [status, setStatus] = useState<string>(""); // empty = all
  const [selected, setSelected] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [viewMode, setViewMode] = useState<"list" | "board">("board");
  const [listSort, setListSort] = useState<"score" | "updated" | "title">("score");
  const [listSortDir, setListSortDir] = useState<"desc" | "asc">("desc");
  const [quickMine, setQuickMine] = useState(false);
  const [quickKevOnly, setQuickKevOnly] = useState(false);
  const [quickNeedsReview, setQuickNeedsReview] = useState(false);
  const [quickMinScore, setQuickMinScore] = useState<number | null>(null);
  const [boardGroupBy, setBoardGroupBy] = useState<"none" | "vendor" | "owner">("none");

  const [optimisticStatus, setOptimisticStatus] = useState<Record<string, string>>({});
  const [draggingTaskId, setDraggingTaskId] = useState<string | null>(null);
  const [boardOrder, setBoardOrder] = useState<Record<string, string[]>>({});

  const listQuery = useQuery({
    queryKey: ["vuln-tasks", "list", q, status],
    queryFn: async () => {
      const url = new URL(`/api/vuln-tasks`, window.location.origin);
      if (q.trim()) url.searchParams.set("q", q.trim());
      if (status) url.searchParams.set("status", status);
      url.searchParams.set("limit", "200");
      const res = await apiFetch(url.toString(), { cache: "no-store" });
      if (!res.ok) throw new Error(`Failed to fetch tasks (${res.status})`);
      return (await res.json()) as { items: TaskListRow[] };
    },
    staleTime: 15_000
  });

  const detailQuery = useQuery({
    queryKey: ["vuln-tasks", "detail", selected],
    enabled: Boolean(selected),
    queryFn: async () => {
      const res = await apiFetch(`/api/vuln-tasks/${encodeURIComponent(selected!)}`, { cache: "no-store" });
      if (!res.ok) throw new Error(`Failed to fetch task (${res.status})`);
      return (await res.json()) as TaskDetail;
    }
  });

  const items = useMemo(() => listQuery.data?.items ?? [], [listQuery.data?.items]);
  const draggingTask = useMemo(() => {
    if (!draggingTaskId) return null;
    return items.find((t) => t.id === draggingTaskId) ?? null;
  }, [draggingTaskId, items]);
  const listContainerRef = useRef<HTMLDivElement | null>(null);
  const listRowRefs = useRef<Record<string, HTMLDivElement | null>>({});
  const [listPicked, setListPicked] = useState<Record<string, boolean>>({});
  const lastPickIdRef = useRef<string | null>(null);
  const [bulkOwner, setBulkOwner] = useState<string>("");
  const listItems = useMemo(() => {
    const arr = items.filter((t) => {
      if (quickKevOnly && !((t.stats?.kevCount ?? 0) > 0)) return false;
      if (quickMinScore != null && Number(t.score_final ?? 0) < quickMinScore) return false;
      if (quickNeedsReview) {
        const iso = t.review_date ? String(t.review_date) : "";
        if (!iso) return true;
        const d = new Date(iso);
        if (Number.isNaN(d.getTime())) return true;
        if (d.getTime() < Date.now()) return true;
        return false;
      }
      if (quickMine) {
        const me = (typeof window !== "undefined" ? (localStorage.getItem("vip:userEmail") ?? "") : "").trim().toLowerCase();
        if (!me || !t.owner) return false;
        return String(t.owner).trim().toLowerCase().includes(me.split("@")[0] || me);
      }
      return true;
    });
    const getUpdated = (t: TaskListRow) => (t.updated_at ? new Date(t.updated_at).getTime() : 0);
    const getTitle = (t: TaskListRow) => String(t.title || "").toLowerCase();
    arr.sort((a, b) => {
      let x = 0;
      if (listSort === "score") x = (a.score_final ?? 0) - (b.score_final ?? 0);
      else if (listSort === "updated") x = getUpdated(a) - getUpdated(b);
      else x = getTitle(a).localeCompare(getTitle(b));
      return listSortDir === "asc" ? x : -x;
    });
    return arr;
  }, [items, listSort, listSortDir, quickKevOnly, quickMinScore, quickNeedsReview, quickMine]);
  const taskStats = useMemo(() => {
    const counts: Record<TaskStatus, number> = { new: 0, in_progress: 0, closed: 0 };
    let kev = 0;
    let high = 0;
    for (const t of items) {
      counts[normalizeUiTaskStatus(t.status)] += 1;
      if ((t.stats?.kevCount ?? 0) > 0) kev += 1;
      if (Number(t.score_final ?? 0) >= 70) high += 1;
    }
    return { total: items.length, ...counts, kev, high };
  }, [items]);
  const pickedIds = useMemo(() => Object.keys(listPicked).filter((id) => listPicked[id]), [listPicked]);
  const pickedCount = pickedIds.length;
  const clearPicked = () => setListPicked({});
  const togglePick = (id: string, next?: boolean) => {
    setListPicked((m) => {
      const v = next ?? !m[id];
      if (!v) {
        const n = { ...m };
        delete n[id];
        return n;
      }
      return { ...m, [id]: true };
    });
  };
  const pickRange = (fromId: string, toId: string) => {
    const ids = listItems.map((t) => t.id);
    const a = ids.indexOf(fromId);
    const b = ids.indexOf(toId);
    if (a < 0 || b < 0) return;
    const [lo, hi] = a < b ? [a, b] : [b, a];
    const slice = ids.slice(lo, hi + 1);
    setListPicked((m) => {
      const n = { ...m };
      for (const id of slice) n[id] = true;
      return n;
    });
  };
  const selectAllVisible = () => {
    const ids = listItems.map((t) => t.id);
    setListPicked((m) => {
      const n: Record<string, boolean> = { ...m };
      for (const id of ids) n[id] = true;
      return n;
    });
  };
  const selectedTaskInList = useMemo(() => (selected ? listItems.find((t) => t.id === selected) ?? null : null), [selected, listItems]);
  const scrollToSelected = () => {
    if (!selected) return;
    listRowRefs.current[selected]?.scrollIntoView({ block: "nearest" });
  };
  const active = detailQuery.data?.task ?? null;
  const activeCves = detailQuery.data?.cves ?? [];
  const activeEvents = detailQuery.data?.events ?? [];
  useEffect(() => {
    if (selectedTaskId === undefined) return;
    setSelected(selectedTaskId);
  }, [selectedTaskId]);

  useEffect(() => {
    setAddOpen(false);
    setAddPicked({});
    setAddQ("");
  }, [selected]);

  const vendorOptions = useMemo(() => {
    const v = vendorsHint?.vendors ?? [];
    return v.slice(0, 80);
  }, [vendorsHint]);

  const [newVendor, setNewVendor] = useState<string>("");
  const productOptions = useMemo(() => {
    const p = vendorsHint?.products ?? [];
    const pickVendor = newVendor.trim().toLowerCase();
    if (!pickVendor) return [];
    return p.filter((x) => x.vendor.toLowerCase() === pickVendor).slice(0, 120);
  }, [vendorsHint, newVendor]);
  const [newProduct, setNewProduct] = useState<string>("");
  const [newTitle, setNewTitle] = useState<string>("");
  const [saveBusy, setSaveBusy] = useState(false);
  const [saveErr, setSaveErr] = useState<string | null>(null);
  const [rightTab, setRightTab] = useState<"cves" | "fields" | "events">("cves");

  useEffect(() => {
    try {
      const v = window.localStorage.getItem("vip:vulnTask:rightTab");
      if (v === "cves" || v === "fields" || v === "events") setRightTab(v);
    } catch {
      // localStorage может быть недоступен (private mode / policy)
    }
  }, []);

  useEffect(() => {
    try {
      window.localStorage.setItem("vip:vulnTask:rightTab", rightTab);
    } catch {
      // localStorage может быть недоступен (private mode / policy)
    }
  }, [rightTab]);

  // Keep form fields readable even if user hasn't blurred yet (status validation needs them).
  const reviewDateRef = useRef<HTMLInputElement | null>(null);
  const decisionRef = useRef<HTMLInputElement | null>(null);
  const decisionNotesRef = useRef<HTMLTextAreaElement | null>(null);
  const evidenceRef = useRef<HTMLTextAreaElement | null>(null);

  const readPatchFieldsForValidation = useCallback(
    (nextStatus: string) => {
      const patch: Record<string, unknown> = { status: nextStatus };

      const reviewDate = reviewDateRef.current?.value?.trim() ?? "";
      const decision = decisionRef.current?.value?.trim() ?? "";
      const decisionNotes = decisionNotesRef.current?.value?.trim() ?? "";
      const evidence = evidenceRef.current?.value?.trim() ?? "";

      // Always include the latest values if present (so status change won't race with onBlur).
      if (reviewDate) patch.reviewDate = new Date(reviewDate).toISOString();
      if (decision) patch.decision = decision;
      if (decisionNotes) patch.decisionNotes = decisionNotes;
      if (evidence) patch.evidence = evidence;

      return patch;
    },
    [reviewDateRef, decisionRef, decisionNotesRef, evidenceRef]
  );

  const [addOpen, setAddOpen] = useState(false);
  const [addQ, setAddQ] = useState("");
  const [addPicked, setAddPicked] = useState<Record<string, true>>({});

  const cveSearchQuery = useQuery({
    queryKey: ["vuln-tasks", "cve-search", addQ],
    enabled: addOpen && addQ.trim().length >= 3,
    queryFn: async () => {
      const url = new URL(`/api/cves`, window.location.origin);
      url.searchParams.set("q", addQ.trim());
      url.searchParams.set("limit", "50");
      url.searchParams.set("view", "latest");
      url.searchParams.set("sort", "rank");
      const res = await apiFetch(url.toString(), { cache: "no-store" });
      if (!res.ok) throw new Error(`search failed (${res.status})`);
      return (await res.json()) as { items: Array<Record<string, unknown>> };
    },
    staleTime: 10_000
  });

  const createTask = useCallback(async () => {
    const vendorDisplay = newVendor.trim();
    const productDisplay = newProduct.trim();
    if (!vendorDisplay) return;
    const vendorKey = vendorDisplay.toLowerCase();
    const productKeyNorm = productDisplay ? productDisplay.toLowerCase().replace(/\s+/g, "_") : "";
    const title = newTitle.trim() || `${vendorDisplay}${productDisplay ? ` / ${productDisplay}` : ""} — кампания по уязвимостям`;
    const res = await apiFetch(`/api/vuln-tasks`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        title,
        vendorKey,
        vendorDisplay,
        productKeyNorm,
        productDisplay,
        cveIds: []
      })
    });
    if (!res.ok) throw new Error("create failed");
    const j = (await res.json()) as unknown;
    setCreateOpen(false);
    setNewTitle("");
    setNewProduct("");
    // Keep vendor selection for fast batching
    await listQuery.refetch();
    if (j && typeof j === "object" && !Array.isArray(j) && "id" in j) {
      const id = (j as Record<string, unknown>).id;
      if (typeof id === "string" && id) setSelected(id);
    }
  }, [newVendor, newProduct, newTitle, listQuery]);

  const savePatch = useCallback(async (patch: Record<string, unknown>) => {
    if (!selected || saveBusy) return;
    setSaveBusy(true);
    setSaveErr(null);
    try {
      const res = await apiFetch(`/api/vuln-tasks/${encodeURIComponent(selected)}`, {
        method: "PATCH",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(patch)
      });
      if (!res.ok) {
        const txt = await res.text().catch(() => "");
        throw new Error(txt || `save failed (${res.status})`);
      }
      await detailQuery.refetch();
      await listQuery.refetch();
    } catch (e) {
      setSaveErr(e instanceof Error ? e.message : String(e));
    } finally {
      setSaveBusy(false);
    }
  }, [selected, saveBusy, detailQuery, listQuery]);

  const addCves = useCallback(async () => {
    if (!selected) return;
    const ids = Object.keys(addPicked);
    if (ids.length === 0) return;
    const res = await apiFetch(`/api/vuln-tasks/${encodeURIComponent(selected)}/cves`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ cveIds: ids })
    });
    if (!res.ok) throw new Error("add cves failed");
    setAddPicked({});
    setAddQ("");
    setAddOpen(false);
    await detailQuery.refetch();
    await listQuery.refetch();
  }, [selected, addPicked, detailQuery, listQuery]);

  const removeCve = useCallback(async (cveId: string) => {
    if (!selected) return;
    const res = await apiFetch(
      `/api/vuln-tasks/${encodeURIComponent(selected)}/cves/${encodeURIComponent(cveId)}/remove`,
      { method: "POST" }
    );
    if (!res.ok) throw new Error("remove failed");
    await detailQuery.refetch();
    await listQuery.refetch();
  }, [selected, detailQuery, listQuery]);

  const refresh = useCallback(async () => {
    await listQuery.refetch();
    if (selected) await detailQuery.refetch();
  }, [listQuery, selected, detailQuery]);

  useEffect(() => {
    try {
      const raw = localStorage.getItem("vip:vulnTasks:boardOrder");
      if (raw) setBoardOrder(JSON.parse(raw));
    } catch {
      // ignore
    }
  }, []);
  useEffect(() => {
    try {
      localStorage.setItem("vip:vulnTasks:boardOrder", JSON.stringify(boardOrder));
    } catch {
      // ignore
    }
  }, [boardOrder]);

  const patchTask = useCallback(
    async (taskId: string, patch: Record<string, unknown>) => {
      setSaveBusy(true);
      setSaveErr(null);
      try {
        const res = await apiFetch(`/api/vuln-tasks/${encodeURIComponent(taskId)}`, {
          method: "PATCH",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(patch)
        });
        if (!res.ok) {
          const txt = await res.text().catch(() => "");
          try {
            const j = JSON.parse(txt) as { message?: string; error?: string };
            const msg = j?.message ? String(j.message) : txt;
            throw new Error(msg || `save failed (${res.status})`);
          } catch {
            throw new Error(txt || `save failed (${res.status})`);
          }
        }
        await listQuery.refetch();
        if (selected === taskId) await detailQuery.refetch();
      } catch (e) {
        setSaveErr(e instanceof Error ? e.message : String(e));
        throw e;
      } finally {
        setSaveBusy(false);
      }
    },
    [detailQuery, listQuery, selected]
  );

  const bulkPatch = useCallback(
    async (patch: Record<string, unknown>) => {
      const ids = pickedIds.length ? pickedIds : selected ? [selected] : [];
      if (!ids.length) return;
      setSaveErr(null);
      setSaveBusy(true);
      try {
        const results = await Promise.allSettled(ids.map((id) => patchTask(id, patch)));
        const failed = results.filter((r) => r.status === "rejected") as PromiseRejectedResult[];
        if (failed.length) {
          const msg = failed[0]?.reason instanceof Error ? failed[0].reason.message : String(failed[0]?.reason ?? "Bulk patch failed");
          setSaveErr(`Не удалось обновить ${failed.length}/${ids.length}. ${msg}`);
        } else {
          clearPicked();
          await refresh();
        }
      } finally {
        setSaveBusy(false);
      }
    },
    [pickedIds, selected, patchTask, refresh]
  );

  const columns = useMemo(() => {
    const by: Record<string, TaskListRow[]> = {};
    const withOptimistic = items.map((t) => {
      const st = optimisticStatus[t.id];
      return st ? ({ ...t, status: st } as TaskListRow) : t;
    });
    const filtered = withOptimistic.filter((t) => {
      if (quickKevOnly && !((t.stats?.kevCount ?? 0) > 0)) return false;
      if (quickMinScore != null && Number(t.score_final ?? 0) < quickMinScore) return false;
      if (quickNeedsReview) {
        const iso = t.review_date ? String(t.review_date) : "";
        if (!iso) return true;
        const d = new Date(iso);
        if (Number.isNaN(d.getTime())) return true;
        if (d.getTime() < Date.now()) return true;
        return false;
      }
      if (quickMine) {
        const me = (typeof window !== "undefined" ? (localStorage.getItem("vip:userEmail") ?? "") : "").trim().toLowerCase();
        // If we don't know "me", treat as not matching.
        if (!me) return false;
        if (!t.owner) return false;
        return String(t.owner).trim().toLowerCase().includes(me.split("@")[0] || me);
      }
      return true;
    });

    for (const t of filtered) {
      const k = normalizeUiTaskStatus(t.status);
      if (!by[k]) by[k] = [];
      by[k].push(t);
    }
    const applyOrder = (colKey: string, its: TaskListRow[]) => {
      const ids = its.map((t) => t.id);
      const want = (boardOrder[colKey] ?? []).filter((id) => ids.includes(id));
      const rest = ids.filter((id) => !want.includes(id));
      const finalIds = [...want, ...rest];
      const map = new Map(its.map((t) => [t.id, t]));
      return finalIds.map((id) => map.get(id)!).filter(Boolean);
    };
    return TASK_STATUS_COLUMNS.map((o) => ({ ...o, items: applyOrder(o.key, by[o.key] ?? []) }));
  }, [items, optimisticStatus, quickKevOnly, quickMinScore, quickNeedsReview, quickMine, boardOrder]);

  const groupKeyFor = useCallback(
    (t: TaskListRow): string => {
      if (boardGroupBy === "vendor") return (t.vendor_display || "—").trim() || "—";
      if (boardGroupBy === "owner") return (t.owner || "—").trim() || "—";
      return "—";
    },
    [boardGroupBy]
  );

  const sensors = useSensors(useSensor(PointerSensor, { activationConstraint: { distance: 6 } }));

  const onDragStart = useCallback((e: DragStartEvent) => {
    const data = (e.active.data.current ?? null) as DragTaskData | null;
    const taskId = typeof data?.taskId === "string" ? data.taskId : undefined;
    if (taskId) setDraggingTaskId(taskId);
  }, []);

  const onDragEnd = useCallback(
    async (e: DragEndEvent) => {
      setDraggingTaskId(null);
      const activeData = (e.active.data.current ?? null) as DragTaskData | null;
      const taskId = typeof activeData?.taskId === "string" ? activeData.taskId : undefined;
      const fromStatus = typeof activeData?.fromStatus === "string" ? activeData.fromStatus : undefined;
      const overId = e.over?.id ? String(e.over.id) : null;
      const overData = (e.over?.data.current ?? null) as DragTaskData | null;
      const overContainerId = typeof overData?.containerId === "string" ? overData.containerId : undefined;
      const toStatus =
        overId && overId.startsWith("col:")
          ? overId.slice("col:".length)
          : overContainerId
            ? String(overContainerId)
            : null;
      if (!taskId || !toStatus) return;

      // Reorder within column if dropped over another card.
      if (fromStatus && toStatus === fromStatus && overId && overId.startsWith("task:")) {
        const activeId = taskId;
        const overTaskId = overId.slice("task:".length);
        const colItems = columns.find((c) => c.key === fromStatus)?.items ?? [];
        const ids = colItems.map((t) => t.id);
        const oldIndex = ids.indexOf(activeId);
        const newIndex = ids.indexOf(overTaskId);
        if (oldIndex >= 0 && newIndex >= 0 && oldIndex !== newIndex) {
          setBoardOrder((m) => ({ ...m, [fromStatus]: arrayMove(ids, oldIndex, newIndex) }));
        }
        return;
      }
      if (fromStatus && toStatus === fromStatus) return;

      // optimistic
      setOptimisticStatus((m) => ({ ...m, [taskId]: toStatus }));
      try {
        await patchTask(taskId, { status: toStatus });
        setOptimisticStatus((m) => {
          const n = { ...m };
          delete n[taskId];
          return n;
        });
      } catch (err) {
        // rollback and guide user to required fields
        setOptimisticStatus((m) => {
          const n = { ...m };
          if (fromStatus) n[taskId] = fromStatus;
          else delete n[taskId];
          return n;
        });
        setSelected(taskId);
        setRightTab("fields");
        setSaveErr(err instanceof Error ? err.message : String(err));
      }
    },
    [patchTask, columns]
  );

  const showBoard = viewMode === "board";
  const hasQuickFilters = boardGroupBy !== "none" || quickKevOnly || quickNeedsReview || quickMinScore != null || quickMine;
  const boardHasFilters = showBoard && hasQuickFilters;
  const resetQuickFilters = () => {
    setBoardGroupBy("none");
    setQuickKevOnly(false);
    setQuickNeedsReview(false);
    setQuickMinScore(null);
    setQuickMine(false);
  };

  useEffect(() => {
    if (showBoard) return;
    const el = listContainerRef.current;
    if (!el) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key !== "ArrowDown" && e.key !== "ArrowUp" && e.key !== "Enter" && e.key !== "Escape") return;
      if (!listItems.length) return;
      e.preventDefault();
      e.stopPropagation();

      if (e.key === "Escape") {
        setSelected(null);
        onSelectTaskId?.(null);
        return;
      }

      const idx = selected ? listItems.findIndex((t) => t.id === selected) : -1;
      const nextIdx =
        e.key === "ArrowDown" ? Math.min(listItems.length - 1, Math.max(0, idx + 1)) : e.key === "ArrowUp" ? Math.max(0, idx <= 0 ? 0 : idx - 1) : idx;
      const next = listItems[nextIdx] ?? listItems[0]!;
      setSelected(next.id);
      setRightTab("fields");
      onSelectTaskId?.(next.id);
      requestAnimationFrame(() => listRowRefs.current[next.id]?.scrollIntoView({ block: "nearest" }));
    };
    el.addEventListener("keydown", onKeyDown);
    return () => el.removeEventListener("keydown", onKeyDown);
  }, [showBoard, listItems, selected, onSelectTaskId]);

  useEffect(() => {
    if (!showBoard || !selected) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") setSelected(null);
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [showBoard, selected]);

  const boardView = (
    <div className="rounded-2xl border border-border bg-white p-4 shadow-sm dark:bg-black/15 dark:shadow-none">
      {items.length === 0 && !listQuery.isLoading ? (
        <div className="text-sm text-muted">Пока нет задач.</div>
      ) : (
        <div className="overflow-x-auto pb-2">
          {boardGroupBy === "none" ? (
            <DndContext
              sensors={sensors}
              collisionDetection={closestCenter}
              onDragStart={onDragStart}
              onDragEnd={onDragEnd}
            >
              <div className="flex gap-3">
                {columns.map((col) => (
                  <BoardColumn
                    key={col.key}
                    colKey={col.key}
                    title={col.title}
                    count={col.items.length}
                    wip={null}
                    items={col.items.map((t) => `task:${t.id}`)}
                    dragging={!!draggingTaskId}
                  >
                    {col.items.map((t) => (
                      <TaskCardDraggable
                        key={t.id}
                        task={t}
                        active={selected === t.id}
                        containerId={col.key}
                        onClick={() => {
                          setSelected(t.id);
                          onSelectTaskId?.(t.id);
                        }}
                      />
                    ))}
                    {draggingTaskId ? <div className="h-2" /> : null}
                  </BoardColumn>
                ))}
              </div>
              <DragOverlay dropAnimation={null}>
                {draggingTask ? <TaskCardGhost task={draggingTask} /> : null}
              </DragOverlay>
            </DndContext>
          ) : (
            <div className="flex gap-3">
              {columns.map((col) => (
                <div
                  key={col.key}
                  className="w-[320px] shrink-0 rounded-xl border border-slate-200 bg-slate-50 p-3 dark:border-white/10 dark:bg-white/5"
                >
                  <div className="flex items-center justify-between gap-2">
                    <div className="text-[11px] font-medium text-fg/85">{col.title}</div>
                    <div className="text-[11px] tabular-nums text-muted">{col.items.length}</div>
                  </div>
                  <div className="mt-2 max-h-[520px] overflow-auto pr-1">
                    <div className="space-y-2">
                      {(() => {
                        let lastGroup = "";
                        return col.items.map((t) => {
                          const g = groupKeyFor(t);
                          const showHeader = g !== lastGroup;
                          lastGroup = g;
                          return (
                            <div key={t.id}>
                              {showHeader ? (
                                <div className="mb-2 mt-3 flex items-center gap-2 text-[10px] font-medium text-muted">
                                  <div className="h-px flex-1 bg-slate-200/70 dark:bg-white/10" />
                                  <div className="max-w-[240px] truncate">{g}</div>
                                  <div className="h-px flex-1 bg-slate-200/70 dark:bg-white/10" />
                                </div>
                              ) : null}
                              <button
                                type="button"
                                onClick={() => {
                                  setSelected(t.id);
                                  onSelectTaskId?.(t.id);
                                }}
                                className={cn(
                                  "w-full rounded-lg border px-3 py-2 text-left transition",
                                  selected === t.id ? "border-accent/40 shadow-glass" : "border-border",
                                  "bg-white/85 hover:bg-white dark:bg-black/20 dark:hover:bg-black/30"
                                )}
                              >
                                <div className="flex items-start justify-between gap-2">
                                  <div className="min-w-0">
                                    <div className="line-clamp-1 text-[12px] font-semibold leading-4 text-fg/90">{t.title}</div>
                                    <div className="mt-1 line-clamp-1 text-[11px] leading-4 text-muted">
                                      {t.vendor_display}
                                      {t.product_display ? ` / ${t.product_display}` : ""}
                                    </div>
                                    <div className="mt-1 flex flex-wrap items-center gap-1 text-[10px] text-muted">
                                      <span className={cn("rounded-full border px-2 py-0.5", statusPill(t.status).cls)}>
                                        {statusPill(t.status).label}
                                      </span>
                                      <span className={cn("rounded-full border px-2 py-0.5 tabular-nums", scoreCls(t.score_final))}>
                                        {t.score_final}
                                      </span>
                                      {typeof t.stats?.cveCount === "number" ? (
                                        <span className="rounded-full border border-slate-200 bg-slate-50 px-2 py-0.5 tabular-nums dark:border-white/10 dark:bg-white/5">
                                          CVE {t.stats.cveCount}
                                        </span>
                                      ) : null}
                                      {typeof t.stats?.kevCount === "number" && t.stats.kevCount > 0 ? (
                                        <span className="rounded-full border border-danger/30 bg-danger/10 px-2 py-0.5 text-danger">
                                          KEV {t.stats.kevCount}
                                        </span>
                                      ) : null}
                                    </div>
                                  </div>
                                  <div className="shrink-0 text-[10px] text-muted">
                                    {t.updated_at ? new Date(t.updated_at).toLocaleDateString() : "—"}
                                  </div>
                                </div>
                              </button>
                            </div>
                          );
                        });
                      })()}
                    </div>
                  </div>
                  <div className="mt-2 text-[10px] text-muted">Swimlanes включены: drag&drop отключён.</div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );

  const detailsView = (opts?: { inDrawer?: boolean }) => {
    const inDrawer = opts?.inDrawer === true;
    const activeStatus = normalizeUiTaskStatus(active?.status);
    const activeClosureText = `${active?.evidence ?? ""}${active?.decision_notes ?? ""}`.trim();
    return (
      <div className={cn("space-y-4", inDrawer ? "" : "")}>
        <div
          className={cn(
            "sticky top-0 z-10 border-b border-white/10 bg-white/85 py-4 backdrop-blur dark:bg-black/55",
            inDrawer ? "-mx-4 -mt-4 px-4" : "-mx-5 -mt-5 px-5 sm:-mx-6 sm:-mt-6 sm:px-6"
          )}
        >
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="min-w-0">
              <div className="truncate text-base font-semibold tracking-tight">{active?.title ?? selected}</div>
              <div className="mt-1 text-xs text-muted">
                {active?.vendor_display}
                {active?.product_display ? ` / ${active?.product_display}` : ""}
              </div>
            </div>
            <div className="flex items-center gap-2 text-[11px]">
              <span className={cn("rounded-full border px-2 py-0.5 tabular-nums", scoreCls(Number(active?.score_final ?? 0)))}>
                Score {Number(active?.score_final ?? 0)}
              </span>
              <span className={cn("rounded-full border px-2 py-0.5", statusPill(activeStatus).cls)}>
                {statusPill(activeStatus).label}
              </span>
              <button
                type="button"
                onClick={() => void refresh()}
                className="ml-1 inline-flex items-center gap-2 rounded-full border border-slate-200 bg-slate-50 px-2.5 py-0.5 text-[11px] text-fg/85 hover:bg-slate-100 dark:border-border dark:bg-black/20 dark:hover:bg-black/30"
                title="Обновить"
              >
                <RefreshCw className={cn("h-3.5 w-3.5", listQuery.isFetching || detailQuery.isFetching ? "animate-spin" : "")} />
                Sync
              </button>
            </div>
          </div>

          <div className="mt-3 flex flex-wrap gap-2">
            {TASK_STATUS_COLUMNS.map((s) => (
              <button
                key={s.key}
                type="button"
                onClick={() => void savePatch(readPatchFieldsForValidation(s.key))}
                disabled={saveBusy || activeStatus === s.key}
                className={cn(
                  "inline-flex items-center gap-2 rounded-full border px-3 py-1 text-[11px] font-medium transition",
                  activeStatus === s.key
                    ? "border-accent/40 bg-accent/10 text-fg/90"
                    : "border-slate-200 bg-slate-50 text-fg/80 hover:bg-slate-100 dark:border-border dark:bg-black/20 dark:hover:bg-black/30",
                  saveBusy || activeStatus === s.key ? "cursor-default opacity-75" : ""
                )}
                title={`Перевести в статус: ${s.title}`}
              >
                {s.title}
              </button>
            ))}
          </div>

          <div className="mt-2 flex flex-wrap gap-2">
            {(
              [
                { key: "cves", label: "CVE", n: activeCves.length },
                { key: "fields", label: "Поля", n: null },
                { key: "events", label: "История", n: activeEvents.length }
              ] as const
            ).map((t) => (
              <button
                key={t.key}
                type="button"
                onClick={() => setRightTab(t.key)}
                className={cn(
                  "inline-flex items-center gap-2 rounded-full border px-3 py-1 text-[11px] font-medium transition",
                  rightTab === t.key
                    ? "border-accent/40 bg-accent/10 text-fg/90"
                    : "border-slate-200 bg-slate-50 text-fg/80 hover:bg-slate-100 dark:border-border dark:bg-black/20 dark:hover:bg-black/30"
                )}
              >
                {t.label}
                {typeof t.n === "number" ? (
                  <span className="rounded-full border border-slate-200 bg-white px-2 py-0.5 text-[10px] tabular-nums dark:border-white/10 dark:bg-black/20">
                    {t.n}
                  </span>
                ) : null}
              </button>
            ))}
          </div>
        </div>

        {rightTab === "cves" ? (
          <div className="rounded-xl border border-border bg-white p-4 shadow-sm dark:bg-black/20 dark:shadow-none">
            <div className="flex items-center justify-between gap-3">
              <div className="text-xs text-muted">CVE в задаче</div>
              <button
                type="button"
                onClick={() => setAddOpen((v) => !v)}
                className="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-slate-50 px-2.5 py-1.5 text-[11px] text-fg/90 hover:bg-slate-100 dark:border-border dark:bg-black/20 dark:hover:bg-black/35"
              >
                <Search className="h-3.5 w-3.5" />
                Добавить CVE
              </button>
            </div>
            {addOpen ? (
              <div className="mt-3 rounded-xl border border-slate-200 bg-slate-50 p-3 dark:border-white/10 dark:bg-white/5">
                <div className="text-[11px] text-muted">Поиск CVE (минимум 3 символа)</div>
                <div className="mt-2 flex items-center gap-2">
                  <input
                    value={addQ}
                    onChange={(e) => setAddQ(e.target.value)}
                    placeholder="CVE-2026-… или vendor/product"
                    className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm dark:border-border dark:bg-black/20"
                  />
                  <button
                    type="button"
                    onClick={() => void addCves()}
                    className="shrink-0 rounded-lg border border-accent/30 bg-accent/10 px-3 py-2 text-sm text-fg/90 hover:bg-accent/15"
                  >
                    Добавить
                  </button>
                </div>
                <div className="mt-2 grid items-start gap-2 sm:grid-cols-2">
                  {(cveSearchQuery.data?.items ?? []).slice(0, 20).map((c) => (
                    <label
                      key={String((c as Record<string, unknown>).cve_id ?? "")}
                      className="flex cursor-pointer items-start gap-2 rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm dark:border-white/10 dark:bg-black/20"
                    >
                      <input
                        type="checkbox"
                        checked={Boolean(addPicked[String((c as Record<string, unknown>).cve_id ?? "")])}
                        onChange={(e) =>
                          setAddPicked((m) => {
                            const n = { ...m };
                            const id = String((c as Record<string, unknown>).cve_id ?? "");
                            if (e.target.checked) n[id] = true;
                            else delete n[id];
                            return n;
                          })
                        }
                      />
                      <div className="min-w-0">
                        <div className="font-mono text-[12px] font-semibold">
                          {String((c as Record<string, unknown>).cve_id ?? "")}
                        </div>
                        <div className="mt-1 line-clamp-2 text-[11px] text-muted">
                          {String(
                            (c as Record<string, unknown>).short_ru ??
                              (c as Record<string, unknown>).short_description ??
                              ""
                          )}
                        </div>
                      </div>
                    </label>
                  ))}
                </div>
              </div>
            ) : null}
            <div className="mt-2 max-h-[420px] overflow-auto pr-1">
              <div className="grid items-start gap-2 sm:grid-cols-2">
                {activeCves.slice(0, 50).map((c) => (
                  <div
                    key={c.cve_id}
                    className="rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-left text-sm dark:border-white/10 dark:bg-white/5"
                  >
                    <div className="flex items-start justify-between gap-2">
                      <button onClick={() => onOpenCve?.(String(c.cve_id))} className="min-w-0 text-left hover:underline" title="Открыть CVE">
                        <div className="font-mono text-[12px] font-semibold text-fg/90">{String(c.cve_id)}</div>
                        <div className="mt-1 text-[11px] text-muted">
                          {c.exploit_known ? "KEV • " : ""}EPSS{" "}
                          {typeof c.epss === "number" ? `${(Number(c.epss) * 100).toFixed(2)}%` : "—"} • CVSS{" "}
                          {typeof c.cvss_base === "number" ? Number(c.cvss_base).toFixed(1) : "—"}
                        </div>
                      </button>
                      <div className="flex items-center gap-2">
                        <div className="text-[11px] text-muted tabular-nums">{typeof c.risk_score === "number" ? c.risk_score : "—"}</div>
                        <button
                          type="button"
                          onClick={() => void removeCve(String(c.cve_id))}
                          className="rounded-lg border border-slate-200 bg-white px-2 py-1 text-[11px] text-fg/80 hover:bg-slate-100 dark:border-white/10 dark:bg-black/20 dark:hover:bg-black/30"
                          title="Убрать из задачи"
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
            {activeCves.length > 50 ? <div className="mt-2 text-[11px] text-muted">Показаны первые 50 CVE…</div> : null}
          </div>
        ) : null}

        {rightTab === "fields" ? (
          <div className="rounded-xl border border-border bg-white p-4 shadow-sm dark:bg-black/20 dark:shadow-none">
            <div className="flex items-center justify-between gap-3">
              <div className="text-xs text-muted">Поля задачи</div>
              <div className="text-[11px] text-muted">{saveBusy ? "Сохраняем…" : ""}</div>
            </div>
            {saveErr ? <div className="mt-2 text-[11px] text-rose-700">{saveErr}</div> : null}
            {activeStatus === "closed" && !activeClosureText ? (
              <div className="mt-2 rounded-lg border border-warn/25 bg-warn/10 px-3 py-2 text-[11px] text-warn">
                Задача закрыта без evidence/decision notes. Лучше добавить ссылку на патч, advisory, проверку или короткое обоснование.
              </div>
            ) : null}
            <div className="mt-3 grid grid-cols-12 gap-3">
              <div className="col-span-12 md:col-span-4">
                <div className="text-[11px] text-muted">Статус</div>
                <select
                  defaultValue={normalizeUiTaskStatus(active?.status)}
                  onChange={(e) => void savePatch(readPatchFieldsForValidation(e.target.value))}
                  className="mt-1 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm dark:border-border dark:bg-black/20"
                >
                  <option value="new">Новая</option>
                  <option value="in_progress">В работе</option>
                  <option value="closed">Закрыта</option>
                </select>
                <div className="mt-2 text-[10px] text-muted">
                  Рабочий поток простой: новая → в работе → закрыта. Детали решения фиксируйте ниже.
                </div>
              </div>
              <div className="col-span-12 md:col-span-4">
                <div className="text-[11px] text-muted">Приоритет (ручной)</div>
                <select
                  defaultValue={String(active?.priority_local ?? "medium")}
                  onChange={(e) => void savePatch({ priorityLocal: e.target.value })}
                  className="mt-1 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm dark:border-border dark:bg-black/20"
                >
                  <option value="low">Низкий</option>
                  <option value="medium">Средний</option>
                  <option value="high">Высокий</option>
                  <option value="critical">Критичный</option>
                </select>
              </div>
              <div className="col-span-12 md:col-span-4">
                <div className="text-[11px] text-muted">Owner</div>
                <input
                  defaultValue={String(active?.owner ?? "")}
                  onBlur={(e) => void savePatch({ owner: e.target.value || null })}
                  className="mt-1 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm dark:border-border dark:bg-black/20"
                  placeholder="Иван / Коллега"
                />
              </div>
              <div className="col-span-12 md:col-span-4">
                <div className="text-[11px] text-muted">Due date</div>
                <input
                  defaultValue={active?.due_date ? String(active.due_date).slice(0, 10) : ""}
                  onBlur={(e) => void savePatch({ dueDate: e.target.value ? new Date(e.target.value).toISOString() : null })}
                  type="date"
                  className="mt-1 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm dark:border-border dark:bg-black/20"
                />
              </div>
              <div className="col-span-12 md:col-span-4">
                <div className="text-[11px] text-muted">Review date</div>
                <input
                  ref={reviewDateRef}
                  defaultValue={active?.review_date ? String(active.review_date).slice(0, 10) : ""}
                  onBlur={(e) => void savePatch({ reviewDate: e.target.value ? new Date(e.target.value).toISOString() : null })}
                  type="date"
                  className="mt-1 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm dark:border-border dark:bg-black/20"
                />
              </div>
              <div className="col-span-12 md:col-span-4">
                <div className="text-[11px] text-muted">Decision</div>
                <input
                  ref={decisionRef}
                  defaultValue={String(active?.decision ?? "")}
                  onBlur={(e) => void savePatch({ decision: e.target.value || null })}
                  className="mt-1 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm dark:border-border dark:bg-black/20"
                  placeholder="patch / mitigation / accept / n/a"
                />
              </div>
              <div className="col-span-12">
                <div className="text-[11px] text-muted">Decision notes</div>
                <textarea
                  ref={decisionNotesRef}
                  defaultValue={String(active?.decision_notes ?? "")}
                  onBlur={(e) => void savePatch({ decisionNotes: e.target.value || null })}
                  className="mt-1 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm dark:border-border dark:bg-black/20"
                  rows={3}
                  placeholder="Почему так решили, какой план, кто делает…"
                />
              </div>
              <div className="col-span-12">
                <div className="text-[11px] text-muted">Evidence</div>
                <textarea
                  ref={evidenceRef}
                  defaultValue={String(active?.evidence ?? "")}
                  onBlur={(e) => void savePatch({ evidence: e.target.value || null })}
                  className="mt-1 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm dark:border-border dark:bg-black/20"
                  rows={2}
                  placeholder="Ссылка на advisory / версия / тикет / скрин / команда проверки…"
                />
              </div>
              <div className="col-span-12">
                <div className="text-[11px] text-muted">Notes (Markdown)</div>
                <textarea
                  defaultValue={String(active?.notes_md ?? "")}
                  onBlur={(e) => void savePatch({ notesMd: e.target.value })}
                  className="mt-1 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm font-mono dark:border-border dark:bg-black/20"
                  rows={8}
                />
              </div>
            </div>
          </div>
        ) : null}

        {rightTab === "events" ? (
          <div className="rounded-xl border border-border bg-white p-4 shadow-sm dark:bg-black/20 dark:shadow-none">
            <div className="flex items-center justify-between gap-3">
              <div className="text-xs text-muted">История</div>
              <div className="text-[11px] text-muted">{activeEvents.length} событий</div>
            </div>
            {activeEvents.length ? (
              <div className="mt-3 max-h-[520px] space-y-2 overflow-auto pr-1">
                {activeEvents.slice(0, 80).map((ev, idx: number) => (
                  <div
                    key={`${String(ev?.id ?? "")}-${idx}`}
                    className="rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 text-[11px] dark:border-white/10 dark:bg-white/5"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="min-w-0 truncate font-mono text-[10px] text-fg/80">
                        {String(ev?.action ?? "event")}
                        {ev?.actor ? <span className="ml-2 text-muted">· {String(ev.actor)}</span> : null}
                      </div>
                      <div className="shrink-0 font-mono text-[10px] text-muted tabular-nums">
                        {ev?.ts ? new Date(String(ev.ts)).toLocaleString() : "—"}
                      </div>
                    </div>
                    {ev?.meta ? (
                      <pre className="mt-2 max-h-40 overflow-auto rounded-lg border border-slate-200 bg-white p-2 text-[10px] text-fg/80 dark:border-border dark:bg-black/20">
                        {JSON.stringify(ev.meta, null, 2).slice(0, 3000)}
                      </pre>
                    ) : null}
                  </div>
                ))}
                {activeEvents.length > 80 ? <div className="text-[10px] text-muted">Показаны первые 80…</div> : null}
              </div>
            ) : (
              <div className="mt-3 text-[11px] text-muted">Пока нет событий.</div>
            )}
          </div>
        ) : null}
      </div>
    );
  };

  return (
    <div className={cn("grid grid-cols-12 gap-6", showBoard ? "items-start" : "")}>
      <section className="col-span-12">
        <div className={cn("glass rounded-2xl p-4", showBoard ? "p-0" : "")}>
          <div
            className={cn(
              "flex items-start justify-between gap-3",
              showBoard
                ? "sticky top-3 z-20 rounded-2xl border border-border/60 bg-white/70 p-4 shadow-sm backdrop-blur dark:bg-black/30 dark:shadow-none"
                : ""
            )}
          >
            <div className="min-w-0">
              <div className="text-sm font-medium">Задачник по уязвимостям</div>
              <div className="mt-1 text-[11px] text-muted">
                Triage-доска: новая → в работе → закрыта. Приоритет задаётся CVE-сигналами, KEV, EPSS и локальным контекстом.
              </div>
            </div>
            <div className="flex shrink-0 items-center gap-2">
              <button
                type="button"
                onClick={() => setViewMode("board")}
                className={cn(
                  "inline-flex items-center gap-2 rounded-xl border px-2.5 py-1.5 text-[11px] text-fg/90",
                  viewMode === "board"
                    ? "border-accent/40 bg-accent/10"
                    : "border-slate-200 bg-white hover:bg-slate-50 dark:border-border dark:bg-black/20 dark:hover:bg-black/35"
                )}
                title="Kanban"
              >
                Доска
              </button>
              <button
                type="button"
                onClick={() => setViewMode("list")}
                className={cn(
                  "inline-flex items-center gap-2 rounded-xl border px-2.5 py-1.5 text-[11px] text-fg/90",
                  viewMode === "list"
                    ? "border-accent/40 bg-accent/10"
                    : "border-slate-200 bg-white hover:bg-slate-50 dark:border-border dark:bg-black/20 dark:hover:bg-black/35"
                )}
                title="Список"
              >
                Список
              </button>
              <button
                type="button"
                onClick={() => void refresh()}
                className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-slate-50 px-2.5 py-1.5 text-[11px] text-fg/90 hover:bg-slate-100 dark:border-border dark:bg-black/20 dark:hover:bg-black/35"
                title="Обновить"
              >
                {listQuery.isFetching ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
                Обновить
              </button>
              <button
                type="button"
                onClick={() => setCreateOpen((v) => !v)}
                className="inline-flex items-center gap-2 rounded-xl border border-accent/30 bg-accent/10 px-2.5 py-1.5 text-[11px] text-fg/90 hover:bg-accent/15"
                title="Создать задачу"
              >
                <Plus className="h-3.5 w-3.5" />
                Новая
              </button>
            </div>
          </div>

          <div className={cn("mt-3", showBoard ? "px-4 pb-4" : "")}>
            {viewMode === "list" ? (
              <div className="rounded-2xl border border-slate-200 bg-slate-50/80 p-3 dark:border-white/10 dark:bg-white/5">
                <div className="grid gap-2 lg:grid-cols-[150px_130px_44px_auto]">
                  <select
                    value={status}
                    onChange={(e) => setStatus(e.target.value)}
                    className="rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm dark:border-border dark:bg-black/20"
                    title="Статус"
                  >
                    <option value="">Все статусы</option>
                    <option value="new">Новая</option>
                    <option value="in_progress">В работе</option>
                    <option value="closed">Закрыта</option>
                  </select>
                  <select
                    value={listSort}
                    onChange={(e) => setListSort(e.target.value as "score" | "updated" | "title")}
                    className="rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm dark:border-border dark:bg-black/20"
                    title="Сортировка"
                  >
                    <option value="score">Score</option>
                    <option value="updated">Updated</option>
                    <option value="title">Title</option>
                  </select>
                  <button
                    type="button"
                    onClick={() => setListSortDir((d) => (d === "desc" ? "asc" : "desc"))}
                    className="rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-fg/80 hover:bg-slate-50 dark:border-border dark:bg-black/20 dark:hover:bg-black/35"
                    title="Направление сортировки"
                  >
                    {listSortDir === "desc" ? "↓" : "↑"}
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setQ("");
                      setStatus("");
                      resetQuickFilters();
                    }}
                    className="rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-fg/80 hover:bg-slate-50 dark:border-border dark:bg-black/20 dark:hover:bg-black/35"
                    title="Сбросить поиск и фильтры"
                  >
                    Сбросить
                  </button>
                </div>

                <div className="mt-2 flex flex-wrap items-center justify-between gap-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <button
                      type="button"
                      onClick={() => setQuickKevOnly((v) => !v)}
                      className={cn(
                        "rounded-full border px-3 py-1 text-[11px] font-medium",
                        quickKevOnly ? "border-danger/30 bg-danger/10 text-danger" : "border-slate-200 bg-white text-fg/80 dark:border-border dark:bg-black/20"
                      )}
                    >
                      KEV
                    </button>
                    <button
                      type="button"
                      onClick={() => setQuickNeedsReview((v) => !v)}
                      className={cn(
                        "rounded-full border px-3 py-1 text-[11px] font-medium",
                        quickNeedsReview ? "border-warn/30 bg-warn/10 text-warn" : "border-slate-200 bg-white text-fg/80 dark:border-border dark:bg-black/20"
                      )}
                    >
                      Просрочено/нет review
                    </button>
                    <button
                      type="button"
                      onClick={() => setQuickMinScore((v) => (v == null ? 70 : v === 70 ? 85 : null))}
                      className={cn(
                        "rounded-full border px-3 py-1 text-[11px] font-medium",
                        quickMinScore != null ? "border-accent/30 bg-accent/10 text-fg/85" : "border-slate-200 bg-white text-fg/80 dark:border-border dark:bg-black/20"
                      )}
                      title="Фильтр по score: ≥70 → ≥85 → off"
                    >
                      Score {quickMinScore == null ? "—" : `≥${quickMinScore}`}
                    </button>
                    <button
                      type="button"
                      onClick={() => setQuickMine((v) => !v)}
                      className={cn(
                        "rounded-full border px-3 py-1 text-[11px] font-medium",
                        quickMine ? "border-accent/40 bg-accent/10 text-fg/85" : "border-slate-200 bg-white text-fg/80 dark:border-border dark:bg-black/20"
                      )}
                      title="Только мои (по owner)"
                    >
                      Mine
                    </button>
                  </div>
                  <div className="text-[11px] text-muted">
                    Показано {listItems.length} из {items.length}
                    {listQuery.isFetching ? " · обновляем…" : ""}
                  </div>
                </div>
              </div>
            ) : (
              <div className="grid grid-cols-2 gap-2">
                <input
                  value={q}
                  onChange={(e) => setQ(e.target.value)}
                  placeholder="поиск по названию / vendor / product"
                  className="col-span-2 rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm dark:border-border dark:bg-black/20"
                />
                <div className="col-span-2 flex flex-wrap items-center gap-2">
                <div className="mr-1 text-[10px] text-muted">Swimlanes</div>
                <button
                  type="button"
                  onClick={() => setBoardGroupBy("none")}
                  className={cn(
                    "rounded-full border px-3 py-1 text-[11px] font-medium",
                    boardGroupBy === "none"
                      ? "border-accent/40 bg-accent/10 text-fg/85"
                      : "border-slate-200 bg-white text-fg/80 dark:border-border dark:bg-black/20"
                  )}
                >
                  off
                </button>
                <button
                  type="button"
                  onClick={() => setBoardGroupBy("vendor")}
                  className={cn(
                    "rounded-full border px-3 py-1 text-[11px] font-medium",
                    boardGroupBy === "vendor"
                      ? "border-accent/40 bg-accent/10 text-fg/85"
                      : "border-slate-200 bg-white text-fg/80 dark:border-border dark:bg-black/20"
                  )}
                >
                  vendor
                </button>
                <button
                  type="button"
                  onClick={() => setBoardGroupBy("owner")}
                  className={cn(
                    "rounded-full border px-3 py-1 text-[11px] font-medium",
                    boardGroupBy === "owner"
                      ? "border-accent/40 bg-accent/10 text-fg/85"
                      : "border-slate-200 bg-white text-fg/80 dark:border-border dark:bg-black/20"
                  )}
                >
                  owner
                </button>

                <button
                  type="button"
                  onClick={() => setQuickKevOnly((v) => !v)}
                  className={cn(
                    "rounded-full border px-3 py-1 text-[11px] font-medium",
                    quickKevOnly ? "border-danger/30 bg-danger/10 text-danger" : "border-slate-200 bg-white text-fg/80 dark:border-border dark:bg-black/20"
                  )}
                >
                  KEV
                </button>
                <button
                  type="button"
                  onClick={() => setQuickNeedsReview((v) => !v)}
                  className={cn(
                    "rounded-full border px-3 py-1 text-[11px] font-medium",
                    quickNeedsReview ? "border-warn/30 bg-warn/10 text-warn" : "border-slate-200 bg-white text-fg/80 dark:border-border dark:bg-black/20"
                  )}
                >
                  Review
                </button>
                <button
                  type="button"
                  onClick={() => setQuickMinScore((v) => (v == null ? 70 : v === 70 ? 85 : null))}
                  className={cn(
                    "rounded-full border px-3 py-1 text-[11px] font-medium",
                    quickMinScore != null ? "border-accent/30 bg-accent/10 text-fg/85" : "border-slate-200 bg-white text-fg/80 dark:border-border dark:bg-black/20"
                  )}
                  title="Фильтр по score: ≥70 → ≥85 → off"
                >
                  Score {quickMinScore == null ? "—" : `≥${quickMinScore}`}
                </button>

                <button
                  type="button"
                  onClick={() => setQuickMine((v) => !v)}
                  className={cn(
                    "rounded-full border px-3 py-1 text-[11px] font-medium",
                    quickMine ? "border-accent/40 bg-accent/10 text-fg/85" : "border-slate-200 bg-white text-fg/80 dark:border-border dark:bg-black/20"
                  )}
                  title="Только мои (по owner)"
                >
                  Mine
                </button>

                {boardHasFilters ? (
                  <button
                    type="button"
                    onClick={resetQuickFilters}
                    className="rounded-full border border-slate-200 bg-white px-3 py-1 text-[11px] font-medium text-fg/80 hover:bg-slate-50 dark:border-border dark:bg-black/20 dark:hover:bg-black/35"
                    title="Сбросить быстрые фильтры"
                  >
                    Сброс
                  </button>
                ) : null}
              </div>
              </div>
            )}
          </div>

          <div className="mt-3 grid grid-cols-2 gap-2 md:grid-cols-5">
            {[
              ["Всего", taskStats.total],
              ["Новые", taskStats.new],
              ["В работе", taskStats.in_progress],
              ["Закрыты", taskStats.closed],
              ["KEV / Score ≥70", `${taskStats.kev} / ${taskStats.high}`]
            ].map(([label, value]) => (
              <div
                key={String(label)}
                className="rounded-xl border border-slate-200 bg-white px-3 py-2 shadow-sm dark:border-white/10 dark:bg-black/20 dark:shadow-none"
              >
                <div className="text-[10px] uppercase tracking-wide text-muted">{label}</div>
                <div className="mt-1 text-lg font-semibold tabular-nums text-fg/90">{value}</div>
              </div>
            ))}
          </div>

          {createOpen ? (
            <div className="mt-3 rounded-xl border border-slate-200 bg-slate-50 p-3 dark:border-white/10 dark:bg-white/5">
              <div className="text-[11px] font-medium text-fg/85">Новая задача (vendor/product)</div>
              <div className="mt-2 space-y-2">
                <input
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                  placeholder="Название (опционально)"
                  className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm dark:border-border dark:bg-black/20"
                />
                <input
                  list="vip-vendors"
                  value={newVendor}
                  onChange={(e) => setNewVendor(e.target.value)}
                  placeholder="Vendor (например, Citrix)"
                  className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm dark:border-border dark:bg-black/20"
                />
                <datalist id="vip-vendors">
                  {vendorOptions.map((v) => (
                    <option key={v.vendor} value={v.vendor} />
                  ))}
                </datalist>
                <input
                  list="vip-products"
                  value={newProduct}
                  onChange={(e) => setNewProduct(e.target.value)}
                  placeholder="Product (например, NetScaler)"
                  className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm dark:border-border dark:bg-black/20"
                />
                <datalist id="vip-products">
                  {productOptions.map((p) => (
                    <option key={`${p.vendor}:${p.product}`} value={p.product} />
                  ))}
                </datalist>
                <button
                  type="button"
                  onClick={() => void createTask()}
                  className="w-full rounded-lg border border-accent/30 bg-accent/10 px-3 py-2 text-sm text-fg/90 hover:bg-accent/15"
                >
                  Создать
                </button>
              </div>
            </div>
          ) : null}

          <div className={cn("mt-4 space-y-2", showBoard ? "hidden" : "")}>
            {listQuery.isLoading ? (
              <div className="text-sm text-muted">Загрузка…</div>
            ) : items.length === 0 ? (
              <div className="text-sm text-muted">Пока нет задач.</div>
            ) : (
              viewMode === "list" ? (
                <div className="rounded-2xl border border-border bg-white shadow-sm dark:bg-black/15 dark:shadow-none">
                  <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200 px-4 py-3 dark:border-white/10">
                    <div>
                      <div className="text-sm font-medium text-fg/90">Triage-список</div>
                      <div className="mt-0.5 text-[11px] text-muted">Компактный вид для массовой обработки задач.</div>
                    </div>
                    <div className="rounded-full border border-slate-200 bg-slate-50 px-3 py-1 text-[11px] text-muted dark:border-white/10 dark:bg-white/5">
                      {listItems.length} / {items.length}
                    </div>
                  </div>

                  <div
                    ref={listContainerRef}
                    tabIndex={0}
                    className="max-h-[calc(100vh-330px)] space-y-1 overflow-auto bg-slate-50 p-2 outline-none focus:ring-2 focus:ring-accent/30 dark:bg-white/5"
                    title="Навигация: ↑/↓, Enter, Esc"
                  >
                    {selectedTaskInList ? (
                      <div className="sticky top-0 z-10 mb-1 rounded-xl border border-slate-200 bg-white/80 px-3 py-2 backdrop-blur dark:border-white/10 dark:bg-black/40">
                        <div className="flex items-center justify-between gap-2">
                          <div className="min-w-0 text-[11px] text-muted">
                            Выбрано: <span className="font-medium text-fg/85">{selectedTaskInList.title}</span>
                          </div>
                          <button
                            type="button"
                            onClick={scrollToSelected}
                            className="rounded-lg border border-slate-200 bg-white px-2 py-1 text-[11px] text-fg/80 hover:bg-slate-50 dark:border-border dark:bg-black/20 dark:hover:bg-black/35"
                          >
                            К выбранной
                          </button>
                        </div>
                      </div>
                    ) : null}

                    {pickedCount > 0 ? (
                      <div className="sticky top-0 z-10 mb-1 rounded-xl border border-accent/25 bg-accent/10 px-3 py-2 backdrop-blur">
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <div className="text-[11px] text-fg/85">
                            Выбрано: <span className="font-semibold">{pickedCount}</span>
                          </div>
                          <div className="flex flex-wrap items-center gap-2">
                            <button
                              type="button"
                              onClick={selectAllVisible}
                              className="rounded-lg border border-accent/25 bg-white/70 px-2 py-1 text-[11px] text-fg/80 hover:bg-white"
                              title="Выбрать все в текущем списке"
                            >
                              Выбрать все
                            </button>
                            <select
                              defaultValue=""
                              onChange={(e) => {
                                const v = e.target.value;
                                if (!v) return;
                                void bulkPatch({ status: v });
                                e.currentTarget.value = "";
                              }}
                              className="rounded-lg border border-accent/25 bg-white/70 px-2 py-1 text-[11px] text-fg/85"
                              title="Массово сменить статус"
                            >
                              <option value="">Статус…</option>
                              <option value="new">Новая</option>
                              <option value="in_progress">В работе</option>
                              <option value="closed">Закрыта</option>
                            </select>
                            <input
                              value={bulkOwner}
                              onChange={(e) => setBulkOwner(e.target.value)}
                              placeholder="Owner…"
                              className="w-[140px] rounded-lg border border-accent/25 bg-white/70 px-2 py-1 text-[11px] text-fg/85 placeholder:text-muted"
                            />
                            <button
                              type="button"
                              onClick={() => void bulkPatch({ owner: bulkOwner.trim() ? bulkOwner.trim() : null })}
                              className="rounded-lg border border-accent/25 bg-white/70 px-2 py-1 text-[11px] text-fg/85 hover:bg-white"
                              title="Применить owner"
                              disabled={saveBusy}
                            >
                              Owner
                            </button>
                            <button
                              type="button"
                              onClick={clearPicked}
                              className="rounded-lg border border-accent/25 bg-white/70 px-2 py-1 text-[11px] text-fg/80 hover:bg-white"
                              title="Снять выделение"
                            >
                              Очистить
                            </button>
                          </div>
                        </div>
                        {saveErr ? <div className="mt-1 text-[11px] text-rose-700">{saveErr}</div> : null}
                      </div>
                    ) : null}

                    <div className="sticky top-0 z-[1] hidden grid-cols-[32px_minmax(0,1fr)_180px_96px] gap-3 rounded-lg border border-slate-200 bg-white/90 px-3 py-2 text-[10px] uppercase tracking-wide text-muted backdrop-blur md:grid dark:border-white/10 dark:bg-black/50">
                      <div />
                      <div>Задача</div>
                      <div>Контекст</div>
                      <div className="text-right">Обновлена</div>
                    </div>

                    {listItems.length === 0 ? (
                      <div className="rounded-xl border border-slate-200 bg-white px-4 py-8 text-center text-sm text-muted dark:border-white/10 dark:bg-black/20">
                        По текущим фильтрам задач нет.
                      </div>
                    ) : null}

                    {listItems.map((t) => {
                      const st = statusPill(t.status);
                      const cveCount = t.stats?.cveCount ?? null;
                      const kevCount = t.stats?.kevCount ?? null;
                      const activeRow = selected === t.id;
                      const picked = !!listPicked[t.id];
                      return (
                        <div
                          key={t.id}
                          ref={(el) => {
                            listRowRefs.current[t.id] = el;
                          }}
                          onClick={(e) => {
                            if (e.shiftKey && lastPickIdRef.current) {
                              pickRange(lastPickIdRef.current, t.id);
                              return;
                            }
                            setSelected(t.id);
                            setRightTab("fields");
                            onSelectTaskId?.(t.id);
                          }}
                          className={cn(
                            "group grid w-full cursor-pointer grid-cols-[32px_minmax(0,1fr)_auto] items-start gap-3 rounded-xl border px-3 py-2 text-left transition md:grid-cols-[32px_minmax(0,1fr)_180px_96px]",
                            activeRow
                              ? "border-accent/40 bg-white shadow-sm"
                              : "border-transparent bg-white/70 hover:border-slate-200 hover:bg-white",
                            picked ? "ring-2 ring-accent/20" : "",
                            "dark:bg-black/20 dark:hover:bg-black/30"
                          )}
                          aria-selected={activeRow}
                        >
                          <div className="mt-1">
                            <input
                              type="checkbox"
                              checked={picked}
                              onChange={(e) => {
                                const next = e.target.checked;
                                togglePick(t.id, next);
                                lastPickIdRef.current = t.id;
                              }}
                              onClick={(e) => e.stopPropagation()}
                              className="h-4 w-4 rounded border-slate-300 text-accent"
                              title="Выбрать"
                            />
                          </div>
                          <button
                            type="button"
                            className="min-w-0 text-left"
                          >
                              <div className="flex items-center gap-2">
                                <div className="min-w-0 truncate text-[13px] font-semibold leading-5 text-fg/90">{t.title}</div>
                                {kevCount != null && kevCount > 0 ? (
                                  <span className="shrink-0 rounded-full border border-danger/30 bg-danger/10 px-2 py-0.5 text-[10px] font-medium text-danger">
                                    KEV {kevCount}
                                  </span>
                                ) : null}
                              </div>
                              <div className="mt-0.5 flex flex-wrap items-center gap-1.5 text-[11px] text-muted">
                                <span className={cn("rounded-full border px-2 py-0.5", st.cls)}>{st.label}</span>
                                <span className={cn("rounded-full border px-2 py-0.5 tabular-nums", scoreCls(t.score_final))}>
                                  {t.score_final}
                                </span>
                                {cveCount != null ? (
                                  <span className="rounded-full border border-slate-200 bg-slate-50 px-2 py-0.5 tabular-nums dark:border-white/10 dark:bg-white/5">
                                    CVE {cveCount}
                                  </span>
                                ) : null}
                                {t.owner ? (
                                  <span className="rounded-full border border-slate-200 bg-white px-2 py-0.5 text-[10px] text-fg/75 dark:border-white/10 dark:bg-black/20">
                                    {t.owner}
                                  </span>
                                ) : null}
                              </div>
                              <div className="mt-0.5 line-clamp-1 text-[11px] text-muted">
                                {t.vendor_display}
                                {t.product_display ? ` / ${t.product_display}` : ""}
                              </div>
                          </button>
                          <div className="hidden min-w-0 pt-0.5 text-[11px] text-muted md:block">
                            <div className="truncate">{t.owner || "owner —"}</div>
                            <div className="mt-0.5 truncate">
                              due {t.due_date ? String(t.due_date).slice(0, 10) : "—"} · review{" "}
                              {t.review_date ? String(t.review_date).slice(0, 10) : "—"}
                            </div>
                          </div>
                          <div className="shrink-0 pt-0.5 text-right text-[10px] text-muted tabular-nums">
                            {t.updated_at ? new Date(t.updated_at).toLocaleDateString() : "—"}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              ) : (
                <div className="mt-2 overflow-x-auto pb-2">
                  {boardGroupBy === "none" ? (
                    <DndContext
                      sensors={sensors}
                      collisionDetection={closestCenter}
                      onDragStart={onDragStart}
                      onDragEnd={onDragEnd}
                    >
                      <div className="flex gap-3">
                        {columns.map((col) => (
                          <BoardColumn
                            key={col.key}
                            colKey={col.key}
                            title={col.title}
                            count={col.items.length}
                            wip={null}
                            items={col.items.map((t) => `task:${t.id}`)}
                          >
                            {col.items.map((t) => (
                              <TaskCardDraggable
                                key={t.id}
                                task={t}
                                active={selected === t.id}
                                containerId={col.key}
                                onClick={() => {
                                  setSelected(t.id);
                                  onSelectTaskId?.(t.id);
                                }}
                              />
                            ))}
                            {draggingTaskId ? <div className="h-2" /> : null}
                          </BoardColumn>
                        ))}
                      </div>
                    </DndContext>
                  ) : (
                    <div className="flex gap-3">
                      {columns.map((col) => (
                        <div
                          key={col.key}
                          className="w-[320px] shrink-0 rounded-xl border border-slate-200 bg-slate-50 p-3 dark:border-white/10 dark:bg-white/5"
                        >
                          <div className="flex items-center justify-between gap-2">
                            <div className="text-[11px] font-medium text-fg/85">{col.title}</div>
                            <div className="flex items-center gap-2 text-[11px] tabular-nums">
                              <span className="text-muted">{col.items.length}</span>
                            </div>
                          </div>
                          <div className="mt-2 max-h-[520px] overflow-auto pr-1">
                            <div className="space-y-2">
                              {(() => {
                                let lastGroup = "";
                                return col.items.map((t) => {
                                  const g = groupKeyFor(t);
                                  const showHeader = g !== lastGroup;
                                  lastGroup = g;
                                  return (
                                    <div key={t.id}>
                                      {showHeader ? (
                                        <div className="mb-2 mt-3 flex items-center gap-2 text-[10px] font-medium text-muted">
                                          <div className="h-px flex-1 bg-slate-200/70 dark:bg-white/10" />
                                          <div className="max-w-[240px] truncate">{g}</div>
                                          <div className="h-px flex-1 bg-slate-200/70 dark:bg-white/10" />
                                        </div>
                                      ) : null}
                                      <button
                                        type="button"
                                        onClick={() => {
                                          setSelected(t.id);
                                          onSelectTaskId?.(t.id);
                                        }}
                                        className={cn(
                                          "w-full rounded-lg border px-3 py-2 text-left transition",
                                          selected === t.id ? "border-accent/40 shadow-glass" : "border-border",
                                          "bg-white/85 hover:bg-white dark:bg-black/20 dark:hover:bg-black/30"
                                        )}
                                      >
                                        <div className="flex items-start justify-between gap-2">
                                          <div className="min-w-0">
                                            <div className="line-clamp-1 text-[12px] font-semibold leading-4 text-fg/90">
                                              {t.title}
                                            </div>
                                            <div className="mt-1 line-clamp-1 text-[11px] leading-4 text-muted">
                                              {t.vendor_display}
                                              {t.product_display ? ` / ${t.product_display}` : ""}
                                            </div>
                                            <div className="mt-1 flex flex-wrap items-center gap-1 text-[10px] text-muted">
                                              <span className={cn("rounded-full border px-2 py-0.5", statusPill(t.status).cls)}>
                                                {statusPill(t.status).label}
                                              </span>
                                              <span className={cn("rounded-full border px-2 py-0.5 tabular-nums", scoreCls(t.score_final))}>
                                                {t.score_final}
                                              </span>
                                              {typeof t.stats?.cveCount === "number" ? (
                                                <span className="rounded-full border border-slate-200 bg-slate-50 px-2 py-0.5 tabular-nums dark:border-white/10 dark:bg-white/5">
                                                  CVE {t.stats.cveCount}
                                                </span>
                                              ) : null}
                                              {typeof t.stats?.kevCount === "number" && t.stats.kevCount > 0 ? (
                                                <span className="rounded-full border border-danger/30 bg-danger/10 px-2 py-0.5 text-danger">
                                                  KEV {t.stats.kevCount}
                                                </span>
                                              ) : null}
                                            </div>
                                          </div>
                                          <div className="shrink-0 text-[10px] text-muted">
                                            {t.updated_at ? new Date(t.updated_at).toLocaleDateString() : "—"}
                                          </div>
                                        </div>
                                      </button>
                                    </div>
                                  );
                                });
                              })()}
                            </div>
                          </div>
                          <div className="mt-2 text-[10px] text-muted">
                            Swimlanes включены: drag&drop отключён (чтобы группы были предсказуемыми).
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )
            )}
          </div>
        </div>
      </section>

      {showBoard ? <section className="col-span-12">{boardView}</section> : null}

      {selected ? (
        <div
          className={cn(
            "fixed inset-0 z-[8000]",
            selected ? "pointer-events-auto" : "pointer-events-none"
          )}
          aria-hidden={!selected}
        >
          {/* overlay */}
          <button
            type="button"
            onClick={() => setSelected(null)}
            className={cn(
              "absolute inset-0 bg-black/30 backdrop-blur-[2px] transition",
              selected ? "opacity-100" : "opacity-0"
            )}
            title="Закрыть"
          />
          {/* drawer */}
          <aside
            className={cn(
              "absolute right-0 top-0 h-dvh w-[min(980px,96vw)] overflow-y-auto border-l border-border bg-white p-4 shadow-2xl transition",
              "dark:bg-black/70",
              selected ? "translate-x-0" : "translate-x-full"
            )}
          >
            <button
              type="button"
              onClick={() => setSelected(null)}
              className="sticky right-0 top-0 z-20 ml-auto mb-2 block rounded-full border border-slate-200 bg-white px-3 py-1 text-[11px] text-fg/80 shadow-sm hover:bg-slate-50 dark:border-white/10 dark:bg-black/70 dark:hover:bg-black/50"
              title="Закрыть задачу"
            >
              Закрыть
            </button>
            {selected ? (
              detailQuery.isLoading ? (
                <div className="text-sm text-muted">Загрузка…</div>
              ) : detailQuery.isError ? (
                <div className="text-sm text-danger">Не удалось загрузить задачу.</div>
              ) : (
                detailsView({ inDrawer: true })
              )
            ) : null}
          </aside>
        </div>
      ) : null}
    </div>
  );
}

