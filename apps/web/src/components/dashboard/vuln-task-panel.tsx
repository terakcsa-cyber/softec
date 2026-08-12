"use client";

import { useCallback, useEffect, useMemo, useRef, useState, type CSSProperties } from "react";
import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "@/lib/api-fetch";
import { useAuth } from "@/contexts/auth-context";
import { cn } from "../ui/cn";
import {
  Columns3,
  LayoutList,
  Loader2,
  Plus,
  RefreshCw,
  Search,
  Trash2,
  X
} from "lucide-react";
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
import {
  AssigneeCell,
  FilterChip,
  PriorityMark,
  StatusChip,
  TASK_STATUS_COLUMNS,
  normalizeUiTaskStatus,
  priorityMeta,
  scoreTone,
  statusMeta,
  taskIssueKey,
  type TaskStatus
} from "./vuln-task-ui";

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
  const cveCount = task.stats?.cveCount ?? null;
  const kevCount = task.stats?.kevCount ?? null;
  const reviewIso = task.review_date ? String(task.review_date) : null;
  const reviewDate = reviewIso ? new Date(reviewIso) : null;
  const reviewOverdue = reviewDate && !Number.isNaN(reviewDate.getTime()) ? reviewDate.getTime() < Date.now() : false;

  const style: CSSProperties = {
    transform: CSS.Translate.toString(transform),
    transition,
    opacity: isDragging ? 0.45 : 1
  };

  return (
    <button
      ref={setNodeRef}
      type="button"
      onClick={onClick}
      style={style}
      className={cn(
        "group w-full select-none rounded border px-2 py-1.5 text-left transition",
        active
          ? "border-accent/45 bg-accent/[0.07] ring-1 ring-accent/25"
          : "border-border/80 bg-white hover:border-border hover:bg-slate-50/80 dark:bg-black/25 dark:hover:bg-black/40",
        isDragging ? "cursor-grabbing" : "cursor-grab",
        reviewOverdue ? "border-l-2 border-l-danger" : ""
      )}
      {...attributes}
      {...listeners}
    >
      <div className="flex items-center gap-1.5">
        <PriorityMark priority={task.priority_local} />
        <span className="font-mono text-[10px] text-muted">{taskIssueKey(task.id)}</span>
        <span className={cn("ml-auto text-[10px] font-semibold tabular-nums", scoreTone(task.score_final))}>
          {task.score_final}
        </span>
      </div>
      <div className="mt-0.5 line-clamp-2 text-[12px] font-medium leading-4 text-fg/90">{task.title}</div>
      <div className="mt-1 flex items-center gap-1.5 text-[10px] text-muted">
        <span className="min-w-0 truncate">
          {task.vendor_display}
          {task.product_display ? ` / ${task.product_display}` : ""}
        </span>
        <span className="ml-auto flex shrink-0 items-center gap-1">
          {cveCount != null ? <span className="tabular-nums">CVE {cveCount}</span> : null}
          {kevCount != null && kevCount > 0 ? <span className="font-medium text-danger">KEV</span> : null}
        </span>
      </div>
      <div className="mt-1 flex min-w-0 items-center gap-1 text-[10px] text-muted" title={task.owner ? `В работе у ${task.owner}` : "Без исполнителя"}>
        <AssigneeCell name={task.owner} emptyLabel="нет" />
      </div>
    </button>
  );
}

function TaskCardGhost({ task }: { task: TaskListRow }) {
  return (
    <div className="w-[240px] rounded border border-accent/30 bg-white p-2 shadow-lg dark:bg-black/85">
      <div className="flex items-center gap-1.5">
        <PriorityMark priority={task.priority_local} />
        <span className="font-mono text-[10px] text-muted">{taskIssueKey(task.id)}</span>
      </div>
      <div className="mt-0.5 line-clamp-2 text-[12px] font-medium leading-4">{task.title}</div>
    </div>
  );
}

function BoardColumn({
  colKey,
  title,
  count,
  items,
  dragging,
  children
}: {
  colKey: string;
  title: string;
  count: number;
  items: string[];
  dragging?: boolean;
  children: React.ReactNode;
}) {
  const id = `col:${colKey}`;
  const { setNodeRef, isOver } = useDroppable({ id, data: { status: colKey } });
  const tint = statusMeta(colKey).colTint;
  return (
    <div
      ref={setNodeRef}
      className={cn(
        "flex w-[260px] shrink-0 flex-col overflow-hidden rounded border border-border bg-slate-50/70 dark:bg-white/[0.03]",
        "max-h-[min(640px,calc(100vh-280px))] border-t-2",
        tint,
        isOver ? "ring-2 ring-accent/25" : "",
        dragging ? "transition-[box-shadow] duration-150" : ""
      )}
    >
      <div className="flex items-center justify-between gap-2 border-b border-border/70 px-2.5 py-1.5">
        <div className="flex items-center gap-1.5 text-[11px] font-semibold text-fg/85">
          <span className={cn("h-1.5 w-1.5 rounded-full", statusMeta(colKey).dot)} />
          {title}
        </div>
        <span className="rounded bg-black/[0.04] px-1.5 py-0.5 text-[10px] tabular-nums text-muted dark:bg-white/10">
          {count}
        </span>
      </div>
      <div className={cn("flex-1 space-y-1.5 overflow-auto p-1.5", isOver ? "bg-accent/[0.04]" : "")}>
        <SortableContext items={items} strategy={verticalListSortingStrategy}>
          {count === 0 ? (
            <div
              className={cn(
                "rounded border border-dashed px-2 py-5 text-center text-[11px] text-muted",
                isOver ? "border-accent/40 bg-accent/5" : "border-border/70"
              )}
            >
              {dragging ? "Перетащи сюда" : "Пусто"}
            </div>
          ) : null}
          {children}
        </SortableContext>
      </div>
    </div>
  );
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
  const { user } = useAuth();
  const meEmail = (user?.email ?? "").trim();
  const [q, setQ] = useState("");
  const [status, setStatus] = useState<string>("");
  const [selected, setSelected] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [viewMode, setViewMode] = useState<"list" | "board">("list");
  const [listSort, setListSort] = useState<"score" | "updated" | "title" | "priority">("score");
  const [listSortDir, setListSortDir] = useState<"desc" | "asc">("desc");
  const [quickMine, setQuickMine] = useState(false);
  const [quickKevOnly, setQuickKevOnly] = useState(false);
  const [quickNeedsReview, setQuickNeedsReview] = useState(false);
  const [quickMinScore, setQuickMinScore] = useState<number | null>(null);
  const [boardGroupBy, setBoardGroupBy] = useState<"none" | "vendor" | "owner">("none");

  const [optimisticStatus, setOptimisticStatus] = useState<Record<string, string>>({});
  const [optimisticOwner, setOptimisticOwner] = useState<Record<string, string | null>>({});
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

  const applyQuickFilters = useCallback(
    (arr: TaskListRow[]) =>
      arr.filter((t) => {
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
          const me = (
            meEmail ||
            (typeof window !== "undefined" ? (localStorage.getItem("vip:userEmail") ?? "") : "")
          )
            .trim()
            .toLowerCase();
          if (!me || !t.owner) return false;
          return String(t.owner)
            .trim()
            .toLowerCase()
            .includes(me.split("@")[0] || me);
        }
        return true;
      }),
    [quickKevOnly, quickMinScore, quickNeedsReview, quickMine, meEmail]
  );

  const listItems = useMemo(() => {
    const arr = applyQuickFilters(items);
    const getUpdated = (t: TaskListRow) => (t.updated_at ? new Date(t.updated_at).getTime() : 0);
    const getTitle = (t: TaskListRow) => String(t.title || "").toLowerCase();
    arr.sort((a, b) => {
      let x = 0;
      if (listSort === "score") x = (a.score_final ?? 0) - (b.score_final ?? 0);
      else if (listSort === "updated") x = getUpdated(a) - getUpdated(b);
      else if (listSort === "priority") x = priorityMeta(a.priority_local).sort - priorityMeta(b.priority_local).sort;
      else x = getTitle(a).localeCompare(getTitle(b));
      return listSortDir === "asc" ? x : -x;
    });
    return arr;
  }, [items, listSort, listSortDir, applyQuickFilters]);

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
  const [rightTab, setRightTab] = useState<"cves" | "fields" | "events">("fields");

  useEffect(() => {
    try {
      const v = window.localStorage.getItem("vip:vulnTask:rightTab");
      if (v === "cves" || v === "fields" || v === "events") setRightTab(v);
    } catch {
      // ignore
    }
  }, []);

  useEffect(() => {
    try {
      window.localStorage.setItem("vip:vulnTask:rightTab", rightTab);
    } catch {
      // ignore
    }
  }, [rightTab]);

  useEffect(() => {
    try {
      const v = window.localStorage.getItem("vip:vulnTask:viewMode");
      if (v === "list" || v === "board") setViewMode(v);
    } catch {
      // ignore
    }
  }, []);

  useEffect(() => {
    try {
      window.localStorage.setItem("vip:vulnTask:viewMode", viewMode);
    } catch {
      // ignore
    }
  }, [viewMode]);

  const reviewDateRef = useRef<HTMLInputElement | null>(null);
  const decisionRef = useRef<HTMLInputElement | null>(null);
  const decisionNotesRef = useRef<HTMLTextAreaElement | null>(null);
  const evidenceRef = useRef<HTMLTextAreaElement | null>(null);

  const readPatchFieldsForValidation = useCallback((nextStatus: string) => {
    const patch: Record<string, unknown> = { status: nextStatus };
    const reviewDate = reviewDateRef.current?.value?.trim() ?? "";
    const decision = decisionRef.current?.value?.trim() ?? "";
    const decisionNotes = decisionNotesRef.current?.value?.trim() ?? "";
    const evidence = evidenceRef.current?.value?.trim() ?? "";
    if (reviewDate) patch.reviewDate = new Date(reviewDate).toISOString();
    if (decision) patch.decision = decision;
    if (decisionNotes) patch.decisionNotes = decisionNotes;
    if (evidence) patch.evidence = evidence;
    return patch;
  }, []);

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
    const title =
      newTitle.trim() || `${vendorDisplay}${productDisplay ? ` / ${productDisplay}` : ""} — кампания по уязвимостям`;
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
    await listQuery.refetch();
    if (j && typeof j === "object" && !Array.isArray(j) && "id" in j) {
      const id = (j as Record<string, unknown>).id;
      if (typeof id === "string" && id) {
        setSelected(id);
        onSelectTaskId?.(id);
      }
    }
  }, [newVendor, newProduct, newTitle, listQuery, onSelectTaskId]);

  const withAutoAssignee = useCallback(
    (patch: Record<string, unknown>) => {
      if (typeof patch.status !== "string" || patch.owner !== undefined) return patch;
      const st = normalizeUiTaskStatus(patch.status);
      if (st === "in_progress" && meEmail) return { ...patch, owner: meEmail };
      if (st === "new") return { ...patch, owner: null };
      return patch;
    },
    [meEmail]
  );

  const savePatch = useCallback(
    async (patch: Record<string, unknown>) => {
      if (!selected || saveBusy) return;
      setSaveBusy(true);
      setSaveErr(null);
      try {
        const body = withAutoAssignee(patch);
        const res = await apiFetch(`/api/vuln-tasks/${encodeURIComponent(selected)}`, {
          method: "PATCH",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(body)
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
    },
    [selected, saveBusy, detailQuery, listQuery, withAutoAssignee]
  );

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

  const removeCve = useCallback(
    async (cveId: string) => {
      if (!selected) return;
      const res = await apiFetch(
        `/api/vuln-tasks/${encodeURIComponent(selected)}/cves/${encodeURIComponent(cveId)}/remove`,
        { method: "POST" }
      );
      if (!res.ok) throw new Error("remove failed");
      await detailQuery.refetch();
      await listQuery.refetch();
    },
    [selected, detailQuery, listQuery]
  );

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
        const body = withAutoAssignee(patch);
        const res = await apiFetch(`/api/vuln-tasks/${encodeURIComponent(taskId)}`, {
          method: "PATCH",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(body)
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
    [detailQuery, listQuery, selected, withAutoAssignee]
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
          const msg =
            failed[0]?.reason instanceof Error ? failed[0].reason.message : String(failed[0]?.reason ?? "Bulk patch failed");
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
      const ow = Object.prototype.hasOwnProperty.call(optimisticOwner, t.id)
        ? optimisticOwner[t.id]
        : undefined;
      if (!st && ow === undefined) return t;
      return {
        ...t,
        ...(st ? { status: st } : null),
        ...(ow !== undefined ? { owner: ow } : null)
      } as TaskListRow;
    });
    const filtered = applyQuickFilters(withOptimistic);

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
  }, [items, optimisticStatus, optimisticOwner, applyQuickFilters, boardOrder]);

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

      const toNorm = normalizeUiTaskStatus(toStatus);
      const nextOwner =
        toNorm === "in_progress" && meEmail ? meEmail : toNorm === "new" ? null : undefined;
      setOptimisticStatus((m) => ({ ...m, [taskId]: toStatus }));
      if (nextOwner !== undefined) {
        setOptimisticOwner((m) => ({ ...m, [taskId]: nextOwner }));
      }
      try {
        await patchTask(taskId, { status: toStatus });
        setOptimisticStatus((m) => {
          const n = { ...m };
          delete n[taskId];
          return n;
        });
        setOptimisticOwner((m) => {
          const n = { ...m };
          delete n[taskId];
          return n;
        });
      } catch (err) {
        setOptimisticStatus((m) => {
          const n = { ...m };
          if (fromStatus) n[taskId] = fromStatus;
          else delete n[taskId];
          return n;
        });
        setOptimisticOwner((m) => {
          const n = { ...m };
          delete n[taskId];
          return n;
        });
        setSelected(taskId);
        setRightTab("fields");
        setSaveErr(err instanceof Error ? err.message : String(err));
      }
    },
    [patchTask, columns, meEmail]
  );

  const showBoard = viewMode === "board";
  const hasQuickFilters =
    boardGroupBy !== "none" || quickKevOnly || quickNeedsReview || quickMinScore != null || quickMine;
  const resetQuickFilters = () => {
    setBoardGroupBy("none");
    setQuickKevOnly(false);
    setQuickNeedsReview(false);
    setQuickMinScore(null);
    setQuickMine(false);
  };

  const openTask = useCallback(
    (id: string) => {
      setSelected(id);
      setRightTab("fields");
      onSelectTaskId?.(id);
    },
    [onSelectTaskId]
  );

  const closeTask = useCallback(() => {
    setSelected(null);
    onSelectTaskId?.(null);
  }, [onSelectTaskId]);

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
        closeTask();
        return;
      }

      const idx = selected ? listItems.findIndex((t) => t.id === selected) : -1;
      const nextIdx =
        e.key === "ArrowDown"
          ? Math.min(listItems.length - 1, Math.max(0, idx + 1))
          : e.key === "ArrowUp"
            ? Math.max(0, idx <= 0 ? 0 : idx - 1)
            : idx;
      const next = listItems[nextIdx] ?? listItems[0]!;
      openTask(next.id);
      requestAnimationFrame(() => listRowRefs.current[next.id]?.scrollIntoView({ block: "nearest" }));
    };
    el.addEventListener("keydown", onKeyDown);
    return () => el.removeEventListener("keydown", onKeyDown);
  }, [showBoard, listItems, selected, openTask, closeTask]);

  useEffect(() => {
    if (!selected) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") closeTask();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [selected, closeTask]);

  const quickFilterBar = (
    <div className="flex flex-wrap items-center gap-1.5">
      <FilterChip active={quickKevOnly} tone="danger" onClick={() => setQuickKevOnly((v) => !v)}>
        KEV
      </FilterChip>
      <FilterChip active={quickNeedsReview} tone="warn" onClick={() => setQuickNeedsReview((v) => !v)}>
        Review
      </FilterChip>
      <FilterChip
        active={quickMinScore != null}
        tone="accent"
        title="≥70 → ≥85 → off"
        onClick={() => setQuickMinScore((v) => (v == null ? 70 : v === 70 ? 85 : null))}
      >
        Score {quickMinScore == null ? "—" : `≥${quickMinScore}`}
      </FilterChip>
      <FilterChip active={quickMine} tone="accent" title="Только мои (по исполнителю)" onClick={() => setQuickMine((v) => !v)}>
        Mine
      </FilterChip>
      {showBoard ? (
        <>
          <span className="mx-1 h-3 w-px bg-border" />
          <span className="text-[10px] text-muted">Swimlanes</span>
          {(["none", "vendor", "owner"] as const).map((g) => (
            <FilterChip key={g} active={boardGroupBy === g} onClick={() => setBoardGroupBy(g)}>
              {g === "none" ? "off" : g === "owner" ? "исполнитель" : g}
            </FilterChip>
          ))}
        </>
      ) : null}
      {hasQuickFilters ? (
        <button type="button" onClick={resetQuickFilters} className="text-[11px] text-muted underline-offset-2 hover:underline">
          Сброс
        </button>
      ) : null}
    </div>
  );

  const boardBody =
    items.length === 0 && !listQuery.isLoading ? (
      <div className="px-1 py-8 text-center text-sm text-muted">Пока нет задач.</div>
    ) : boardGroupBy === "none" ? (
      <DndContext sensors={sensors} collisionDetection={closestCenter} onDragStart={onDragStart} onDragEnd={onDragEnd}>
        <div className="flex gap-2 overflow-x-auto pb-1">
          {columns.map((col) => (
            <BoardColumn
              key={col.key}
              colKey={col.key}
              title={col.title}
              count={col.items.length}
              items={col.items.map((t) => `task:${t.id}`)}
              dragging={!!draggingTaskId}
            >
              {col.items.map((t) => (
                <TaskCardDraggable
                  key={t.id}
                  task={t}
                  active={selected === t.id}
                  containerId={col.key}
                  onClick={() => openTask(t.id)}
                />
              ))}
            </BoardColumn>
          ))}
        </div>
        <DragOverlay dropAnimation={null}>{draggingTask ? <TaskCardGhost task={draggingTask} /> : null}</DragOverlay>
      </DndContext>
    ) : (
      <div className="flex gap-2 overflow-x-auto pb-1">
        {columns.map((col) => (
          <div
            key={col.key}
            className={cn(
              "flex w-[260px] shrink-0 flex-col overflow-hidden rounded border border-border bg-slate-50/70 dark:bg-white/[0.03]",
              "max-h-[min(640px,calc(100vh-280px))] border-t-2",
              statusMeta(col.key).colTint
            )}
          >
            <div className="flex items-center justify-between gap-2 border-b border-border/70 px-2.5 py-1.5">
              <div className="text-[11px] font-semibold text-fg/85">{col.title}</div>
              <span className="text-[10px] tabular-nums text-muted">{col.items.length}</span>
            </div>
            <div className="flex-1 space-y-1.5 overflow-auto p-1.5">
              {(() => {
                let lastGroup = "";
                return col.items.map((t) => {
                  const g = groupKeyFor(t);
                  const showHeader = g !== lastGroup;
                  lastGroup = g;
                  return (
                    <div key={t.id}>
                      {showHeader ? (
                        <div className="mb-1 mt-2 truncate px-0.5 text-[10px] font-medium uppercase tracking-wide text-muted">
                          {g}
                        </div>
                      ) : null}
                      <button
                        type="button"
                        onClick={() => openTask(t.id)}
                        className={cn(
                          "w-full rounded border px-2 py-1.5 text-left transition",
                          selected === t.id
                            ? "border-accent/45 bg-accent/[0.07]"
                            : "border-border/80 bg-white hover:bg-slate-50 dark:bg-black/25 dark:hover:bg-black/40"
                        )}
                      >
                        <div className="flex items-center gap-1.5">
                          <PriorityMark priority={t.priority_local} />
                          <span className="font-mono text-[10px] text-muted">{taskIssueKey(t.id)}</span>
                          <span className={cn("ml-auto text-[10px] font-semibold tabular-nums", scoreTone(t.score_final))}>
                            {t.score_final}
                          </span>
                        </div>
                        <div className="mt-0.5 line-clamp-2 text-[12px] font-medium leading-4">{t.title}</div>
                      </button>
                    </div>
                  );
                });
              })()}
            </div>
            <div className="border-t border-border/60 px-2 py-1 text-[10px] text-muted">Swimlanes: DnD выкл.</div>
          </div>
        ))}
      </div>
    );

  const detailsView = () => {
    const activeStatus = normalizeUiTaskStatus(active?.status);
    const activeClosureText = `${active?.evidence ?? ""}${active?.decision_notes ?? ""}`.trim();
    const key = selected ? taskIssueKey(selected) : "";
    return (
      <div className="flex min-h-0 flex-col">
        <div className="sticky top-0 z-10 border-b border-border bg-white/95 px-4 py-3 backdrop-blur dark:bg-black/80">
          <div className="flex items-start gap-3">
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-[12px] font-semibold text-accent">{key}</span>
                <StatusChip status={activeStatus} compact />
                <span className={cn("text-[11px] font-semibold tabular-nums", scoreTone(Number(active?.score_final ?? 0)))}>
                  Score {Number(active?.score_final ?? 0)}
                </span>
              </div>
              <h2 className="mt-1 text-[15px] font-semibold leading-snug tracking-tight text-fg/95">
                {active?.title ?? selected}
              </h2>
              <div className="mt-0.5 text-[11px] text-muted">
                {active?.vendor_display}
                {active?.product_display ? ` / ${active?.product_display}` : ""}
              </div>
            </div>
            <div className="flex shrink-0 items-center gap-1.5">
              <button
                type="button"
                onClick={() => void refresh()}
                className="rounded border border-border p-1.5 text-muted hover:bg-black/[0.03] hover:text-fg dark:hover:bg-white/5"
                title="Обновить"
              >
                <RefreshCw className={cn("h-3.5 w-3.5", listQuery.isFetching || detailQuery.isFetching ? "animate-spin" : "")} />
              </button>
              <button
                type="button"
                onClick={closeTask}
                className="rounded border border-border p-1.5 text-muted hover:bg-black/[0.03] hover:text-fg dark:hover:bg-white/5"
                title="Закрыть"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>

          <div className="mt-2.5 flex flex-wrap items-center gap-1">
            {TASK_STATUS_COLUMNS.map((s) => (
              <button
                key={s.key}
                type="button"
                onClick={() => void savePatch(readPatchFieldsForValidation(s.key))}
                disabled={saveBusy || activeStatus === s.key}
                className={cn(
                  "rounded border px-2 py-0.5 text-[11px] font-medium transition",
                  activeStatus === s.key
                    ? "border-accent/40 bg-accent/10 text-fg/90"
                    : "border-border text-muted hover:bg-black/[0.03] hover:text-fg/85 dark:hover:bg-white/5",
                  saveBusy || activeStatus === s.key ? "cursor-default opacity-70" : ""
                )}
              >
                {s.title}
              </button>
            ))}
          </div>

          <div className="mt-2 flex gap-0 border-b border-border">
            {(
              [
                { key: "fields", label: "Детали" },
                { key: "cves", label: `CVE (${activeCves.length})` },
                { key: "events", label: `История (${activeEvents.length})` }
              ] as const
            ).map((t) => (
              <button
                key={t.key}
                type="button"
                onClick={() => setRightTab(t.key)}
                className={cn(
                  "-mb-px border-b-2 px-3 py-1.5 text-[12px] font-medium transition",
                  rightTab === t.key
                    ? "border-accent text-fg/90"
                    : "border-transparent text-muted hover:text-fg/80"
                )}
              >
                {t.label}
              </button>
            ))}
          </div>
        </div>

        <div className="flex-1 space-y-3 overflow-y-auto px-4 py-3">
          {rightTab === "fields" ? (
            <div>
              {saveErr ? <div className="mb-2 text-[11px] text-rose-700">{saveErr}</div> : null}
              {saveBusy ? <div className="mb-2 text-[11px] text-muted">Сохраняем…</div> : null}
              {activeStatus === "closed" && !activeClosureText ? (
                <div className="mb-2 rounded border border-warn/25 bg-warn/10 px-2.5 py-1.5 text-[11px] text-warn">
                  Закрыта без evidence/decision notes — добавьте обоснование.
                </div>
              ) : null}

              <div className="grid grid-cols-2 gap-x-3 gap-y-2.5">
                <label className="block">
                  <span className="text-[10px] font-medium uppercase tracking-wide text-muted">Статус</span>
                  <select
                    defaultValue={normalizeUiTaskStatus(active?.status)}
                    onChange={(e) => void savePatch(readPatchFieldsForValidation(e.target.value))}
                    className="mt-0.5 w-full rounded border border-border bg-transparent px-2 py-1.5 text-[13px]"
                  >
                    <option value="new">Новая</option>
                    <option value="in_progress">В работе</option>
                    <option value="closed">Закрыта</option>
                  </select>
                </label>
                <label className="block">
                  <span className="text-[10px] font-medium uppercase tracking-wide text-muted">Приоритет</span>
                  <select
                    defaultValue={String(active?.priority_local ?? "medium")}
                    onChange={(e) => void savePatch({ priorityLocal: e.target.value })}
                    className="mt-0.5 w-full rounded border border-border bg-transparent px-2 py-1.5 text-[13px]"
                  >
                    <option value="low">Низкий</option>
                    <option value="medium">Средний</option>
                    <option value="high">Высокий</option>
                    <option value="critical">Критичный</option>
                  </select>
                </label>
                <label className="col-span-2 block sm:col-span-1">
                  <span className="text-[10px] font-medium uppercase tracking-wide text-muted">Исполнитель</span>
                  <input
                    key={`owner-${selected}-${String(active?.owner ?? "")}`}
                    defaultValue={String(active?.owner ?? "")}
                    onBlur={(e) => void savePatch({ owner: e.target.value || null })}
                    className="mt-0.5 w-full rounded border border-border bg-transparent px-2 py-1.5 text-[13px]"
                    placeholder="ставится при «В работе»"
                  />
                </label>
                <label className="block">
                  <span className="text-[10px] font-medium uppercase tracking-wide text-muted">Due</span>
                  <input
                    defaultValue={active?.due_date ? String(active.due_date).slice(0, 10) : ""}
                    onBlur={(e) => void savePatch({ dueDate: e.target.value ? new Date(e.target.value).toISOString() : null })}
                    type="date"
                    className="mt-0.5 w-full rounded border border-border bg-transparent px-2 py-1.5 text-[13px]"
                  />
                </label>
                <label className="block">
                  <span className="text-[10px] font-medium uppercase tracking-wide text-muted">Review</span>
                  <input
                    ref={reviewDateRef}
                    defaultValue={active?.review_date ? String(active.review_date).slice(0, 10) : ""}
                    onBlur={(e) =>
                      void savePatch({ reviewDate: e.target.value ? new Date(e.target.value).toISOString() : null })
                    }
                    type="date"
                    className="mt-0.5 w-full rounded border border-border bg-transparent px-2 py-1.5 text-[13px]"
                  />
                </label>
                <label className="block">
                  <span className="text-[10px] font-medium uppercase tracking-wide text-muted">Decision</span>
                  <input
                    ref={decisionRef}
                    defaultValue={String(active?.decision ?? "")}
                    onBlur={(e) => void savePatch({ decision: e.target.value || null })}
                    className="mt-0.5 w-full rounded border border-border bg-transparent px-2 py-1.5 text-[13px]"
                    placeholder="patch / mitigation / accept"
                  />
                </label>
                <label className="col-span-2 block">
                  <span className="text-[10px] font-medium uppercase tracking-wide text-muted">Decision notes</span>
                  <textarea
                    ref={decisionNotesRef}
                    defaultValue={String(active?.decision_notes ?? "")}
                    onBlur={(e) => void savePatch({ decisionNotes: e.target.value || null })}
                    className="mt-0.5 w-full rounded border border-border bg-transparent px-2 py-1.5 text-[13px]"
                    rows={2}
                    placeholder="Почему так решили…"
                  />
                </label>
                <label className="col-span-2 block">
                  <span className="text-[10px] font-medium uppercase tracking-wide text-muted">Evidence</span>
                  <textarea
                    ref={evidenceRef}
                    defaultValue={String(active?.evidence ?? "")}
                    onBlur={(e) => void savePatch({ evidence: e.target.value || null })}
                    className="mt-0.5 w-full rounded border border-border bg-transparent px-2 py-1.5 text-[13px]"
                    rows={2}
                    placeholder="Advisory / версия / тикет / проверка…"
                  />
                </label>
                <label className="col-span-2 block">
                  <span className="text-[10px] font-medium uppercase tracking-wide text-muted">Notes (Markdown)</span>
                  <textarea
                    defaultValue={String(active?.notes_md ?? "")}
                    onBlur={(e) => void savePatch({ notesMd: e.target.value })}
                    className="mt-0.5 w-full rounded border border-border bg-transparent px-2 py-1.5 font-mono text-[12px]"
                    rows={6}
                  />
                </label>
              </div>
            </div>
          ) : null}

          {rightTab === "cves" ? (
            <div>
              <div className="flex items-center justify-between gap-2">
                <div className="text-[11px] text-muted">CVE в задаче</div>
                <button
                  type="button"
                  onClick={() => setAddOpen((v) => !v)}
                  className="inline-flex items-center gap-1 rounded border border-border px-2 py-1 text-[11px] hover:bg-black/[0.03] dark:hover:bg-white/5"
                >
                  <Search className="h-3 w-3" />
                  Добавить
                </button>
              </div>
              {addOpen ? (
                <div className="mt-2 rounded border border-border bg-slate-50/80 p-2 dark:bg-white/[0.03]">
                  <div className="flex items-center gap-2">
                    <input
                      value={addQ}
                      onChange={(e) => setAddQ(e.target.value)}
                      placeholder="CVE-… или vendor/product (≥3)"
                      className="w-full rounded border border-border bg-transparent px-2 py-1.5 text-[13px]"
                    />
                    <button
                      type="button"
                      onClick={() => void addCves()}
                      className="shrink-0 rounded border border-accent/30 bg-accent/10 px-2.5 py-1.5 text-[12px]"
                    >
                      Добавить
                    </button>
                  </div>
                  <div className="mt-2 max-h-48 space-y-1 overflow-auto">
                    {(cveSearchQuery.data?.items ?? []).slice(0, 20).map((c) => {
                      const id = String((c as Record<string, unknown>).cve_id ?? "");
                      return (
                        <label
                          key={id}
                          className="flex cursor-pointer items-start gap-2 rounded border border-transparent px-1.5 py-1 hover:border-border hover:bg-white dark:hover:bg-black/20"
                        >
                          <input
                            type="checkbox"
                            className="mt-0.5"
                            checked={Boolean(addPicked[id])}
                            onChange={(e) =>
                              setAddPicked((m) => {
                                const n = { ...m };
                                if (e.target.checked) n[id] = true;
                                else delete n[id];
                                return n;
                              })
                            }
                          />
                          <div className="min-w-0">
                            <div className="font-mono text-[12px] font-semibold">{id}</div>
                            <div className="line-clamp-1 text-[11px] text-muted">
                              {String(
                                (c as Record<string, unknown>).short_ru ??
                                  (c as Record<string, unknown>).short_description ??
                                  ""
                              )}
                            </div>
                          </div>
                        </label>
                      );
                    })}
                  </div>
                </div>
              ) : null}
              <div className="mt-2 divide-y divide-border/70 rounded border border-border">
                {activeCves.length === 0 ? (
                  <div className="px-3 py-6 text-center text-[11px] text-muted">Нет связанных CVE.</div>
                ) : (
                  activeCves.slice(0, 50).map((c) => (
                    <div key={c.cve_id} className="flex items-start gap-2 px-2.5 py-1.5">
                      <button
                        type="button"
                        onClick={() => onOpenCve?.(String(c.cve_id))}
                        className="min-w-0 flex-1 text-left hover:underline"
                      >
                        <div className="font-mono text-[12px] font-semibold">{String(c.cve_id)}</div>
                        <div className="text-[10px] text-muted">
                          {c.exploit_known ? "KEV · " : ""}
                          EPSS {typeof c.epss === "number" ? `${(Number(c.epss) * 100).toFixed(2)}%` : "—"} · CVSS{" "}
                          {typeof c.cvss_base === "number" ? Number(c.cvss_base).toFixed(1) : "—"}
                        </div>
                      </button>
                      <div className="text-[11px] tabular-nums text-muted">
                        {typeof c.risk_score === "number" ? c.risk_score : "—"}
                      </div>
                      <button
                        type="button"
                        onClick={() => void removeCve(String(c.cve_id))}
                        className="rounded p-1 text-muted hover:bg-danger/10 hover:text-danger"
                        title="Убрать"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  ))
                )}
              </div>
              {activeCves.length > 50 ? <div className="mt-1 text-[10px] text-muted">Показаны первые 50…</div> : null}
            </div>
          ) : null}

          {rightTab === "events" ? (
            <div>
              {activeEvents.length === 0 ? (
                <div className="py-6 text-center text-[11px] text-muted">Пока нет событий.</div>
              ) : (
                <div className="space-y-1.5">
                  {activeEvents.slice(0, 80).map((ev, idx: number) => (
                    <div
                      key={`${String(ev?.id ?? "")}-${idx}`}
                      className="rounded border border-border/80 px-2.5 py-1.5 text-[11px]"
                    >
                      <div className="flex items-center justify-between gap-2">
                        <div className="min-w-0 truncate font-mono text-[10px]">
                          {String(ev?.action ?? "event")}
                          {ev?.actor ? <span className="ml-1.5 text-muted">· {String(ev.actor)}</span> : null}
                        </div>
                        <div className="shrink-0 font-mono text-[10px] tabular-nums text-muted">
                          {ev?.ts ? new Date(String(ev.ts)).toLocaleString() : "—"}
                        </div>
                      </div>
                      {ev?.meta ? (
                        <pre className="mt-1 max-h-28 overflow-auto rounded bg-slate-50 p-1.5 text-[10px] text-fg/75 dark:bg-black/30">
                          {JSON.stringify(ev.meta, null, 2).slice(0, 3000)}
                        </pre>
                      ) : null}
                    </div>
                  ))}
                </div>
              )}
            </div>
          ) : null}
        </div>
      </div>
    );
  };

  const inputCls = "rounded border border-border bg-transparent px-2 py-1.5 text-[13px] placeholder:text-muted/70";

  return (
    <div className="flex min-h-0 flex-col gap-2.5">
      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-2 border-b border-border/80 pb-2.5">
        <div className="min-w-0">
          <div className="text-[13px] font-semibold text-fg/90">Задачи</div>
        </div>

        <div className="flex items-center rounded border border-border p-0.5">
          <button
            type="button"
            onClick={() => setViewMode("list")}
            className={cn(
              "inline-flex items-center gap-1 rounded px-2 py-1 text-[11px] font-medium",
              viewMode === "list" ? "bg-accent/15 text-fg/90" : "text-muted hover:text-fg/80"
            )}
            title="Список"
          >
            <LayoutList className="h-3.5 w-3.5" />
            Список
          </button>
          <button
            type="button"
            onClick={() => setViewMode("board")}
            className={cn(
              "inline-flex items-center gap-1 rounded px-2 py-1 text-[11px] font-medium",
              viewMode === "board" ? "bg-accent/15 text-fg/90" : "text-muted hover:text-fg/80"
            )}
            title="Доска"
          >
            <Columns3 className="h-3.5 w-3.5" />
            Доска
          </button>
        </div>

        <div className="relative min-w-[180px] flex-1">
          <Search className="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted" />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Поиск: название, vendor, product…"
            className={cn(inputCls, "w-full pl-7")}
          />
        </div>

        {!showBoard ? (
          <>
            <select value={status} onChange={(e) => setStatus(e.target.value)} className={inputCls} title="Статус">
              <option value="">Все статусы</option>
              <option value="new">Новая</option>
              <option value="in_progress">В работе</option>
              <option value="closed">Закрыта</option>
            </select>
            <select
              value={listSort}
              onChange={(e) => setListSort(e.target.value as typeof listSort)}
              className={inputCls}
              title="Сортировка"
            >
              <option value="score">Score</option>
              <option value="priority">Priority</option>
              <option value="updated">Updated</option>
              <option value="title">Title</option>
            </select>
            <button
              type="button"
              onClick={() => setListSortDir((d) => (d === "desc" ? "asc" : "desc"))}
              className={cn(inputCls, "px-2.5")}
              title="Направление"
            >
              {listSortDir === "desc" ? "↓" : "↑"}
            </button>
          </>
        ) : null}

        <button
          type="button"
          onClick={() => void refresh()}
          className="inline-flex items-center gap-1 rounded border border-border px-2 py-1.5 text-[11px] text-fg/80 hover:bg-black/[0.03] dark:hover:bg-white/5"
          title="Обновить"
        >
          {listQuery.isFetching ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
        </button>
        <button
          type="button"
          onClick={() => setCreateOpen((v) => !v)}
          className="inline-flex items-center gap-1 rounded border border-accent/30 bg-accent/10 px-2.5 py-1.5 text-[11px] font-medium text-fg/90 hover:bg-accent/15"
        >
          <Plus className="h-3.5 w-3.5" />
          Создать
        </button>
      </div>

      {/* Compact stats + filters */}
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-muted">
          <span>
            <span className="font-semibold tabular-nums text-fg/85">{taskStats.total}</span> всего
          </span>
          <span>
            <span className="font-semibold tabular-nums text-fg/85">{taskStats.new}</span> новые
          </span>
          <span>
            <span className="font-semibold tabular-nums text-fg/85">{taskStats.in_progress}</span> в работе
          </span>
          <span>
            <span className="font-semibold tabular-nums text-fg/85">{taskStats.closed}</span> закрыты
          </span>
          <span>
            KEV <span className="font-semibold tabular-nums text-fg/85">{taskStats.kev}</span>
            {" · "}≥70 <span className="font-semibold tabular-nums text-fg/85">{taskStats.high}</span>
          </span>
          {listQuery.isFetching ? <span className="text-muted/70">обновляем…</span> : null}
        </div>
        {quickFilterBar}
      </div>

      {createOpen ? (
        <div className="rounded border border-border bg-slate-50/80 p-2.5 dark:bg-white/[0.03]">
          <div className="mb-1.5 text-[11px] font-medium text-fg/85">Новая задача</div>
          <div className="grid gap-1.5 sm:grid-cols-2 lg:grid-cols-4">
            <input
              value={newTitle}
              onChange={(e) => setNewTitle(e.target.value)}
              placeholder="Название (опционально)"
              className={cn(inputCls, "sm:col-span-2")}
            />
            <input
              list="vip-vendors"
              value={newVendor}
              onChange={(e) => setNewVendor(e.target.value)}
              placeholder="Vendor *"
              className={inputCls}
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
              placeholder="Product"
              className={inputCls}
            />
            <datalist id="vip-products">
              {productOptions.map((p) => (
                <option key={`${p.vendor}:${p.product}`} value={p.product} />
              ))}
            </datalist>
            <button
              type="button"
              onClick={() => void createTask()}
              className="rounded border border-accent/30 bg-accent/10 px-3 py-1.5 text-[12px] font-medium hover:bg-accent/15 sm:col-span-2 lg:col-span-4"
            >
              Создать задачу
            </button>
          </div>
        </div>
      ) : null}

      {/* List view */}
      {!showBoard ? (
        <div className="overflow-hidden rounded border border-border">
          {pickedCount > 0 ? (
            <div className="flex flex-wrap items-center gap-2 border-b border-accent/20 bg-accent/10 px-2.5 py-1.5">
              <span className="text-[11px] font-medium">
                Выбрано: <span className="tabular-nums">{pickedCount}</span>
              </span>
              <button type="button" onClick={selectAllVisible} className="text-[11px] text-fg/80 underline-offset-2 hover:underline">
                Все видимые
              </button>
              <select
                defaultValue=""
                onChange={(e) => {
                  const v = e.target.value;
                  if (!v) return;
                  void bulkPatch({ status: v });
                  e.currentTarget.value = "";
                }}
                className="rounded border border-border bg-white/70 px-1.5 py-0.5 text-[11px] dark:bg-black/30"
              >
                <option value="">Статус…</option>
                <option value="new">Новая</option>
                <option value="in_progress">В работе</option>
                <option value="closed">Закрыта</option>
              </select>
              <input
                value={bulkOwner}
                onChange={(e) => setBulkOwner(e.target.value)}
                placeholder="Исполнитель…"
                className="w-[120px] rounded border border-border bg-white/70 px-1.5 py-0.5 text-[11px] dark:bg-black/30"
              />
              <button
                type="button"
                disabled={saveBusy}
                onClick={() => void bulkPatch({ owner: bulkOwner.trim() ? bulkOwner.trim() : null })}
                className="text-[11px] underline-offset-2 hover:underline"
              >
                Назначить
              </button>
              <button type="button" onClick={clearPicked} className="ml-auto text-[11px] text-muted hover:text-fg/80">
                Снять
              </button>
              {saveErr ? <div className="w-full text-[11px] text-rose-700">{saveErr}</div> : null}
            </div>
          ) : null}

          <div
            className="sticky top-0 z-[1] hidden grid-cols-[28px_88px_minmax(0,1fr)_100px_72px_minmax(100px,140px)_44px_72px] gap-2 border-b border-border bg-slate-50/95 px-2 py-1.5 text-[10px] font-medium uppercase tracking-wide text-muted backdrop-blur md:grid dark:bg-black/50"
          >
            <div />
            <div>Ключ</div>
            <div>Summary</div>
            <div>Статус</div>
            <div>Prio</div>
            <div>Исполнитель</div>
            <div className="text-right">Score</div>
            <div className="text-right">Updated</div>
          </div>

          <div
            ref={listContainerRef}
            tabIndex={0}
            className="max-h-[calc(100vh-320px)] overflow-auto outline-none focus:ring-1 focus:ring-accent/30"
            title="↑/↓ · Enter · Esc"
          >
            {listQuery.isLoading ? (
              <div className="px-3 py-8 text-center text-sm text-muted">Загрузка…</div>
            ) : listItems.length === 0 ? (
              <div className="px-3 py-8 text-center text-sm text-muted">
                {items.length === 0 ? "Пока нет задач." : "По текущим фильтрам задач нет."}
              </div>
            ) : (
              listItems.map((t) => {
                const activeRow = selected === t.id;
                const picked = !!listPicked[t.id];
                const kevCount = t.stats?.kevCount ?? 0;
                const cveCount = t.stats?.cveCount;
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
                      openTask(t.id);
                    }}
                    className={cn(
                      "grid cursor-pointer grid-cols-[28px_minmax(0,1fr)] items-center gap-2 border-b border-border/60 px-2 py-1.5 text-left transition md:grid-cols-[28px_88px_minmax(0,1fr)_100px_72px_minmax(100px,140px)_44px_72px]",
                      activeRow ? "bg-accent/[0.08]" : "hover:bg-black/[0.025] dark:hover:bg-white/[0.04]",
                      picked ? "bg-accent/[0.05]" : ""
                    )}
                    aria-selected={activeRow}
                  >
                    <div>
                      <input
                        type="checkbox"
                        checked={picked}
                        onChange={(e) => {
                          togglePick(t.id, e.target.checked);
                          lastPickIdRef.current = t.id;
                        }}
                        onClick={(e) => e.stopPropagation()}
                        className="h-3.5 w-3.5 rounded border-slate-300"
                      />
                    </div>
                    <div className="hidden font-mono text-[11px] font-medium text-accent md:block">{taskIssueKey(t.id)}</div>
                    <div className="min-w-0">
                      <div className="flex items-center gap-1.5">
                        <span className="truncate text-[13px] font-medium text-fg/90">{t.title}</span>
                        {kevCount > 0 ? <span className="shrink-0 text-[10px] font-semibold text-danger">KEV</span> : null}
                      </div>
                      <div className="mt-0.5 flex items-center gap-2 truncate text-[10px] text-muted md:hidden">
                        <span className="font-mono text-accent">{taskIssueKey(t.id)}</span>
                        <StatusChip status={t.status} compact />
                        {t.owner ? <span className="truncate">· {t.owner}</span> : null}
                      </div>
                      <div className="truncate text-[11px] text-muted">
                        {t.vendor_display}
                        {t.product_display ? ` / ${t.product_display}` : ""}
                        {cveCount != null ? ` · CVE ${cveCount}` : ""}
                      </div>
                    </div>
                    <div className="hidden md:block">
                      <StatusChip status={t.status} compact />
                    </div>
                    <div className="hidden items-center gap-1 md:flex">
                      <PriorityMark priority={t.priority_local} />
                      <span className="text-[10px] text-muted">{priorityMeta(t.priority_local).label.slice(0, 4)}</span>
                    </div>
                    <div className="hidden min-w-0 md:block" title={t.owner ? `В работе у ${t.owner}` : "Без исполнителя"}>
                      <AssigneeCell name={t.owner} />
                    </div>
                    <div className={cn("hidden text-right text-[12px] font-semibold tabular-nums md:block", scoreTone(t.score_final))}>
                      {t.score_final}
                    </div>
                    <div className="hidden text-right text-[10px] tabular-nums text-muted md:block">
                      {t.updated_at ? new Date(t.updated_at).toLocaleDateString() : "—"}
                    </div>
                  </div>
                );
              })
            )}
          </div>
          <div className="border-t border-border/70 px-2.5 py-1 text-[10px] text-muted">
            Показано {listItems.length} из {items.length}
          </div>
        </div>
      ) : (
        <div className="min-h-[320px]">{boardBody}</div>
      )}

      {/* Issue drawer */}
      {selected ? (
        <div className="fixed inset-0 z-[8000]">
          <button type="button" onClick={closeTask} className="absolute inset-0 bg-black/25 backdrop-blur-[1px]" title="Закрыть" />
          <aside className="absolute right-0 top-0 flex h-dvh w-[min(560px,96vw)] flex-col border-l border-border bg-white shadow-2xl dark:bg-[#0b1220]">
            {detailQuery.isLoading ? (
              <div className="p-4 text-sm text-muted">Загрузка…</div>
            ) : detailQuery.isError ? (
              <div className="p-4 text-sm text-danger">Не удалось загрузить задачу.</div>
            ) : (
              detailsView()
            )}
          </aside>
        </div>
      ) : null}
    </div>
  );
}
