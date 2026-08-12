"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
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
import { SortableContext, arrayMove, verticalListSortingStrategy } from "@dnd-kit/sortable";
import {
  AssigneeCell,
  DueBadge,
  Field,
  FilterChip,
  MetaRow,
  PriorityBadge,
  ScoreBadge,
  SectionCard,
  SelectField,
  StatusChip,
  TASK_STATUS_COLUMNS,
  TextareaField,
  TextField,
  controlCls,
  normalizeUiTaskStatus,
  priorityMeta,
  scoreTone,
  statusMeta,
  taskIssueKey,
  type TaskStatus
} from "./vuln-task-ui";
import { TaskCardDraggable, TaskCardGhost, TaskCardStatic } from "./vuln-task-card";

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
        "flex w-[300px] shrink-0 flex-col overflow-hidden rounded-xl border border-border bg-slate-50/80 dark:bg-white/[0.03]",
        "max-h-[min(680px,calc(100vh-260px))] border-t-[3px]",
        tint,
        isOver ? "ring-2 ring-accent/30" : "",
        dragging ? "transition-[box-shadow] duration-150" : ""
      )}
    >
      <div className="flex items-center justify-between gap-2 border-b border-border/70 px-3 py-2">
        <div className="flex items-center gap-2 text-[12px] font-semibold text-fg/90">
          <span className={cn("h-2 w-2 rounded-full", statusMeta(colKey).dot)} />
          {title}
        </div>
        <span className="rounded-md bg-black/[0.05] px-1.5 py-0.5 text-[11px] font-semibold tabular-nums text-fg/75 dark:bg-white/10">
          {count}
        </span>
      </div>
      <div className={cn("flex-1 space-y-2 overflow-auto p-2", isOver ? "bg-accent/[0.04]" : "")}>
        <SortableContext items={items} strategy={verticalListSortingStrategy}>
          {count === 0 ? (
            <div
              className={cn(
                "rounded-xl border border-dashed px-2 py-8 text-center text-[12px] text-muted",
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
      <div className="flex gap-2.5 overflow-x-auto pb-1">
        {columns.map((col) => (
          <div
            key={col.key}
            className={cn(
              "flex w-[300px] shrink-0 flex-col overflow-hidden rounded-xl border border-border bg-slate-50/80 dark:bg-white/[0.03]",
              "max-h-[min(680px,calc(100vh-260px))] border-t-[3px]",
              statusMeta(col.key).colTint
            )}
          >
            <div className="flex items-center justify-between gap-2 border-b border-border/70 px-3 py-2">
              <div className="flex items-center gap-2 text-[12px] font-semibold text-fg/90">
                <span className={cn("h-2 w-2 rounded-full", statusMeta(col.key).dot)} />
                {col.title}
              </div>
              <span className="rounded-md bg-black/[0.05] px-1.5 py-0.5 text-[11px] font-semibold tabular-nums text-fg/75 dark:bg-white/10">
                {col.items.length}
              </span>
            </div>
            <div className="flex-1 space-y-2 overflow-auto p-2">
              {(() => {
                let lastGroup = "";
                return col.items.map((t) => {
                  const g = groupKeyFor(t);
                  const showHeader = g !== lastGroup;
                  lastGroup = g;
                  return (
                    <div key={t.id}>
                      {showHeader ? (
                        <div className="mb-1 mt-1 truncate px-0.5 text-[10px] font-semibold uppercase tracking-wide text-muted">
                          {g}
                        </div>
                      ) : null}
                      <TaskCardStatic task={t} active={selected === t.id} onClick={() => openTask(t.id)} />
                    </div>
                  );
                });
              })()}
            </div>
            <div className="border-t border-border/60 px-2.5 py-1.5 text-[10px] text-muted">Swimlanes: DnD выкл.</div>
          </div>
        ))}
      </div>
    );

  const detailsView = () => {
    const activeStatus = normalizeUiTaskStatus(active?.status);
    const activeClosureText = `${active?.evidence ?? ""}${active?.decision_notes ?? ""}`.trim();
    const key = selected ? taskIssueKey(selected) : "";
    const dueIso = active?.due_date ? String(active.due_date) : null;
    const reviewIso = active?.review_date ? String(active.review_date) : null;
    return (
      <div className="flex min-h-0 flex-col">
        <div className="sticky top-0 z-10 border-b border-border bg-white/95 px-4 py-3.5 backdrop-blur dark:bg-[#0b1220]/95">
          <div className="flex items-start gap-3">
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-[13px] font-bold text-accent">{key}</span>
                <StatusChip status={activeStatus} />
                <ScoreBadge score={Number(active?.score_final ?? 0)} />
                <PriorityBadge priority={String(active?.priority_local ?? "medium")} />
              </div>
              <h2 className="mt-2 text-[17px] font-semibold leading-snug tracking-tight text-fg/95">
                {active?.title ?? selected}
              </h2>
              <MetaRow
                vendor={active?.vendor_display}
                product={active?.product_display}
                className="mt-1 text-[12px]"
              />
            </div>
            <div className="flex shrink-0 items-center gap-1.5">
              <button
                type="button"
                onClick={() => void refresh()}
                className="rounded-lg border border-border p-2 text-muted hover:bg-slate-50 hover:text-fg dark:hover:bg-white/5"
                title="Обновить"
              >
                <RefreshCw
                  className={cn(
                    "h-3.5 w-3.5",
                    listQuery.isFetching || detailQuery.isFetching ? "animate-spin" : ""
                  )}
                />
              </button>
              <button
                type="button"
                onClick={closeTask}
                className="rounded-lg border border-border p-2 text-muted hover:bg-slate-50 hover:text-fg dark:hover:bg-white/5"
                title="Закрыть"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>

          <div className="mt-3 flex flex-wrap gap-1.5 rounded-xl border border-border bg-slate-50/80 p-1 dark:bg-black/30">
            {TASK_STATUS_COLUMNS.map((s) => {
              const activeSeg = activeStatus === s.key;
              return (
                <button
                  key={s.key}
                  type="button"
                  onClick={() => void savePatch(readPatchFieldsForValidation(s.key))}
                  disabled={saveBusy || activeSeg}
                  className={cn(
                    "min-w-[88px] flex-1 rounded-lg border px-3 py-1.5 text-[12px] font-semibold transition",
                    activeSeg
                      ? statusMeta(s.key).segmentActive
                      : "border-transparent text-muted hover:bg-white hover:text-fg/85 dark:hover:bg-white/5",
                    saveBusy || activeSeg ? "cursor-default opacity-90" : ""
                  )}
                >
                  {s.title}
                </button>
              );
            })}
          </div>

          <div className="mt-3 flex gap-0 border-b border-border">
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
                  "-mb-px border-b-2 px-3.5 py-2 text-[13px] font-semibold transition",
                  rightTab === t.key
                    ? "border-accent text-fg/95"
                    : "border-transparent text-muted hover:text-fg/80"
                )}
              >
                {t.label}
              </button>
            ))}
          </div>
        </div>

        <div className="flex-1 space-y-3 overflow-y-auto px-4 py-3.5">
          {rightTab === "fields" ? (
            <div className="space-y-3">
              {saveErr ? (
                <div className="rounded-lg border border-danger/30 bg-danger/10 px-3 py-2 text-[12px] text-danger">
                  {saveErr}
                </div>
              ) : null}
              {saveBusy ? <div className="text-[12px] text-muted">Сохраняем…</div> : null}
              {activeStatus === "closed" && !activeClosureText ? (
                <div className="rounded-lg border border-warn/30 bg-warn/10 px-3 py-2 text-[12px] text-warn">
                  Закрыта без evidence/decision notes — добавьте обоснование.
                </div>
              ) : null}

              <SectionCard title="Workflow">
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                  <SelectField
                    label="Статус"
                    key={`status-${selected}-${activeStatus}`}
                    defaultValue={activeStatus}
                    onChange={(e) => void savePatch(readPatchFieldsForValidation(e.target.value))}
                  >
                    <option value="new">Новая</option>
                    <option value="in_progress">В работе</option>
                    <option value="closed">Закрыта</option>
                  </SelectField>
                  <SelectField
                    label="Приоритет"
                    key={`prio-${selected}-${String(active?.priority_local ?? "medium")}`}
                    defaultValue={String(active?.priority_local ?? "medium")}
                    onChange={(e) => void savePatch({ priorityLocal: e.target.value })}
                  >
                    <option value="low">Низкий</option>
                    <option value="medium">Средний</option>
                    <option value="high">Высокий</option>
                    <option value="critical">Критичный</option>
                  </SelectField>
                  <Field label="Исполнитель" className="sm:col-span-2">
                    <div className="flex gap-2">
                      <input
                        key={`owner-${selected}-${String(active?.owner ?? "")}`}
                        defaultValue={String(active?.owner ?? "")}
                        onBlur={(e) => void savePatch({ owner: e.target.value || null })}
                        className={controlCls}
                        placeholder="email или имя"
                      />
                      {meEmail ? (
                        <button
                          type="button"
                          onClick={() => void savePatch({ owner: meEmail, status: "in_progress" })}
                          className="shrink-0 rounded-lg border border-accent/35 bg-accent/10 px-3 text-[12px] font-semibold text-fg/90 hover:bg-accent/15"
                        >
                          Мне
                        </button>
                      ) : null}
                    </div>
                  </Field>
                </div>
              </SectionCard>

              <SectionCard
                title="Сроки"
                action={
                  <div className="flex flex-wrap gap-1">
                    <DueBadge iso={dueIso} label="Due" />
                    <DueBadge iso={reviewIso} label="Review" />
                  </div>
                }
              >
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                  <TextField
                    label="Due date"
                    key={`due-${selected}-${dueIso ?? ""}`}
                    type="date"
                    defaultValue={dueIso ? dueIso.slice(0, 10) : ""}
                    onBlur={(e) =>
                      void savePatch({ dueDate: e.target.value ? new Date(e.target.value).toISOString() : null })
                    }
                  />
                  <TextField
                    label="Review date"
                    ref={reviewDateRef}
                    key={`rev-${selected}-${reviewIso ?? ""}`}
                    type="date"
                    defaultValue={reviewIso ? reviewIso.slice(0, 10) : ""}
                    onBlur={(e) =>
                      void savePatch({
                        reviewDate: e.target.value ? new Date(e.target.value).toISOString() : null
                      })
                    }
                    hint="Просроченный review подсвечивается на карточке"
                  />
                </div>
              </SectionCard>

              <SectionCard title="Закрытие / решение">
                <div className="grid grid-cols-1 gap-3">
                  <TextField
                    label="Decision"
                    ref={decisionRef}
                    key={`dec-${selected}-${String(active?.decision ?? "")}`}
                    defaultValue={String(active?.decision ?? "")}
                    onBlur={(e) => void savePatch({ decision: e.target.value || null })}
                    placeholder="patch / mitigation / accept / false_positive"
                  />
                  <TextareaField
                    label="Decision notes"
                    ref={decisionNotesRef}
                    key={`decn-${selected}-${String(active?.decision_notes ?? "")}`}
                    defaultValue={String(active?.decision_notes ?? "")}
                    onBlur={(e) => void savePatch({ decisionNotes: e.target.value || null })}
                    rows={3}
                    placeholder="Почему так решили…"
                  />
                  <TextareaField
                    label="Evidence"
                    ref={evidenceRef}
                    key={`ev-${selected}-${String(active?.evidence ?? "")}`}
                    defaultValue={String(active?.evidence ?? "")}
                    onBlur={(e) => void savePatch({ evidence: e.target.value || null })}
                    rows={3}
                    placeholder="Advisory / версия / тикет / проверка на инфре…"
                  />
                </div>
              </SectionCard>

              <SectionCard title="Notes">
                <TextareaField
                  label="Markdown"
                  key={`notes-${selected}-${String(active?.notes_md ?? "").slice(0, 24)}`}
                  defaultValue={String(active?.notes_md ?? "")}
                  onBlur={(e) => void savePatch({ notesMd: e.target.value })}
                  className="font-mono text-[12px]"
                  rows={8}
                  hint="Бриф VOC / чеклист / контекст проверки"
                />
              </SectionCard>
            </div>
          ) : null}

          {rightTab === "cves" ? (
            <div className="space-y-3">
              <div className="flex items-center justify-between gap-2">
                <div className="text-[12px] font-medium text-fg/80">Связанные CVE</div>
                <button
                  type="button"
                  onClick={() => setAddOpen((v) => !v)}
                  className="inline-flex items-center gap-1 rounded-lg border border-border bg-white px-2.5 py-1.5 text-[12px] font-medium hover:bg-slate-50 dark:bg-black/30 dark:hover:bg-white/5"
                >
                  <Search className="h-3.5 w-3.5" />
                  Добавить
                </button>
              </div>
              {addOpen ? (
                <div className="rounded-xl border border-border bg-slate-50/80 p-3 dark:bg-white/[0.03]">
                  <div className="flex items-center gap-2">
                    <input
                      value={addQ}
                      onChange={(e) => setAddQ(e.target.value)}
                      placeholder="CVE-… или vendor/product (≥3)"
                      className={controlCls}
                    />
                    <button
                      type="button"
                      onClick={() => void addCves()}
                      className="shrink-0 rounded-lg border border-accent/35 bg-accent/10 px-3 py-2 text-[12px] font-semibold"
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
                          className="flex cursor-pointer items-start gap-2 rounded-lg border border-transparent px-2 py-1.5 hover:border-border hover:bg-white dark:hover:bg-black/20"
                        >
                          <input
                            type="checkbox"
                            className="mt-1"
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
              <div className="divide-y divide-border/70 overflow-hidden rounded-xl border border-border bg-white dark:bg-black/20">
                {activeCves.length === 0 ? (
                  <div className="px-3 py-8 text-center text-[12px] text-muted">Нет связанных CVE.</div>
                ) : (
                  activeCves.slice(0, 50).map((c) => (
                    <div key={c.cve_id} className="flex items-start gap-2 px-3 py-2.5">
                      <button
                        type="button"
                        onClick={() => onOpenCve?.(String(c.cve_id))}
                        className="min-w-0 flex-1 text-left hover:underline"
                      >
                        <div className="font-mono text-[13px] font-semibold">{String(c.cve_id)}</div>
                        <div className="mt-1 flex flex-wrap gap-1.5 text-[10px]">
                          {c.exploit_known ? (
                            <span className="rounded border border-danger/35 bg-danger/10 px-1.5 py-0.5 font-bold text-danger">
                              KEV
                            </span>
                          ) : null}
                          <span className="rounded border border-border px-1.5 py-0.5 tabular-nums text-muted">
                            EPSS{" "}
                            {typeof c.epss === "number" ? `${(Number(c.epss) * 100).toFixed(2)}%` : "—"}
                          </span>
                          <span className="rounded border border-border px-1.5 py-0.5 tabular-nums text-muted">
                            CVSS {typeof c.cvss_base === "number" ? Number(c.cvss_base).toFixed(1) : "—"}
                          </span>
                          <span
                            className={cn(
                              "rounded border px-1.5 py-0.5 font-semibold tabular-nums",
                              scoreTone(Number(c.risk_score ?? 0))
                            )}
                          >
                            risk {typeof c.risk_score === "number" ? c.risk_score : "—"}
                          </span>
                        </div>
                      </button>
                      <button
                        type="button"
                        onClick={() => void removeCve(String(c.cve_id))}
                        className="rounded-lg p-1.5 text-muted hover:bg-danger/10 hover:text-danger"
                        title="Убрать"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  ))
                )}
              </div>
              {activeCves.length > 50 ? (
                <div className="text-[11px] text-muted">Показаны первые 50…</div>
              ) : null}
            </div>
          ) : null}

          {rightTab === "events" ? (
            <div>
              {activeEvents.length === 0 ? (
                <div className="py-8 text-center text-[12px] text-muted">Пока нет событий.</div>
              ) : (
                <div className="space-y-2">
                  {activeEvents.slice(0, 80).map((ev, idx: number) => (
                    <div
                      key={`${String(ev?.id ?? "")}-${idx}`}
                      className="rounded-xl border border-border bg-white px-3 py-2 text-[12px] dark:bg-black/20"
                    >
                      <div className="flex items-center justify-between gap-2">
                        <div className="min-w-0 truncate font-semibold">
                          {String(ev?.action ?? "event")}
                          {ev?.actor ? <span className="ml-1.5 font-normal text-muted">· {String(ev.actor)}</span> : null}
                        </div>
                        <div className="shrink-0 font-mono text-[10px] tabular-nums text-muted">
                          {ev?.ts ? new Date(String(ev.ts)).toLocaleString() : "—"}
                        </div>
                      </div>
                      {ev?.meta ? (
                        <pre className="mt-1.5 max-h-28 overflow-auto rounded-lg bg-slate-50 p-2 text-[10px] text-fg/75 dark:bg-black/40">
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

  return (
    <div className="flex min-h-0 flex-col gap-2.5">
      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-2 border-b border-border/80 pb-2.5">
        <div className="min-w-0">
          <div className="text-[13px] font-semibold text-fg/90">Задачи</div>
        </div>

        <div className="flex items-center rounded-lg border border-border bg-white p-0.5 dark:bg-black/30">
          <button
            type="button"
            onClick={() => setViewMode("list")}
            className={cn(
              "inline-flex items-center gap-1 rounded-md px-2.5 py-1.5 text-[11px] font-semibold",
              viewMode === "list" ? "bg-accent/15 text-fg/90" : "text-muted hover:text-fg/80"
            )}
            title="Список"
          >
            <LayoutList className="h-3.5 w-3.5" />
            Список
          </button>
          <button
            type="button"
            onClick={() => {
              setStatus("");
              setViewMode("board");
            }}
            className={cn(
              "inline-flex items-center gap-1 rounded-md px-2.5 py-1.5 text-[11px] font-semibold",
              viewMode === "board" ? "bg-accent/15 text-fg/90" : "text-muted hover:text-fg/80"
            )}
            title="Доска"
          >
            <Columns3 className="h-3.5 w-3.5" />
            Доска
          </button>
        </div>

        <div className="flex flex-wrap items-center gap-1">
          {TASK_STATUS_COLUMNS.map((col) => {
            const active = !showBoard && status === col.key;
            return (
              <button
                key={col.key}
                type="button"
                title={showBoard ? col.title : `Фильтр: ${col.title}`}
                disabled={showBoard}
                onClick={() => {
                  if (showBoard) return;
                  setStatus((s) => (s === col.key ? "" : col.key));
                }}
                className={cn(
                  "inline-flex items-center gap-1.5 rounded-md border px-2 py-1 text-[11px] font-semibold transition",
                  active
                    ? statusMeta(col.key).segmentActive
                    : "border-border bg-white text-muted dark:bg-black/30",
                  showBoard ? "cursor-default" : "hover:bg-slate-50 hover:text-fg/85 dark:hover:bg-white/5"
                )}
              >
                <span className={cn("h-1.5 w-1.5 rounded-full", statusMeta(col.key).dot)} />
                {col.title}
                <span className="tabular-nums text-fg/75">{taskStats[col.key]}</span>
              </button>
            );
          })}
          <span className="ml-0.5 rounded-md border border-border bg-slate-50 px-2 py-1 text-[11px] font-semibold tabular-nums text-fg/75 dark:bg-white/[0.04]">
            {taskStats.total} всего
            <span className="mx-1 text-border">·</span>
            KEV {taskStats.kev}
            <span className="mx-1 text-border">·</span>
            ≥70 {taskStats.high}
          </span>
          {listQuery.isFetching ? <span className="text-[10px] text-muted">обновляем…</span> : null}
        </div>

        <div className="relative min-w-[180px] flex-1">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted" />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Поиск: название, vendor, product…"
            className={cn(controlCls, "w-full pl-8")}
          />
        </div>

        {!showBoard ? (
          <>
            <select
              value={listSort}
              onChange={(e) => setListSort(e.target.value as typeof listSort)}
              className={controlCls}
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
              className={cn(controlCls, "px-2.5")}
              title="Направление"
            >
              {listSortDir === "desc" ? "↓" : "↑"}
            </button>
          </>
        ) : null}

        <button
          type="button"
          onClick={() => void refresh()}
          className="inline-flex items-center gap-1 rounded-lg border border-border bg-white px-2.5 py-1.5 text-[11px] font-medium text-fg/80 hover:bg-slate-50 dark:bg-black/30 dark:hover:bg-white/5"
          title="Обновить"
        >
          {listQuery.isFetching ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
        </button>
        <button
          type="button"
          onClick={() => setCreateOpen((v) => !v)}
          className="inline-flex items-center gap-1 rounded-lg border border-accent/30 bg-accent/10 px-2.5 py-1.5 text-[11px] font-semibold text-fg/90 hover:bg-accent/15"
        >
          <Plus className="h-3.5 w-3.5" />
          Создать
        </button>
      </div>

      {/* Quick filters */}
      <div className="flex flex-wrap items-center justify-between gap-2">{quickFilterBar}</div>

      {createOpen ? (
        <div className="rounded-xl border border-border bg-slate-50/80 p-3 dark:bg-white/[0.03]">
          <div className="mb-2 text-[12px] font-semibold text-fg/85">Новая задача</div>
          <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
            <input
              value={newTitle}
              onChange={(e) => setNewTitle(e.target.value)}
              placeholder="Название (опционально)"
              className={cn(controlCls, "sm:col-span-2")}
            />
            <input
              list="vip-vendors"
              value={newVendor}
              onChange={(e) => setNewVendor(e.target.value)}
              placeholder="Vendor *"
              className={controlCls}
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
              className={controlCls}
            />
            <datalist id="vip-products">
              {productOptions.map((p) => (
                <option key={`${p.vendor}:${p.product}`} value={p.product} />
              ))}
            </datalist>
            <button
              type="button"
              onClick={() => void createTask()}
              className="rounded-lg border border-accent/30 bg-accent/10 px-3 py-2 text-[12px] font-semibold hover:bg-accent/15 sm:col-span-2 lg:col-span-4"
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
                      <StatusChip status={t.status} />
                    </div>
                    <div className="hidden md:block">
                      <PriorityBadge priority={t.priority_local} compact />
                    </div>
                    <div className="hidden min-w-0 md:block" title={t.owner ? `В работе у ${t.owner}` : "Без исполнителя"}>
                      <AssigneeCell name={t.owner} />
                    </div>
                    <div className="hidden justify-end md:flex">
                      <ScoreBadge score={t.score_final} />
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
