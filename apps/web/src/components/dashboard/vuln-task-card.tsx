"use client";

import type { CSSProperties } from "react";
import { useSortable } from "@dnd-kit/sortable";
import { CSS } from "@dnd-kit/utilities";
import { cn } from "../ui/cn";
import {
  AssigneeCell,
  DueBadge,
  MetaRow,
  PriorityBadge,
  ScoreBadge,
  StatusChip,
  normalizeUiTaskStatus,
  priorityMeta,
  taskIssueKey
} from "./vuln-task-ui";

export type TaskCardModel = {
  id: string;
  title: string;
  status: string;
  priority_local: string;
  owner: string | null;
  due_date: string | null;
  review_date: string | null;
  vendor_display: string;
  product_display: string;
  score_final: number;
  stats?: { cveCount?: number; kevCount?: number; perimeterHighCount?: number } | null;
  updated_at?: string;
};

function useTaskCardFlags(task: TaskCardModel) {
  const cveCount = task.stats?.cveCount ?? null;
  const kevCount = task.stats?.kevCount ?? 0;
  const reviewIso = task.review_date ? String(task.review_date) : null;
  const reviewDate = reviewIso ? new Date(reviewIso) : null;
  const reviewOverdue =
    reviewDate && !Number.isNaN(reviewDate.getTime()) ? reviewDate.getTime() < Date.now() : false;
  const dueIso = task.due_date ? String(task.due_date) : null;
  const dueDate = dueIso ? new Date(dueIso) : null;
  const dueOverdue = dueDate && !Number.isNaN(dueDate.getTime()) ? dueDate.getTime() < Date.now() : false;
  return { cveCount, kevCount, reviewOverdue, dueOverdue, dueIso, reviewIso };
}

function accentRail(task: TaskCardModel, flags: ReturnType<typeof useTaskCardFlags>) {
  if (flags.reviewOverdue || flags.dueOverdue) return "before:bg-danger";
  if (flags.kevCount > 0) return "before:bg-warn";
  const p = String(task.priority_local || "").toLowerCase();
  if (p === "critical") return "before:bg-danger";
  if (p === "high") return "before:bg-warn";
  if (normalizeUiTaskStatus(task.status) === "in_progress") return "before:bg-accent";
  return "before:bg-border";
}

function cardShellCls(active: boolean | undefined, dragging?: boolean) {
  return cn(
    "relative w-full select-none overflow-hidden rounded-lg border text-left transition",
    "before:absolute before:inset-y-0 before:left-0 before:w-[3px] before:content-['']",
    "bg-white dark:bg-[#0d1524]",
    active
      ? "border-accent/45 bg-accent/[0.06] shadow-sm ring-1 ring-accent/20"
      : "border-border/90 hover:border-border hover:bg-slate-50/80 dark:hover:bg-white/[0.03]",
    dragging ? "cursor-grabbing opacity-50" : "cursor-grab"
  );
}

export function TaskCardBody({
  task,
  dense
}: {
  task: TaskCardModel;
  dense?: boolean;
}) {
  const flags = useTaskCardFlags(task);
  const { cveCount, kevCount, reviewOverdue, dueIso, reviewIso } = flags;
  const prio = priorityMeta(task.priority_local);

  return (
    <div className={cn("px-3 py-2.5", dense && "py-2")}>
      {/* Header: key · status · score */}
      <div className="flex items-center gap-2">
        <span className="font-mono text-[11px] font-semibold tracking-wide text-accent/90">
          {taskIssueKey(task.id)}
        </span>
        <StatusChip status={task.status} compact />
        <div className="ml-auto flex items-center gap-1.5">
          {kevCount > 0 ? (
            <span className="rounded border border-danger/40 bg-danger/10 px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wide text-danger">
              KEV
            </span>
          ) : null}
          <ScoreBadge score={task.score_final} />
        </div>
      </div>

      {/* Title */}
      <div
        className={cn(
          "mt-2 font-semibold leading-snug tracking-tight text-fg/95",
          dense ? "line-clamp-2 text-[13px]" : "line-clamp-2 text-[13.5px]"
        )}
      >
        {task.title}
      </div>

      {/* Asset line */}
      <MetaRow
        vendor={task.vendor_display}
        product={task.product_display}
        className="mt-1 text-[11px] text-muted/90"
      />

      {/* Priority + CVE chips */}
      <div className="mt-2 flex flex-wrap items-center gap-1.5">
        <PriorityBadge priority={task.priority_local} compact />
        {cveCount != null ? (
          <span className="rounded border border-border bg-slate-50 px-1.5 py-0.5 text-[10px] font-medium tabular-nums text-fg/70 dark:bg-white/[0.04]">
            CVE {cveCount}
          </span>
        ) : null}
        {prio.sort >= 3 ? (
          <span className="text-[10px] text-muted" title="Приоритет">
            P{5 - prio.sort}
          </span>
        ) : null}
      </div>

      {/* Footer */}
      <div className="mt-2.5 flex min-w-0 items-center gap-2 border-t border-border/70 pt-2">
        <AssigneeCell name={task.owner} emptyLabel="Unassigned" />
        <div className="ml-auto flex min-w-0 flex-wrap items-center justify-end gap-1">
          <DueBadge iso={dueIso} label="Due" />
          {reviewOverdue || reviewIso ? <DueBadge iso={reviewIso} label="Rev" /> : null}
        </div>
      </div>
    </div>
  );
}

export function TaskCardDraggable({
  task,
  active,
  containerId,
  onClick
}: {
  task: TaskCardModel;
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
  const flags = useTaskCardFlags(task);

  const style: CSSProperties = {
    transform: CSS.Translate.toString(transform),
    transition
  };

  return (
    <button
      ref={setNodeRef}
      type="button"
      onClick={onClick}
      style={style}
      className={cn(cardShellCls(active, isDragging), accentRail(task, flags))}
      {...attributes}
      {...listeners}
    >
      <TaskCardBody task={task} />
    </button>
  );
}

export function TaskCardGhost({ task }: { task: TaskCardModel }) {
  const flags = useTaskCardFlags(task);
  return (
    <div
      className={cn(
        cardShellCls(true, false),
        accentRail(task, flags),
        "w-[288px] cursor-grabbing shadow-xl ring-1 ring-accent/25"
      )}
    >
      <TaskCardBody task={task} dense />
    </div>
  );
}

export function TaskCardStatic({
  task,
  active,
  onClick
}: {
  task: TaskCardModel;
  active?: boolean;
  onClick: () => void;
}) {
  const flags = useTaskCardFlags(task);
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(cardShellCls(active, false), "cursor-pointer", accentRail(task, flags))}
    >
      <TaskCardBody task={task} />
    </button>
  );
}
