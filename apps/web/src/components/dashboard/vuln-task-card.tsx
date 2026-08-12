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

export function TaskCardBody({
  task,
  dense
}: {
  task: TaskCardModel;
  dense?: boolean;
}) {
  const { cveCount, kevCount, reviewOverdue, dueIso, reviewIso } = useTaskCardFlags(task);
  return (
    <>
      <div className="flex items-center gap-1.5">
        <span className="font-mono text-[11px] font-semibold text-accent">{taskIssueKey(task.id)}</span>
        <StatusChip status={task.status} compact />
        <ScoreBadge score={task.score_final} className="ml-auto" />
      </div>
      <div
        className={cn(
          "mt-1.5 font-semibold leading-snug text-fg/95",
          dense ? "line-clamp-2 text-[13px]" : "line-clamp-2 text-[13px]"
        )}
      >
        {task.title}
      </div>
      <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
        <PriorityBadge priority={task.priority_local} compact />
        {kevCount > 0 ? (
          <span className="rounded-md border border-danger/35 bg-danger/10 px-1.5 py-0.5 text-[10px] font-bold text-danger">
            KEV
          </span>
        ) : null}
        {cveCount != null ? (
          <span className="rounded-md border border-border bg-white/80 px-1.5 py-0.5 text-[10px] font-medium tabular-nums text-fg/75 dark:bg-black/30">
            CVE {cveCount}
          </span>
        ) : null}
      </div>
      <MetaRow vendor={task.vendor_display} product={task.product_display} className="mt-1.5" />
      <div className="mt-2 flex min-w-0 flex-wrap items-center gap-1.5">
        <AssigneeCell name={task.owner} emptyLabel="без исполнителя" />
        <span className="ml-auto flex flex-wrap items-center justify-end gap-1">
          <DueBadge iso={dueIso} label="Due" />
          {reviewOverdue || reviewIso ? <DueBadge iso={reviewIso} label="Rev" /> : null}
        </span>
      </div>
    </>
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
  const { reviewOverdue, dueOverdue, kevCount } = useTaskCardFlags(task);

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
        "group w-full select-none rounded-xl border px-2.5 py-2 text-left transition",
        active
          ? "border-accent/50 bg-accent/[0.08] ring-1 ring-accent/30"
          : "border-border bg-white hover:border-border hover:bg-slate-50/90 dark:bg-black/30 dark:hover:bg-black/45",
        isDragging ? "cursor-grabbing" : "cursor-grab",
        reviewOverdue || dueOverdue ? "border-l-[3px] border-l-danger" : kevCount > 0 ? "border-l-[3px] border-l-warn" : ""
      )}
      {...attributes}
      {...listeners}
    >
      <TaskCardBody task={task} />
    </button>
  );
}

export function TaskCardGhost({ task }: { task: TaskCardModel }) {
  return (
    <div className="w-[280px] rounded-xl border border-accent/35 bg-white p-2.5 shadow-xl dark:bg-[#0b1220]">
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
  const { reviewOverdue, dueOverdue, kevCount } = useTaskCardFlags(task);
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        "w-full rounded-xl border px-2.5 py-2 text-left transition",
        active
          ? "border-accent/50 bg-accent/[0.08]"
          : "border-border/90 bg-white hover:bg-slate-50 dark:bg-black/30 dark:hover:bg-black/45",
        reviewOverdue || dueOverdue ? "border-l-[3px] border-l-danger" : kevCount > 0 ? "border-l-[3px] border-l-warn" : ""
      )}
    >
      <TaskCardBody task={task} />
    </button>
  );
}
