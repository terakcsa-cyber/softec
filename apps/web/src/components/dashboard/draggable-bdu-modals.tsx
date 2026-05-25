"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { GripVertical, X } from "lucide-react";
import { apiFetch } from "@/lib/api-fetch";
import { needsOnDemandBduEnrich, shouldAutoEnrichBduOnOpen } from "@/lib/bdu-enrich-ui";
import { CVE_POLL_WHILE_ENRICH_MS, ENRICH_UI_WAIT_MS } from "@/lib/enrich-ui-wait";
import { BduDetailPanel, type BduDetailsPayload } from "./bdu-detail-panel";

export const DASHBOARD_BDU_MODAL_BASE_WIDTH_PX = 1040;
const modalWidthStyle = `min(${DASHBOARD_BDU_MODAL_BASE_WIDTH_PX}px, calc(100vw - 24px))`;

export type DashboardBduModalFrame = {
  instanceId: string;
  bduId: string;
  x: number;
  y: number;
  z: number;
};

function BduModalBody({
  bduId,
  manualEnrichAllowed,
  onOpenCve,
  onOpenTask
}: {
  bduId: string;
  manualEnrichAllowed: boolean;
  onOpenCve?: (cveId: string) => void;
  onOpenTask?: (taskId: string) => void;
}) {
  const queryClient = useQueryClient();
  const [enrichPosted, setEnrichPosted] = useState(false);
  const [enrichStalled, setEnrichStalled] = useState(false);
  const enrichPollDeadlineRef = useRef<number | null>(null);
  const autoEnrichForBduRef = useRef<string | null>(null);

  const detailsQuery = useQuery({
    queryKey: ["bdu", "detail", bduId],
    staleTime: 8_000,
    refetchOnWindowFocus: false,
    queryFn: async () => {
      const res = await apiFetch(`/api/bdu/${encodeURIComponent(bduId)}`, { cache: "no-store" });
      if (!res.ok) throw new Error(`Не удалось загрузить BDU (${res.status})`);
      return (await res.json()) as BduDetailsPayload;
    },
    refetchInterval: (q) => {
      const d = q.state.data;
      if (!d?.found) return false;
      if (manualEnrichAllowed && enrichPosted) {
        if (!needsOnDemandBduEnrich(d)) return false;
        const deadline = enrichPollDeadlineRef.current;
        if (deadline != null && Date.now() > deadline) return false;
        return CVE_POLL_WHILE_ENRICH_MS;
      }
      return false;
    },
    refetchIntervalInBackground: false
  });

  useEffect(() => {
    setEnrichPosted(false);
    setEnrichStalled(false);
    enrichPollDeadlineRef.current = null;
    autoEnrichForBduRef.current = null;
  }, [bduId]);

  useEffect(() => {
    const d = detailsQuery.data;
    if (!d?.found) return;
    if (needsOnDemandBduEnrich(d)) return;
    enrichPollDeadlineRef.current = null;
    setEnrichPosted(false);
    setEnrichStalled(false);
  }, [detailsQuery.data]);

  useEffect(() => {
    if (!enrichPosted) return;
    const tick = () => {
      const deadline = enrichPollDeadlineRef.current;
      if (deadline != null && Date.now() > deadline) {
        enrichPollDeadlineRef.current = null;
        setEnrichPosted(false);
        setEnrichStalled(true);
      }
    };
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, [enrichPosted]);

  const requestEnrich = useCallback(
    async (force = false) => {
      setEnrichPosted(true);
      setEnrichStalled(false);
      enrichPollDeadlineRef.current = Date.now() + ENRICH_UI_WAIT_MS;
      try {
        const q = force ? "?force=1" : "";
        const res = await apiFetch(`/api/bdu/${encodeURIComponent(bduId)}/enrich${q}`, { method: "POST" });
        if (!res.ok) throw new Error("bdu enrich request failed");
        await queryClient.invalidateQueries({ queryKey: ["bdu", "detail", bduId] });
      } catch {
        enrichPollDeadlineRef.current = null;
        setEnrichPosted(false);
        setEnrichStalled(true);
      }
    },
    [bduId, queryClient]
  );

  useEffect(() => {
    if (!manualEnrichAllowed || detailsQuery.isLoading) return;
    const d = detailsQuery.data;
    if (!d) return;
    if (!shouldAutoEnrichBduOnOpen(d)) return;
    if (autoEnrichForBduRef.current === bduId) return;
    autoEnrichForBduRef.current = bduId;
    void requestEnrich(false);
  }, [bduId, manualEnrichAllowed, detailsQuery.data, detailsQuery.isLoading, requestEnrich]);

  const payload = detailsQuery.data?.found ? detailsQuery.data : null;
  const aiPending = Boolean(
    payload && manualEnrichAllowed && enrichPosted && needsOnDemandBduEnrich(payload)
  );

  return (
    <BduDetailPanel
      bduId={bduId}
      data={payload}
      loading={detailsQuery.isLoading}
      aiPending={aiPending}
      aiStalled={enrichStalled}
      manualEnrichAllowed={manualEnrichAllowed}
      onRequestEnrich={(opts) => void requestEnrich(Boolean(opts?.force))}
      onOpenCve={onOpenCve}
      onOpenTask={onOpenTask}
    />
  );
}

function DraggableShell({
  frame,
  manualEnrichAllowed,
  onClose,
  onFocus,
  onMove,
  onOpenCve,
  onOpenTask
}: {
  frame: DashboardBduModalFrame;
  manualEnrichAllowed: boolean;
  onClose: () => void;
  onFocus: () => void;
  onMove: (x: number, y: number) => void;
  onOpenCve?: (cveId: string) => void;
  onOpenTask?: (taskId: string) => void;
}) {
  const [pos, setPos] = useState({ x: frame.x, y: frame.y });
  const posRef = useRef(pos);
  posRef.current = pos;
  const drag = useRef<{ sx: number; sy: number; ox: number; oy: number } | null>(null);

  useEffect(() => {
    setPos({ x: frame.x, y: frame.y });
  }, [frame.x, frame.y]);

  const onHeaderDown = useCallback(
    (e: React.MouseEvent) => {
      if (e.button !== 0) return;
      e.preventDefault();
      onFocus();
      const { x, y } = posRef.current;
      drag.current = {
        sx: e.clientX,
        sy: e.clientY,
        ox: x,
        oy: y
      };
      const last = { x, y };
      const move = (ev: MouseEvent) => {
        if (!drag.current) return;
        const nx = drag.current.ox + (ev.clientX - drag.current.sx);
        const ny = drag.current.oy + (ev.clientY - drag.current.sy);
        last.x = nx;
        last.y = ny;
        setPos({ x: nx, y: ny });
      };
      const up = () => {
        drag.current = null;
        document.removeEventListener("mousemove", move);
        document.removeEventListener("mouseup", up);
        onMove(last.x, last.y);
      };
      document.addEventListener("mousemove", move);
      document.addEventListener("mouseup", up);
    },
    [onFocus, onMove]
  );

  return (
    <div
      className="fixed min-h-[280px] min-w-[min(520px,calc(100vw-32px))] max-h-[min(94vh,980px)] max-w-[calc(100vw-16px)] resize overflow-hidden rounded-2xl shadow-2xl"
      style={{
        left: pos.x,
        top: pos.y,
        zIndex: frame.z,
        width: modalWidthStyle,
        height: "min(82vh, 860px)"
      }}
      onMouseDown={() => onFocus()}
      role="dialog"
      aria-label={`BDU ${frame.bduId}`}
      title="Потяните за правый нижний угол, чтобы изменить размер окна"
    >
      <div className="glass flex h-full min-h-0 flex-col overflow-hidden rounded-2xl border border-border ring-1 ring-slate-200/70 dark:ring-white/[0.08]">
        <div
          className="flex shrink-0 cursor-grab select-none items-center justify-between gap-2 border-b border-slate-200 bg-slate-50 px-3 py-2 active:cursor-grabbing dark:border-white/[0.08] dark:bg-black/50"
          onMouseDown={onHeaderDown}
        >
          <div className="flex min-w-0 items-center gap-2 text-xs font-medium text-fg/90">
            <GripVertical className="h-4 w-4 shrink-0 text-muted" aria-hidden />
            <span className="truncate font-mono">BDU:{frame.bduId}</span>
          </div>
          <button
            type="button"
            className="rounded-lg border border-slate-200 bg-white p-1 text-muted hover:bg-slate-100 hover:text-fg dark:border-border dark:bg-black/30 dark:hover:bg-black/40"
            onClick={(e) => {
              e.stopPropagation();
              onClose();
            }}
            aria-label="Закрыть"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="min-h-0 flex-1 overflow-y-auto p-3 sm:p-4">
          <BduModalBody
            bduId={frame.bduId}
            manualEnrichAllowed={manualEnrichAllowed}
            onOpenCve={onOpenCve}
            onOpenTask={onOpenTask}
          />
        </div>
      </div>
    </div>
  );
}

export function DraggableBduModals({
  modals,
  manualEnrichAllowed,
  onClose,
  onMove,
  onFocus,
  onOpenCve,
  onOpenTask
}: {
  modals: DashboardBduModalFrame[];
  manualEnrichAllowed: boolean;
  onClose: (instanceId: string) => void;
  onMove: (instanceId: string, x: number, y: number) => void;
  onFocus: (instanceId: string) => void;
  onOpenCve?: (cveId: string) => void;
  onOpenTask?: (taskId: string) => void;
}) {
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);

  if (!mounted || modals.length === 0) return null;

  return createPortal(
    <div className="pointer-events-none fixed inset-0 z-[3100]">
      {modals.map((m) => (
        <div key={m.instanceId} className="pointer-events-auto">
          <DraggableShell
            frame={m}
            manualEnrichAllowed={manualEnrichAllowed}
            onClose={() => onClose(m.instanceId)}
            onFocus={() => onFocus(m.instanceId)}
            onMove={(x, y) => onMove(m.instanceId, x, y)}
            onOpenCve={onOpenCve}
            onOpenTask={onOpenTask}
          />
        </div>
      ))}
    </div>,
    document.body
  );
}
