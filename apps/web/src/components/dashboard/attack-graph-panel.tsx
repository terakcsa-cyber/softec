"use client";

import { useMemo, useState } from "react";
import ReactFlow, { Background, Controls, Edge, MiniMap, Node, ReactFlowProvider, useReactFlow } from "reactflow";
import "reactflow/dist/style.css";
import { buildBaselineAttackGraph, isUsableAttackGraph } from "@/lib/baseline-enrichment";

type Graph = {
  nodes?: { id: string; label?: string; type?: string }[];
  edges?: { from: string; to: string; label?: string }[];
};

function graphFromAttackFlow(steps: string[], entityId = "vuln"): Graph | null {
  const clean = steps.map((s) => s.trim()).filter(Boolean);
  if (clean.length === 0) return null;
  // Prefer the richer baseline topology over a flat step chain.
  return buildBaselineAttackGraph({
    entityId,
    attackFlow: clean,
    summary: clean.join(" ")
  });
}

function toNodes(graph: Graph | null): Node[] {
  const nodes = graph?.nodes ?? [];
  return nodes.map((n, idx) => ({
    id: n.id,
    data: { label: n.label ?? n.id, type: n.type ?? "asset" },
    position: { x: (idx % 5) * 220, y: Math.floor(idx / 5) * 120 },
    style: {
      borderRadius: 12,
      border: "1px solid rgba(255,255,255,0.12)",
      background:
        n.type === "attacker"
          ? "rgba(255,80,120,0.14)"
          : n.type === "vector"
            ? "rgba(179,136,255,0.14)"
            : n.type === "service"
              ? "rgba(80,200,255,0.14)"
              : n.type === "impact"
                ? "rgba(255,190,80,0.14)"
                : "rgba(0,0,0,0.35)",
      color: "rgba(255,255,255,0.92)",
      padding: 10,
      minWidth: 160
    }
  }));
}

function toEdges(graph: Graph | null): Edge[] {
  const edges = graph?.edges ?? [];
  return edges.map((e, idx) => ({
    id: `${e.from}->${e.to}:${idx}`,
    source: e.from,
    target: e.to,
    label: e.label,
    animated: true,
    style: { stroke: "rgba(179, 136, 255, 0.9)", strokeWidth: 2 }
  }));
}

function Inner({
  graph,
  attackFlow,
  entityId
}: {
  graph: Graph | null;
  attackFlow: string[];
  entityId?: string;
}) {
  const usable = isUsableAttackGraph(graph) ? graph : null;
  const derived = usable ?? graphFromAttackFlow(attackFlow, entityId ?? "vuln");
  const nodes = useMemo(() => toNodes(derived), [derived]);
  const edges = useMemo(() => toEdges(derived), [derived]);
  const rf = useReactFlow();
  const [hover, setHover] = useState<{ title: string; subtitle?: string } | null>(null);
  const sourceLabel = usable
    ? "Из enrichment-графа"
    : attackFlow.length > 0
      ? "Построена из Attack flow"
      : "Нет данных графа";

  return (
    <div className="glass overflow-hidden rounded-2xl">
      <div className="flex items-center justify-between px-5 py-4">
        <div>
          <div className="text-sm font-medium">Схема атаки</div>
          <div className="text-xs text-muted">{sourceLabel}</div>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => rf.fitView({ padding: 0.2, duration: 250 })}
            className="rounded-lg border border-slate-200 bg-white px-2 py-1 text-xs text-fg/90 shadow-sm dark:border-border dark:bg-black/20 dark:shadow-none"
          >
            Сбросить вид
          </button>
          <div className="text-xs text-muted">
            {derived ? `${nodes.length} узлов` : "—"}
          </div>
        </div>
      </div>
      <div className="h-[520px] rounded-xl bg-slate-100 ring-1 ring-slate-200/80 dark:bg-black/30 dark:ring-white/10">
        <div className="relative h-full">
          {hover && (
            <div className="pointer-events-none absolute left-4 top-4 z-10 max-w-[420px] rounded-xl border border-slate-200 bg-white px-3 py-2 text-xs text-fg/90 shadow-lg backdrop-blur dark:border-white/10 dark:bg-black/60">
              <div className="font-medium">{hover.title}</div>
              {hover.subtitle ? <div className="mt-0.5 text-[11px] text-muted">{hover.subtitle}</div> : null}
            </div>
          )}
          <ReactFlow
            nodes={nodes}
            edges={edges}
            fitView
            onNodeMouseEnter={(_, n) => {
              const d = (n.data ?? null) as null | { label?: unknown; type?: unknown };
              setHover({ title: String(d?.label ?? n.id), subtitle: String(d?.type ?? "") });
            }}
            onNodeMouseLeave={() => setHover(null)}
            onEdgeMouseEnter={(_, e) => setHover({ title: String(e.label ?? "Step"), subtitle: `${e.source} → ${e.target}` })}
            onEdgeMouseLeave={() => setHover(null)}
          >
          <Background gap={18} size={1} color="rgba(255,255,255,0.06)" />
          <MiniMap zoomable pannable />
          <Controls />
          </ReactFlow>
        </div>
      </div>
    </div>
  );
}

export function AttackGraphPanel({
  graph,
  attackFlow,
  entityId
}: {
  graph: Graph | null;
  attackFlow: string[];
  entityId?: string;
}) {
  return (
    <ReactFlowProvider>
      <Inner graph={graph} attackFlow={attackFlow} entityId={entityId} />
    </ReactFlowProvider>
  );
}
