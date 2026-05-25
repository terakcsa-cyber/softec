"use client";

import dynamic from "next/dynamic";
import { useMemo, useState } from "react";
import {
  AlertTriangle,
  Brain,
  CheckCircle2,
  ChevronDown,
  Clock,
  GitBranch,
  Shield,
  Target,
  TrendingUp
} from "lucide-react";
import { parseAiOutputJson } from "@/lib/cve-enrich-ui";
import { cn } from "../ui/cn";

const AttackGraphPanel = dynamic(
  () => import("../dashboard/attack-graph-panel").then((m) => m.AttackGraphPanel),
  { ssr: false, loading: () => <div className="h-[320px] animate-pulse rounded-2xl bg-fg/5" /> }
);

type ItemSummary = {
  ordinal?: number;
  bduId?: string;
  priority?: number;
  headline?: string;
  summary?: string;
  businessImpact?: string;
  cvssFromBulletin?: string;
  registryCvss?: number | null;
  exploitUrgency?: string;
  attackFlow?: string[];
  remediation?: string[];
  compensatingIfAny?: string[];
  linkedCves?: string[];
  urgencyScore?: number;
};

function riskBadge(rating: string | null | undefined) {
  const r = (rating ?? "mixed").toLowerCase();
  const cls =
    r === "critical"
      ? "bg-red-500/20 text-red-200 border-red-500/40"
      : r === "high"
        ? "bg-orange-500/20 text-orange-200 border-orange-500/40"
        : r === "medium"
          ? "bg-amber-500/20 text-amber-200 border-amber-500/40"
          : r === "low"
            ? "bg-emerald-500/20 text-emerald-200 border-emerald-500/40"
            : "bg-fg/10 text-fg/70 border-fg/20";
  const label =
    r === "critical"
      ? "Критический"
      : r === "high"
        ? "Высокий"
        : r === "medium"
          ? "Средний"
          : r === "low"
            ? "Низкий"
            : "Смешанный";
  return (
    <span className={cn("rounded-full border px-2.5 py-0.5 text-[10px] font-semibold uppercase", cls)}>
      {label}
    </span>
  );
}

const ACTION_TYPE_STYLE: Record<string, string> = {
  patch: "bg-emerald-500/15 text-emerald-200",
  compensate: "bg-amber-500/15 text-amber-200",
  inventory: "bg-sky-500/15 text-sky-200",
  governance: "bg-violet-500/15 text-violet-200",
  monitor: "bg-fg/10 text-fg/65"
};

function urgencyChip(u: string | undefined) {
  const map: Record<string, string> = {
    immediate: "Срочно",
    soon: "В ближайшие дни",
    planned: "Планово",
    monitor: "Мониторинг"
  };
  const label = map[(u ?? "").toLowerCase()] ?? u ?? "—";
  const urgent = u === "immediate";
  return (
    <span
      className={cn(
        "rounded px-1.5 py-0.5 text-[10px] font-medium",
        urgent ? "bg-red-500/20 text-red-200" : "bg-fg/10 text-fg/60"
      )}
    >
      {label}
    </span>
  );
}

function MetricCard({
  label,
  value,
  sub
}: {
  label: string;
  value: string | number;
  sub?: string;
}) {
  return (
    <div className="rounded-xl border border-fg/10 bg-fg/[0.04] px-3 py-2.5">
      <div className="text-[10px] font-medium uppercase tracking-wide text-fg/45">{label}</div>
      <div className="mt-0.5 text-lg font-semibold tabular-nums text-fg/95">{value}</div>
      {sub ? <div className="mt-0.5 text-[10px] text-fg/50">{sub}</div> : null}
    </div>
  );
}

export function FstecBulletinAnalysisView({
  outputJson,
  onOpenBdu
}: {
  outputJson: Record<string, unknown> | null;
  onOpenBdu?: (bduId: string) => void;
}) {
  const [itemsOpen, setItemsOpen] = useState(false);
  const [graphOpen, setGraphOpen] = useState(false);
  const ai = useMemo(() => parseAiOutputJson(outputJson), [outputJson]);

  const combinedGraph = useMemo(() => {
    const g = ai?.combinedGraph;
    if (g && typeof g === "object" && !Array.isArray(g)) {
      return g as {
        nodes?: { id: string; label?: string; type?: string }[];
        edges?: { from: string; to: string; label?: string }[];
      };
    }
    return null;
  }, [ai]);

  const attackFlowSteps = useMemo(() => {
    if (!ai) return [];
    const items = (Array.isArray(ai.itemSummaries) ? ai.itemSummaries : []) as ItemSummary[];
    const steps: string[] = [];
    for (const it of items) {
      if (Array.isArray(it.attackFlow)) steps.push(...it.attackFlow.map(String));
    }
    return steps.slice(0, 12);
  }, [ai]);

  const hasGraphData =
    (combinedGraph?.nodes?.length ?? 0) > 0 || attackFlowSteps.length > 0;

  const actionPlan = useMemo(() => {
    if (!ai) return null;
    const ap = ai.actionPlan;
    if (!ap || typeof ap !== "object" || Array.isArray(ap)) return null;
    return ap as {
      introduction?: string;
      complianceNote?: string | null;
      phases?: Array<{
        id?: string;
        title?: string;
        horizon?: string;
        owner?: string;
        goal?: string;
        steps?: Array<{
          order?: number;
          bduId?: string | null;
          title?: string;
          detail?: string;
          actionType?: string;
        }>;
      }>;
    };
  }, [ai]);

  if (!ai) return null;

  const title = typeof ai.title === "string" ? ai.title : null;
  const executiveSummary = typeof ai.executiveSummary === "string" ? ai.executiveSummary : null;
  const keyFindings = Array.isArray(ai.keyFindings) ? (ai.keyFindings as string[]) : [];
  const managementBrief = typeof ai.managementBrief === "string" ? ai.managementBrief : null;
  const technicalBrief = typeof ai.technicalBrief === "string" ? ai.technicalBrief : null;
  const bulletinContext = typeof ai.bulletinContext === "string" ? ai.bulletinContext : null;
  const regulatory = Array.isArray(ai.regulatoryObligations) ? (ai.regulatoryObligations as string[]) : [];
  const themes = Array.isArray(ai.crossCuttingThemes) ? (ai.crossCuttingThemes as string[]) : [];
  const uncertainties = Array.isArray(ai.uncertainties) ? (ai.uncertainties as string[]) : [];
  const priorityOrder = Array.isArray(ai.priorityOrder) ? (ai.priorityOrder as string[]) : [];
  const rm =
    ai.riskMatrix && typeof ai.riskMatrix === "object" ? (ai.riskMatrix as Record<string, unknown>) : null;

  const items = (Array.isArray(ai.itemSummaries) ? ai.itemSummaries : []) as ItemSummary[];
  const sortedItems = [...items].sort((a, b) => (a.priority ?? 99) - (b.priority ?? 99));

  return (
    <div className="space-y-5">
      <header className="rounded-2xl border border-accent/20 bg-gradient-to-br from-accent/10 via-transparent to-indigo-500/5 p-5">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <div className="flex items-center gap-2 text-xs font-semibold text-accent">
              <Shield className="h-4 w-4" />
              Сводный ИИ-отчёт
            </div>
            {title ? <h3 className="mt-2 text-base font-semibold text-fg/95">{title}</h3> : null}
          </div>
          {riskBadge(typeof ai.overallRiskRating === "string" ? ai.overallRiskRating : null)}
        </div>
        {executiveSummary ? (
          <p className="mt-3 text-sm leading-relaxed text-fg/88">{executiveSummary}</p>
        ) : null}
      </header>

      {rm ? (
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
          <MetricCard label="Позиций BDU" value={Number(rm.itemCount) || items.length} />
          <MetricCard label="Высокий / крит." value={Number(rm.highOrCriticalCount) || "—"} />
          <MetricCard label="С эксплойтом" value={Number(rm.withPublicExploit) || 0} />
          <MetricCard
            label="Срочный патч"
            value={Number(rm.needsImmediatePatch) || 0}
            sub={
              typeof rm.inRegistry === "number"
                ? `в БДУ: ${rm.inRegistry}/${Number(rm.itemCount) || items.length}`
                : undefined
            }
          />
        </div>
      ) : null}

      {keyFindings.length > 0 ? (
        <section className="rounded-xl border border-fg/10 bg-fg/[0.03] p-4">
          <div className="flex items-center gap-2 text-xs font-semibold text-fg/80">
            <Target className="h-3.5 w-3.5" />
            Ключевые выводы
          </div>
          <ul className="mt-3 space-y-2">
            {keyFindings.map((f, i) => (
              <li key={i} className="flex gap-2 text-sm text-fg/80">
                <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-accent" />
                <span>{f}</span>
              </li>
            ))}
          </ul>
        </section>
      ) : null}

      {managementBrief ? (
        <section className="rounded-xl border border-fg/10 p-4">
          <div className="text-xs font-semibold text-fg/70">Для руководства (CISO)</div>
          <p className="mt-2 text-sm leading-relaxed text-fg/85">{managementBrief}</p>
        </section>
      ) : null}

      {technicalBrief ? (
        <section className="rounded-xl border border-fg/10 p-4">
          <div className="text-xs font-semibold text-fg/70">Технический разбор</div>
          <p className="mt-2 whitespace-pre-wrap text-sm leading-relaxed text-fg/80">{technicalBrief}</p>
        </section>
      ) : null}

      {bulletinContext ? (
        <section className="rounded-xl border border-dashed border-fg/15 p-4">
          <div className="text-xs font-semibold text-fg/60">Контекст бюллетеня</div>
          <p className="mt-2 text-xs leading-relaxed text-fg/65">{bulletinContext}</p>
        </section>
      ) : null}

      {themes.length > 0 ? (
        <section>
          <div className="text-xs font-semibold text-fg/70">Сквозные темы</div>
          <div className="mt-2 flex flex-wrap gap-2">
            {themes.map((t) => (
              <span
                key={t}
                className="rounded-full border border-indigo-500/25 bg-indigo-500/10 px-2.5 py-1 text-[11px] text-fg/75"
              >
                {t}
              </span>
            ))}
          </div>
        </section>
      ) : null}

      {priorityOrder.length > 0 ? (
        <section>
          <div className="flex items-center gap-2 text-xs font-semibold text-fg/70">
            <TrendingUp className="h-3.5 w-3.5" />
            Очередь устранения
          </div>
          <div className="mt-2 flex flex-wrap gap-1.5">
            {priorityOrder.map((bdu, i) => (
              <button
                key={`${bdu}-${i}`}
                type="button"
                onClick={() => {
                  const id = bdu.replace(/^BDU:/i, "").trim();
                  if (id) onOpenBdu?.(id);
                }}
                className="rounded-lg border border-fg/10 bg-fg/5 px-2 py-1 font-mono text-[10px] text-accent hover:bg-accent/10"
              >
                {i + 1}. {bdu}
              </button>
            ))}
          </div>
        </section>
      ) : null}

      {actionPlan?.phases && actionPlan.phases.length > 0 ? (
        <section className="rounded-2xl border border-emerald-500/25 bg-gradient-to-b from-emerald-500/8 to-transparent p-5">
          <div className="flex items-center gap-2 text-sm font-semibold text-emerald-100/95">
            <CheckCircle2 className="h-4 w-4" />
            План действий по бюллетеню
          </div>
          {actionPlan.introduction ? (
            <p className="mt-2 text-sm leading-relaxed text-fg/80">{actionPlan.introduction}</p>
          ) : null}
          {actionPlan.complianceNote ? (
            <p className="mt-2 rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-100/90">
              {actionPlan.complianceNote}
            </p>
          ) : null}
          <div className="mt-4 space-y-4">
            {actionPlan.phases.map((ph) => (
              <div
                key={ph.id ?? ph.title}
                className="rounded-xl border border-fg/10 bg-fg/[0.03] p-4"
              >
                <div className="flex flex-wrap items-baseline justify-between gap-2">
                  <h4 className="text-sm font-semibold text-fg/92">{ph.title}</h4>
                  <span className="flex items-center gap-1 font-mono text-[10px] text-fg/45">
                    <Clock className="h-3 w-3" />
                    {ph.horizon}
                  </span>
                </div>
                {ph.owner ? (
                  <p className="mt-1 text-[11px] text-fg/50">
                    <span className="text-fg/40">Ответственные: </span>
                    {ph.owner}
                  </p>
                ) : null}
                {ph.goal ? (
                  <p className="mt-2 text-xs leading-relaxed text-fg/70">{ph.goal}</p>
                ) : null}
                {ph.steps && ph.steps.length > 0 ? (
                  <ol className="mt-3 space-y-3">
                    {ph.steps.map((step) => {
                      const typeCls =
                        ACTION_TYPE_STYLE[step.actionType ?? ""] ?? ACTION_TYPE_STYLE.monitor;
                      return (
                        <li
                          key={`${ph.id}-${step.order}-${step.bduId ?? step.title}`}
                          className="rounded-lg border border-fg/8 bg-black/10 px-3 py-2.5"
                        >
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="font-mono text-[10px] text-fg/35">{step.order}.</span>
                            {step.actionType ? (
                              <span className={cn("rounded px-1.5 py-0.5 text-[9px] font-medium", typeCls)}>
                                {step.actionType === "patch"
                                  ? "Патч"
                                  : step.actionType === "compensate"
                                    ? "Компенсация"
                                    : step.actionType === "inventory"
                                      ? "Проверка"
                                      : step.actionType === "governance"
                                        ? "Отчёт"
                                        : "Мониторинг"}
                              </span>
                            ) : null}
                            {step.bduId ? (
                              <button
                                type="button"
                                onClick={() => onOpenBdu?.(step.bduId!)}
                                className="font-mono text-[10px] text-accent hover:underline"
                              >
                                BDU:{step.bduId}
                              </button>
                            ) : null}
                          </div>
                          {step.title ? (
                            <p className="mt-1.5 text-xs font-medium text-fg/88">{step.title}</p>
                          ) : null}
                          {step.detail ? (
                            <p className="mt-1 text-[11px] leading-relaxed text-fg/65">{step.detail}</p>
                          ) : null}
                        </li>
                      );
                    })}
                  </ol>
                ) : null}
              </div>
            ))}
          </div>
        </section>
      ) : null}

      {regulatory.length > 0 ? (
        <section className="rounded-xl border border-amber-500/25 bg-amber-500/5 p-4">
          <div className="text-xs font-semibold text-amber-200/90">Обязательства оператора КИИ</div>
          <ul className="mt-2 list-disc space-y-1 pl-4 text-xs text-fg/75">
            {regulatory.map((r, i) => (
              <li key={i}>{r}</li>
            ))}
          </ul>
        </section>
      ) : null}

      {uncertainties.length > 0 ? (
        <section className="rounded-xl border border-fg/10 p-4">
          <div className="flex items-center gap-2 text-xs font-semibold text-fg/60">
            <AlertTriangle className="h-3.5 w-3.5" />
            Что уточнить в инвентаризации
          </div>
          <ul className="mt-2 list-disc space-y-1 pl-4 text-xs text-fg/60">
            {uncertainties.map((u, i) => (
              <li key={i}>{u}</li>
            ))}
          </ul>
        </section>
      ) : null}

      {sortedItems.length > 0 ? (
        <section className="rounded-xl border border-fg/10">
          <button
            type="button"
            onClick={() => setItemsOpen((v) => !v)}
            className="flex w-full items-center justify-between gap-2 px-4 py-3 text-left text-xs font-medium text-fg/70 hover:bg-fg/5"
          >
            <span className="flex items-center gap-2">
              <Brain className="h-3.5 w-3.5 text-muted" />
              ИИ-анализ по позициям ({sortedItems.length}, опционально)
            </span>
            <ChevronDown
              className={cn("h-4 w-4 shrink-0 transition", itemsOpen && "rotate-180")}
            />
          </button>
          {itemsOpen ? (
            <div className="space-y-3 border-t border-fg/10 p-4">
              <p className="text-[11px] text-muted">
                Интерпретация модели по каждой BDU. Исходный текст бюллетеня — в блоке «Исходные позиции»
                выше.
              </p>
              {sortedItems.map((it) => {
                const bdu = String(it.bduId ?? "").replace(/^BDU:/i, "");
                return (
                  <article
                    key={`${it.ordinal}-${bdu}`}
                    className="rounded-xl border border-fg/10 bg-gradient-to-br from-fg/[0.04] to-transparent p-4"
                  >
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-[10px] text-fg/40">P{it.priority ?? "—"}</span>
                      {bdu ? (
                        <button
                          type="button"
                          onClick={() => onOpenBdu?.(bdu)}
                          className="font-mono text-xs font-medium text-accent hover:underline"
                        >
                          BDU:{bdu}
                        </button>
                      ) : null}
                      {urgencyChip(it.exploitUrgency)}
                      {it.cvssFromBulletin ? (
                        <span className="text-[10px] text-fg/50">бюллетень: {it.cvssFromBulletin}</span>
                      ) : null}
                      {it.registryCvss != null ? (
                        <span className="text-[10px] text-fg/50">CVSS {it.registryCvss}</span>
                      ) : null}
                    </div>
                    {it.headline ? <h4 className="mt-2 text-sm font-semibold text-fg/92">{it.headline}</h4> : null}
                    {it.summary ? <p className="mt-1.5 text-xs leading-relaxed text-fg/75">{it.summary}</p> : null}
                    {it.businessImpact ? (
                      <p className="mt-2 rounded-lg bg-amber-500/5 px-2 py-1.5 text-xs text-amber-100/90">
                        <span className="font-medium">Влияние: </span>
                        {it.businessImpact}
                      </p>
                    ) : null}
                    {Array.isArray(it.attackFlow) && it.attackFlow.length > 0 ? (
                      <div className="mt-3">
                        <div className="text-[10px] font-medium uppercase text-fg/45">Цепочка атаки</div>
                        <ol className="mt-1 list-decimal space-y-0.5 pl-4 text-[11px] text-fg/70">
                          {it.attackFlow.map((s, i) => (
                            <li key={i}>{s}</li>
                          ))}
                        </ol>
                      </div>
                    ) : null}
                    {Array.isArray(it.remediation) && it.remediation.length > 0 ? (
                      <div className="mt-2 text-[11px] text-emerald-200/85">
                        <span className="font-medium">Устранение: </span>
                        {it.remediation.join(" ")}
                      </div>
                    ) : null}
                    {Array.isArray(it.compensatingIfAny) && it.compensatingIfAny.length > 0 ? (
                      <div className="mt-1 text-[11px] text-fg/55">
                        <span className="font-medium">Компенсация: </span>
                        {it.compensatingIfAny.join(" ")}
                      </div>
                    ) : null}
                    {Array.isArray(it.linkedCves) && it.linkedCves.length > 0 ? (
                      <div className="mt-2 flex flex-wrap gap-1">
                        {it.linkedCves.map((c) => (
                          <span key={c} className="font-mono text-[10px] text-fg/45">
                            {c}
                          </span>
                        ))}
                      </div>
                    ) : null}
                  </article>
                );
              })}
            </div>
          ) : null}
        </section>
      ) : null}

      {hasGraphData ? (
        <section className="rounded-xl border border-fg/10">
          <button
            type="button"
            onClick={() => setGraphOpen((v) => !v)}
            className="flex w-full items-center justify-between gap-2 px-4 py-3 text-left text-xs font-medium text-fg/70 hover:bg-fg/5"
          >
            <span className="flex items-center gap-2">
              <GitBranch className="h-3.5 w-3.5 text-muted" />
              Сводная схема атаки (опционально)
            </span>
            <ChevronDown
              className={cn("h-4 w-4 shrink-0 transition", graphOpen && "rotate-180")}
            />
          </button>
          {graphOpen ? (
            <div className="border-t border-fg/10 px-1 pb-1">
              <p className="px-3 py-2 text-[11px] text-muted">
                Обобщённый граф по бюллетеню. Детальные цепочки — в блоке «ИИ-анализ по позициям»; в Excel —
                лист Attack map.
              </p>
              <AttackGraphPanel graph={combinedGraph} attackFlow={attackFlowSteps} />
            </div>
          ) : null}
        </section>
      ) : null}
    </div>
  );
}
