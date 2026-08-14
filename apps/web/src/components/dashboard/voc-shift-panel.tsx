"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Bell, ClipboardCopy, FileText, Loader2, Plus, Radio, Trash2 } from "lucide-react";
import { useState } from "react";
import { cn } from "../ui/cn";
import { LiveNumber, LiveText } from "../ui/live-number";
import { useLiveQueryOptions } from "@/lib/live-refresh";
import {
  addVocAlertRule,
  createVocHandover,
  deleteVocAlertRule,
  evaluateVocAlerts,
  fetchVocAlertRules,
  fetchVocKpis,
  patchVocAlertRule
} from "@/lib/voc-shift-api";
import { VOC_ALERT_CONDITIONS, vocAlertConditionLabel } from "@/lib/voc-shift-client";

export function VocShiftPanel({ className }: { className?: string }) {
  const queryClient = useQueryClient();
  const [handoverNotes, setHandoverNotes] = useState("");
  const [handoverMd, setHandoverMd] = useState<string | null>(null);
  const [newRuleName, setNewRuleName] = useState("");
  const [newRuleCondition, setNewRuleCondition] = useState<(typeof VOC_ALERT_CONDITIONS)[number]>("p1_open");
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const liveOpts = useLiveQueryOptions();

  const kpiQ = useQuery({
    queryKey: ["voc", "kpis", 8],
    queryFn: () => fetchVocKpis(8),
    ...liveOpts
  });

  const rulesQ = useQuery({
    queryKey: ["voc", "alert-rules"],
    queryFn: fetchVocAlertRules,
    staleTime: 20_000
  });

  const handoverMut = useMutation({
    mutationFn: () => createVocHandover({ hours: 8, notes: handoverNotes.trim() || null }),
    onSuccess: (data) => {
      setHandoverMd(data.markdown);
      setMsg("Handover сохранён");
      setErr(null);
    },
    onError: (e) => setErr(e instanceof Error ? e.message : "Ошибка handover")
  });

  const evalMut = useMutation({
    mutationFn: evaluateVocAlerts,
    onSuccess: (data) => {
      setMsg(`Алерты: отправлено ${data.fired}`);
      setErr(null);
    },
    onError: (e) => setErr(e instanceof Error ? e.message : "Ошибка алертов")
  });

  const addRuleMut = useMutation({
    mutationFn: () => addVocAlertRule({ name: newRuleName.trim(), condition: newRuleCondition, channel: "telegram" }),
    onSuccess: () => {
      setNewRuleName("");
      void queryClient.invalidateQueries({ queryKey: ["voc", "alert-rules"] });
      setMsg("Правило добавлено");
    },
    onError: (e) => setErr(e instanceof Error ? e.message : "Ошибка")
  });

  const kpi = kpiQ.data;

  return (
    <div className={cn("rounded-2xl border border-slate-200/80 bg-white/70 p-4 dark:border-white/10 dark:bg-black/25", className)}>
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 text-sm font-semibold">
          <Radio className="h-4 w-4 text-sky-500" />
          Смена и KPI
        </div>
        <span className="text-[10px] text-muted">окно 8ч</span>
      </div>

      {kpi ? (
        <div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-4">
          {[
            { l: "P1 открыто", v: kpi.queue.p1Open, kind: "num" as const },
            { l: "Просрочен SLA", v: kpi.cases.slaBreached, kind: "num" as const },
            { l: "Закрыто за смену", v: kpi.cases.resolvedInWindow, kind: "num" as const },
            {
              l: "Среднее закрытие",
              v: kpi.cases.avgResolutionHours != null ? `${kpi.cases.avgResolutionHours}ч` : "—",
              kind: "text" as const
            },
            { l: "Backlog triage", v: kpi.triage.open + kpi.triage.claimed, kind: "num" as const },
            { l: "Кейсы активны", v: kpi.cases.active, kind: "num" as const },
            { l: "Watchlist hits", v: kpi.queue.watchlistHits, kind: "num" as const },
            {
              l: "Шум TG",
              v: kpi.tg.noiseRatio != null ? `${kpi.tg.noiseRatio}%` : "—",
              kind: "text" as const
            }
          ].map((c) => (
            <div key={c.l} className="rounded-lg border border-slate-200/80 bg-slate-50/80 px-2 py-1.5 dark:border-white/10 dark:bg-black/20">
              <div className="text-[9px] text-muted">{c.l}</div>
              <div className="text-sm font-semibold tabular-nums">
                {c.kind === "num" ? <LiveNumber value={c.v as number} /> : <LiveText value={c.v as string} />}
              </div>
            </div>
          ))}
        </div>
      ) : kpiQ.isLoading ? (
        <div className="mt-3 text-[11px] text-muted">Загрузка KPI…</div>
      ) : null}

      <div className="mt-4 space-y-2 border-t border-slate-200/80 pt-3 dark:border-white/10">
        <div className="flex items-center gap-2 text-[11px] font-medium">
          <FileText className="h-3.5 w-3.5" />
          Handover следующей смене
        </div>
        <textarea
          value={handoverNotes}
          onChange={(e) => setHandoverNotes(e.target.value)}
          rows={2}
          placeholder="Заметки для следующей смены (опционально)"
          className="w-full rounded-lg border border-slate-200 bg-white px-2.5 py-2 text-[11px] dark:border-white/10 dark:bg-black/30"
        />
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            disabled={handoverMut.isPending}
            onClick={() => handoverMut.mutate()}
            className="inline-flex items-center gap-1 rounded-lg border border-sky-400/35 bg-sky-500/12 px-2.5 py-1.5 text-[10px] font-medium"
          >
            {handoverMut.isPending ? <Loader2 className="h-3 w-3 animate-spin" /> : <FileText className="h-3 w-3" />}
            Сформировать
          </button>
          {handoverMd ? (
            <button
              type="button"
              onClick={() => void navigator.clipboard.writeText(handoverMd)}
              className="inline-flex items-center gap-1 rounded-lg border border-slate-200 px-2.5 py-1.5 text-[10px] dark:border-white/10"
            >
              <ClipboardCopy className="h-3 w-3" />
              Копировать
            </button>
          ) : null}
        </div>
        {handoverMd ? (
          <pre className="max-h-40 overflow-auto rounded-lg border border-slate-200/80 bg-slate-50/90 p-2 text-[10px] leading-relaxed dark:border-white/10 dark:bg-black/30">
            {handoverMd}
          </pre>
        ) : null}
      </div>

      <div className="mt-4 space-y-2 border-t border-slate-200/80 pt-3 dark:border-white/10">
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-2 text-[11px] font-medium">
            <Bell className="h-3.5 w-3.5" />
            Правила алертов
          </div>
          <button
            type="button"
            disabled={evalMut.isPending}
            onClick={() => evalMut.mutate()}
            className="rounded border border-slate-200 px-2 py-0.5 text-[9px] dark:border-white/10"
          >
            {evalMut.isPending ? "…" : "Проверить"}
          </button>
        </div>
        <div className="flex flex-wrap gap-1.5">
          <input
            value={newRuleName}
            onChange={(e) => setNewRuleName(e.target.value)}
            placeholder="Название правила"
            className="min-w-[8rem] flex-1 rounded-lg border border-slate-200 bg-white px-2 py-1 text-[10px] dark:border-white/10 dark:bg-black/30"
          />
          <select
            value={newRuleCondition}
            onChange={(e) => setNewRuleCondition(e.target.value as (typeof VOC_ALERT_CONDITIONS)[number])}
            className="rounded-lg border border-slate-200 bg-white px-2 py-1 text-[10px] dark:border-white/10 dark:bg-black/30"
          >
            {VOC_ALERT_CONDITIONS.map((c) => (
              <option key={c} value={c}>
                {vocAlertConditionLabel(c)}
              </option>
            ))}
          </select>
          <button
            type="button"
            disabled={!newRuleName.trim() || addRuleMut.isPending}
            onClick={() => addRuleMut.mutate()}
            className="inline-flex items-center gap-0.5 rounded-lg border border-amber-400/35 bg-amber-500/10 px-2 py-1 text-[10px]"
          >
            <Plus className="h-3 w-3" />
            Добавить
          </button>
        </div>
        <div className="space-y-1">
          {(rulesQ.data ?? []).map((rule) => (
            <div
              key={rule.id}
              className="flex items-center justify-between gap-2 rounded-lg border border-slate-200/80 px-2 py-1.5 text-[10px] dark:border-white/10"
            >
              <label className="flex min-w-0 flex-1 items-center gap-2">
                <input
                  type="checkbox"
                  checked={rule.active}
                  onChange={(e) =>
                    void patchVocAlertRule(rule.id, { active: e.target.checked }).then(() =>
                      queryClient.invalidateQueries({ queryKey: ["voc", "alert-rules"] })
                    )
                  }
                />
                <span className="truncate font-medium">{rule.name}</span>
                <span className="text-muted">{vocAlertConditionLabel(rule.condition)}</span>
              </label>
              <button
                type="button"
                onClick={() =>
                  void deleteVocAlertRule(rule.id).then(() =>
                    queryClient.invalidateQueries({ queryKey: ["voc", "alert-rules"] })
                  )
                }
                className="shrink-0 rounded p-0.5 text-muted hover:text-danger"
              >
                <Trash2 className="h-3.5 w-3.5" />
              </button>
            </div>
          ))}
          {!rulesQ.data?.length && !rulesQ.isLoading ? (
            <div className="text-[10px] text-muted">Нет правил — добавьте P1 или SLA алерт в Telegram.</div>
          ) : null}
        </div>
      </div>

      {msg ? <div className="mt-2 text-[10px] text-ok">{msg}</div> : null}
      {err ? <div className="mt-2 text-[10px] text-danger">{err}</div> : null}
    </div>
  );
}
