"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, CheckCircle2, ClipboardList, Link2, Loader2, MessageSquarePlus, Sparkles } from "lucide-react";
import { useState } from "react";
import { cn } from "../ui/cn";
import {
  addVocCaseEvidence,
  fetchVocCaseDetail,
  patchVocCasePlaybook,
  regenerateVocCasePlaybook,
  resolveVocCase,
  type VocCaseRow
} from "@/lib/voc-case-api";
import {
  VOC_OUTCOMES,
  playbookProgress,
  vocOutcomeLabel,
  type VocOutcome
} from "@/lib/voc-verification-client";
import { TelegramPostButton } from "./telegram-post-button";

function escalationFromCase(caseRow: VocCaseRow): { kind: "cve" | "bdu"; entityId: string } | null {
  const primary = caseRow.refs.find((r) => r.refKey === caseRow.primaryRefKey) ?? caseRow.refs[0];
  if (!primary) return null;
  if (primary.source === "cve") return { kind: "cve", entityId: primary.refId };
  if (primary.source === "bdu") return { kind: "bdu", entityId: primary.refId };
  const cve = caseRow.refs.find((r) => r.source === "cve");
  if (cve) return { kind: "cve", entityId: cve.refId };
  const bdu = caseRow.refs.find((r) => r.source === "bdu");
  if (bdu) return { kind: "bdu", entityId: bdu.refId };
  return null;
}

export function VocVerificationPanel({
  caseId,
  onResolved,
  variant = "card"
}: {
  caseId: string;
  onResolved?: () => void;
  variant?: "card" | "plain";
}) {
  const queryClient = useQueryClient();
  const [evidenceBody, setEvidenceBody] = useState("");
  const [evidenceUrl, setEvidenceUrl] = useState("");
  const [outcome, setOutcome] = useState<VocOutcome>("not_affected");
  const [outcomeNotes, setOutcomeNotes] = useState("");
  const [err, setErr] = useState<string | null>(null);

  const detailQ = useQuery({
    queryKey: ["voc", "case", caseId],
    queryFn: () => fetchVocCaseDetail(caseId),
    staleTime: 10_000
  });

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: ["voc", "case", caseId] });
    void queryClient.invalidateQueries({ queryKey: ["voc", "cases"] });
    void queryClient.invalidateQueries({ queryKey: ["voc", "queue"] });
  };

  const playbookMut = useMutation({
    mutationFn: ({ stepId, done }: { stepId: string; done: boolean }) =>
      patchVocCasePlaybook(caseId, { stepId, done }),
    onSuccess: () => invalidate(),
    onError: (e) => setErr(e instanceof Error ? e.message : "Ошибка playbook")
  });

  const evidenceMut = useMutation({
    mutationFn: () =>
      addVocCaseEvidence(caseId, {
        body: evidenceBody,
        url: evidenceUrl.trim() || null
      }),
    onSuccess: () => {
      setEvidenceBody("");
      setEvidenceUrl("");
      setErr(null);
      invalidate();
    },
    onError: (e) => setErr(e instanceof Error ? e.message : "Ошибка evidence")
  });

  const resolveMut = useMutation({
    mutationFn: () => resolveVocCase(caseId, { outcome, notes: outcomeNotes.trim() || null }),
    onSuccess: () => {
      setErr(null);
      invalidate();
      onResolved?.();
    },
    onError: (e) => setErr(e instanceof Error ? e.message : "Ошибка закрытия")
  });

  const regenMut = useMutation({
    mutationFn: () => regenerateVocCasePlaybook(caseId),
    onSuccess: () => {
      setErr(null);
      invalidate();
    },
    onError: (e) => setErr(e instanceof Error ? e.message : "Ошибка генерации playbook")
  });

  const caseRow = detailQ.data;
  const progress = playbookProgress(caseRow?.playbook);
  const resolved = caseRow?.status === "resolved" || caseRow?.status === "cancelled";
  const escalate = caseRow ? escalationFromCase(caseRow) : null;

  if (detailQ.isLoading) {
    return (
      <div className="flex items-center gap-2 rounded-xl border border-slate-200/80 bg-slate-50/80 px-3 py-4 text-[11px] text-muted dark:border-white/10 dark:bg-black/20">
        <Loader2 className="h-4 w-4 animate-spin" />
        Генерация ИИ-playbook…
      </div>
    );
  }

  if (!caseRow) return null;

  return (
    <div
      className={cn(
        "space-y-3",
        variant === "card" &&
          "rounded-xl border border-teal-200/70 bg-teal-50/40 p-3 dark:border-teal-900/40 dark:bg-teal-950/20"
      )}
    >
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 text-[12px] font-semibold text-fg/95">
          <ClipboardList className="h-4 w-4 text-teal-600 dark:text-teal-400" />
          Верификация
          {caseRow.playbook?.aiGenerated ? (
            <span className="inline-flex items-center gap-0.5 rounded-full border border-violet-400/35 bg-violet-500/10 px-1.5 py-0.5 text-[9px] font-normal text-violet-700 dark:text-violet-300">
              <Sparkles className="h-3 w-3" />
              ИИ
            </span>
          ) : null}
        </div>
        <div className="flex items-center gap-2">
          <span className="text-[10px] tabular-nums text-muted">
            Playbook {progress.done}/{progress.total}
          </span>
          {!resolved ? (
            <button
              type="button"
              disabled={regenMut.isPending}
              onClick={() => regenMut.mutate()}
              className="rounded border border-slate-200 px-1.5 py-0.5 text-[9px] text-muted hover:text-fg/80 dark:border-white/10"
              title="Перегенерировать playbook по контексту уязвимости"
            >
              {regenMut.isPending ? "…" : "↻ ИИ"}
            </button>
          ) : null}
        </div>
      </div>

      {caseRow.playbook?.contextSummary ? (
        <p className="text-[11px] leading-relaxed text-fg/85">{caseRow.playbook.contextSummary}</p>
      ) : null}

      {resolved && caseRow.outcome ? (
        <div className="rounded-lg border border-ok/30 bg-ok/10 px-3 py-2 text-[11px]">
          <div className="flex items-center gap-1.5 font-medium text-ok">
            <CheckCircle2 className="h-3.5 w-3.5" />
            {vocOutcomeLabel(caseRow.outcome)}
          </div>
          {caseRow.outcomeNotes ? (
            <p className="mt-1 text-fg/80">{caseRow.outcomeNotes}</p>
          ) : null}
        </div>
      ) : (
        <>
          <div className="space-y-1.5">
            {(caseRow.playbook?.steps ?? []).map((step) => (
              <label
                key={step.id}
                className={cn(
                  "flex cursor-pointer items-start gap-2 rounded-lg border px-2.5 py-2 text-[11px] transition",
                  step.done
                    ? "border-ok/30 bg-ok/8"
                    : "border-slate-200/80 bg-white/70 dark:border-white/10 dark:bg-black/20"
                )}
              >
                <input
                  type="checkbox"
                  className="mt-0.5"
                  checked={step.done}
                  disabled={playbookMut.isPending}
                  onChange={(e) =>
                    playbookMut.mutate({ stepId: step.id, done: e.target.checked })
                  }
                />
                <span className={cn("leading-snug", step.done && "text-muted line-through")}>{step.label}</span>
              </label>
            ))}
          </div>

          <div className="space-y-2 border-t border-teal-200/50 pt-3 dark:border-teal-900/30">
            <div className="text-[10px] font-medium uppercase tracking-wide text-muted">Evidence</div>
            <textarea
              value={evidenceBody}
              onChange={(e) => setEvidenceBody(e.target.value)}
              rows={2}
              placeholder="Что проверили: версия, хост, тикет, ссылка на advisory…"
              className="w-full rounded-lg border border-slate-200 bg-white px-2.5 py-2 text-[11px] dark:border-white/10 dark:bg-black/30"
            />
            <input
              value={evidenceUrl}
              onChange={(e) => setEvidenceUrl(e.target.value)}
              placeholder="URL (опционально)"
              className="w-full rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-[11px] dark:border-white/10 dark:bg-black/30"
            />
            <button
              type="button"
              disabled={!evidenceBody.trim() || evidenceMut.isPending}
              onClick={() => evidenceMut.mutate()}
              className="inline-flex items-center gap-1 rounded-lg border border-teal-400/35 bg-teal-500/12 px-2.5 py-1.5 text-[10px] font-medium"
            >
              {evidenceMut.isPending ? (
                <Loader2 className="h-3 w-3 animate-spin" />
              ) : (
                <MessageSquarePlus className="h-3 w-3" />
              )}
              Добавить запись
            </button>
            {(caseRow.evidence ?? []).length > 0 ? (
              <div className="max-h-28 space-y-1.5 overflow-y-auto pr-1 [scrollbar-width:thin]">
                {(caseRow.evidence ?? []).map((ev) => (
                  <div
                    key={ev.id}
                    className="rounded-lg border border-slate-200/80 bg-white/80 px-2 py-1.5 text-[10px] dark:border-white/10 dark:bg-black/25"
                  >
                    <div className="text-fg/90">{ev.body}</div>
                    <div className="mt-0.5 flex flex-wrap items-center gap-2 text-muted">
                      {ev.authorEmail ? <span>{ev.authorEmail}</span> : null}
                      {ev.url ? (
                        <a
                          href={ev.url}
                          target="_blank"
                          rel="noreferrer"
                          className="inline-flex items-center gap-0.5 text-teal-700 hover:underline dark:text-teal-300"
                        >
                          <Link2 className="h-3 w-3" />
                          ссылка
                        </a>
                      ) : null}
                    </div>
                  </div>
                ))}
              </div>
            ) : null}
          </div>

          <div className="space-y-2 border-t border-teal-200/50 pt-3 dark:border-teal-900/30">
            <div className="text-[10px] font-medium uppercase tracking-wide text-muted">Исход</div>
            <select
              value={outcome}
              onChange={(e) => setOutcome(e.target.value as VocOutcome)}
              className="w-full rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-[11px] dark:border-white/10 dark:bg-black/30"
            >
              {VOC_OUTCOMES.map((o) => (
                <option key={o} value={o}>
                  {vocOutcomeLabel(o)}
                </option>
              ))}
            </select>
            <textarea
              value={outcomeNotes}
              onChange={(e) => setOutcomeNotes(e.target.value)}
              rows={2}
              placeholder="Комментарий к исходу (опционально)"
              className="w-full rounded-lg border border-slate-200 bg-white px-2.5 py-2 text-[11px] dark:border-white/10 dark:bg-black/30"
            />
            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                disabled={resolveMut.isPending}
                onClick={() => resolveMut.mutate()}
                className="inline-flex items-center gap-1 rounded-lg border border-ok/35 bg-ok/12 px-3 py-1.5 text-[11px] font-medium text-ok"
              >
                {resolveMut.isPending ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <Check className="h-3.5 w-3.5" />
                )}
                Закрыть кейс
              </button>
              {escalate ? (
                <TelegramPostButton
                  kind={escalate.kind}
                  entityId={escalate.entityId}
                  className="text-[10px]"
                />
              ) : null}
            </div>
          </div>
        </>
      )}

      {err ? <div className="text-[10px] text-danger">{err}</div> : null}
    </div>
  );
}
