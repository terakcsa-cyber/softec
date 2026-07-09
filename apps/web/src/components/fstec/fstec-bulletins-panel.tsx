"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  extractPlainTextFromDocx,
  guessBulletinReferenceFromFilename,
  type FstecBulletinParsedItemClient
} from "@/lib/fstec-bulletin-client";
import {
  AlertCircle,
  Brain,
  CheckCircle2,
  Download,
  FileText,
  Loader2,
  Trash2,
  Upload
} from "lucide-react";
import { useCallback, useMemo, useRef, useState } from "react";
import { apiFetch } from "@/lib/api-fetch";
import { parseAiOutputJson } from "@/lib/cve-enrich-ui";
import { cn } from "../ui/cn";
import { FstecBulletinAnalysisView } from "./fstec-bulletin-analysis-view";

type BulletinListItem = {
  id: string;
  title: string | null;
  reference_no: string | null;
  source_filename: string | null;
  status: string;
  created_at: string;
  item_count: number;
  has_analysis: boolean;
};

type BulletinDetail = {
  bulletin: {
    id: string;
    title: string | null;
    referenceNo: string | null;
    sourceFilename: string | null;
    status: string;
    itemCount: number;
    createdAt: string;
  };
  parsed: {
    title: string | null;
    subject: string | null;
    intro: string | null;
    items: FstecBulletinParsedItemClient[];
    orphanBduIds: string[];
  };
  registry: {
    bduId: string;
    found: boolean;
    name: string | null;
    cvssScore: number | null;
    severity: string | null;
    hasExploit: boolean;
  }[];
  analysis: {
    status: string;
    outputJson: Record<string, unknown> | null;
    outputText: string | null;
    errorText: string | null;
  } | null;
};

export type FstecBulletinsPanelProps = {
  onOpenBdu?: (bduId: string) => void;
};

async function readFileAsText(file: File): Promise<{ plainText: string; referenceNo: string | null }> {
  const name = file.name;
  const ref = guessBulletinReferenceFromFilename(name);
  const lower = name.toLowerCase();
  if (lower.endsWith(".docx")) {
    const buf = new Uint8Array(await file.arrayBuffer());
    return { plainText: extractPlainTextFromDocx(buf), referenceNo: ref };
  }
  if (lower.endsWith(".txt")) {
    return { plainText: await file.text(), referenceNo: ref };
  }
  throw new Error("Поддерживаются файлы .docx и .txt");
}

function cvssBadge(label: string) {
  const l = label.toLowerCase();
  const cls =
    l.includes("крит") ? "bg-red-500/20 text-red-200" :
    l.includes("высок") ? "bg-orange-500/20 text-orange-200" :
    l.includes("средн") ? "bg-amber-500/20 text-amber-200" :
    "bg-fg/10 text-fg/70";
  return (
    <span className={cn("rounded px-1.5 py-0.5 text-[10px] font-medium uppercase", cls)}>
      {label}
    </span>
  );
}

export function FstecBulletinsPanel({ onOpenBdu }: FstecBulletinsPanelProps) {
  const qc = useQueryClient();
  const fileRef = useRef<HTMLInputElement>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [dlBusy, setDlBusy] = useState(false);
  const [dlErr, setDlErr] = useState<string | null>(null);
  const [deleteErr, setDeleteErr] = useState<string | null>(null);

  const listQ = useQuery({
    queryKey: ["fstec", "bulletins"],
    queryFn: async () => {
      const res = await apiFetch("/api/fstec/bulletins?limit=40", { cache: "no-store" });
      const body = (await res.json()) as { items?: BulletinListItem[]; error?: string };
      if (!res.ok) throw new Error(body.error ?? `Ошибка ${res.status}`);
      return body.items ?? [];
    },
    refetchInterval: 8_000
  });

  const detailQ = useQuery({
    queryKey: ["fstec", "bulletins", selectedId],
    enabled: selectedId != null,
    queryFn: async () => {
      const res = await apiFetch(`/api/fstec/bulletins/${selectedId}`, { cache: "no-store" });
      const body = (await res.json()) as BulletinDetail & { message?: string };
      if (!res.ok) throw new Error(body.message ?? `Ошибка ${res.status}`);
      return body;
    },
    refetchInterval: (q) => {
      const st = q.state.data?.bulletin.status;
      return st === "analyzing" ? 3_000 : false;
    }
  });

  const uploadMut = useMutation({
    mutationFn: async (file: File) => {
      setUploadError(null);
      const { plainText, referenceNo } = await readFileAsText(file);
      const res = await apiFetch("/api/fstec/bulletins", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          plainText,
          referenceNo,
          sourceFilename: file.name,
          title: referenceNo ? `Бюллетень ${referenceNo}` : file.name
        })
      });
      const body = (await res.json()) as BulletinDetail & { error?: string; message?: string };
      if (!res.ok) {
        throw new Error(
          body.error ?? body.message ?? (typeof body === "object" ? JSON.stringify(body).slice(0, 400) : `Ошибка загрузки (${res.status})`)
        );
      }
      return body;
    },
    onSuccess: (data) => {
      void qc.invalidateQueries({ queryKey: ["fstec", "bulletins"] });
      setSelectedId(data.bulletin.id);
    },
    onError: (e) => setUploadError(e instanceof Error ? e.message : String(e))
  });

  const deleteMut = useMutation({
    mutationFn: async (id: string) => {
      const res = await apiFetch(`/api/fstec/bulletins/${encodeURIComponent(id)}`, {
        method: "DELETE",
        cache: "no-store"
      });
      if (!res.ok) {
        const body = (await res.json().catch(() => ({}))) as { error?: string; message?: string };
        throw new Error(body.error ?? body.message ?? `Ошибка удаления (${res.status})`);
      }
    },
    onSuccess: (_data, id) => {
      setDeleteErr(null);
      if (selectedId === id) setSelectedId(null);
      void qc.invalidateQueries({ queryKey: ["fstec", "bulletins"] });
      void qc.removeQueries({ queryKey: ["fstec", "bulletins", id] });
    },
    onError: (e) => setDeleteErr(e instanceof Error ? e.message : String(e))
  });

  const requestDelete = useCallback(
    (id: string, label: string) => {
      const ok = window.confirm(
        `Удалить бюллетень «${label}»?\n\nЗапись и ИИ-анализ будут удалены без восстановления.`
      );
      if (ok) deleteMut.mutate(id);
    },
    [deleteMut]
  );

  const analyzeMut = useMutation({
    mutationFn: async (id: string) => {
      const res = await apiFetch(`/api/fstec/bulletins/${id}/analyze`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ force: true })
      });
      if (!res.ok) {
        const body = (await res.json()) as { message?: string };
        throw new Error(body.message ?? `Ошибка ${res.status}`);
      }
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["fstec", "bulletins"] });
      if (selectedId) void qc.invalidateQueries({ queryKey: ["fstec", "bulletins", selectedId] });
    }
  });

  const onFile = useCallback(
    (files: FileList | null) => {
      const f = files?.[0];
      if (f) uploadMut.mutate(f);
    },
    [uploadMut]
  );

  const analysis = detailQ.data?.analysis;
  const aiJson = analysis?.outputJson;
  const aiParsed = useMemo(() => parseAiOutputJson(aiJson ?? null), [aiJson]);
  const executiveSummary =
    typeof aiParsed?.executiveSummary === "string"
      ? aiParsed.executiveSummary
      : analysis?.outputText ?? null;

  const hasRichAnalysis = analysis?.status === "ready" && aiParsed != null;

  const onDownloadXlsx = useCallback(async () => {
    if (!selectedId || dlBusy) return;
    setDlBusy(true);
    setDlErr(null);
    try {
      const href = `/api/fstec/bulletins/${encodeURIComponent(selectedId)}/risk-xlsx`;
      const res = await apiFetch(href, { cache: "no-store" });
      if (!res.ok) {
        const txt = await res.text().catch(() => "");
        throw new Error(txt || `Ошибка загрузки (${res.status})`);
      }
      const blob = await res.blob();
      const cd = res.headers.get("content-disposition") ?? "";
      const m = cd.match(/filename="([^"]+)"/i);
      const filename = m?.[1] || `FSTEC-bulletin-${selectedId}.xlsx`;
      const url = URL.createObjectURL(blob);
      try {
        const a = document.createElement("a");
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        a.remove();
      } finally {
        setTimeout(() => URL.revokeObjectURL(url), 2000);
      }
    } catch (e) {
      setDlErr(e instanceof Error ? e.message : String(e));
    } finally {
      setDlBusy(false);
    }
  }, [selectedId, dlBusy]);

  const registryMap = useMemo(() => {
    const m = new Map<string, BulletinDetail["registry"][0]>();
    for (const r of detailQ.data?.registry ?? []) m.set(r.bduId, r);
    return m;
  }, [detailQ.data?.registry]);

  return (
    <div className="grid gap-4 lg:grid-cols-[minmax(0,280px)_1fr]">
      <div className="glass rounded-2xl p-4">
        <div className="flex items-center gap-2 text-sm font-medium">
          <FileText className="h-4 w-4 text-accent" />
          Бюллетени
        </div>
        <p className="mt-1 text-xs text-fg/60">
          Загрузите .docx или .txt — парсинг по BDU и сводный ИИ-анализ.
        </p>

        <input
          ref={fileRef}
          type="file"
          accept=".docx,.txt,text/plain"
          className="hidden"
          onChange={(e) => onFile(e.target.files)}
        />
        <button
          type="button"
          disabled={uploadMut.isPending}
          onClick={() => fileRef.current?.click()}
          className="mt-3 flex w-full items-center justify-center gap-2 rounded-xl border border-dashed border-accent/40 bg-accent/5 px-3 py-3 text-xs font-medium text-accent hover:bg-accent/10 disabled:opacity-50"
        >
          {uploadMut.isPending ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <Upload className="h-4 w-4" />
          )}
          Загрузить бюллетень
        </button>
        {uploadError ? (
          <p className="mt-2 text-xs text-red-400">{uploadError}</p>
        ) : null}
        {deleteErr ? <p className="mt-2 text-xs text-red-400">{deleteErr}</p> : null}

        <ul className="mt-4 max-h-[min(60vh,520px)] space-y-1 overflow-y-auto">
          {(listQ.data ?? []).map((b) => {
            const label = b.title ?? b.source_filename ?? b.id;
            return (
              <li key={b.id} className="group flex items-stretch gap-0.5">
                <button
                  type="button"
                  onClick={() => setSelectedId(b.id)}
                  className={cn(
                    "min-w-0 flex-1 rounded-lg px-2 py-2 text-left text-xs transition",
                    selectedId === b.id ? "bg-accent/15 text-fg" : "hover:bg-fg/5 text-fg/80"
                  )}
                >
                  <div className="font-medium line-clamp-2">{label}</div>
                  <div className="mt-0.5 flex flex-wrap gap-2 text-[10px] text-fg/50">
                    <span>{b.item_count} BDU</span>
                    {b.has_analysis ? (
                      <span className="text-emerald-400">ИИ готов</span>
                    ) : b.status === "analyzing" ? (
                      <span className="text-amber-400">анализ…</span>
                    ) : null}
                  </div>
                </button>
                <button
                  type="button"
                  title="Удалить"
                  disabled={deleteMut.isPending}
                  onClick={(e) => {
                    e.stopPropagation();
                    requestDelete(b.id, label);
                  }}
                  className="shrink-0 rounded-lg px-2 text-fg/35 opacity-0 transition hover:bg-red-500/15 hover:text-red-400 group-hover:opacity-100 disabled:opacity-40"
                >
                  {deleteMut.isPending && deleteMut.variables === b.id ? (
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  ) : (
                    <Trash2 className="h-3.5 w-3.5" />
                  )}
                </button>
              </li>
            );
          })}
          {listQ.isLoading ? (
            <li className="flex justify-center py-6">
              <Loader2 className="h-5 w-5 animate-spin text-fg/40" />
            </li>
          ) : null}
          {!listQ.isLoading && (listQ.data?.length ?? 0) === 0 ? (
            <li className="py-4 text-center text-xs text-fg/45">Пока нет загруженных бюллетеней</li>
          ) : null}
        </ul>
      </div>

      <div className="glass min-h-[320px] rounded-2xl p-5 sm:p-6">
        {!selectedId ? (
          <div className="flex h-full min-h-[240px] flex-col items-center justify-center text-center text-sm text-fg/50">
            <FileText className="mb-3 h-10 w-10 text-fg/25" />
            Выберите бюллетень или загрузите новый документ ФСТЭК
          </div>
        ) : detailQ.isLoading ? (
          <div className="flex justify-center py-16">
            <Loader2 className="h-8 w-8 animate-spin text-fg/40" />
          </div>
        ) : detailQ.error ? (
          <p className="text-sm text-red-400">{String(detailQ.error)}</p>
        ) : detailQ.data ? (
          <div className="space-y-5">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <h2 className="text-base font-semibold">{detailQ.data.bulletin.title}</h2>
                {detailQ.data.bulletin.referenceNo ? (
                  <p className="mt-0.5 font-mono text-xs text-fg/55">
                    № {detailQ.data.bulletin.referenceNo}
                  </p>
                ) : null}
                <p className="mt-1 text-xs text-fg/50">
                  {detailQ.data.parsed.items.length} уязвимостей · статус{" "}
                  <span className="font-mono">{detailQ.data.bulletin.status}</span>
                </p>
              </div>
              <div className="flex flex-wrap gap-2">
                <button
                  type="button"
                  disabled={dlBusy}
                  onClick={() => void onDownloadXlsx()}
                  className="inline-flex items-center gap-2 rounded-xl border border-fg/15 bg-fg/5 px-3 py-2 text-xs font-medium text-fg/85 hover:bg-fg/10 disabled:opacity-50"
                >
                  {dlBusy ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <Download className="h-4 w-4" />
                  )}
                  Excel
                </button>
                <button
                  type="button"
                  disabled={
                    analyzeMut.isPending || detailQ.data.bulletin.status === "analyzing"
                  }
                  onClick={() => analyzeMut.mutate(detailQ.data!.bulletin.id)}
                  className="inline-flex items-center gap-2 rounded-xl bg-accent px-3 py-2 text-xs font-medium text-bg hover:opacity-90 disabled:opacity-50"
                >
                  {detailQ.data.bulletin.status === "analyzing" || analyzeMut.isPending ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <Brain className="h-4 w-4" />
                  )}
                  Сводный ИИ-анализ
                </button>
                <button
                  type="button"
                  disabled={deleteMut.isPending}
                  onClick={() =>
                    requestDelete(
                      detailQ.data!.bulletin.id,
                      detailQ.data!.bulletin.title ?? detailQ.data!.bulletin.referenceNo ?? "бюллетень"
                    )
                  }
                  className="inline-flex items-center gap-2 rounded-xl border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs font-medium text-red-300 hover:bg-red-500/20 disabled:opacity-50"
                >
                  {deleteMut.isPending ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <Trash2 className="h-4 w-4" />
                  )}
                  Удалить
                </button>
              </div>
            </div>
            {dlErr ? <p className="text-xs text-red-400">{dlErr}</p> : null}

            {analysis?.status === "failed" ? (
              <div className="flex gap-2 rounded-xl border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-200">
                <AlertCircle className="h-4 w-4 shrink-0" />
                {analysis.errorText ?? "Ошибка ИИ-анализа"}
              </div>
            ) : null}

            {analysis?.status === "analyzing" ? (
              <div className="flex items-center gap-3 rounded-xl border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-sm text-amber-100/90">
                <Loader2 className="h-5 w-5 animate-spin shrink-0" />
                Запущены сводный ИИ-отчёт и обогащение карточек BDU из бюллетеня…
              </div>
            ) : null}

            <section>
              <h3 className="text-xs font-semibold text-fg/70">Исходные позиции бюллетеня</h3>
              <p className="mt-1 text-[11px] text-fg/50">
                Текст из документа ФСТЭК — основа для сводного анализа и плана действий ниже.
              </p>
              <div className="mt-2 space-y-3">
                {detailQ.data.parsed.items.map((item) => {
                  const reg = registryMap.get(item.bduId);
                  return (
                    <article
                      key={`${item.ordinal}-${item.bduId}`}
                      className="rounded-xl border border-fg/10 bg-fg/[0.03] p-3"
                    >
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-mono text-[10px] text-fg/45">#{item.ordinal}</span>
                        <button
                          type="button"
                          onClick={() => onOpenBdu?.(item.bduId)}
                          className="font-mono text-xs text-accent hover:underline"
                        >
                          BDU:{item.bduId}
                        </button>
                        {cvssBadge(item.cvssLabel)}
                        {reg?.found ? (
                          <span title="В реестре БДУ">
                            <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500" />
                          </span>
                        ) : (
                          <span title="Нет в локальной БД">
                            <AlertCircle className="h-3.5 w-3.5 text-amber-500" />
                          </span>
                        )}
                        {reg?.cvssScore != null ? (
                          <span className="text-[10px] text-fg/50">CVSS {reg.cvssScore}</span>
                        ) : null}
                      </div>
                      <p className="mt-1 text-sm font-medium text-fg/90">{item.headline}</p>
                      <p className="mt-1 text-xs leading-relaxed text-fg/60 whitespace-pre-wrap">
                        {item.body}
                      </p>
                      {item.remediation ? (
                        <p className="mt-2 text-xs text-emerald-200/80">
                          <span className="font-medium text-emerald-200/90">Устранение: </span>
                          {item.remediation}
                        </p>
                      ) : null}
                      {item.compensatingMeasures ? (
                        <p className="mt-1 text-xs text-fg/55">
                          <span className="font-medium">Компенсация: </span>
                          {item.compensatingMeasures}
                        </p>
                      ) : null}
                    </article>
                  );
                })}
              </div>
            </section>

            {hasRichAnalysis ? (
              <FstecBulletinAnalysisView
                outputJson={analysis!.outputJson as Record<string, unknown>}
                onOpenBdu={onOpenBdu}
              />
            ) : executiveSummary ? (
              <section className="rounded-xl border border-accent/25 bg-accent/5 p-4">
                <div className="flex items-center gap-2 text-xs font-semibold text-accent">
                  <SparklesIcon />
                  Сводка (черновик)
                </div>
                <p className="mt-2 text-sm leading-relaxed text-fg/85 whitespace-pre-wrap">
                  {executiveSummary}
                </p>
                <p className="mt-2 text-xs text-fg/50">Запустите «Сводный ИИ-анализ» для полного отчёта.</p>
              </section>
            ) : null}
          </div>
        ) : null}
      </div>
    </div>
  );
}

function SparklesIcon() {
  return (
    <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M12 3l1.5 5.5L19 10l-5.5 1.5L12 17l-1.5-5.5L5 10l5.5-1.5L12 3z" />
    </svg>
  );
}
