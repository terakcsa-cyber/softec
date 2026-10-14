"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { X } from "lucide-react";
import { useVc } from "./vc-context";
import { useCveDetail, useTasksForCve } from "@/lib/vulncontrol/live";
import { buildVulnCard } from "@/lib/vulncontrol/vuln-model";
import { TelegramPostButton } from "../dashboard/telegram-post-button";
import { CveAiButton } from "./cve-ai-button";
import { BadgeRow, BduMappingBlock, CardActions, ContextBlock, FactList, HistoryList, ProductBlock, ReferenceList, RemediationBlock, ScoreGrid, SeverityBadge, TaskBlock, hasContext, mappedBduIds } from "./vulnerability-sections";

export function DetailDrawer() {
  const { selectedId, setSelectedId, openTask } = useVc();
  const router = useRouter();
  const detail = useCveDetail(selectedId);
  const tasks = useTasksForCve(selectedId);
  const card = selectedId ? buildVulnCard(selectedId, detail.data, tasks.data?.items ?? []) : null;

  useEffect(() => {
    if (!selectedId) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key !== "Escape" || document.querySelector("[role='dialog']")) return;
      setSelectedId(null);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [selectedId, setSelectedId]);

  if (!selectedId) return null;
  const openFull = (tab?: string) => {
    const query = tab ? `?tab=${tab}` : "";
    router.push(`/vulnerabilities/${encodeURIComponent(selectedId)}${query}`);
  };

  return (
    <div className="fixed inset-0 z-40">
      <button type="button" aria-label="Закрыть просмотр" className="absolute inset-0 bg-black/45" onClick={() => setSelectedId(null)} />
      <aside className="absolute inset-y-0 right-0 flex w-full flex-col border-l border-[var(--vc-border)] bg-[var(--vc-inset-2)] shadow-2xl sm:w-[460px]">
        <div className="flex items-start justify-between gap-3 border-b border-[var(--vc-border)] px-4 py-3">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-[14px] font-semibold">{selectedId}</span>
              {card?.severity ? <SeverityBadge label={card.severity.label} color={card.severity.color} /> : null}
            </div>
            <p className="mt-1 text-[12px] leading-5 text-[var(--vc-text)]">{card?.title || "Карточка CVE"}</p>
          </div>
          <div className="flex shrink-0 items-center gap-1.5">
            {selectedId ? <CveAiButton cveId={selectedId} /> : null}
            {selectedId ? <TelegramPostButton kind="cve" entityId={selectedId} /> : null}
            <button type="button" onClick={() => setSelectedId(null)} className="rounded p-1 text-[var(--vc-muted)] hover:bg-[var(--vc-hover)]" aria-label="Закрыть">
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>
        <div className="min-h-0 flex-1 space-y-4 overflow-y-auto px-4 py-3">
          {detail.isLoading ? <p className="text-[12px] text-[var(--vc-muted)]">Загрузка карточки…</p> : null}
          {detail.data && detail.data.found === false ? <p className="text-[12px] text-[var(--vc-muted)]">CVE нет в каталоге.</p> : null}
          {detail.isError ? <p className="text-[12px] text-[var(--vc-danger-text)]">Карточка не загрузилась.</p> : null}
          {card ? (
            <>
              <BadgeRow card={card} />
              <ScoreGrid card={card} />
              <section>
                <h3 className="mb-2 text-[11px] font-semibold uppercase tracking-wide text-[var(--vc-muted)]">Уязвимость</h3>
                <FactList rows={[
                  { label: "CVE", value: card.id },
                  { label: "CVSS", value: card.severity ? `${card.cvss?.toFixed(1)} · ${card.severity.label}` : "—", tone: card.severity?.color },
                  { label: "EPSS", value: card.epss == null ? "—" : String(card.epss.toFixed(3)), tone: "var(--vc-epss)" },
                  { label: "БДУ", value: mappedBduIds(card).length ? mappedBduIds(card).join(", ") : "нет", tone: mappedBduIds(card).length ? "var(--vc-primary-ink)" : "var(--vc-muted)" },
                  { label: "Источник", value: card.source || "—" },
                  { label: "Опубликована", value: card.publishedAt ? new Date(card.publishedAt).toLocaleDateString("ru-RU") : "—" }
                ]} />
                <p className="mt-2 text-[12px] leading-5">{card.nvdText || card.description || "Описания нет."}</p>
                <div className="mt-3">
                  <BduMappingBlock card={card} />
                </div>
                {card.ai?.facts.length ? (
                  <div className="mt-3">
                    <h4 className="text-[12px] font-semibold">Дополнительная фактура</h4>
                    <ul className="mt-1 space-y-1 text-[12px] leading-5">{card.ai.facts.map((fact) => <li key={fact}>• {fact}</li>)}</ul>
                  </div>
                ) : null}
                {card.ai?.attack.length ? (
                  <p className="mt-2 text-[12px] leading-5">{card.ai.attack.map((stage) => stage.title).join(" → ")}</p>
                ) : null}
              </section>
              <section>
                <h3 className="mb-2 text-[11px] font-semibold uppercase tracking-wide text-[var(--vc-muted)]">Продукт</h3>
                <ProductBlock card={card} />
              </section>
              <section>
                <h3 className="mb-2 text-[11px] font-semibold uppercase tracking-wide text-[var(--vc-muted)]">Устранение</h3>
                <RemediationBlock card={card} />
              </section>
              {hasContext(card) ? (
                <section>
                  <h3 className="mb-2 text-[11px] font-semibold uppercase tracking-wide text-[var(--vc-muted)]">Контекст</h3>
                  <ContextBlock card={card} />
                </section>
              ) : null}
              <section>
                <h3 className="mb-2 text-[11px] font-semibold uppercase tracking-wide text-[var(--vc-muted)]">Задача</h3>
                <TaskBlock card={card} onOpen={openTask} />
              </section>
              <section>
                <h3 className="mb-2 text-[11px] font-semibold uppercase tracking-wide text-[var(--vc-muted)]">Ссылки</h3>
                <ReferenceList card={card} />
              </section>
              <section>
                <h3 className="mb-2 text-[11px] font-semibold uppercase tracking-wide text-[var(--vc-muted)]">История</h3>
                <HistoryList card={card} />
              </section>
            </>
          ) : null}
        </div>
        {card ? (
          <div className="shrink-0 border-t border-[var(--vc-border)] bg-[var(--vc-inset-2)] px-4 py-3">
            <CardActions card={card} onOpenFull={() => openFull()} onOpenRemediation={() => openFull("remediation")} onOpenTask={openTask} />
          </div>
        ) : null}
      </aside>
    </div>
  );
}
