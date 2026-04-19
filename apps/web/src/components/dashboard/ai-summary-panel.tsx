"use client";

import { parseAiOutputJson } from "@/lib/cve-enrich-ui";
import { RefreshCw } from "lucide-react";
import { cn } from "../ui/cn";

export function AiSummaryPanel({
  data,
  loading,
  aiPending,
  aiStalled,
  manualEnrichAllowed = false,
  onRequestEnrich
}: {
  data: unknown | null;
  loading: boolean;
  /** True while enrich was requested and the AI row is not back yet (on-demand generation). */
  aiPending?: boolean;
  /** True after timeout or failed POST — worker/LLM did not produce a row in time. */
  aiStalled?: boolean;
  /** When false, manual POST /enrich is disabled server-side; UI hides the request button. */
  manualEnrichAllowed?: boolean;
  /** `force: true` — перегенерировать сводку даже если уже есть строка (ошибка/заглушка). */
  onRequestEnrich?: (opts?: { force?: boolean }) => void;
}) {
  const d = (data ?? null) as null | {
    cve?: { cve_id?: string | null } | null;
    ai?: { output_json?: Record<string, unknown> | null; output_text?: unknown } | null;
  };
  const out = parseAiOutputJson(d?.ai?.output_json ?? null);
  const get = (k: string): unknown => (out ? out[k] : undefined);
  const enrichError = Boolean(get("_enrich_error"));
  const summary = get("summary") ?? d?.ai?.output_text ?? null;
  const summaryText =
    summary == null ? null : typeof summary === "string" ? summary : JSON.stringify(summary, null, 2);
  const explanation = get("explanation") ?? null;
  const attackFlow = get("attackFlow") ?? null;
  const remediation = get("remediation") ?? null;
  const consequences = get("consequences") ?? null;

  const canRefresh = Boolean(manualEnrichAllowed && onRequestEnrich && d?.cve?.cve_id && data);

  return (
    <div className="glass rounded-2xl p-5">
      <div className="flex items-center justify-between gap-2">
        <div className="text-sm font-medium">ИИ‑сводка</div>
        <div className="flex items-center gap-2">
          {canRefresh ? (
            <button
              type="button"
              title="Перегенерировать сводку (LLM), если висит ошибка или устарело"
              onClick={() => onRequestEnrich?.({ force: true })}
              className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-border bg-black/25 text-fg/85 hover:bg-black/35"
            >
              <RefreshCw className="h-3.5 w-3.5" aria-hidden />
            </button>
          ) : null}
          <div className="text-xs text-muted">
            {loading
              ? "Загрузка…"
              : aiPending
                ? "Генерация…"
                : aiStalled
                  ? "Нет ответа"
                  : enrichError
                    ? "Ошибка LLM"
                    : data
                      ? "Готово"
                      : "Выберите CVE"}
          </div>
        </div>
      </div>

      <div className="mt-4 grid grid-cols-12 gap-4">
        <div className="col-span-12 xl:col-span-7">
          <div
            className={cn(
              "rounded-xl border bg-black/20 p-4",
              enrichError ? "border-warn/50" : "border-border",
              !summary && "opacity-70"
            )}
          >
            <div className="text-xs text-muted">Описание простыми словами</div>
            <div className="mt-2 text-sm leading-relaxed">
              {summaryText ??
                (aiPending
                  ? "Генерируем сводку по CVE (воркер + LLM). Обычно занимает несколько секунд."
                  : aiStalled
                    ? manualEnrichAllowed
                      ? "За несколько минут не пришла ИИ‑сводка (локальный LLM может дольше). Проверьте Ollama/сеть, RabbitMQ и `LLM_*` / `LLM_TIMEOUT_MS`. Закройте панель и откройте CVE снова или нажмите «Повторить»."
                      : "ИИ‑сводка ещё не готова или воркер недоступен. Обогащение идёт в фоне — страница обновляется сама."
                    : manualEnrichAllowed
                      ? "ИИ‑данных пока нет. Свежие CVE (24ч) подхватывает фон из ingest; старше 24ч — только кнопкой ниже."
                      : "ИИ‑данных пока нет. Обогащение в фоне для свежих CVE; для остальных — когда сервер разрешит on-demand enrich.")}
            </div>
            {!aiPending && manualEnrichAllowed && d?.cve?.cve_id && onRequestEnrich ? (
              <div className="mt-3 flex flex-wrap gap-2">
                {(enrichError || !summaryText) ? (
                  <button
                    type="button"
                    onClick={() => onRequestEnrich(enrichError ? { force: true } : undefined)}
                    className="rounded-lg border border-border bg-black/30 px-3 py-1.5 text-xs text-fg/90 hover:bg-black/40"
                  >
                    {enrichError ? "Повторить ИИ‑обогащение" : "Запросить ИИ‑обогащение"}
                  </button>
                ) : null}
                {summaryText && !enrichError ? (
                  <button
                    type="button"
                    title="Новый запрос к LLM (в логах Ollama будет POST /v1/chat/completions)"
                    onClick={() => onRequestEnrich({ force: true })}
                    className="rounded-lg border border-accent/35 bg-accent/10 px-3 py-1.5 text-xs text-fg/90 hover:bg-accent/15"
                  >
                    Обновить сводку (LLM)
                  </button>
                ) : null}
              </div>
            ) : null}
            {explanation && (
              <div className="mt-4 text-xs text-muted">
                <div className="font-medium text-fg">Детали</div>
                <div className="mt-1 whitespace-pre-wrap">{String(explanation)}</div>
              </div>
            )}
          </div>
        </div>

        <div className="col-span-12 xl:col-span-5 space-y-3">
          <div className="rounded-xl border border-border bg-black/20 p-4">
            <div className="text-xs text-muted">Ход атаки</div>
            <div className="mt-2 text-sm">
              {Array.isArray(attackFlow) ? (
                attackFlow.length > 0 ? (
                  <ol className="list-decimal space-y-1 pl-5">
                    {attackFlow.slice(0, 10).map((s: unknown, i: number) => (
                      <li key={i} className="text-sm text-fg/90">
                        {String(s)}
                      </li>
                    ))}
                  </ol>
                ) : (
                  <div className="text-sm text-fg/90">—</div>
                )
              ) : (
                <div className="text-sm text-fg/90">{attackFlow ? String(attackFlow) : "—"}</div>
              )}
            </div>
          </div>

          <div className="rounded-xl border border-border bg-black/20 p-4">
            <div className="text-xs text-muted">Ремедиация</div>
            <div className="mt-2 text-sm">
              {Array.isArray(remediation) ? (
                <ul className="list-disc space-y-1 pl-5">
                  {remediation.slice(0, 6).map((r: unknown, i: number) => (
                    <li key={i} className="text-sm text-fg/90">
                      {String(r)}
                    </li>
                  ))}
                </ul>
              ) : (
                <div className="text-sm text-fg/90">{remediation ? String(remediation) : "—"}</div>
              )}
            </div>
          </div>

          <div className="rounded-xl border border-border bg-black/20 p-4">
            <div className="text-xs text-muted">Последствия</div>
            <div className="mt-2 text-sm">
              {Array.isArray(consequences) ? (
                <ul className="list-disc space-y-1 pl-5">
                  {consequences.slice(0, 6).map((c: unknown, i: number) => (
                    <li key={i} className="text-sm text-fg/90">
                      {String(c)}
                    </li>
                  ))}
                </ul>
              ) : (
                <div className="text-sm text-fg/90">{consequences ? String(consequences) : "—"}</div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

