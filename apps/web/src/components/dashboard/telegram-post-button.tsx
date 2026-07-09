"use client";

import * as Dialog from "@radix-ui/react-dialog";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Loader2, Send, X } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { apiFetch } from "@/lib/api-fetch";
import { cn } from "../ui/cn";

type IntegrationState = {
  telegram?: {
    enabled?: boolean;
    hasBotToken?: boolean;
    chatId?: string;
  };
};

type TrafficPreset = "yellow" | "red" | "green" | "white";

const STATUS_PRESETS: { id: TrafficPreset; label: string; hint: string }[] = [
  { id: "yellow", label: "🟡 В работе", hint: "В работе — проводится анализ / устранение" },
  { id: "red", label: "🔴 Срочно", hint: "Срочно — требуется немедленное реагирование" },
  { id: "green", label: "🟢 Устранено", hint: "Устранено — патч применён / риск принят" },
  { id: "white", label: "⚪ Не применимо", hint: "Не применимо — ПО отсутствует в инфраструктуре" }
];
const DEFAULT_STATUS = STATUS_PRESETS[0]!;

function buildStatusPayload(preset: TrafficPreset | null, detail: string): string {
  const d = detail.trim();
  if (!d) throw new Error("Введите текст статуса");
  const emoji =
    preset === "red" ? "🔴" : preset === "green" ? "🟢" : preset === "white" ? "⚪" : preset === "yellow" ? "🟡" : "";
  if (/^[🟡🔴🟢⚪]/u.test(d)) return d;
  if (emoji) return `${emoji} ${d}`;
  return d;
}

function extractApiErrorMessage(status: number, raw: string): string {
  let message = raw.trim();
  if (message) {
    try {
      const parsed = JSON.parse(message) as unknown;
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        const obj = parsed as Record<string, unknown>;
        const m = obj.message;
        if (Array.isArray(m)) message = m.map(String).join("; ");
        else if (typeof m === "string") message = m;
        else if (typeof obj.error === "string") message = obj.error;
      }
    } catch {
      // Non-JSON responses are handled below.
    }
  }

  if (status >= 500 || !message || message === "Internal server error") {
    return "Не удалось отправить пост в Telegram. Проверьте настройки бота/чата и попробуйте ещё раз.";
  }
  if (status === 401 || status === 403) return "Нет доступа к публикации. Обновите сессию и попробуйте снова.";
  if (status === 404) return "Запись не найдена, пост не отправлен.";
  return message;
}

export function TelegramPostButton({
  kind,
  entityId,
  className,
  disabled
}: {
  kind: "cve" | "bdu";
  entityId: string | null | undefined;
  className?: string;
  disabled?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [preset, setPreset] = useState<TrafficPreset>("yellow");
  const [detail, setDetail] = useState("");
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const textareaRef = useRef<HTMLTextAreaElement | null>(null);
  const closeTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const cfgQ = useQuery({
    queryKey: ["settings", "integrations", "telegram-enabled"],
    queryFn: async () => {
      const res = await apiFetch("/api/settings/integrations", { cache: "no-store" });
      if (!res.ok) throw new Error("integrations");
      return (await res.json()) as IntegrationState;
    },
    staleTime: 30_000
  });

  const configured = Boolean(cfgQ.data?.telegram?.enabled && cfgQ.data.telegram.hasBotToken);

  const postMut = useMutation({
    mutationFn: async (status: string) => {
      const id = String(entityId ?? "").trim();
      if (!id) throw new Error("Нет идентификатора");
      const path =
        kind === "cve"
          ? `/api/telegram/post/cve/${encodeURIComponent(id)}`
          : `/api/telegram/post/bdu/${encodeURIComponent(id.replace(/^BDU:/i, ""))}`;
      const res = await apiFetch(path, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ status })
      });
      if (!res.ok) {
        const t = await res.text().catch(() => "");
        throw new Error(extractApiErrorMessage(res.status, t));
      }
      return (await res.json()) as { ok?: boolean; identifier?: string };
    },
    onSuccess: (data) => {
      setErr(null);
      setMsg(data.identifier ? `Отправлено в Telegram: ${data.identifier}` : "Отправлено в Telegram");
      if (closeTimerRef.current) clearTimeout(closeTimerRef.current);
      closeTimerRef.current = setTimeout(() => {
        setOpen(false);
        setDetail("");
        closeTimerRef.current = null;
      }, 2000);
      setTimeout(() => setMsg(null), 5000);
    },
    onError: (e: unknown) => {
      setMsg(null);
      setErr(e instanceof Error ? e.message : String(e));
      setTimeout(() => setErr(null), 8000);
    }
  });

  const applyPreset = (p: (typeof STATUS_PRESETS)[number]) => {
    setPreset(p.id);
    setDetail(p.hint.replace(/^[🟡🔴🟢⚪]\s*/u, ""));
  };

  const handleOpenChange = (nextOpen: boolean) => {
    if (closeTimerRef.current) {
      clearTimeout(closeTimerRef.current);
      closeTimerRef.current = null;
    }
    setOpen(nextOpen);
    if (!nextOpen) return;
    setErr(null);
    setMsg(null);
    postMut.reset();
    if (!detail.trim()) {
      applyPreset(DEFAULT_STATUS);
    }
  };

  const handleSubmit = () => {
    try {
      const status = buildStatusPayload(preset, detail);
      void postMut.mutate(status);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  };

  useEffect(() => {
    return () => {
      if (closeTimerRef.current) clearTimeout(closeTimerRef.current);
    };
  }, []);

  if (!entityId) return null;

  return (
    <div className={cn("inline-flex flex-col items-end gap-1", className)}>
      <Dialog.Root open={open} onOpenChange={handleOpenChange}>
        <Dialog.Trigger asChild>
          <button
            type="button"
            title={
              configured
                ? "Опубликовать карточку в Telegram — сначала укажите статус"
                : "Настройте бота в Настройки → Интеграции → Telegram"
            }
            disabled={disabled || postMut.isPending || !configured}
            className={cn(
              "inline-flex items-center gap-2 rounded-lg border px-3 py-1.5 text-xs shadow-sm",
              configured
                ? "border-sky-300/60 bg-sky-500/15 text-sky-100 hover:bg-sky-500/25 dark:border-sky-700/50"
                : "border-slate-200 bg-white text-fg/50 dark:border-border dark:bg-black/25",
              (disabled || postMut.isPending || !configured) && "pointer-events-none opacity-50"
            )}
          >
            {postMut.isPending ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <Send className="h-3.5 w-3.5" aria-hidden />
            )}
            Пост в ТГ
          </button>
        </Dialog.Trigger>

        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 z-[7000] bg-black/65 backdrop-blur-sm" />
          <Dialog.Content
            className={cn(
              "fixed left-1/2 top-1/2 z-[7001] w-[min(440px,calc(100vw-2rem))] -translate-x-1/2 -translate-y-1/2",
              "rounded-xl border border-border bg-panel p-4 shadow-2xl outline-none"
            )}
            onOpenAutoFocus={(event) => {
              event.preventDefault();
              requestAnimationFrame(() => textareaRef.current?.focus());
            }}
          >
            <div className="flex items-start justify-between gap-3">
              <div>
                <Dialog.Title className="text-sm font-semibold text-fg/95">Статус для Telegram</Dialog.Title>
                <Dialog.Description className="mt-1 text-[11px] text-muted">
                  Укажите статус (светофор). Остальной блок «Комплексный анализ» заполнится автоматически из NVD,
                  БДУ, KEV, EPSS и ИИ-обогащения.
                </Dialog.Description>
              </div>
              <Dialog.Close asChild>
                <button
                  type="button"
                  className="rounded-md p-1 text-muted hover:bg-black/10 dark:hover:bg-white/10"
                  aria-label="Закрыть"
                >
                  <X className="h-4 w-4" />
                </button>
              </Dialog.Close>
            </div>

            <p className="mt-3 text-[10px] uppercase tracking-wide text-muted">Светофор</p>
            <div className="mt-1.5 flex flex-wrap gap-1.5">
              {STATUS_PRESETS.map((p) => (
                <button
                  key={p.id}
                  type="button"
                  onClick={() => applyPreset(p)}
                  className={cn(
                    "rounded-md border px-2 py-1 text-[11px]",
                    preset === p.id
                      ? "border-sky-400/70 bg-sky-500/20 text-sky-100"
                      : "border-border bg-black/5 text-fg/80 dark:bg-white/5"
                  )}
                >
                  {p.label}
                </button>
              ))}
            </div>

            <label className="mt-3 block text-[10px] text-muted" htmlFor="tg-status-detail">
              Текст статуса
            </label>
            <textarea
              id="tg-status-detail"
              ref={textareaRef}
              rows={3}
              value={detail}
              onChange={(e) => setDetail(e.target.value)}
              disabled={postMut.isPending}
              placeholder="Например: В работе — ожидаем патч от вендора, затронуты 12 хостов"
              className="mt-1 w-full resize-y rounded-lg border border-border bg-black/5 px-2.5 py-2 text-xs text-fg placeholder:text-muted/70 dark:bg-white/5"
            />

            {msg ? (
              <div className="mt-3 rounded-lg border border-ok/30 bg-ok/10 px-3 py-2 text-xs text-ok">
                {msg}. Окно закроется автоматически.
              </div>
            ) : null}

            {err ? (
              <div className="mt-3 rounded-lg border border-danger/30 bg-danger/10 px-3 py-2 text-xs leading-relaxed text-danger">
                {err}
              </div>
            ) : null}

            <div className="mt-4 flex justify-end gap-2">
              <Dialog.Close asChild>
                <button
                  type="button"
                  disabled={postMut.isPending}
                  className="rounded-lg border border-border px-3 py-1.5 text-xs text-muted hover:bg-black/5 dark:hover:bg-white/5"
                >
                  Отмена
                </button>
              </Dialog.Close>
              <button
                type="button"
                disabled={postMut.isPending || Boolean(msg) || !detail.trim()}
                onClick={handleSubmit}
                className="inline-flex items-center gap-2 rounded-lg border border-sky-400/60 bg-sky-500/20 px-3 py-1.5 text-xs text-sky-100 disabled:opacity-50"
              >
                {postMut.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Send className="h-3.5 w-3.5" />}
                Отправить в Telegram
              </button>
            </div>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>

      {msg ? <span className="max-w-[220px] text-right text-[10px] text-ok">{msg}</span> : null}
      {err ? <span className="max-w-[220px] text-right text-[10px] text-danger">{err}</span> : null}
    </div>
  );
}
