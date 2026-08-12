"use client";

import { apiFetch } from "@/lib/api-fetch";
import { cn } from "@/components/ui/cn";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";

type TlsStatus = {
  configured: boolean;
  selfSigned: boolean;
  commonName: string | null;
  subjectAltNames: string[];
  validFrom: string | null;
  validTo: string | null;
  daysRemaining: number | null;
  fingerprintSha256: string | null;
  certsDir: string;
  certPresent: boolean;
  keyPresent: boolean;
  proxy: {
    adminUrlConfigured: boolean;
    reachable: boolean;
    reloadedAtGenerate: boolean | null;
    message: string;
  };
  localProxy?: {
    running: boolean;
    listenPort: number | null;
    publicUrl: string | null;
    message: string;
  };
  applied?: boolean;
  httpsUrl?: string | null;
  publishedTlsPort: string | null;
  defaultDomain: string;
  warningRu: string;
  issuer?: "letsencrypt" | "selfsigned" | "unknown";
  certbotAvailable?: boolean;
  acmeWebroot?: string;
  letsEncryptReadyHintRu?: string;
};

type GenerateResult = TlsStatus & {
  generated: true;
  domain: string;
  days: number;
  applied?: boolean;
  messageRu: string;
  provider?: string;
  renewed?: boolean;
};

async function readApiError(res: Response, fallback: string) {
  try {
    const data = (await res.json()) as { message?: unknown; error?: unknown };
    if (typeof data.message === "string") return data.message;
    if (Array.isArray(data.message)) return data.message.join(", ");
    if (typeof data.error === "string") return data.error;
  } catch {
    // ignore
  }
  return fallback;
}

function formatDate(iso: string | null): string {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString("ru-RU", {
      dateStyle: "medium",
      timeStyle: "short"
    });
  } catch {
    return iso;
  }
}

export function WebTlsSettingsPanel({ embedded = false }: { embedded?: boolean }) {
  const qc = useQueryClient();
  const [domain, setDomain] = useState("");
  const [email, setEmail] = useState("");
  const [staging, setStaging] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const statusQ = useQuery({
    queryKey: ["settings", "tls"],
    queryFn: async () => {
      const res = await apiFetch("/api/settings/tls", { cache: "no-store" });
      if (!res.ok) throw new Error(await readApiError(res, "Не удалось загрузить статус TLS"));
      return (await res.json()) as TlsStatus;
    },
    refetchInterval: 10_000
  });

  useEffect(() => {
    if (!domain && statusQ.data?.defaultDomain) {
      setDomain(statusQ.data.defaultDomain);
    }
  }, [domain, statusQ.data?.defaultDomain]);

  const letsencrypt = useMutation({
    mutationFn: async () => {
      const res = await apiFetch("/api/settings/tls/letsencrypt", {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify({
          domain: domain.trim() || undefined,
          email: email.trim(),
          staging
        }),
        cache: "no-store"
      });
      if (!res.ok) throw new Error(await readApiError(res, "Не удалось получить Let's Encrypt"));
      return (await res.json()) as GenerateResult;
    },
    onSuccess: async (data) => {
      setErr(null);
      setMsg(data.messageRu);
      await qc.invalidateQueries({ queryKey: ["settings", "tls"] });
    },
    onError: (e) => {
      setMsg(null);
      setErr(e instanceof Error ? e.message : "Ошибка Let's Encrypt");
    }
  });

  const renew = useMutation({
    mutationFn: async () => {
      const res = await apiFetch("/api/settings/tls/letsencrypt/renew", {
        method: "POST",
        headers: { accept: "application/json" },
        cache: "no-store"
      });
      if (!res.ok) throw new Error(await readApiError(res, "Не удалось обновить Let's Encrypt"));
      return (await res.json()) as GenerateResult;
    },
    onSuccess: async (data) => {
      setErr(null);
      setMsg(data.messageRu);
      await qc.invalidateQueries({ queryKey: ["settings", "tls"] });
    },
    onError: (e) => {
      setMsg(null);
      setErr(e instanceof Error ? e.message : "Ошибка renew");
    }
  });

  const selfSigned = useMutation({
    mutationFn: async () => {
      const res = await apiFetch("/api/settings/tls/generate", {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify({ domain: domain.trim() || undefined, days: 825 }),
        cache: "no-store"
      });
      if (!res.ok) throw new Error(await readApiError(res, "Не удалось сгенерировать сертификат"));
      return (await res.json()) as GenerateResult;
    },
    onSuccess: async (data) => {
      setErr(null);
      setMsg(data.messageRu);
      await qc.invalidateQueries({ queryKey: ["settings", "tls"] });
    },
    onError: (e) => {
      setMsg(null);
      setErr(e instanceof Error ? e.message : "Ошибка генерации сертификата");
    }
  });

  const st = statusQ.data;
  const expiryTone =
    st?.daysRemaining == null
      ? "text-muted"
      : st.daysRemaining < 14
        ? "text-amber-700 dark:text-amber-300"
        : st.daysRemaining < 0
          ? "text-red-700 dark:text-red-300"
          : "text-fg/85";
  const busy = letsencrypt.isPending || renew.isPending || selfSigned.isPending;

  return (
    <div className={cn(!embedded && "glass rounded-2xl p-5 sm:p-6")}>
      {!embedded ? (
        <div className="mb-4">
          <div className="text-sm font-semibold tracking-tight text-fg/95">Веб / TLS</div>
          <p className="mt-1 text-xs text-muted">
            Let's Encrypt через certbot под капотом (HTTP-01) с авто-применением на веб. Для лаборатории —
            самоподписанный запасной вариант.
          </p>
        </div>
      ) : null}

      {statusQ.isLoading ? (
        <p className="text-sm text-muted">Загрузка статуса сертификата…</p>
      ) : statusQ.isError ? (
        <p className="rounded-xl border border-red-200 bg-red-50/80 px-3 py-2 text-sm text-red-800 dark:border-red-900/50 dark:bg-red-950/30 dark:text-red-200">
          {statusQ.error instanceof Error ? statusQ.error.message : "Ошибка загрузки"}
        </p>
      ) : st ? (
        <div className="space-y-4">
          <div className="rounded-xl border border-slate-200 bg-slate-50/70 px-4 py-3 dark:border-border dark:bg-white/[0.03]">
            <div className="flex flex-wrap items-center gap-2">
              <span
                className={cn(
                  "inline-flex rounded-md px-2 py-0.5 text-[11px] font-medium",
                  st.configured
                    ? "bg-emerald-500/15 text-emerald-800 dark:text-emerald-300"
                    : "bg-slate-500/15 text-slate-700 dark:text-slate-300"
                )}
              >
                {st.configured ? "Сертификат на диске" : "Сертификат не найден"}
              </span>
              <span
                className={cn(
                  "inline-flex rounded-md px-2 py-0.5 text-[11px] font-medium",
                  st.applied
                    ? "bg-emerald-500/15 text-emerald-800 dark:text-emerald-300"
                    : "bg-amber-500/15 text-amber-800 dark:text-amber-300"
                )}
              >
                {st.applied ? "HTTPS на веб" : "HTTPS не слушает"}
              </span>
              {st.issuer === "letsencrypt" ? (
                <span className="inline-flex rounded-md bg-sky-500/15 px-2 py-0.5 text-[11px] font-medium text-sky-800 dark:text-sky-300">
                  Let's Encrypt
                </span>
              ) : st.selfSigned && st.configured ? (
                <span className="inline-flex rounded-md bg-amber-500/15 px-2 py-0.5 text-[11px] font-medium text-amber-800 dark:text-amber-300">
                  Самоподписанный
                </span>
              ) : null}
              {st.certbotAvailable === false ? (
                <span className="inline-flex rounded-md bg-rose-500/15 px-2 py-0.5 text-[11px] font-medium text-rose-800 dark:text-rose-300">
                  certbot недоступен
                </span>
              ) : null}
            </div>

            <dl className="mt-3 grid gap-2 text-xs sm:grid-cols-2">
              <div className="sm:col-span-2">
                <dt className="text-muted">Открыть веб по HTTPS</dt>
                <dd className="mt-0.5 break-all font-medium text-fg/90">
                  {st.httpsUrl ? (
                    <a className="text-accent underline-offset-2 hover:underline" href={st.httpsUrl} target="_blank" rel="noreferrer">
                      {st.httpsUrl}
                    </a>
                  ) : (
                    "—"
                  )}
                </dd>
              </div>
              <div>
                <dt className="text-muted">Домен (CN)</dt>
                <dd className="mt-0.5 font-medium text-fg/90">{st.commonName ?? "—"}</dd>
              </div>
              <div>
                <dt className="text-muted">Срок действия</dt>
                <dd className={cn("mt-0.5 font-medium", expiryTone)}>
                  {formatDate(st.validTo)}
                  {st.daysRemaining != null ? ` (${st.daysRemaining} дн.)` : ""}
                </dd>
              </div>
              <div className="sm:col-span-2">
                <dt className="text-muted">ACME webroot</dt>
                <dd className="mt-0.5 break-all font-mono text-[11px] text-fg/75">{st.acmeWebroot ?? "—"}</dd>
              </div>
            </dl>

            <p className="mt-3 text-[11px] leading-relaxed text-muted">
              {st.letsEncryptReadyHintRu ?? st.proxy.message}
            </p>
            <p className="mt-1 text-[11px] leading-relaxed text-muted">{st.proxy.message}</p>
          </div>

          <div className="space-y-3">
            <label className="block">
              <span className="text-xs font-medium text-fg/85">Домен</span>
              <input
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                placeholder={st.defaultDomain}
                className="mt-1.5 w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-fg outline-none ring-accent/30 focus:ring-2 dark:border-border dark:bg-black/30"
                autoComplete="off"
                spellCheck={false}
              />
            </label>
            <label className="block">
              <span className="text-xs font-medium text-fg/85">Email для Let's Encrypt</span>
              <input
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="admin@example.com"
                type="email"
                className="mt-1.5 w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-fg outline-none ring-accent/30 focus:ring-2 dark:border-border dark:bg-black/30"
                autoComplete="email"
              />
            </label>
            <label className="flex items-center gap-2 text-xs text-fg/80">
              <input type="checkbox" checked={staging} onChange={(e) => setStaging(e.target.checked)} />
              Staging CA (тест, браузеры не доверяют)
            </label>

            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                disabled={busy || !domain.trim() || !email.trim()}
                onClick={() => letsencrypt.mutate()}
                className={cn(
                  "inline-flex items-center justify-center rounded-xl px-4 py-2.5 text-sm font-medium transition",
                  "bg-accent text-white hover:opacity-95 disabled:cursor-not-allowed disabled:opacity-50"
                )}
              >
                {letsencrypt.isPending ? "Certbot…" : "Получить Let's Encrypt"}
              </button>
              <button
                type="button"
                disabled={busy || st.issuer !== "letsencrypt"}
                onClick={() => renew.mutate()}
                className="inline-flex items-center justify-center rounded-xl border border-border bg-white/70 px-4 py-2.5 text-sm font-medium text-fg/90 disabled:opacity-50 dark:bg-black/30"
              >
                {renew.isPending ? "Renew…" : "Обновить LE"}
              </button>
              <button
                type="button"
                disabled={busy || !domain.trim()}
                onClick={() => selfSigned.mutate()}
                className="inline-flex items-center justify-center rounded-xl border border-border bg-white/70 px-4 py-2.5 text-sm font-medium text-fg/90 disabled:opacity-50 dark:bg-black/30"
              >
                {selfSigned.isPending ? "Генерация…" : "Самоподписанный (lab)"}
              </button>
            </div>

            <p className="text-[11px] leading-relaxed text-muted">{st.warningRu}</p>
          </div>
        </div>
      ) : null}

      {msg ? (
        <p className="mt-4 rounded-xl border border-emerald-200 bg-emerald-50/80 px-3 py-2 text-sm text-emerald-900 dark:border-emerald-900/40 dark:bg-emerald-950/30 dark:text-emerald-200">
          {msg}
        </p>
      ) : null}
      {err ? (
        <p className="mt-4 rounded-xl border border-red-200 bg-red-50/80 px-3 py-2 text-sm text-red-800 dark:border-red-900/50 dark:bg-red-950/30 dark:text-red-200">
          {err}
        </p>
      ) : null}
    </div>
  );
}
