"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Loader2, Plus, Save, Trash2 } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { apiFetch } from "@/lib/api-fetch";
import { cn } from "../ui/cn";

type LlmProfileUi = {
  id: string;
  name: string;
  endpoint: string;
  model: string;
  promptVersion: string;
  hasApiKey: boolean;
  apiKeyDraft: string;
  clearApiKey: boolean;
};

type MpvmUiState = {
  enabled: boolean;
  baseUrl: string;
  username: string;
  hasApiToken: boolean;
  hasPassword: boolean;
  hasClientSecret: boolean;
  authPort: number;
  tlsInsecure: boolean;
  pdql: string;
  assetCount: number;
  softwareCount: number;
  vulnerabilityCount: number;
  lastSyncAt: string | null;
  lastSyncFetched: number | null;
  lastSyncError: string | null;
};

type MpvmVerifyResult = {
  ok: boolean;
  ms: number;
  error: string | null;
  assetSample: number;
  pdql: string;
};

type MpvmSyncResult = {
  ok: boolean;
  fetched: number;
  upserted: number;
  softwareUpserted: number;
  vulnerabilitiesUpserted: number;
  pdql: string;
  warning: string | null;
  error: string | null;
  ms: number;
};

type TelegramUiState = {
  enabled: boolean;
  hasBotToken: boolean;
  chatId: string;
  lastPostAt: string | null;
  lastPostIdentifier: string | null;
};

type TelegramVerifyResult = {
  ok: boolean;
  messageId: number | null;
  error: string | null;
  chatId?: string;
};

type IntegrationState = {
  llm: {
    profiles: Array<{
      id: string;
      name: string;
      endpoint: string;
      hasApiKey: boolean;
      model: string;
      promptVersion: string;
    }>;
    activeId: string | null;
    envFallback: { endpoint: string; model: string; hasApiKey: boolean };
  };
  nvd: { hasDbKey: boolean; hasEnvKey: boolean; activeKeySource: "db" | "env" | "none" };
  mpvm: MpvmUiState;
  telegram: TelegramUiState;
};

type NvdVerifyResult = {
  ok: boolean;
  status: number | null;
  apiKeyRejected: boolean;
  ms: number;
  error: string | null;
  keySource: string;
  hasApiKey: boolean;
};

type IntegrationPutResponse = IntegrationState & { nvdVerification?: NvdVerifyResult };

function emptyProfile(): LlmProfileUi {
  return {
    id: crypto.randomUUID(),
    name: "Новый профиль",
    endpoint: "http://127.0.0.1:11434/v1/chat/completions",
    model: "qwen2.5:7b",
    promptVersion: "v1",
    hasApiKey: false,
    apiKeyDraft: "",
    clearApiKey: false
  };
}

type QueueHealth = {
  ok?: boolean;
  bdu?: {
    ok?: boolean;
    sourceProbeOk?: boolean;
    ms?: number;
    status?: number;
    error?: string | null;
    tlsInsecure?: boolean;
    recordCount?: number;
    cveLinkCount?: number;
    maxBduId?: string | null;
    lastIngestAt?: string | null;
    lastIngestRecords?: number | null;
    lastIngestUsedFallback?: boolean | null;
    ingestStale?: boolean;
    ingestStaleHint?: string | null;
    endpoint?: string | null;
  };
  nvd?: {
    ok?: boolean;
    apiProbeOk?: boolean;
    ms?: number;
    status?: number;
    error?: string | null;
    hasApiKey?: boolean;
    watermarkTs?: string | null;
    watermarkEnd?: string | null;
    lastProcessed?: number | null;
    lastAttemptProcessed?: number | null;
    ingestStale?: boolean;
    ingestStaleHint?: string | null;
    endpoint?: string | null;
    activeKeySource?: "db" | "env" | "none";
    apiKeyRejected?: boolean;
  };
};

export function IntegrationSettingsPanel() {
  const qc = useQueryClient();
  const q = useQuery({
    queryKey: ["settings", "integrations"],
    queryFn: async () => {
      const res = await apiFetch("/api/settings/integrations", { cache: "no-store" });
      if (!res.ok) throw new Error(await res.text().catch(() => res.statusText));
      return (await res.json()) as IntegrationState;
    }
  });

  const queueQ = useQuery({
    queryKey: ["stats", "queue"],
    queryFn: async () => {
      const res = await apiFetch("/api/stats/queue", { cache: "no-store" });
      if (!res.ok) throw new Error(await res.text().catch(() => res.statusText));
      return (await res.json()) as QueueHealth;
    },
    refetchInterval: 30_000
  });

  const [profiles, setProfiles] = useState<LlmProfileUi[] | null>(null);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [nvdKeyDraft, setNvdKeyDraft] = useState("");
  const [nvdVerify, setNvdVerify] = useState<NvdVerifyResult | null>(null);
  const [mpvmBaseUrl, setMpvmBaseUrl] = useState("");
  const [mpvmUsername, setMpvmUsername] = useState("");
  const [mpvmTokenDraft, setMpvmTokenDraft] = useState("");
  const [mpvmPdql, setMpvmPdql] = useState("");
  const [mpvmTlsInsecure, setMpvmTlsInsecure] = useState(false);
  const [mpvmVerify, setMpvmVerify] = useState<MpvmVerifyResult | null>(null);
  const [tgBotTokenDraft, setTgBotTokenDraft] = useState("");
  const [tgChatId, setTgChatId] = useState("");
  const [tgVerify, setTgVerify] = useState<TelegramVerifyResult | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const sourceLabel = (s: "db" | "env" | "none") =>
    s === "db" ? "БД (настройки UI)" : s === "env" ? ".env (NVD_API_KEY)" : "не задан";

  const merged = useMemo(() => {
    if (!q.data) return null;
    if (profiles === null) {
      return {
        profiles: q.data.llm.profiles.map((p) => ({
          ...p,
          apiKeyDraft: "",
          clearApiKey: false
        })),
        activeId: q.data.llm.activeId
      };
    }
    return { profiles, activeId };
  }, [q.data, profiles, activeId]);

  useEffect(() => {
    if (!q.data || profiles !== null) return;
    setProfiles(
      q.data.llm.profiles.map((p) => ({
        ...p,
        apiKeyDraft: "",
        clearApiKey: false
      }))
    );
    setActiveId(q.data.llm.activeId ?? null);
  }, [q.data, profiles]);

  useEffect(() => {
    if (!q.data?.mpvm) return;
    setMpvmBaseUrl(q.data.mpvm.baseUrl ?? "");
    setMpvmUsername(q.data.mpvm.username ?? "");
    setMpvmPdql(q.data.mpvm.pdql ?? "");
    setMpvmTlsInsecure(Boolean(q.data.mpvm.tlsInsecure));
  }, [q.data?.mpvm]);

  useEffect(() => {
    if (!q.data?.telegram) return;
    setTgChatId(q.data.telegram.chatId ?? "");
  }, [q.data?.telegram]);

  const verifyNvdMut = useMutation({
    mutationFn: async (apiKey?: string) => {
      const res = await apiFetch("/api/settings/integrations/nvd/verify", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(apiKey?.trim() ? { apiKey: apiKey.trim() } : {})
      });
      if (!res.ok) throw new Error(await res.text().catch(() => res.statusText));
      return (await res.json()) as NvdVerifyResult;
    },
    onSuccess: (v) => {
      setNvdVerify(v);
      setErr(null);
    },
    onError: (e: unknown) => {
      setNvdVerify(null);
      setErr(e instanceof Error ? e.message : String(e));
    }
  });

  const verifyTgMut = useMutation({
    mutationFn: async () => {
      const res = await apiFetch("/api/settings/integrations/telegram/verify", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          botToken: tgBotTokenDraft.trim() || undefined,
          chatId: tgChatId.trim() || undefined
        })
      });
      if (!res.ok) throw new Error(await res.text().catch(() => res.statusText));
      return (await res.json()) as TelegramVerifyResult;
    },
    onSuccess: (v) => {
      setTgVerify(v);
      setErr(null);
    },
    onError: (e: unknown) => {
      setTgVerify(null);
      setErr(e instanceof Error ? e.message : String(e));
    }
  });

  const saveTgMut = useMutation({
    mutationFn: async (): Promise<IntegrationState> => {
      const body: Record<string, unknown> = {
        enabled: true,
        chatId: tgChatId.trim()
      };
      if (tgBotTokenDraft.trim()) body.botToken = tgBotTokenDraft.trim();
      const res = await apiFetch("/api/settings/integrations", {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ telegram: body })
      });
      if (!res.ok) throw new Error(await res.text().catch(() => res.statusText));
      return (await res.json()) as IntegrationState;
    },
    onSuccess: (data) => {
      setMsg("Настройки Telegram сохранены.");
      setErr(null);
      setTgBotTokenDraft("");
      void qc.setQueryData(["settings", "integrations"], data);
    },
    onError: (e: unknown) => {
      setMsg(null);
      setErr(e instanceof Error ? e.message : String(e));
    }
  });

  const verifyMpvmMut = useMutation({
    mutationFn: async () => {
      const res = await apiFetch("/api/settings/integrations/mpvm/verify", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          baseUrl: mpvmBaseUrl.trim(),
          username: mpvmUsername.trim() || undefined,
          apiToken: mpvmTokenDraft.trim() || undefined,
          tlsInsecure: mpvmTlsInsecure,
          pdql: mpvmPdql.trim() || undefined
        })
      });
      if (!res.ok) throw new Error(await res.text().catch(() => res.statusText));
      return (await res.json()) as MpvmVerifyResult;
    },
    onSuccess: (v) => {
      setMpvmVerify(v);
      setErr(null);
    },
    onError: (e: unknown) => {
      setMpvmVerify(null);
      setErr(e instanceof Error ? e.message : String(e));
    }
  });

  const saveMpvmMut = useMutation({
    mutationFn: async (): Promise<IntegrationState> => {
      const mpvm: Record<string, unknown> = {
        enabled: true,
        baseUrl: mpvmBaseUrl.trim(),
        username: mpvmUsername.trim(),
        pdql: mpvmPdql.trim(),
        tlsInsecure: mpvmTlsInsecure
      };
      if (mpvmTokenDraft.trim()) mpvm.apiToken = mpvmTokenDraft.trim();
      const res = await apiFetch("/api/settings/integrations", {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ mpvm })
      });
      if (!res.ok) throw new Error(await res.text().catch(() => res.statusText));
      return (await res.json()) as IntegrationState;
    },
    onSuccess: (data) => {
      setMsg("Настройки MaxPatrol VM сохранены.");
      setErr(null);
      setMpvmTokenDraft("");
      void qc.setQueryData(["settings", "integrations"], data);
    },
    onError: (e: unknown) => {
      setMsg(null);
      setErr(e instanceof Error ? e.message : String(e));
    }
  });

  const syncMpvmMut = useMutation({
    mutationFn: async () => {
      const res = await apiFetch("/api/settings/integrations/mpvm/sync", { method: "POST" });
      if (!res.ok) throw new Error(await res.text().catch(() => res.statusText));
      return (await res.json()) as MpvmSyncResult;
    },
    onSuccess: (r) => {
      if (r.ok) {
        const warn = r.warning ? ` Предупреждение: ${r.warning}` : "";
        setMsg(
          `MP VM: загружено ${r.fetched} активов, обновлено ${r.upserted} активов, ${r.softwareUpserted} ПО/пакетов, ${r.vulnerabilitiesUpserted} уязвимостей (${r.ms} ms).${warn}`
        );
      } else {
        setErr(r.error ?? "Синхронизация MP VM не удалась");
      }
      void qc.invalidateQueries({ queryKey: ["settings", "integrations"] });
    },
    onError: (e: unknown) => {
      setErr(e instanceof Error ? e.message : String(e));
    }
  });

  const saveNvdMut = useMutation({
    mutationFn: async (apiKey: string): Promise<IntegrationPutResponse> => {
      const res = await apiFetch("/api/settings/integrations", {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ nvd: { apiKey: apiKey.trim() } })
      });
      if (!res.ok) throw new Error(await res.text().catch(() => res.statusText));
      return (await res.json()) as IntegrationPutResponse;
    },
    onSuccess: (data) => {
      if (data.nvdVerification) setNvdVerify(data.nvdVerification);
      const v = data.nvdVerification;
      if (v?.apiKeyRejected) {
        setMsg(
          "Ключ сохранён в БД, но NVD вернул 404 — ключ недействителен. Ingest временно идёт без ключа. Вставьте новый ключ с nist.gov."
        );
      } else if (v?.ok) {
        setMsg(
          "Ключ NVD сохранён в БД и принят API. Ingest подхватит его в этом или следующем цикле (pub-sync + lastModified)."
        );
      } else {
        setMsg("Ключ сохранён в БД. Проверка API: см. статус ниже.");
      }
      setErr(null);
      void qc.setQueryData(["settings", "integrations"], data);
      void qc.invalidateQueries({ queryKey: ["stats", "queue"] });
      setNvdKeyDraft("");
    },
    onError: (e: unknown) => {
      setMsg(null);
      setErr(e instanceof Error ? e.message : String(e));
    }
  });

  const saveMut = useMutation({
    mutationFn: async (): Promise<IntegrationPutResponse> => {
      if (!merged) throw new Error("Нет данных формы");
      const body: Record<string, unknown> = {
        llm: {
          profiles: merged.profiles.map((p) => {
            const row: Record<string, unknown> = {
              id: p.id,
              name: p.name,
              endpoint: p.endpoint,
              model: p.model,
              promptVersion: p.promptVersion || "v1"
            };
            if (p.clearApiKey) row.apiKey = "";
            else if (p.apiKeyDraft.trim()) row.apiKey = p.apiKeyDraft.trim();
            return row;
          }),
          activeId: merged.activeId
        }
      };
      if (nvdKeyDraft.trim()) body.nvd = { apiKey: nvdKeyDraft.trim() };
      const res = await apiFetch("/api/settings/integrations", {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body)
      });
      if (!res.ok) throw new Error(await res.text().catch(() => res.statusText));
      return (await res.json()) as IntegrationPutResponse;
    },
    onSuccess: (data: IntegrationPutResponse) => {
      if (data.nvdVerification) setNvdVerify(data.nvdVerification);
      setMsg("Сохранено. LLM — воркеры apps/ai; ключ NVD в БД — ingest на ближайшем цикле.");
      setErr(null);
      void qc.setQueryData(["settings", "integrations"], data);
      void qc.invalidateQueries({ queryKey: ["stats", "queue"] });
      setProfiles(
        data.llm.profiles.map((p) => ({
          ...p,
          apiKeyDraft: "",
          clearApiKey: false
        }))
      );
      setActiveId(data.llm.activeId ?? null);
      setNvdKeyDraft("");
    },
    onError: (e: unknown) => {
      setMsg(null);
      setErr(e instanceof Error ? e.message : String(e));
    }
  });

  const clearNvdMut = useMutation({
    mutationFn: async (): Promise<IntegrationState> => {
      const res = await apiFetch("/api/settings/integrations", {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ nvd: { apiKey: null } })
      });
      if (!res.ok) throw new Error(await res.text().catch(() => res.statusText));
      return (await res.json()) as IntegrationState;
    },
    onSuccess: (data: IntegrationState) => {
      setMsg("Ключ NVD в БД удалён — будет использоваться NVD_API_KEY из .env (если задан).");
      setErr(null);
      void qc.setQueryData(["settings", "integrations"], data);
      void qc.invalidateQueries({ queryKey: ["stats", "queue"] });
      setProfiles(null);
    },
    onError: (e: unknown) => {
      setMsg(null);
      setErr(e instanceof Error ? e.message : String(e));
    }
  });

  if (q.isLoading) {
    return (
      <div className="flex items-center gap-2 text-sm text-muted">
        <Loader2 className="h-4 w-4 animate-spin" />
        Загрузка интеграций…
      </div>
    );
  }

  if (q.isError) {
    return <div className="text-sm text-danger">Не удалось загрузить настройки: {(q.error as Error)?.message ?? "ошибка"}</div>;
  }

  const data = q.data!;
  const list = merged?.profiles ?? [];
  const nvdH = queueQ.data?.nvd;
  const bduH = queueQ.data?.bdu;

  return (
    <div className="space-y-8">
      <div>
        <div className="text-sm font-medium">Интеграции</div>
        <div className="mt-1 text-[11px] text-muted">
          LLM, NVD, БДУ, MaxPatrol VM, Telegram-бот для постов из карточек CVE/BDU.
        </div>
      </div>

      {msg ? <div className="rounded-lg border border-ok/30 bg-ok/10 px-3 py-2 text-[11px] text-ok">{msg}</div> : null}
      {err ? <div className="rounded-lg border border-danger/30 bg-danger/10 px-3 py-2 text-[11px] text-danger">{err}</div> : null}

      <div className="rounded-xl border border-slate-200/90 bg-slate-50/90 p-4 dark:border-white/[0.06] dark:bg-black/20">
        <div className="text-[12px] font-medium text-fg/90">NVD API key</div>
        <div className="mt-1 text-[11px] text-muted">
          В БД: {data.nvd.hasDbKey ? "задан" : "нет"} · в .env: {data.nvd.hasEnvKey ? "есть NVD_API_KEY" : "нет"} ·
          активный: <span className="font-medium text-fg/85">{sourceLabel(data.nvd.activeKeySource)}</span>
        </div>
        {data.nvd.hasDbKey && data.nvd.hasEnvKey ? (
          <div className="mt-2 text-[10px] text-warn">
            Ключ в БД имеет приоритет над .env. Удалите или исправьте неверный NVD_API_KEY в .env, чтобы не путаться.
          </div>
        ) : null}
        {nvdH ? (
          <div className="mt-3 rounded-lg border border-slate-200 bg-white px-3 py-2 text-[11px] dark:border-white/10 dark:bg-black/30">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="text-muted">
                Статус API{" "}
                {nvdH.ok ? <span className="text-ok">OK</span> : <span className="text-danger">DOWN</span>}
                {nvdH.ingestStale ? <span className="ml-1 text-warn">· ingest устарел</span> : null}
              </span>
              <span className="font-mono tabular-nums text-fg/80">{typeof nvdH.ms === "number" ? `${nvdH.ms}ms` : "—"}</span>
            </div>
            <div className="mt-1 flex flex-wrap gap-2 text-[10px] text-muted">
              {typeof nvdH.status === "number" ? <span>HTTP {nvdH.status}</span> : null}
              {typeof nvdH.lastProcessed === "number" ? (
                <span>посл. успешный: {nvdH.lastProcessed} CVE</span>
              ) : typeof nvdH.lastAttemptProcessed === "number" ? (
                <span>посл. попытка: {nvdH.lastAttemptProcessed} CVE</span>
              ) : null}
              {nvdH.watermarkEnd ? (
                <span>окно до: {new Date(nvdH.watermarkEnd).toLocaleString()}</span>
              ) : null}
              {nvdH.watermarkTs ? <span>запись: {new Date(nvdH.watermarkTs).toLocaleString()}</span> : null}
            </div>
            {nvdH.activeKeySource ? (
              <span className="text-fg/75">ключ: {sourceLabel(nvdH.activeKeySource)}</span>
            ) : null}
            {nvdH.apiKeyRejected ? (
              <span className="text-danger"> · ключ отклонён (404)</span>
            ) : null}
            {nvdH.error ? (
              <div className={cn("mt-1 text-[10px]", nvdH.ok ? "text-warn" : "text-danger")}>{nvdH.error}</div>
            ) : null}
            {nvdH.ingestStale && nvdH.ingestStaleHint ? (
              <div className="mt-2 text-[10px] text-warn">{nvdH.ingestStaleHint}</div>
            ) : null}
          </div>
        ) : queueQ.isLoading ? (
          <div className="mt-2 flex items-center gap-2 text-[11px] text-muted">
            <Loader2 className="h-3.5 w-3.5 animate-spin" />
            Проверка NVD…
          </div>
        ) : null}
        <input
          type="password"
          autoComplete="off"
          value={nvdKeyDraft}
          onChange={(e) => setNvdKeyDraft(e.target.value)}
          placeholder="Новый ключ (сохранить в БД)…"
          className="mt-3 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm dark:border-border dark:bg-black/25"
        />
        {nvdVerify ? (
          <div
            className={cn(
              "mt-3 rounded-lg border px-3 py-2 text-[11px]",
              nvdVerify.ok && !nvdVerify.apiKeyRejected
                ? "border-ok/30 bg-ok/10 text-ok"
                : "border-warn/35 bg-warn/10 text-warn"
            )}
          >
            Проверка: {nvdVerify.ok ? "OK" : "ошибка"} · HTTP {nvdVerify.status ?? "—"} · {nvdVerify.ms}ms
            {nvdVerify.apiKeyRejected ? " · ключ недействителен (404)" : ""}
            {nvdVerify.error ? <div className="mt-1 text-[10px] opacity-90">{nvdVerify.error}</div> : null}
          </div>
        ) : null}
        <div className="mt-2 flex flex-wrap gap-2">
          <button
            type="button"
            disabled={verifyNvdMut.isPending}
            onClick={() =>
              void verifyNvdMut.mutate(nvdKeyDraft.trim() || undefined)
            }
            className="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-[11px] text-fg/85 hover:bg-slate-50 disabled:opacity-50 dark:border-border dark:bg-black/25"
          >
            {verifyNvdMut.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : null}
            Проверить ключ
          </button>
          <button
            type="button"
            disabled={saveNvdMut.isPending || !nvdKeyDraft.trim()}
            onClick={() => void saveNvdMut.mutateAsync(nvdKeyDraft)}
            className={cn(
              "inline-flex items-center gap-2 rounded-lg border px-3 py-1.5 text-[11px]",
              "border-accent/30 bg-accent/10 text-fg/90 hover:bg-accent/15",
              (!nvdKeyDraft.trim() || saveNvdMut.isPending) && "pointer-events-none opacity-50"
            )}
          >
            {saveNvdMut.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Save className="h-3.5 w-3.5" />}
            Сохранить в БД
          </button>
          <button
            type="button"
            disabled={clearNvdMut.isPending || !data.nvd.hasDbKey}
            onClick={() => void clearNvdMut.mutateAsync()}
            className="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-[11px] text-fg/85 hover:bg-slate-50 disabled:opacity-50 dark:border-border dark:bg-black/25"
          >
            {clearNvdMut.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Trash2 className="h-3.5 w-3.5" />}
            Удалить ключ из БД
          </button>
        </div>
      </div>

      <div className="rounded-xl border border-sky-200/90 bg-sky-50/50 p-4 dark:border-sky-900/40 dark:bg-sky-950/25">
        <div className="text-[12px] font-medium text-fg/90">Telegram-бот</div>
        <div className="mt-1 text-[11px] text-muted">
          Токен от <span className="font-mono">@BotFather</span>, chat id канала/чата (например{" "}
          <span className="font-mono">-100…</span>). Кнопка «Пост в ТГ» в карточке CVE/BDU шлёт сообщение по шаблону
          банка.
        </div>
        {data.telegram ? (
          <div className="mt-2 flex flex-wrap gap-2 text-[10px] text-muted">
            {data.telegram.hasBotToken ? <span className="text-ok">токен в БД</span> : <span className="text-warn">токен не задан</span>}
            {data.telegram.chatId ? (
              <span>
                chat: <span className="font-mono text-fg/75">{data.telegram.chatId}</span>
              </span>
            ) : null}
            {data.telegram.lastPostAt ? (
              <span>посл. пост: {new Date(data.telegram.lastPostAt).toLocaleString()}</span>
            ) : null}
            {data.telegram.lastPostIdentifier ? <span>({data.telegram.lastPostIdentifier})</span> : null}
          </div>
        ) : null}
        <label className="mt-3 block text-[10px] text-muted">Токен бота</label>
        <input
          type="password"
          autoComplete="off"
          value={tgBotTokenDraft}
          onChange={(e) => setTgBotTokenDraft(e.target.value)}
          placeholder={data.telegram?.hasBotToken ? "Новый токен…" : "123456:ABC…"}
          className="mt-1 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm dark:border-border dark:bg-black/25"
        />
        <label className="mt-2 block text-[10px] text-muted">Chat ID</label>
        <input
          value={tgChatId}
          onChange={(e) => setTgChatId(e.target.value)}
          placeholder="-1001234567890"
          className="mt-1 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 font-mono text-sm dark:border-border dark:bg-black/25"
        />
        {tgVerify ? (
          <div
            className={cn(
              "mt-3 rounded-lg border px-3 py-2 text-[11px]",
              tgVerify.ok ? "border-ok/30 bg-ok/10 text-ok" : "border-warn/35 bg-warn/10 text-warn"
            )}
          >
            Проверка: {tgVerify.ok ? "тестовое сообщение отправлено" : "ошибка"}
            {tgVerify.error ? <div className="mt-1 opacity-90">{tgVerify.error}</div> : null}
          </div>
        ) : null}
        <div className="mt-3 flex flex-wrap gap-2">
          <button
            type="button"
            disabled={verifyTgMut.isPending || (!tgBotTokenDraft.trim() && !data.telegram?.hasBotToken) || !tgChatId.trim()}
            onClick={() => void verifyTgMut.mutate()}
            className="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-[11px] hover:bg-slate-50 disabled:opacity-50 dark:border-border dark:bg-black/25"
          >
            {verifyTgMut.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : null}
            Проверить (тест в канал)
          </button>
          <button
            type="button"
            disabled={
              saveTgMut.isPending ||
              !tgChatId.trim() ||
              (!tgBotTokenDraft.trim() && !data.telegram?.hasBotToken)
            }
            onClick={() => void saveTgMut.mutateAsync()}
            className="inline-flex items-center gap-2 rounded-lg border border-accent/30 bg-accent/10 px-3 py-1.5 text-[11px] disabled:opacity-50"
          >
            {saveTgMut.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Save className="h-3.5 w-3.5" />}
            Сохранить
          </button>
        </div>
      </div>

      <div className="rounded-xl border border-violet-200/90 bg-violet-50/50 p-4 dark:border-violet-900/40 dark:bg-violet-950/25">
        <div className="text-[12px] font-medium text-fg/90">MaxPatrol VM</div>
        <div className="mt-1 text-[11px] text-muted">
          URL консоли MP VM (HTTPS, порт 443), логин учётки и API-токен (Bearer). Синхронизация забирает активы,
          установленное ПО/пакеты, версии и уязвимости через <span className="font-mono">assets_grid</span>.
        </div>
        {data.mpvm ? (
          <div className="mt-2 flex flex-wrap gap-2 text-[10px] text-muted">
            <span>
              в системе: <span className="font-medium text-fg/85">{data.mpvm.assetCount.toLocaleString()}</span> активов
            </span>
            <span>
              <span className="font-medium text-fg/85">{data.mpvm.softwareCount.toLocaleString()}</span> ПО/пакетов
            </span>
            <span>
              <span className="font-medium text-fg/85">{data.mpvm.vulnerabilityCount.toLocaleString()}</span> уязвимостей
            </span>
            {data.mpvm.hasApiToken ? <span className="text-ok">токен в БД</span> : <span className="text-warn">токен не задан</span>}
            {data.mpvm.lastSyncAt ? (
              <span>посл. sync: {new Date(data.mpvm.lastSyncAt).toLocaleString()}</span>
            ) : null}
            {typeof data.mpvm.lastSyncFetched === "number" ? (
              <span>({data.mpvm.lastSyncFetched} шт.)</span>
            ) : null}
          </div>
        ) : null}
        {data.mpvm?.lastSyncError ? (
          <div className="mt-2 text-[10px] text-danger">{data.mpvm.lastSyncError}</div>
        ) : null}
        <label className="mt-3 block text-[10px] text-muted">URL MP VM</label>
        <input
          value={mpvmBaseUrl}
          onChange={(e) => setMpvmBaseUrl(e.target.value)}
          placeholder="https://mpvm.company.local"
          className="mt-1 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm dark:border-border dark:bg-black/25"
        />
        <label className="mt-2 block text-[10px] text-muted">Логин (учётная запись)</label>
        <input
          value={mpvmUsername}
          onChange={(e) => setMpvmUsername(e.target.value)}
          placeholder="admin"
          className="mt-1 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm dark:border-border dark:bg-black/25"
        />
        <label className="mt-2 block text-[10px] text-muted">API-токен</label>
        <input
          type="password"
          autoComplete="off"
          value={mpvmTokenDraft}
          onChange={(e) => setMpvmTokenDraft(e.target.value)}
          placeholder={data.mpvm?.hasApiToken ? "Новый токен (оставьте пустым — не менять)…" : "Bearer / API token…"}
          className="mt-1 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm dark:border-border dark:bg-black/25"
        />
        <label className="mt-2 block text-[10px] text-muted">PDQL (активы + ПО/пакеты + уязвимости)</label>
        <textarea
          value={mpvmPdql}
          onChange={(e) => setMpvmPdql(e.target.value)}
          rows={3}
          className="mt-1 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 font-mono text-[11px] dark:border-border dark:bg-black/25"
        />
        <label className="mt-2 flex items-center gap-2 text-[11px] text-fg/75">
          <input
            type="checkbox"
            checked={mpvmTlsInsecure}
            onChange={(e) => setMpvmTlsInsecure(e.target.checked)}
          />
          Не проверять TLS (самоподписанный сертификат)
        </label>
        {mpvmVerify ? (
          <div
            className={cn(
              "mt-3 rounded-lg border px-3 py-2 text-[11px]",
              mpvmVerify.ok ? "border-ok/30 bg-ok/10 text-ok" : "border-warn/35 bg-warn/10 text-warn"
            )}
          >
            Проверка: {mpvmVerify.ok ? "OK" : "ошибка"} · {mpvmVerify.ms}ms
            {mpvmVerify.ok ? ` · образец: ${mpvmVerify.assetSample} записей` : ""}
            {mpvmVerify.error ? <div className="mt-1 opacity-90">{mpvmVerify.error}</div> : null}
          </div>
        ) : null}
        <div className="mt-3 flex flex-wrap gap-2">
          <button
            type="button"
            disabled={verifyMpvmMut.isPending || !mpvmBaseUrl.trim()}
            onClick={() => void verifyMpvmMut.mutate()}
            className="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-[11px] hover:bg-slate-50 disabled:opacity-50 dark:border-border dark:bg-black/25"
          >
            {verifyMpvmMut.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : null}
            Проверить подключение
          </button>
          <button
            type="button"
            disabled={saveMpvmMut.isPending || !mpvmBaseUrl.trim()}
            onClick={() => void saveMpvmMut.mutateAsync()}
            className="inline-flex items-center gap-2 rounded-lg border border-accent/30 bg-accent/10 px-3 py-1.5 text-[11px] disabled:opacity-50"
          >
            {saveMpvmMut.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Save className="h-3.5 w-3.5" />}
            Сохранить
          </button>
          <button
            type="button"
            disabled={
              syncMpvmMut.isPending ||
              (!data.mpvm?.hasApiToken && !mpvmTokenDraft.trim()) ||
              !mpvmBaseUrl.trim()
            }
            onClick={() => void syncMpvmMut.mutateAsync()}
            className="inline-flex items-center gap-2 rounded-lg border border-violet-300/50 bg-violet-500/15 px-3 py-1.5 text-[11px] disabled:opacity-50"
          >
            {syncMpvmMut.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : null}
            Синхронизировать inventory
          </button>
        </div>
      </div>

      <div className="rounded-xl border border-teal-200/90 bg-teal-50/60 p-4 dark:border-teal-900/50 dark:bg-teal-950/20">
        <div className="text-[12px] font-medium text-fg/90">БДУ ФСТЭК (vulxml)</div>
        <div className="mt-1 text-[11px] text-muted">
          Источник по умолчанию:{" "}
          <span className="font-mono text-[10px] text-fg/80">https://bdu.fstec.ru/files/documents/vulxml.zip</span>
          . Override: <span className="font-mono">BDU_XML_URL</span>, зеркало:{" "}
          <span className="font-mono">BDU_ALLOW_MIRROR_FALLBACK=true</span>.
        </div>
        {bduH ? (
          <div className="mt-3 rounded-lg border border-teal-200/80 bg-white px-3 py-2 text-[11px] dark:border-teal-900/40 dark:bg-black/30">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="text-muted">
                Статус{" "}
                {bduH.ok ? <span className="text-ok">OK</span> : <span className="text-danger">DOWN</span>}
                {bduH.sourceProbeOk === false && bduH.ok ? (
                  <span className="ml-1 text-warn">· URL probe</span>
                ) : null}
                {bduH.ingestStale ? <span className="ml-1 text-warn">· ingest устарел</span> : null}
                {bduH.lastIngestUsedFallback ? <span className="ml-1 text-warn">· fallback</span> : null}
              </span>
              <span className="font-mono tabular-nums text-fg/80">{typeof bduH.ms === "number" ? `${bduH.ms}ms` : "—"}</span>
            </div>
            {bduH.endpoint ? (
              <div className="mt-1 truncate font-mono text-[10px] text-fg/80">{bduH.endpoint}</div>
            ) : null}
            <div className="mt-1 flex flex-wrap gap-2 text-[10px] text-muted">
              {typeof bduH.status === "number" ? <span>HTTP {bduH.status}</span> : null}
              {typeof bduH.recordCount === "number" ? <span>в БД: {bduH.recordCount.toLocaleString()}</span> : null}
              {typeof bduH.cveLinkCount === "number" ? <span>связей CVE: {bduH.cveLinkCount.toLocaleString()}</span> : null}
              {bduH.tlsInsecure ? <span className="text-warn">BDU_TLS_INSECURE</span> : null}
              {bduH.maxBduId ? <span>max: {bduH.maxBduId}</span> : null}
              {typeof bduH.lastIngestRecords === "number" ? (
                <span>посл. ingest: {bduH.lastIngestRecords.toLocaleString()}</span>
              ) : null}
              {bduH.lastIngestAt ? <span>{new Date(bduH.lastIngestAt).toLocaleString()}</span> : null}
            </div>
            {bduH.error ? (
              <div className={cn("mt-1 text-[10px]", bduH.ok ? "text-warn" : "text-danger")}>{bduH.error}</div>
            ) : null}
            {bduH.ingestStale && bduH.ingestStaleHint ? (
              <div className="mt-2 text-[10px] text-warn">{bduH.ingestStaleHint}</div>
            ) : null}
          </div>
        ) : queueQ.isLoading ? (
          <div className="mt-2 flex items-center gap-2 text-[11px] text-muted">
            <Loader2 className="h-3.5 w-3.5 animate-spin" />
            Проверка БДУ…
          </div>
        ) : null}
      </div>

      <div className="rounded-xl border border-dashed border-slate-300/90 bg-white/60 p-4 text-[11px] leading-relaxed text-muted dark:border-white/10 dark:bg-black/10">
        <div className="font-medium text-fg/90">Развёртывание (минимум для оператора)</div>
        <ul className="mt-2 list-inside list-disc space-y-1">
          <li>
            <span className="text-fg/80">Postgres + Redis + RabbitMQ</span> —{" "}
            <span className="font-mono">infra/docker-compose.yml</span>, переменная{" "}
            <span className="font-mono">DATABASE_URL</span> в .env.
          </li>
          <li>
            <span className="text-fg/80">Ключ NVD</span> — лучше здесь (БД), не в .env:{" "}
            <a
              className="text-accent hover:underline"
              href="https://nvd.nist.gov/developers/request-an-api-key"
              target="_blank"
              rel="noreferrer"
            >
              запрос ключа на nist.gov
            </a>
            . Неверный ключ даёт HTTP 404 на все запросы.
          </li>
          <li>
            <span className="text-fg/80">LLM</span> — профиль ниже или <span className="font-mono">LLM_*</span> в .env
            (Ollama/OpenAI/x.ai).
          </li>
          <li>
            <span className="text-fg/80">Ingest</span> — <span className="font-mono">apps/ingest</span>, интервал{" "}
            <span className="font-mono">NVD_POLL_INTERVAL_MS</span>, пауза страниц{" "}
            <span className="font-mono">NVD_PAGE_SLEEP_MS=6500</span> с ключом.
          </li>
        </ul>
      </div>

      <div className="rounded-xl border border-slate-200/90 bg-slate-50/90 p-4 dark:border-white/[0.06] dark:bg-black/20">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <div className="text-[12px] font-medium text-fg/90">Профили LLM</div>
            <div className="mt-1 text-[11px] text-muted">
              Fallback из .env: <span className="font-mono">{data.llm.envFallback.endpoint}</span> · модель{" "}
              <span className="font-mono">{data.llm.envFallback.model}</span>
              {data.llm.envFallback.hasApiKey ? " · ключ в .env есть" : ""}
            </div>
          </div>
          <button
            type="button"
            onClick={() => {
              setProfiles((prev) => [...(prev ?? list), emptyProfile()]);
            }}
            className="inline-flex items-center gap-2 rounded-lg border border-accent/30 bg-accent/10 px-3 py-1.5 text-[11px] text-fg/90 hover:bg-accent/15"
          >
            <Plus className="h-3.5 w-3.5" />
            Профиль
          </button>
        </div>

        <div className="mt-4 space-y-4">
          {list.map((p, idx) => (
            <div key={p.id} className="rounded-xl border border-slate-200 bg-white p-3 dark:border-white/10 dark:bg-black/30">
              <div className="flex flex-wrap items-start justify-between gap-2">
                <label className="flex items-center gap-2 text-[11px] text-muted">
                  <input
                    type="radio"
                    name="llm-active"
                    checked={merged?.activeId === p.id}
                    onChange={() => setActiveId(p.id)}
                  />
                  Активный
                </label>
                <button
                  type="button"
                  className="text-[11px] text-danger hover:underline"
                  onClick={() => {
                    setProfiles((prev) => (prev ?? list).filter((x) => x.id !== p.id));
                    if (merged?.activeId === p.id) setActiveId(null);
                  }}
                >
                  Удалить
                </button>
              </div>
              <div className="mt-2 grid grid-cols-1 gap-2 md:grid-cols-2">
                <div>
                  <div className="text-[10px] text-muted">Имя</div>
                  <input
                    value={p.name}
                    onChange={(e) => {
                      const v = e.target.value;
                      setProfiles((prev) => {
                        const base = prev ?? list;
                        const cp = [...base];
                        cp[idx] = { ...cp[idx]!, name: v };
                        return cp;
                      });
                    }}
                    className="mt-1 w-full rounded-lg border border-slate-200 bg-white px-2 py-1.5 text-sm dark:border-border dark:bg-black/25"
                  />
                </div>
                <div>
                  <div className="text-[10px] text-muted">Модель</div>
                  <input
                    value={p.model}
                    onChange={(e) => {
                      const v = e.target.value;
                      setProfiles((prev) => {
                        const base = prev ?? list;
                        const cp = [...base];
                        cp[idx] = { ...cp[idx]!, model: v };
                        return cp;
                      });
                    }}
                    className="mt-1 w-full rounded-lg border border-slate-200 bg-white px-2 py-1.5 text-sm font-mono dark:border-border dark:bg-black/25"
                  />
                </div>
                <div className="md:col-span-2">
                  <div className="text-[10px] text-muted">Endpoint (OpenAI‑compatible)</div>
                  <input
                    value={p.endpoint}
                    onChange={(e) => {
                      const v = e.target.value;
                      setProfiles((prev) => {
                        const base = prev ?? list;
                        const cp = [...base];
                        cp[idx] = { ...cp[idx]!, endpoint: v };
                        return cp;
                      });
                    }}
                    className="mt-1 w-full rounded-lg border border-slate-200 bg-white px-2 py-1.5 text-sm font-mono dark:border-border dark:bg-black/25"
                  />
                </div>
                <div>
                  <div className="text-[10px] text-muted">promptVersion</div>
                  <input
                    value={p.promptVersion}
                    onChange={(e) => {
                      const v = e.target.value;
                      setProfiles((prev) => {
                        const base = prev ?? list;
                        const cp = [...base];
                        cp[idx] = { ...cp[idx]!, promptVersion: v };
                        return cp;
                      });
                    }}
                    className="mt-1 w-full rounded-lg border border-slate-200 bg-white px-2 py-1.5 text-sm dark:border-border dark:bg-black/25"
                  />
                </div>
                <div>
                  <div className="text-[10px] text-muted">API key (опционально)</div>
                  <input
                    type="password"
                    autoComplete="off"
                    value={p.apiKeyDraft}
                    placeholder={p.hasApiKey ? "•••• (в БД есть — оставь пустым чтобы не менять)" : "пусто для Ollama"}
                    onChange={(e) => {
                      const v = e.target.value;
                      setProfiles((prev) => {
                        const base = prev ?? list;
                        const cp = [...base];
                        cp[idx] = { ...cp[idx]!, apiKeyDraft: v, clearApiKey: false };
                        return cp;
                      });
                    }}
                    className="mt-1 w-full rounded-lg border border-slate-200 bg-white px-2 py-1.5 text-sm dark:border-border dark:bg-black/25"
                  />
                  {p.hasApiKey ? (
                    <button
                      type="button"
                      className="mt-1 text-[10px] text-danger hover:underline"
                      onClick={() => {
                        setProfiles((prev) => {
                          const base = prev ?? list;
                          const cp = [...base];
                          cp[idx] = { ...cp[idx]!, clearApiKey: true, apiKeyDraft: "" };
                          return cp;
                        });
                      }}
                    >
                      Очистить ключ в БД для этого профиля
                    </button>
                  ) : null}
                </div>
              </div>
            </div>
          ))}
        </div>

        <div className="mt-4 flex flex-wrap gap-2">
          <button
            type="button"
            disabled={saveMut.isPending || list.length === 0}
            onClick={() => void saveMut.mutateAsync()}
            className="inline-flex items-center gap-2 rounded-lg border border-accent/30 bg-accent/10 px-4 py-2 text-[12px] font-medium text-fg/90 hover:bg-accent/15 disabled:opacity-50"
          >
            {saveMut.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
            Сохранить LLM
          </button>
          <button
            type="button"
            onClick={() => {
              void q.refetch();
              setProfiles(null);
              setMsg(null);
              setErr(null);
            }}
            className="rounded-lg border border-slate-200 bg-white px-4 py-2 text-[12px] text-fg/85 hover:bg-slate-50 dark:border-border dark:bg-black/25"
          >
            Сбросить форму
          </button>
        </div>
      </div>
    </div>
  );
}
