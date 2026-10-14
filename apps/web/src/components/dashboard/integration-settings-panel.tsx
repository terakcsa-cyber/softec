"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Loader2, Plus, Save, Trash2 } from "lucide-react";
import { useEffect, useMemo, useState, type ReactNode } from "react";
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
  textEngine: {
    textEngine: "baseline" | "translate" | "llm";
    translateEndpoint: string;
  };
  digestLlm?: {
    endpoint: string;
    model: string;
    hasApiKey: boolean;
  };
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
  nvd: { hasDbKey: boolean; hasEnvKey: boolean; activeKeySource: "db" | "env" | "none"; catalogStatus?: string; catalogCveCount?: number; catalogPubCursor?: string | null };
  vulncheck?: {
    hasDbToken: boolean;
    hasEnvToken: boolean;
    activeTokenSource: "db" | "env" | "none";
    kevCount: number;
    lastIngestAt: string | null;
    lastIngestItems: number | null;
  };
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

const DEEPSEEK_ENDPOINT = "https://api.deepseek.com";
const DEEPSEEK_MODEL = "deepseek-chat";

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

type IntegrationAppearance = "legacy" | "vc";
type SourceTone = "configured" | "missing" | "error" | "neutral";

const SOURCE_TONE: Record<SourceTone, { label: string; color: string }> = {
  configured: { label: "Настроено", color: "var(--vc-success)" },
  missing: { label: "Не настроено", color: "var(--vc-muted)" },
  error: { label: "Ошибка", color: "var(--vc-critical)" },
  neutral: { label: "Без ключа", color: "var(--vc-nav)" }
};

function nvdTone(nvd: IntegrationState["nvd"]): SourceTone {
  return nvd.activeKeySource === "none" ? "missing" : "configured";
}

function vulncheckTone(row: IntegrationState["vulncheck"]): SourceTone {
  if (!row || row.activeTokenSource === "none") return "missing";
  return "configured";
}

function telegramTone(row: TelegramUiState | undefined): SourceTone {
  if (!row?.hasBotToken || !row.chatId) return "missing";
  return "configured";
}

function mpvmReady(row: MpvmUiState) {
  const passwordAuth = Boolean(row.username) && row.hasPassword && row.hasClientSecret;
  return Boolean(row.baseUrl) && (row.hasApiToken || passwordAuth);
}

function mpvmTone(row: MpvmUiState | undefined): SourceTone {
  if (!row) return "missing";
  if (row.lastSyncError) return "error";
  return mpvmReady(row) ? "configured" : "missing";
}

function StatusMark({ tone }: { tone: SourceTone }) {
  const item = SOURCE_TONE[tone];
  return (
    <span
      className="shrink-0 rounded-md px-2 py-0.5 text-[11px] font-medium"
      style={{ color: item.color, background: `color-mix(in srgb, ${item.color} 14%, transparent)` }}
    >
      {item.label}
    </span>
  );
}

function StatusCard({ name, tone, hint }: { name: string; tone: SourceTone; hint: string }) {
  const item = SOURCE_TONE[tone];
  return (
    <div className="rounded-xl border border-[var(--vc-border)] bg-[var(--vc-surface)] px-3 py-2.5">
      <div className="text-[11px] text-[var(--vc-muted)]">{name}</div>
      <div className="mt-1 text-[13px] font-semibold" style={{ color: item.color }}>{item.label}</div>
      <div className="mt-1 text-[10px] leading-4 text-[var(--vc-muted)]">{hint}</div>
    </div>
  );
}

function controlClass(vc: boolean, kind: "field" | "area" | "ghost" | "primary" | "sync") {
  if (!vc) return "";
  if (kind === "field") {
    return "h-8 w-full rounded-lg border border-[var(--vc-border)] bg-[var(--vc-bg)] px-2.5 text-[12px] text-[var(--vc-text)] outline-none placeholder:text-[var(--vc-muted)]";
  }
  if (kind === "area") {
    return "mt-1 w-full rounded-lg border border-[var(--vc-border)] bg-[var(--vc-bg)] px-2.5 py-2 font-mono text-[11px] text-[var(--vc-text)] outline-none";
  }
  if (kind === "primary") {
    return "inline-flex h-8 items-center gap-1.5 rounded-lg bg-[var(--vc-primary)] px-3 text-[12px] font-medium text-white disabled:opacity-40";
  }
  if (kind === "sync") {
    return "inline-flex h-8 items-center gap-1.5 rounded-lg border border-[var(--vc-border)] bg-[var(--vc-bg)] px-3 text-[12px] font-medium text-[var(--vc-text)] hover:border-[var(--vc-primary)] disabled:opacity-40";
  }
  return "inline-flex h-8 items-center gap-1.5 rounded-lg border border-[var(--vc-border)] bg-[var(--vc-inset-2)] px-3 text-[12px] font-medium text-[var(--vc-text)] hover:border-[var(--vc-primary)] disabled:opacity-40";
}

function noteClass(vc: boolean, ok: boolean) {
  if (!vc) return ok ? "border-ok/30 bg-ok/10 text-ok" : "border-warn/35 bg-warn/10 text-warn";
  return ok
    ? "border-[color-mix(in_srgb,var(--vc-success)_35%,transparent)] bg-[color-mix(in_srgb,var(--vc-success)_12%,transparent)] text-[var(--vc-success-text)]"
    : "border-[color-mix(in_srgb,var(--vc-high)_35%,transparent)] bg-[color-mix(in_srgb,var(--vc-high)_12%,transparent)] text-[var(--vc-high)]";
}

function SettingsBlock({
  title,
  description,
  children,
  appearance = "legacy",
  status
}: {
  title: string;
  description?: ReactNode;
  children: ReactNode;
  appearance?: IntegrationAppearance;
  status?: SourceTone;
}) {
  const vc = appearance === "vc";
  return (
    <section
      className={
        vc
          ? "rounded-xl border border-[var(--vc-border)] bg-[var(--vc-surface)] p-3"
          : "rounded-xl border border-slate-200 bg-white p-4 shadow-sm dark:border-border dark:bg-white/[0.04] dark:shadow-none"
      }
    >
      {vc && status ? (
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="text-[13px] font-semibold text-[var(--vc-text)]">{title}</div>
          <StatusMark tone={status} />
        </div>
      ) : (
        <div className={vc ? "text-[13px] font-semibold text-[var(--vc-text)]" : "text-[13px] font-medium text-fg/90"}>{title}</div>
      )}
      {description ? (
        <div className={vc ? "mt-1 text-[12px] leading-5 text-[var(--vc-muted)]" : "mt-1 text-[11px] leading-relaxed text-muted"}>
          {description}
        </div>
      ) : null}
      <div className="mt-3">{children}</div>
    </section>
  );
}

export type IntegrationSettingsSection = "integrations" | "textEngine" | "all";

export function IntegrationSettingsPanel({
  section = "all",
  appearance = "legacy"
}: {
  section?: IntegrationSettingsSection;
  appearance?: IntegrationAppearance;
}) {
  const vc = appearance === "vc";
  const qc = useQueryClient();
  const showIntegrations = section === "integrations" || section === "all";
  const showTextEngine = section === "textEngine" || section === "all";
  const q = useQuery({
    queryKey: ["settings", "integrations"],
    queryFn: async () => {
      const res = await apiFetch("/api/settings/integrations", { cache: "no-store" });
      if (!res.ok) throw new Error(await res.text().catch(() => res.statusText));
      return (await res.json()) as IntegrationState;
    }
  });

  const [profiles, setProfiles] = useState<LlmProfileUi[] | null>(null);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [textEngine, setTextEngine] = useState<"baseline" | "translate" | "llm">("baseline");
  const [translateEndpoint, setTranslateEndpoint] = useState("");
  const [digestEndpoint, setDigestEndpoint] = useState(DEEPSEEK_ENDPOINT);
  const [digestModel, setDigestModel] = useState(DEEPSEEK_MODEL);
  const [digestKeyDraft, setDigestKeyDraft] = useState("");
  const [digestClearKey, setDigestClearKey] = useState(false);
  const [nvdKeyDraft, setNvdKeyDraft] = useState("");
  const [vcTokenDraft, setVcTokenDraft] = useState("");
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
    if (!q.data?.textEngine) return;
    setTextEngine(q.data.textEngine.textEngine ?? "baseline");
    setTranslateEndpoint(q.data.textEngine.translateEndpoint ?? "");
  }, [q.data?.textEngine]);

  useEffect(() => {
    const row = q.data?.digestLlm;
    if (!row) return;
    setDigestEndpoint(row.endpoint || DEEPSEEK_ENDPOINT);
    setDigestModel(row.model || DEEPSEEK_MODEL);
  }, [q.data?.digestLlm]);

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
          "Ключ NVD сохранён. Ingest сразу начнёт полную загрузку каталога CVE (быстрый режим); после завершения — суточный инкремент как раньше."
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
        textEngine: {
          textEngine,
          translateEndpoint: translateEndpoint.trim()
        },
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
      setMsg("Сохранено. Text engine/LLM — воркеры apps/ai; ключ NVD в БД — ingest на ближайшем цикле.");
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
      setTextEngine(data.textEngine.textEngine ?? "baseline");
      setTranslateEndpoint(data.textEngine.translateEndpoint ?? "");
      setNvdKeyDraft("");
    },
    onError: (e: unknown) => {
      setMsg(null);
      setErr(e instanceof Error ? e.message : String(e));
    }
  });

  const saveDigestMut = useMutation({
    mutationFn: async (): Promise<IntegrationPutResponse> => {
      const digestLlm: Record<string, string> = {
        endpoint: digestEndpoint.trim() || DEEPSEEK_ENDPOINT,
        model: digestModel.trim() || DEEPSEEK_MODEL
      };
      if (digestClearKey) digestLlm.apiKey = "";
      else if (digestKeyDraft.trim()) digestLlm.apiKey = digestKeyDraft.trim();
      const res = await apiFetch("/api/settings/integrations", {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ digestLlm })
      });
      if (!res.ok) throw new Error(await res.text().catch(() => res.statusText));
      return (await res.json()) as IntegrationPutResponse;
    },
    onSuccess: (data) => {
      const hasKey = Boolean(data.digestLlm?.hasApiKey);
      setMsg(
        hasKey
          ? "Ключ сохранён. Каталог, скоринг и очередь разбора не запускаются. DeepSeek вызывается для ежемесячного дайджеста и по кнопке AI на одной карточке CVE."
          : "Настройки дайджеста сохранены без ключа. PDF скачается, связного рассказа в нём не будет."
      );
      setErr(null);
      void qc.setQueryData(["settings", "integrations"], data);
      setDigestKeyDraft("");
      setDigestClearKey(false);
      setDigestEndpoint(data.digestLlm?.endpoint || DEEPSEEK_ENDPOINT);
      setDigestModel(data.digestLlm?.model || DEEPSEEK_MODEL);
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

  const saveVulncheckMut = useMutation({
    mutationFn: async (token: string): Promise<IntegrationState> => {
      const res = await apiFetch("/api/settings/integrations", {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ vulncheck: { apiToken: token.trim() } })
      });
      if (!res.ok) throw new Error(await res.text().catch(() => res.statusText));
      return (await res.json()) as IntegrationState;
    },
    onSuccess: (data) => {
      setMsg("Токен VulnCheck сохранён — ingest подхватит на ближайшем цикле.");
      setErr(null);
      void qc.setQueryData(["settings", "integrations"], data);
      setVcTokenDraft("");
    },
    onError: (e: unknown) => {
      setMsg(null);
      setErr(e instanceof Error ? e.message : String(e));
    }
  });

  const clearVulncheckMut = useMutation({
    mutationFn: async (): Promise<IntegrationState> => {
      const res = await apiFetch("/api/settings/integrations", {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ vulncheck: { apiToken: null } })
      });
      if (!res.ok) throw new Error(await res.text().catch(() => res.statusText));
      return (await res.json()) as IntegrationState;
    },
    onSuccess: (data) => {
      setMsg("Токен VulnCheck удалён из БД.");
      setErr(null);
      void qc.setQueryData(["settings", "integrations"], data);
      setVcTokenDraft("");
    },
    onError: (e: unknown) => {
      setMsg(null);
      setErr(e instanceof Error ? e.message : String(e));
    }
  });

  if (q.isLoading) {
    return (
      <div className={vc ? "flex items-center gap-2 text-[12px] text-[var(--vc-muted)]" : "flex items-center gap-2 text-sm text-muted"}>
        <Loader2 className="h-4 w-4 animate-spin" />
        Загрузка интеграций…
      </div>
    );
  }

  if (q.isError) {
    return (
      <div className={vc ? "text-[12px] text-[var(--vc-danger-text)]" : "text-sm text-danger"}>
        Не удалось загрузить настройки: {(q.error as Error)?.message ?? "ошибка"}
      </div>
    );
  }

  const data = q.data!;
  const list = merged?.profiles ?? [];
  const okText = vc ? "text-[var(--vc-success-text)]" : "text-ok";
  const warnText = vc ? "text-[var(--vc-high)]" : "text-warn";
  const dangerText = vc ? "text-[var(--vc-danger-text)]" : "text-danger";
  const emph = vc ? "font-medium text-[var(--vc-text)]" : "font-medium text-fg/85";
  const monoEmph = vc ? "font-mono text-[var(--vc-text)]" : "font-mono text-fg/75";
  const label = vc ? "block text-[11px] text-[var(--vc-muted)]" : "block text-[10px] text-muted";
  const labelMt = vc ? "mt-2 block text-[11px] text-[var(--vc-muted)]" : "mt-2 block text-[10px] text-muted";
  const field = vc
    ? controlClass(true, "field")
    : "w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm dark:border-border dark:bg-black/25";
  const fieldMt = vc
    ? cn("mt-1", controlClass(true, "field"))
    : "mt-1 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm dark:border-border dark:bg-black/25";
  const fieldMono = vc
    ? cn("mt-1 font-mono", controlClass(true, "field"))
    : "mt-1 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 font-mono text-sm dark:border-border dark:bg-black/25";
  const area = vc
    ? controlClass(true, "area")
    : "mt-1 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 font-mono text-[11px] dark:border-border dark:bg-black/25";
  const ghostStrong = vc
    ? controlClass(true, "ghost")
    : "inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-[11px] text-fg/85 hover:bg-slate-50 disabled:opacity-50 dark:border-border dark:bg-black/25";
  const ghostPlain = vc
    ? controlClass(true, "ghost")
    : "inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-[11px] hover:bg-slate-50 disabled:opacity-50 dark:border-border dark:bg-black/25";
  const ghostQuiet = vc
    ? controlClass(true, "ghost")
    : "inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-[11px] disabled:opacity-50 dark:border-border dark:bg-black/25";
  const primaryPlain = vc
    ? controlClass(true, "primary")
    : "inline-flex items-center gap-2 rounded-lg border border-accent/30 bg-accent/10 px-3 py-1.5 text-[11px] disabled:opacity-50";
  const syncBtn = vc
    ? controlClass(true, "sync")
    : "inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 text-[11px] disabled:opacity-50 dark:border-border dark:bg-white/[0.06]";
  const noteBox = vc ? "mt-3 rounded-lg border px-3 py-2 text-[12px]" : "mt-3 rounded-lg border px-3 py-2 text-[11px]";
  const hint = vc ? "text-[11px] leading-5 text-[var(--vc-muted)]" : "text-[10px] text-muted";
  const profileCard = vc
    ? "rounded-lg border border-[var(--vc-border)] bg-[var(--vc-bg)] p-3"
    : "rounded-lg border border-slate-200 bg-slate-50/80 p-3 dark:border-border dark:bg-black/20";
  const nvdHint =
    data.nvd.activeKeySource === "db" ? "Ключ в БД" : data.nvd.activeKeySource === "env" ? "Ключ в .env" : "Ключ не задан";
  const vulnHint = !data.vulncheck || data.vulncheck.activeTokenSource === "none"
    ? "Токен не задан"
    : data.vulncheck.activeTokenSource === "db"
      ? "Токен в БД"
      : "Токен в .env";
  const tgHint = !data.telegram?.hasBotToken && !data.telegram?.chatId
    ? "Токен и chat id не заданы"
    : !data.telegram?.hasBotToken
      ? "Токен не задан"
      : !data.telegram.chatId
        ? "Chat id не задан"
        : "Токен и chat id заданы";
  const mpvmHint = !data.mpvm
    ? "Нет данных"
    : data.mpvm.lastSyncError
      ? "Последняя синхронизация с ошибкой"
      : mpvmReady(data.mpvm)
        ? "URL и доступ заданы"
        : data.mpvm.baseUrl
          ? "Нет токена или пароля"
          : "URL не задан";

  return (
    <div className={vc ? "space-y-3" : "space-y-5"}>
      {msg ? (
        <div
          className={
            vc
              ? "rounded-lg border border-[color-mix(in_srgb,var(--vc-success)_35%,transparent)] bg-[color-mix(in_srgb,var(--vc-success)_12%,transparent)] px-3 py-2 text-[12px] text-[var(--vc-success-text)]"
              : "rounded-lg border border-ok/30 bg-ok/10 px-3 py-2 text-[11px] text-ok"
          }
        >
          {msg}
        </div>
      ) : null}
      {err ? (
        <div
          className={
            vc
              ? "rounded-lg border border-[color-mix(in_srgb,var(--vc-critical)_35%,transparent)] bg-[color-mix(in_srgb,var(--vc-critical)_12%,transparent)] px-3 py-2 text-[12px] text-[var(--vc-danger-text)]"
              : "rounded-lg border border-danger/30 bg-danger/10 px-3 py-2 text-[11px] text-danger"
          }
        >
          {err}
        </div>
      ) : null}

      {showIntegrations ? (
        <div className={vc ? "space-y-3" : "space-y-4"}>
          {vc ? (
            <div className="grid grid-cols-2 gap-2 xl:grid-cols-5">
              <StatusCard name="NVD" tone={nvdTone(data.nvd)} hint={nvdHint} />
              <StatusCard name="VulnCheck" tone={vulncheckTone(data.vulncheck)} hint={vulnHint} />
              <StatusCard name="Telegram" tone={telegramTone(data.telegram)} hint={tgHint} />
              <StatusCard name="MaxPatrol VM" tone={mpvmTone(data.mpvm)} hint={mpvmHint} />
              <StatusCard name="БДУ ФСТЭК" tone="neutral" hint="URL по умолчанию, ключ не нужен" />
            </div>
          ) : null}
          <SettingsBlock
            appearance={appearance}
            status={nvdTone(data.nvd)}
            title="NVD API key"
            description={
              <>
                В БД: {data.nvd.hasDbKey ? "задан" : "нет"} · в .env: {data.nvd.hasEnvKey ? "есть NVD_API_KEY" : "нет"} ·
                активный: <span className={emph}>{sourceLabel(data.nvd.activeKeySource)}</span>
                {data.nvd.hasDbKey && data.nvd.hasEnvKey ? (
                  <div className={cn("mt-1", warnText)}>
                    Ключ в БД имеет приоритет над .env. Удалите или исправьте неверный NVD_API_KEY в .env, чтобы не путаться.
                  </div>
                ) : null}
                <div className="mt-1">Статус NVD ingest и очередей — в «Здоровье системы».</div>
              </>
            }
          >
            <input
              type="password"
              autoComplete="off"
              value={nvdKeyDraft}
              onChange={(e) => setNvdKeyDraft(e.target.value)}
              placeholder="Новый ключ (сохранить в БД)…"
              className={field}
            />
            {nvdVerify ? (
              <div
                className={cn(noteBox, noteClass(vc, nvdVerify.ok && !nvdVerify.apiKeyRejected))}
              >
                Проверка: {nvdVerify.ok ? "OK" : "ошибка"} · HTTP {nvdVerify.status ?? "—"} · {nvdVerify.ms}ms
                {nvdVerify.apiKeyRejected ? " · ключ недействителен (404)" : ""}
                {nvdVerify.error ? <div className="mt-1 text-[10px] opacity-90">{nvdVerify.error}</div> : null}
              </div>
            ) : null}
            <div className="mt-3 flex flex-wrap gap-2">
              <button
                type="button"
                disabled={verifyNvdMut.isPending}
                onClick={() => void verifyNvdMut.mutate(nvdKeyDraft.trim() || undefined)}
                className={ghostStrong}
              >
                {verifyNvdMut.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : null}
                Проверить ключ
              </button>
              <button
                type="button"
                disabled={saveNvdMut.isPending || !nvdKeyDraft.trim()}
                onClick={() => void saveNvdMut.mutateAsync(nvdKeyDraft)}
                className={
                  vc
                    ? controlClass(true, "primary")
                    : cn(
                        "inline-flex items-center gap-2 rounded-lg border px-3 py-1.5 text-[11px]",
                        "border-accent/30 bg-accent/10 text-fg/90 hover:bg-accent/15",
                        (!nvdKeyDraft.trim() || saveNvdMut.isPending) && "pointer-events-none opacity-50"
                      )
                }
              >
                {saveNvdMut.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Save className="h-3.5 w-3.5" />}
                Сохранить в БД
              </button>
              <button
                type="button"
                disabled={clearNvdMut.isPending || !data.nvd.hasDbKey}
                onClick={() => void clearNvdMut.mutateAsync()}
                className={ghostStrong}
              >
                {clearNvdMut.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Trash2 className="h-3.5 w-3.5" />}
                Удалить ключ из БД
              </button>
            </div>
          </SettingsBlock>

          <SettingsBlock
            appearance={appearance}
            status={vulncheckTone(data.vulncheck)}
            title="VulnCheck API (KEV + XDB)"
            description={
              <>
                Community token для каталога VulnCheck KEV. В БД: {data.vulncheck?.hasDbToken ? "задан" : "нет"} · в .env:{" "}
                {data.vulncheck?.hasEnvToken ? "VULNCHECK_API_TOKEN" : "нет"} · активен:{" "}
                {data.vulncheck?.activeTokenSource === "db"
                  ? "БД"
                  : data.vulncheck?.activeTokenSource === "env"
                    ? ".env"
                    : "не задан"}
                {data.vulncheck?.lastIngestAt ? (
                  <div className="mt-1">
                    Посл. ingest: {new Date(data.vulncheck.lastIngestAt).toLocaleString()}
                    {typeof data.vulncheck.lastIngestItems === "number"
                      ? ` · ${data.vulncheck.lastIngestItems} записей`
                      : ""}
                    {typeof data.vulncheck.kevCount === "number" ? ` · в БД: ${data.vulncheck.kevCount}` : ""}
                  </div>
                ) : null}
              </>
            }
          >
            <input
              type="password"
              autoComplete="off"
              value={vcTokenDraft}
              onChange={(e) => setVcTokenDraft(e.target.value)}
              placeholder={data.vulncheck?.hasDbToken ? "Новый токен…" : "VulnCheck API token"}
              className={field}
            />
            <div className="mt-3 flex flex-wrap gap-2">
              <button
                type="button"
                disabled={saveVulncheckMut.isPending || !vcTokenDraft.trim()}
                onClick={() => void saveVulncheckMut.mutateAsync(vcTokenDraft)}
                className={primaryPlain}
              >
                {saveVulncheckMut.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Save className="h-3.5 w-3.5" />}
                Сохранить в БД
              </button>
              <button
                type="button"
                disabled={clearVulncheckMut.isPending || !data.vulncheck?.hasDbToken}
                onClick={() => void clearVulncheckMut.mutateAsync()}
                className={ghostQuiet}
              >
                {clearVulncheckMut.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Trash2 className="h-3.5 w-3.5" />}
                Удалить из БД
              </button>
            </div>
          </SettingsBlock>

          <SettingsBlock
            appearance={appearance}
            status={telegramTone(data.telegram)}
            title="Telegram-бот"
            description={
              <>
                Токен от <span className="font-mono">@BotFather</span>, chat id канала/чата (например{" "}
                <span className="font-mono">-100…</span>). Кнопка «Пост в ТГ» в карточке CVE/BDU шлёт сообщение по шаблону
                банка.
                {data.telegram ? (
                  <div className="mt-1 flex flex-wrap gap-2">
                    {data.telegram.hasBotToken ? (
                      <span className={okText}>токен в БД</span>
                    ) : (
                      <span className={warnText}>токен не задан</span>
                    )}
                    {data.telegram.chatId ? (
                      <span>
                        chat: <span className={monoEmph}>{data.telegram.chatId}</span>
                      </span>
                    ) : null}
                    {data.telegram.lastPostAt ? (
                      <span>посл. пост: {new Date(data.telegram.lastPostAt).toLocaleString()}</span>
                    ) : null}
                    {data.telegram.lastPostIdentifier ? <span>({data.telegram.lastPostIdentifier})</span> : null}
                  </div>
                ) : null}
              </>
            }
          >
            <label className={label}>Токен бота</label>
            <input
              type="password"
              autoComplete="off"
              value={tgBotTokenDraft}
              onChange={(e) => setTgBotTokenDraft(e.target.value)}
              placeholder={data.telegram?.hasBotToken ? "Новый токен…" : "123456:ABC…"}
              className={fieldMt}
            />
            <label className={labelMt}>Chat ID</label>
            <input
              value={tgChatId}
              onChange={(e) => setTgChatId(e.target.value)}
              placeholder="-1001234567890"
              className={fieldMono}
            />
            {tgVerify ? (
              <div className={cn(noteBox, noteClass(vc, tgVerify.ok))}>
                Проверка: {tgVerify.ok ? "тестовое сообщение отправлено" : "ошибка"}
                {tgVerify.error ? <div className="mt-1 opacity-90">{tgVerify.error}</div> : null}
              </div>
            ) : null}
            <div className="mt-3 flex flex-wrap gap-2">
              <button
                type="button"
                disabled={
                  verifyTgMut.isPending ||
                  (!tgBotTokenDraft.trim() && !data.telegram?.hasBotToken) ||
                  !tgChatId.trim()
                }
                onClick={() => void verifyTgMut.mutate()}
                className={ghostPlain}
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
                className={primaryPlain}
              >
                {saveTgMut.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Save className="h-3.5 w-3.5" />}
                Сохранить
              </button>
            </div>
          </SettingsBlock>

          <SettingsBlock
            appearance={appearance}
            status={mpvmTone(data.mpvm)}
            title="MaxPatrol VM"
            description={
              <>
                URL консоли MP VM (HTTPS, порт 443), логин учётки и API-токен (Bearer). Синхронизация забирает активы,
                установленное ПО/пакеты, версии и уязвимости через <span className="font-mono">assets_grid</span>.
                {data.mpvm ? (
                  <div className="mt-1 flex flex-wrap gap-2">
                    <span>
                      в системе:{" "}
                      <span className={emph}>{data.mpvm.assetCount.toLocaleString()}</span> активов
                    </span>
                    <span>
                      <span className={emph}>{data.mpvm.softwareCount.toLocaleString()}</span> ПО/пакетов
                    </span>
                    <span>
                      <span className={emph}>{data.mpvm.vulnerabilityCount.toLocaleString()}</span>{" "}
                      уязвимостей
                    </span>
                    {data.mpvm.hasApiToken ? (
                      <span className={okText}>токен в БД</span>
                    ) : (
                      <span className={warnText}>токен не задан</span>
                    )}
                    {data.mpvm.lastSyncAt ? (
                      <span>посл. sync: {new Date(data.mpvm.lastSyncAt).toLocaleString()}</span>
                    ) : null}
                    {typeof data.mpvm.lastSyncFetched === "number" ? (
                      <span>({data.mpvm.lastSyncFetched} шт.)</span>
                    ) : null}
                  </div>
                ) : null}
                {data.mpvm?.lastSyncError ? (
                  <div className={cn("mt-1", dangerText)}>{data.mpvm.lastSyncError}</div>
                ) : null}
              </>
            }
          >
            <label className={label}>URL MP VM</label>
            <input
              value={mpvmBaseUrl}
              onChange={(e) => setMpvmBaseUrl(e.target.value)}
              placeholder="https://mpvm.company.local"
              className={fieldMt}
            />
            <label className={labelMt}>Логин (учётная запись)</label>
            <input
              value={mpvmUsername}
              onChange={(e) => setMpvmUsername(e.target.value)}
              placeholder="admin"
              className={fieldMt}
            />
            <label className={labelMt}>API-токен</label>
            <input
              type="password"
              autoComplete="off"
              value={mpvmTokenDraft}
              onChange={(e) => setMpvmTokenDraft(e.target.value)}
              placeholder={
                data.mpvm?.hasApiToken ? "Новый токен (оставьте пустым — не менять)…" : "Bearer / API token…"
              }
              className={fieldMt}
            />
            <label className={labelMt}>PDQL (активы + ПО/пакеты + уязвимости)</label>
            <textarea
              value={mpvmPdql}
              onChange={(e) => setMpvmPdql(e.target.value)}
              rows={3}
              className={area}
            />
            <label className={vc ? "mt-2 flex items-center gap-2 text-[12px] text-[var(--vc-text)]" : "mt-2 flex items-center gap-2 text-[11px] text-fg/75"}>
              <input
                type="checkbox"
                checked={mpvmTlsInsecure}
                onChange={(e) => setMpvmTlsInsecure(e.target.checked)}
              />
              Не проверять TLS (самоподписанный сертификат)
            </label>
            {mpvmVerify ? (
              <div className={cn(noteBox, noteClass(vc, mpvmVerify.ok))}>
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
                className={ghostPlain}
              >
                {verifyMpvmMut.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : null}
                Проверить подключение
              </button>
              <button
                type="button"
                disabled={saveMpvmMut.isPending || !mpvmBaseUrl.trim()}
                onClick={() => void saveMpvmMut.mutateAsync()}
                className={primaryPlain}
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
                className={syncBtn}
              >
                {syncMpvmMut.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : null}
                Синхронизировать inventory
              </button>
            </div>
          </SettingsBlock>

          <SettingsBlock
            appearance={appearance}
            status="neutral"
            title="БДУ ФСТЭК (vulxml)"
            description={
              <>
                Источник по умолчанию:{" "}
                <span className={vc ? "font-mono text-[11px] text-[var(--vc-text)]" : "font-mono text-[10px] text-fg/80"}>
                  https://bdu.fstec.ru/files/documents/vulxml.zip
                </span>
                . Override: <span className="font-mono">BDU_XML_URL</span>, зеркало:{" "}
                <span className="font-mono">BDU_ALLOW_MIRROR_FALLBACK=true</span>.
                <div className="mt-1">Статус БДУ ingest — в «Здоровье системы».</div>
              </>
            }
          >
            <p className={vc ? "text-[12px] text-[var(--vc-muted)]" : "text-[11px] text-muted"}>
              Отдельный ключ в UI не требуется — достаточно доступности источника и ingest.
            </p>
          </SettingsBlock>

          <details
            className={
              vc
                ? "rounded-xl border border-dashed border-[var(--vc-border)] bg-[var(--vc-inset)] px-3 py-2.5 text-[12px] leading-5 text-[var(--vc-muted)]"
                : "rounded-xl border border-dashed border-slate-300 bg-slate-50/60 px-4 py-3 text-[11px] leading-relaxed text-muted open:pb-4 dark:border-border dark:bg-white/[0.03]"
            }
          >
            <summary className={vc ? "cursor-pointer select-none text-[13px] font-semibold text-[var(--vc-text)]" : "cursor-pointer select-none font-medium text-fg/85"}>
              Справка по развёртыванию
            </summary>
            <ul className="mt-2 list-inside list-disc space-y-1">
              <li>
                <span className={vc ? "text-[var(--vc-text)]" : "text-fg/80"}>Postgres + Redis + RabbitMQ</span> —{" "}
                <span className="font-mono">infra/docker-compose.yml</span>, переменная{" "}
                <span className="font-mono">DATABASE_URL</span> в .env.
              </li>
              <li>
                <span className={vc ? "text-[var(--vc-text)]" : "text-fg/80"}>Ключ NVD</span> — лучше здесь (БД), не в .env:{" "}
                <a
                  className={vc ? "text-[var(--vc-link)] hover:underline" : "text-accent hover:underline"}
                  href="https://nvd.nist.gov/developers/request-an-api-key"
                  target="_blank"
                  rel="noreferrer"
                >
                  запрос ключа на nist.gov
                </a>
                . Неверный ключ даёт HTTP 404 на все запросы.
              </li>
              <li>
                <span className={vc ? "text-[var(--vc-text)]" : "text-fg/80"}>Дайджест</span> — ключ DeepSeek в «Текст и LLM». Он нужен ежемесячному дайджесту и кнопке AI на одной карточке. Массовый разбор каталога он не включает.
              </li>
              <li>
                <span className={vc ? "text-[var(--vc-text)]" : "text-fg/80"}>Ingest</span> — <span className="font-mono">apps/ingest</span>, интервал{" "}
                <span className="font-mono">NVD_POLL_INTERVAL_MS</span>, пауза страниц{" "}
                <span className="font-mono">NVD_PAGE_SLEEP_MS=6500</span> с ключом.
              </li>
            </ul>
          </details>
        </div>
      ) : null}

      {showTextEngine ? (
        <div className={vc ? "space-y-3" : "space-y-4"}>
          <SettingsBlock
            appearance={appearance}
            status={data.digestLlm?.hasApiKey ? "configured" : "missing"}
            title="Дайджест уязвимостей"
            description="Ключ для ежемесячного дайджеста и кнопки AI на одной карточке CVE. Сохранение ключа не запускает обсчёт каталога, скоринг и очередь разбора."
          >
            <div className={cn("mb-3", hint)}>
              Endpoint <span className="font-mono">{DEEPSEEK_ENDPOINT}</span>, модель{" "}
              <span className="font-mono">{DEEPSEEK_MODEL}</span>. Ключ после сохранения в форму не возвращается.
              Без ключа PDF всё равно скачивается, а строка рассказа честно говорит, что его нет.
            </div>
            <div className="mb-3 flex flex-wrap justify-end">
              <button
                type="button"
                onClick={() => {
                  setDigestEndpoint(DEEPSEEK_ENDPOINT);
                  setDigestModel(DEEPSEEK_MODEL);
                }}
                className={ghostStrong}
              >
                Подставить DeepSeek
              </button>
            </div>
            <label className={label}>Endpoint</label>
            <input
              value={digestEndpoint}
              onChange={(e) => setDigestEndpoint(e.target.value)}
              placeholder={DEEPSEEK_ENDPOINT}
              className={fieldMono}
              autoComplete="off"
            />
            <label className={cn(label, "mt-3")}>Модель</label>
            <input
              value={digestModel}
              onChange={(e) => setDigestModel(e.target.value)}
              placeholder={DEEPSEEK_MODEL}
              className={fieldMono}
              autoComplete="off"
            />
            <label className={cn(label, "mt-3")}>API key DeepSeek</label>
            <input
              type="password"
              autoComplete="new-password"
              autoCorrect="off"
              spellCheck={false}
              data-lpignore="true"
              value={digestKeyDraft}
              placeholder={
                digestClearKey
                  ? "Ключ будет удалён при сохранении"
                  : data.digestLlm?.hasApiKey
                    ? "•••• ключ уже есть — оставьте пустым, чтобы не менять"
                    : "Ключ для дайджеста и кнопки AI"
              }
              onChange={(e) => {
                setDigestKeyDraft(e.target.value);
                setDigestClearKey(false);
              }}
              className={fieldMono}
            />
            {data.digestLlm?.hasApiKey ? (
              <button
                type="button"
                className={cn("mt-1 text-[10px] hover:underline", dangerText)}
                onClick={() => {
                  setDigestClearKey(true);
                  setDigestKeyDraft("");
                }}
              >
                Удалить ключ дайджеста
              </button>
            ) : null}
            <div className="mt-3">
              <button
                type="button"
                disabled={saveDigestMut.isPending}
                onClick={() => void saveDigestMut.mutateAsync()}
                className={vc ? controlClass(true, "primary") : "inline-flex items-center gap-2 rounded-lg border border-accent/30 bg-accent/10 px-4 py-2 text-[12px] font-medium text-fg/90 hover:bg-accent/15 disabled:opacity-50"}
              >
                {saveDigestMut.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
                Сохранить ключ дайджеста
              </button>
            </div>
          </SettingsBlock>

          <SettingsBlock
            appearance={appearance}
            title="Text engine"
            description="Baseline и translate работают как раньше. Режим llm включает разбор карточек CVE. Ключ дайджеста выше этот режим не переключает и массовую обработку не запускает."
          >
            <label className={label}>Режим</label>
            <select
              value={textEngine}
              onChange={(e) => setTextEngine(e.target.value as "baseline" | "translate" | "llm")}
              className={fieldMt}
            >
              <option value="baseline">baseline — NVD/BDU/CWE templates</option>
              <option value="translate">translate — baseline + LibreTranslate</option>
              <option value="llm">llm — разбор карточек CVE, не дайджест</option>
            </select>
            <label className={cn(label, "mt-3")}>LibreTranslate URL</label>
            <input
              value={translateEndpoint}
              onChange={(e) => setTranslateEndpoint(e.target.value)}
              placeholder="http://libretranslate:5000"
              className={fieldMono}
            />
            <div className={cn("mt-2", hint)}>
              Можно указать base URL или полный путь <span className="font-mono">/translate</span>. Если URL пустой или
              сервис недоступен, режим translate отдаёт baseline.
            </div>
          </SettingsBlock>

          <SettingsBlock
            appearance={appearance}
            title="Профили LLM"
            description={
              <>
                Fallback из .env: <span className="font-mono">{data.llm.envFallback.endpoint}</span> · модель{" "}
                <span className="font-mono">{data.llm.envFallback.model}</span>
                {data.llm.envFallback.hasApiKey ? " · ключ в .env есть" : ""}
              </>
            }
          >
            <div className={cn("mb-3", hint)}>
              Ключ DeepSeek для дайджеста сюда не вставляйте: профиль ниже относится к режиму llm и к карточкам CVE.
            </div>
            <div className="mb-3 flex flex-wrap justify-end gap-2">
              <button
                type="button"
                onClick={() => {
                  setProfiles((prev) => [...(prev ?? list), emptyProfile()]);
                }}
                className={vc ? controlClass(true, "primary") : "inline-flex items-center gap-2 rounded-lg border border-accent/30 bg-accent/10 px-3 py-1.5 text-[11px] text-fg/90 hover:bg-accent/15"}
              >
                <Plus className="h-3.5 w-3.5" />
                Профиль
              </button>
            </div>

            <div className="space-y-3">
              <div className={profileCard}>
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <label className={cn("flex items-center gap-2", hint)}>
                    <input
                      type="radio"
                      name="llm-active"
                      checked={!merged?.activeId}
                      onChange={() => setActiveId(null)}
                    />
                    Использовать Fallback (.env)
                  </label>
                  <span className="text-[10px] text-muted">рекомендуется для локального Ollama</span>
                </div>
                <div className="mt-2 text-[10px] text-muted">
                  Endpoint: <span className="font-mono text-fg/80">{data.llm.envFallback.endpoint}</span> · model:{" "}
                  <span className="font-mono text-fg/80">{data.llm.envFallback.model}</span>
                </div>
              </div>

              {list.map((p, idx) => (
                <div
                  key={p.id}
                  className={profileCard}
                >
                  <div className="flex flex-wrap items-start justify-between gap-2">
                    <label className={cn("flex items-center gap-2", hint)}>
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
                      className={cn("text-[11px] hover:underline", dangerText)}
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
                        className={fieldMt}
                      />
                    </div>
                    <div>
                      <div className="text-[10px] text-muted">Модель</div>
                      <input
                        value={p.model}
                        placeholder="qwen2.5:7b"
                        onChange={(e) => {
                          const v = e.target.value;
                          setProfiles((prev) => {
                            const base = prev ?? list;
                            const cp = [...base];
                            cp[idx] = { ...cp[idx]!, model: v };
                            return cp;
                          });
                        }}
                        className={fieldMono}
                      />
                    </div>
                    <div className="md:col-span-2">
                      <div className="text-[10px] text-muted">Endpoint (OpenAI‑compatible)</div>
                      <input
                        value={p.endpoint}
                        placeholder="http://127.0.0.1:11434/v1/chat/completions"
                        onChange={(e) => {
                          const v = e.target.value;
                          setProfiles((prev) => {
                            const base = prev ?? list;
                            const cp = [...base];
                            cp[idx] = { ...cp[idx]!, endpoint: v };
                            return cp;
                          });
                        }}
                        className={fieldMono}
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
                        className={fieldMt}
                      />
                    </div>
                    <div>
                      <div className="text-[10px] text-muted">API key (опционально)</div>
                      <input
                        type="text"
                        autoComplete="off"
                        autoCorrect="off"
                        spellCheck={false}
                        inputMode="text"
                        data-lpignore="true"
                        value={p.apiKeyDraft}
                        placeholder={
                          p.hasApiKey ? "•••• (в БД есть — оставь пустым чтобы не менять)" : "ключ профиля или пусто для Ollama"
                        }
                        onChange={(e) => {
                          const v = e.target.value;
                          setProfiles((prev) => {
                            const base = prev ?? list;
                            const cp = [...base];
                            cp[idx] = { ...cp[idx]!, apiKeyDraft: v, clearApiKey: false };
                            return cp;
                          });
                        }}
                        className={fieldMono}
                      />
                      <div className="mt-1 text-[10px] text-muted">
                        Если ключ уже есть в БД — оставь поле пустым, чтобы{" "}
                        <span className="text-fg/80">не менять</span>. Новый ключ{" "}
                        <span className="text-fg/80">заменяет</span> секрет этого профиля. Для дайджеста это поле не используется.
                      </div>
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

            <div className={cn("mt-4 flex flex-wrap gap-2 border-t pt-4", vc ? "border-[var(--vc-border)]" : "border-slate-200 dark:border-border")}>
              <button
                type="button"
                disabled={saveMut.isPending}
                onClick={() => void saveMut.mutateAsync()}
                className={vc ? controlClass(true, "primary") : "inline-flex items-center gap-2 rounded-lg border border-accent/30 bg-accent/10 px-4 py-2 text-[12px] font-medium text-fg/90 hover:bg-accent/15 disabled:opacity-50"}
              >
                {saveMut.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
                Сохранить text engine / LLM
              </button>
              <button
                type="button"
                onClick={() => {
                  void q.refetch();
                  setProfiles(null);
                  setMsg(null);
                  setErr(null);
                }}
                className={vc ? controlClass(true, "ghost") : "rounded-lg border border-slate-200 bg-white px-4 py-2 text-[12px] text-fg/85 hover:bg-slate-50 dark:border-border dark:bg-black/25"}
              >
                Сбросить форму
              </button>
            </div>
          </SettingsBlock>
        </div>
      ) : null}
    </div>
  );
}
