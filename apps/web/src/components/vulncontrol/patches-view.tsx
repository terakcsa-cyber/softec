"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { ExternalLink, Loader2, RefreshCw, X } from "lucide-react";
import { apiFetch } from "@/lib/api-fetch";
import { formatInt } from "@/lib/vulncontrol/live";
import { Donut } from "./charts";
import { vulnerabilityPath } from "./vc-context";
import { VcSelect } from "./vc-pop";

const PAGE = 25;

const ADVISORY_NAMES: Record<string, string> = {
  cbr_ru: "Банк России",
  cbr_press_ru: "Банк России · пресс",
  safe_surf_ru: "Safe-Surf",
  opennet_ru: "OpenNET",
  xakep_ru: "Хакер",
  debian: "Debian",
  ubuntu: "Ubuntu",
  suse: "SUSE",
  redhat: "Red Hat",
  oracle: "Oracle",
  microsoft: "Microsoft MSRC",
  aws: "AWS",
  google_cloud: "Google Cloud",
  cisa_alerts: "CISA Alerts",
  cisa_activity: "CISA Current Activity",
  cisa_ics: "CISA ICS",
  kubernetes: "Kubernetes",
  cloudflare: "Cloudflare",
  unit42: "Unit 42",
  sentinelone: "SentinelOne"
};

const SOURCE_COLORS = ["#2f6bff", "#a78bfa", "#22d3ee", "#fb7185", "#f5c451", "#3dd68c", "#ff8a3d", "#7eb6ff", "#f472b6", "#34d399"];

type Kind = "telegram" | "advisory";
type KindFilter = "all" | Kind;
type CveFilter = "all" | "yes" | "no";

type PatchEntry = {
  id: string;
  kind: Kind;
  sourceKey: string;
  sourceLabel: string;
  sourceMeta: string;
  publishedAt: string | null;
  title: string;
  text: string;
  link: string;
  cveIds: string[];
  feedUrl?: string;
};

type TelegramItem = {
  id: string;
  title: string;
  link: string;
  pubDate: string | null;
  descriptionText: string;
  channel: { slug: string; title: string };
  cveIds: string[];
};

type TelegramFeed = {
  items: TelegramItem[];
  source?: { fetchedAt?: string; channels?: Array<{ slug: string; title: string }> };
  errors?: Array<{ url: string; error: string }>;
};

type AdvisoryItem = {
  id: string;
  feedUrl: string;
  vendorSlug: string;
  title: string;
  link: string;
  summary: string | null;
  publishedAt: string | null;
  cveIds: string[];
  fetchedAt: string;
};

type AdvisoryFeed = {
  items: AdvisoryItem[];
  total: number;
  recentDays?: number;
};

function sourceColor(key: string) {
  let hash = 0;
  for (const char of key) hash = (hash * 31 + char.charCodeAt(0)) >>> 0;
  return SOURCE_COLORS[hash % SOURCE_COLORS.length] ?? "#2f6bff";
}

function hostOf(url: string) {
  try {
    return new URL(url).host;
  } catch {
    return "";
  }
}

function plainText(value: string | null | undefined) {
  if (!value) return "";
  return value
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/p>/gi, "\n")
    .replace(/<[^>]+>/g, "")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;|&apos;/g, "'")
    .replace(/&#(\d+);/g, (_, n: string) => {
      const code = Number(n);
      return code > 0 && code < 0x110000 ? String.fromCodePoint(code) : "";
    })
    .replace(/&#x([0-9a-f]+);/gi, (_, n: string) => {
      const code = Number.parseInt(n, 16);
      return code > 0 && code < 0x110000 ? String.fromCodePoint(code) : "";
    })
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

function formatWhen(iso: string | null) {
  if (!iso) return "дата не указана";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString("ru-RU", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit"
  });
}

function timeValue(iso: string | null) {
  if (!iso) return Number.NEGATIVE_INFINITY;
  const value = Date.parse(iso);
  return Number.isNaN(value) ? Number.NEGATIVE_INFINITY : value;
}

function errorText(body: unknown, status: number) {
  if (!body || typeof body !== "object") return `HTTP ${status}`;
  const rec = body as { error?: unknown; message?: unknown };
  if (typeof rec.error === "string" && rec.error.trim()) return rec.error;
  if (typeof rec.message === "string" && rec.message.trim()) return rec.message;
  if (Array.isArray(rec.message)) return rec.message.map(String).join("; ");
  return `HTTP ${status}`;
}

async function readJson<T>(url: string): Promise<T> {
  const res = await apiFetch(url, { cache: "no-store" });
  let body: unknown = null;
  try {
    body = await res.json();
  } catch {
    body = null;
  }
  if (!res.ok) throw new Error(errorText(body, res.status));
  if (!body || typeof body !== "object") throw new Error("Пустой ответ");
  return body as T;
}

function advisoryLabel(slug: string) {
  return ADVISORY_NAMES[slug] ?? slug;
}

export function PatchesView() {
  const [kind, setKind] = useState<KindFilter>("all");
  const [cve, setCve] = useState<CveFilter>("all");
  const [source, setSource] = useState("all");
  const [q, setQ] = useState("");
  const [page, setPage] = useState(0);
  const [openId, setOpenId] = useState<string | null>(null);

  const telegram = useQuery({
    queryKey: ["vc-patches", "telegram"],
    queryFn: () => readJson<TelegramFeed>("/api/patch/feed"),
    staleTime: 60_000,
    retry: 0
  });
  const advisory = useQuery({
    queryKey: ["vc-patches", "advisory"],
    queryFn: () => readJson<AdvisoryFeed>("/api/vendor-advisories?limit=100"),
    staleTime: 60_000,
    retry: 0
  });

  const entries = useMemo(() => {
    const rows: PatchEntry[] = [];
    for (const item of telegram.data?.items ?? []) {
      const slug = item.channel?.slug ?? "telegram";
      rows.push({
        id: `tg:${item.id}`,
        kind: "telegram",
        sourceKey: `tg:${slug}`,
        sourceLabel: item.channel?.title || `@${slug}`,
        sourceMeta: `@${slug}`,
        publishedAt: item.pubDate,
        title: plainText(item.title),
        text: plainText(item.descriptionText),
        link: item.link,
        cveIds: item.cveIds ?? []
      });
    }
    for (const item of advisory.data?.items ?? []) {
      const slug = item.vendorSlug || "advisory";
      rows.push({
        id: `adv:${item.id}`,
        kind: "advisory",
        sourceKey: `adv:${slug}`,
        sourceLabel: advisoryLabel(slug),
        sourceMeta: hostOf(item.feedUrl) || slug,
        publishedAt: item.publishedAt,
        title: plainText(item.title),
        text: plainText(item.summary),
        link: item.link,
        cveIds: item.cveIds ?? [],
        feedUrl: item.feedUrl
      });
    }
    rows.sort((a, b) => timeValue(b.publishedAt) - timeValue(a.publishedAt));
    return rows;
  }, [advisory.data?.items, telegram.data?.items]);

  const sources = useMemo(() => {
    const map = new Map<string, { key: string; label: string; meta: string; kind: Kind; count: number }>();
    for (const row of entries) {
      const current = map.get(row.sourceKey);
      if (current) current.count += 1;
      else map.set(row.sourceKey, { key: row.sourceKey, label: row.sourceLabel, meta: row.sourceMeta, kind: row.kind, count: 1 });
    }
    return [...map.values()].sort((a, b) => b.count - a.count || a.label.localeCompare(b.label, "ru"));
  }, [entries]);

  const visibleSources = useMemo(
    () => sources.filter((item) => kind === "all" || item.kind === kind),
    [kind, sources]
  );

  useEffect(() => {
    if (source !== "all" && !visibleSources.some((item) => item.key === source)) setSource("all");
  }, [source, visibleSources]);

  const filterKey = `${kind}|${cve}|${source}|${q}`;
  useEffect(() => {
    setPage(0);
  }, [filterKey]);

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return entries.filter((row) => {
      if (kind !== "all" && row.kind !== kind) return false;
      if (source !== "all" && row.sourceKey !== source) return false;
      if (cve === "yes" && row.cveIds.length === 0) return false;
      if (cve === "no" && row.cveIds.length > 0) return false;
      if (!needle) return true;
      const hay = `${row.title}\n${row.text}\n${row.sourceLabel}\n${row.sourceMeta}\n${row.cveIds.join(" ")}`.toLowerCase();
      return hay.includes(needle);
    });
  }, [cve, entries, kind, q, source]);

  const withCve = entries.filter((row) => row.cveIds.length > 0).length;
  const telegramCount = entries.filter((row) => row.kind === "telegram").length;
  const advisoryCount = entries.filter((row) => row.kind === "advisory").length;
  const fstecKey = "tg:fstecru";
  const fstecCount = entries.filter((row) => row.sourceKey === fstecKey).length;
  const newest = entries.reduce<string | null>((best, row) => (timeValue(row.publishedAt) > timeValue(best) ? row.publishedAt : best), null);
  const pageRows = filtered.slice(page * PAGE, page * PAGE + PAGE);
  const from = pageRows.length ? page * PAGE + 1 : 0;
  const to = page * PAGE + pageRows.length;
  const filtersOn = kind !== "all" || cve !== "all" || source !== "all" || q.trim().length > 0;
  const open = entries.find((row) => row.id === openId) ?? null;
  const telegramPending = telegram.isPending;
  const advisoryPending = advisory.isPending;
  const waiting = entries.length === 0 && (telegramPending || advisoryPending) && !telegram.isError && !advisory.isError;
  const advisoryWindow = advisory.data?.recentDays ?? 7;
  const advisoryLoaded = advisory.data?.items.length ?? 0;
  const advisoryTotal = advisory.data?.total;

  useEffect(() => {
    if (!openId) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpenId(null);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [openId]);

  const refresh = () => {
    void telegram.refetch();
    void advisory.refetch();
  };

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-[20px] font-semibold tracking-tight">Патчи</h1>
          <p className="max-w-3xl text-[12px] leading-5 text-[var(--vc-muted)]">
            Свежие записи из публичных Telegram-каналов и vendor advisory. В строке — источник, время, текст и CVE, если они есть в записи. Пустые поля не заполняются.
          </p>
        </div>
        <button
          type="button"
          onClick={refresh}
          className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-[var(--vc-border)] bg-[var(--vc-surface)] px-2.5 text-[12px] text-[var(--vc-text)]"
        >
          {telegram.isFetching || advisory.isFetching ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
          Обновить
        </button>
      </div>

      <div className="grid grid-cols-2 gap-3 xl:grid-cols-4">
        <Kpi label="В выборке" value={entries.length} hint="Загруженные записи" color="var(--vc-primary)" />
        <Kpi label="С CVE" value={withCve} hint="В тексте есть CVE" color="var(--vc-success, #3dd68c)" />
        <Kpi label="Без CVE" value={Math.max(0, entries.length - withCve)} hint="CVE в записи нет" color="var(--vc-muted)" />
        <Kpi label="Самая свежая" value={newest ? formatWhen(newest) : "—"} hint="По дате публикации" color="var(--vc-text)" compact />
      </div>

      <div className="grid gap-3 xl:grid-cols-[0.9fr_1.1fr]">
        <section className="rounded-xl border border-[var(--vc-border)] bg-[var(--vc-surface)] p-3">
          <h2 className="mb-2 text-[13px] font-semibold">CVE в загруженных записях</h2>
          {entries.length ? (
            <Donut
              slices={[
                { key: "yes", label: "Есть CVE", value: withCve, pct: 0 },
                { key: "no", label: "Без CVE", value: entries.length - withCve, pct: 0 }
              ]}
              colors={["#3dd68c", "#8ea0b8"]}
              center={formatInt(entries.length)}
              sub="записей"
              onPick={(key) => setCve(key === "yes" ? "yes" : "no")}
            />
          ) : (
            <p className="text-[12px] text-[var(--vc-muted)]">{waiting ? "Жду ответы источников…" : "Нет загруженных записей"}</p>
          )}
        </section>
        <section className="rounded-xl border border-[var(--vc-border)] bg-[var(--vc-surface)] p-3">
          <h2 className="mb-2 text-[13px] font-semibold">Источники в выборке</h2>
          {sources.length ? (
            <div className="flex flex-wrap gap-1.5">
              {sources.map((item) => {
                const on = source === item.key;
                const color = sourceColor(item.key);
                return (
                  <button
                    key={item.key}
                    type="button"
                    onClick={() => {
                      setSource(on ? "all" : item.key);
                      setKind(item.kind);
                    }}
                    className="inline-flex items-center gap-1.5 rounded-full border px-2 py-1 text-[11px]"
                    style={{
                      borderColor: on ? color : "var(--vc-border)",
                      color: "var(--vc-text)",
                      background: on ? "color-mix(in srgb, " + color + " 18%, transparent)" : "transparent"
                    }}
                  >
                    <span className="h-1.5 w-1.5 rounded-full" style={{ background: color }} />
                    <span className="max-w-[180px] truncate">{item.label}</span>
                    <span className="tabular-nums text-[var(--vc-muted)]">{item.count}</span>
                  </button>
                );
              })}
            </div>
          ) : (
            <p className="text-[12px] text-[var(--vc-muted)]">{waiting ? "Источники появятся после загрузки." : "Источников в выборке нет."}</p>
          )}
        </section>
      </div>

      <div className="flex gap-5 overflow-x-auto border-b border-[var(--vc-border)]">
        <Tab label="Все" count={entries.length} color="#2f6bff" on={kind === "all" && source === "all" && cve !== "yes"} onClick={() => { setKind("all"); setSource("all"); setCve("all"); }} />
        <Tab label="Telegram" count={telegramCount} color="#22d3ee" on={kind === "telegram" && source === "all"} onClick={() => { setKind("telegram"); setSource("all"); }} pending={telegramPending} />
        <Tab
          label="ФСТЭК"
          count={fstecCount}
          color="#fb7185"
          on={source === fstecKey}
          onClick={() => {
            setKind("telegram");
            setSource(source === fstecKey ? "all" : fstecKey);
            setCve("all");
          }}
          pending={telegramPending && fstecCount === 0}
        />
        <Tab label="Advisory" count={advisoryCount} color="#a78bfa" on={kind === "advisory" && source === "all"} onClick={() => { setKind("advisory"); setSource("all"); }} pending={advisoryPending} />
        <Tab label="С CVE" count={withCve} color="#3dd68c" on={cve === "yes" && kind === "all" && source === "all"} onClick={() => { setKind("all"); setSource("all"); setCve(cve === "yes" && kind === "all" && source === "all" ? "all" : "yes"); }} />
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <VcSelect
          ariaLabel="Источник"
          value={visibleSources.some((item) => item.key === source) ? source : "all"}
          onChange={setSource}
          options={[["all", "Все источники"], ...visibleSources.map((item) => [item.key, `${item.label} · ${item.meta}`] as [string, string])]}
          className="max-w-[280px] bg-[var(--vc-bg)]"
        />
        <VcSelect
          ariaLabel="Наличие CVE"
          value={cve}
          onChange={(value) => setCve(value as CveFilter)}
          options={[["all", "CVE: все"], ["yes", "Есть CVE"], ["no", "Без CVE"]]}
          className="bg-[var(--vc-bg)]"
        />
        <input
          aria-label="Поиск по патчам"
          value={q}
          onChange={(event) => setQ(event.target.value)}
          placeholder="Заголовок, текст, CVE, источник"
          className="h-8 min-w-[220px] flex-1 rounded-lg border border-[var(--vc-border)] bg-[var(--vc-bg)] px-2.5 text-[12px] text-[var(--vc-text)] outline-none placeholder:text-[var(--vc-muted)]"
        />
        {filtersOn ? (
          <button type="button" className="text-[12px] text-[var(--vc-primary)]" onClick={() => { setKind("all"); setCve("all"); setSource("all"); setQ(""); }}>
            Сбросить фильтры
          </button>
        ) : null}
      </div>

      <p className="text-[11px] leading-5 text-[var(--vc-muted)]">
        Счётчики только по загруженным записям.
        {telegram.data?.source?.fetchedAt ? ` Telegram: ${formatWhen(telegram.data.source.fetchedAt)}.` : telegramPending ? " Telegram ещё загружается — каналы t.me/s отвечают не сразу." : ""}
        {advisory.data ? ` Advisory: окно ${advisoryWindow} сут., загружено ${formatInt(advisoryLoaded)}${advisoryTotal != null && advisoryTotal > advisoryLoaded ? ` из ${formatInt(advisoryTotal)}` : ""}.` : advisoryPending ? " Advisory ещё загружается." : ""}
      </p>

      {telegram.isError ? (
        <Banner
          tone="danger"
          text={`Telegram не загрузился: ${telegram.error instanceof Error ? telegram.error.message : "неизвестная ошибка"}`}
          onRetry={() => void telegram.refetch()}
          busy={telegram.isFetching}
        />
      ) : null}
      {!telegram.isError && telegram.data?.errors?.length ? (
        <Banner
          tone="warn"
          text={`Часть каналов Telegram не ответила (${telegram.data.errors.length}): ${telegram.data.errors.map((item) => item.error).join(" · ")}`}
        />
      ) : null}
      {advisory.isError ? (
        <Banner
          tone="danger"
          text={`Vendor advisory не загрузился: ${advisory.error instanceof Error ? advisory.error.message : "неизвестная ошибка"}`}
          onRetry={() => void advisory.refetch()}
          busy={advisory.isFetching}
        />
      ) : null}

      <section className="overflow-hidden rounded-xl border border-[var(--vc-border)] bg-[var(--vc-surface)]">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--vc-border)] px-3 py-2">
          <p className="text-[12px] text-[var(--vc-muted)]">
            {waiting ? "Загрузка патчей…" : filtered.length ? `${formatInt(from)}–${formatInt(to)} из ${formatInt(filtered.length)}` : "0 записей"}
            {telegram.isFetching && telegram.data ? " · обновляю Telegram…" : ""}
          </p>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[980px] border-separate border-spacing-0 text-left text-[12px]">
            <thead className="text-[10px] uppercase tracking-wide text-[var(--vc-muted)]">
              <tr>
                {["Источник", "Время", "Запись", "CVE", "Фрагмент"].map((label) => (
                  <th key={label} className="bg-[var(--vc-bg)] px-3 py-2.5 font-medium">{label}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {pageRows.map((row) => {
                const selected = row.id === openId;
                const color = sourceColor(row.sourceKey);
                const excerpt = row.text && row.text !== row.title ? row.text : "";
                return (
                  <tr
                    key={row.id}
                    tabIndex={0}
                    aria-label={`${row.sourceLabel}: ${row.title || "запись"}`}
                    onClick={() => setOpenId(row.id)}
                    onKeyDown={(event) => {
                      if (event.key === "Enter" || event.key === " ") {
                        event.preventDefault();
                        setOpenId(row.id);
                      }
                    }}
                    className="cursor-pointer hover:bg-[var(--vc-bg)]"
                    style={selected ? { background: "color-mix(in srgb, var(--vc-primary) 18%, var(--vc-surface))" } : undefined}
                  >
                    <td className="border-b border-[var(--vc-border)] px-3 py-2 align-top">
                      <div className="flex items-center gap-1.5">
                        <span className="h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: color }} />
                        <span className="font-medium">{row.sourceLabel}</span>
                      </div>
                      <div className="mt-0.5 text-[10px] text-[var(--vc-muted)]">{row.kind === "telegram" ? "Telegram" : "Advisory"} · {row.sourceMeta}</div>
                    </td>
                    <td className="whitespace-nowrap border-b border-[var(--vc-border)] px-3 py-2 align-top text-[var(--vc-muted)]">{formatWhen(row.publishedAt)}</td>
                    <td className="max-w-[320px] border-b border-[var(--vc-border)] px-3 py-2 align-top">
                      <button type="button" className="line-clamp-2 text-left font-medium" onClick={() => setOpenId(row.id)}>
                        {row.title || "—"}
                      </button>
                    </td>
                    <td className="border-b border-[var(--vc-border)] px-3 py-2 align-top">
                      <CveChips ids={row.cveIds} limit={3} />
                    </td>
                    <td className="max-w-[280px] border-b border-[var(--vc-border)] px-3 py-2 align-top text-[var(--vc-muted)]">
                      <div className="line-clamp-2">{excerpt || "—"}</div>
                    </td>
                  </tr>
                );
              })}
              {!pageRows.length ? (
                <tr>
                  <td colSpan={5} className="px-3 py-8 text-center text-[12px] text-[var(--vc-muted)]">
                    {waiting ? (
                      <span className="inline-flex items-center gap-2">
                        <Loader2 className="h-4 w-4 animate-spin" />
                        Загружаю ленты. Telegram обычно отвечает дольше advisory.
                      </span>
                    ) : filtersOn ? "Нет записей по этому фильтру." : "Источники ответили, записей нет."}
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
        <div className="flex items-center justify-between border-t border-[var(--vc-border)] px-3 py-2 text-[12px] text-[var(--vc-muted)]">
          <span>{filtered.length ? `${formatInt(from)}–${formatInt(to)} из ${formatInt(filtered.length)}` : "0 записей"}</span>
          <span className="flex gap-3">
            <button type="button" disabled={page === 0} className="disabled:opacity-40" onClick={() => setPage((value) => Math.max(0, value - 1))}>Назад</button>
            <button type="button" disabled={to >= filtered.length} className="disabled:opacity-40" onClick={() => setPage((value) => value + 1)}>Дальше</button>
          </span>
        </div>
      </section>

      {open ? <PatchDrawer row={open} onClose={() => setOpenId(null)} /> : null}
    </div>
  );
}

function Kpi({ label, value, hint, color, compact = false }: { label: string; value: number | string; hint: string; color: string; compact?: boolean }) {
  return (
    <div className="rounded-xl border border-[var(--vc-border)] bg-[var(--vc-surface)] px-3 py-3">
      <div className="text-[11px] text-[var(--vc-muted)]">{label}</div>
      <div className={`mt-1 font-semibold tabular-nums ${compact ? "text-[13px] leading-5" : "text-[22px]"}`} style={{ color }}>
        {typeof value === "number" ? formatInt(value) : value}
      </div>
      <div className="mt-1 text-[10px] text-[var(--vc-muted)]">{hint}</div>
    </div>
  );
}

function Tab({ label, count, color, on, onClick, pending = false }: { label: string; count: number; color: string; on: boolean; onClick: () => void; pending?: boolean }) {
  return (
    <button type="button" onClick={onClick} className={`relative inline-flex shrink-0 items-center gap-2 pb-2.5 text-[13px] ${on ? "font-medium text-[var(--vc-text)]" : "text-[var(--vc-muted)]"}`}>
      {label}
      <span className="rounded-md px-1.5 py-0.5 text-[11px] font-semibold tabular-nums text-white" style={{ background: color }}>
        {pending && count === 0 ? "…" : formatInt(count)}
      </span>
      {on ? <span className="absolute inset-x-0 bottom-0 h-0.5 rounded-full" style={{ background: color }} /> : null}
    </button>
  );
}

function Banner({ tone, text, onRetry, busy = false }: { tone: "danger" | "warn"; text: string; onRetry?: () => void; busy?: boolean }) {
  const color = tone === "danger" ? "var(--vc-critical, #ff4d5e)" : "var(--vc-medium, #f5c451)";
  return (
    <div className="flex flex-wrap items-start justify-between gap-2 rounded-lg border px-3 py-2 text-[12px]" style={{ borderColor: color, color: "var(--vc-text)" }}>
      <p className="min-w-0 flex-1 leading-5">{text}</p>
      {onRetry ? (
        <button type="button" onClick={onRetry} disabled={busy} className="shrink-0 rounded-md border border-[var(--vc-border)] px-2 py-1 text-[12px] disabled:opacity-40">
          {busy ? "Повтор…" : "Повторить"}
        </button>
      ) : null}
    </div>
  );
}

function CveChips({ ids, limit }: { ids: string[]; limit?: number }) {
  if (!ids.length) return <span className="text-[var(--vc-muted)]">—</span>;
  const shown = limit ? ids.slice(0, limit) : ids;
  const rest = ids.length - shown.length;
  return (
    <div className="flex flex-wrap gap-1">
      {shown.map((id) => (
        <Link
          key={id}
          href={vulnerabilityPath(id)}
          onClick={(event) => event.stopPropagation()}
          className="rounded-md border border-[var(--vc-border)] px-1.5 py-0.5 font-mono text-[11px] text-[var(--vc-primary)] hover:underline"
        >
          {id}
        </Link>
      ))}
      {rest > 0 ? <span className="text-[11px] text-[var(--vc-muted)]">+{rest}</span> : null}
    </div>
  );
}

function PatchDrawer({ row, onClose }: { row: PatchEntry; onClose: () => void }) {
  const body = row.text || "";
  const showTitle = row.title && row.title !== body;
  return (
    <div className="fixed inset-0 z-40">
      <button type="button" aria-label="Закрыть запись" className="absolute inset-0 bg-black/45" onClick={onClose} />
      <aside className="absolute inset-y-0 right-0 flex w-full flex-col border-l border-[var(--vc-border)] bg-[var(--vc-surface)] shadow-2xl sm:w-[480px]">
        <div className="flex items-start justify-between gap-3 border-b border-[var(--vc-border)] px-4 py-3">
          <div className="min-w-0">
            <div className="text-[10px] uppercase tracking-wide text-[var(--vc-muted)]">{row.kind === "telegram" ? "Telegram" : "Vendor advisory"}</div>
            <div className="mt-1 text-[14px] font-semibold">{row.sourceLabel}</div>
            <div className="text-[12px] text-[var(--vc-muted)]">{row.sourceMeta} · {formatWhen(row.publishedAt)}</div>
          </div>
          <button type="button" onClick={onClose} className="rounded p-1 text-[var(--vc-muted)]" aria-label="Закрыть">
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="min-h-0 flex-1 space-y-4 overflow-y-auto px-4 py-3">
          {showTitle ? <h2 className="text-[15px] font-semibold leading-snug">{row.title}</h2> : null}
          {body ? (
            <p className="whitespace-pre-wrap text-[13px] leading-6">{body}</p>
          ) : (
            <p className="text-[12px] text-[var(--vc-muted)]">Текста в записи нет.</p>
          )}
          <div>
            <div className="mb-1.5 text-[10px] font-semibold uppercase tracking-wide text-[var(--vc-muted)]">CVE</div>
            <CveChips ids={row.cveIds} />
          </div>
          {row.feedUrl ? <p className="break-all text-[11px] text-[var(--vc-muted)]">Лента: {row.feedUrl}</p> : null}
          {row.link ? (
            <a href={row.link} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1.5 rounded-lg bg-[var(--vc-primary)] px-3 py-1.5 text-[12px] font-medium text-white">
              {row.kind === "telegram" ? "Открыть в Telegram" : "Открыть advisory"}
              <ExternalLink className="h-3.5 w-3.5" />
            </a>
          ) : (
            <p className="text-[12px] text-[var(--vc-muted)]">Ссылки в записи нет.</p>
          )}
          {row.link ? <p className="break-all text-[11px] text-[var(--vc-muted)]">{row.link}</p> : null}
        </div>
      </aside>
    </div>
  );
}
