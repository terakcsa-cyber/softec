"use client";

import { useAuth } from "@/contexts/auth-context";
import { useEffect, useRef, useState } from "react";
import { ExternalLink, X } from "lucide-react";
import { apiFetch } from "@/lib/api-fetch";
import { dropFstecNotices, ingestNotices, markNoticesReady, markNoticesSeeded, noticesSeeded, type VcNotice } from "@/lib/vc-notices";

type Toast = {
  title: string;
  body?: string;
  href?: string;
};

function safeSet(key: string, value: string) {
  try {
    localStorage.setItem(key, value);
  } catch {
    // ignore
  }
}

type FeedItem = { id?: string; title?: string; link?: string; pubDate?: string | null; descriptionText?: string; channel?: { title?: string; slug?: string } };

function noticeBody(title: string, text?: string) {
  const body = (text ?? "").replace(/\s+/g, " ").trim();
  const head = title.replace(/\s+/g, " ").replace(/[…\s]+$/, "").trim();
  const same = head.slice(0, 60);
  if (!body || !same || body.startsWith(same) || head.startsWith(body.slice(0, 60))) return undefined;
  return body.length > 180 ? `${body.slice(0, 177)}…` : body;
}
type CveItem = {
  cve_id?: string;
  published_at?: string | null;
  short_ru?: string | null;
  short_description?: string | null;
  vp_vendor?: string | null;
  vp_product?: string | null;
  risk_score?: number | null;
  exploit_known?: boolean;
};

function mapPatch(payload: { items?: FeedItem[] } | null): Array<Omit<VcNotice, "read">> {
  return (payload?.items ?? []).slice(0, 8).flatMap((item) => {
    if (!item.id || !item.title || !item.link) return [];
    const slug = (item.channel?.slug || "").toLowerCase();
    // Каналы ФСТЭК в тосты/колокольчик не пушим.
    if (slug === "fstecru" || slug === "bdufstecru" || /фстэк|fstec/i.test(item.channel?.title || "")) return [];
    return [{
      id: `news:${item.id}`,
      kind: "news" as const,
      source: item.channel?.title || "Лента ИБ",
      title: item.title,
      body: noticeBody(item.title, item.descriptionText),
      href: item.link,
      at: item.pubDate || new Date().toISOString()
    }];
  });
}

function mapCves(payload: { items?: CveItem[] } | null): Array<Omit<VcNotice, "read">> {
  return (payload?.items ?? []).flatMap((item) => {
    if (!item.cve_id) return [];
    const where = [item.vp_product, item.vp_vendor].filter(Boolean).join(" · ");
    const summary = (item.short_ru || item.short_description || "").trim();
    const bits = [where || null, item.risk_score != null ? `риск ${Math.round(item.risk_score)}` : null, item.exploit_known ? "KEV" : null].filter(Boolean);
    return [{
      id: `cve:${item.cve_id}`,
      kind: "cve" as const,
      source: "Новая CVE",
      title: item.cve_id,
      body: summary || bits.join(" · ") || undefined,
      href: `/vulnerabilities/${encodeURIComponent(item.cve_id)}`,
      at: item.published_at || new Date().toISOString()
    }];
  });
}

async function fetchJson<T>(url: string): Promise<T | null> {
  try {
    const res = await apiFetch(url, { cache: "no-store" });
    if (!res.ok) return null;
    return (await res.json()) as T;
  } catch {
    return null;
  }
}

export function LiveFeedNotifier() {
  const { user, loading } = useAuth();
  const [toast, setToast] = useState<Toast | null>(null);
  const timer = useRef<number | null>(null);

  const enabled = Boolean(user) && !loading;

  useEffect(() => {
    if (!enabled) return;
    dropFstecNotices();
    safeSet("vip:live:global", "1");
    return () => {
      try {
        localStorage.removeItem("vip:live:global");
      } catch {
        // ignore
      }
    };
  }, [enabled]);

  const showToast = (t: Toast) => {
    setToast(t);
    if (timer.current) window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => setToast(null), 7000);
  };

  useEffect(() => {
    return () => {
      if (timer.current) window.clearTimeout(timer.current);
    };
  }, []);

  useEffect(() => {
    if (!enabled) return;
    let cancelled = false;

    let inFlight = false;
    const poll = async () => {
      if (cancelled || inFlight) return;
      inFlight = true;
      const seeded = noticesSeeded();
      const fresh: Array<Omit<VcNotice, "read">> = [];
      let gotAny = false;
      let chain = Promise.resolve();
      const take = (load: () => Promise<Array<Omit<VcNotice, "read">>>) => {
        const run = load()
          .catch(() => [] as Array<Omit<VcNotice, "read">>)
          .then((items) => {
            chain = chain.then(() => {
              if (cancelled || !items.length) return;
              gotAny = true;
              fresh.push(...ingestNotices(items, seeded ? "live" : "seed"));
            });
            return chain;
          });
        return run;
      };
      try {
        await Promise.all([
          take(async () => mapPatch(await fetchJson<{ items?: FeedItem[] }>("/api/patch/feed"))),
          take(async () => mapCves(await fetchJson<{ items?: CveItem[] }>("/api/cves?view=last24h&limit=8")))
        ]);
        await chain;
        if (cancelled) return;
        if (!seeded && gotAny) markNoticesSeeded();
        // ФСТЭК в тосты и колокольчик не пушим — лента только в модуле ФСТЭК.
        const toastable = fresh.filter((item) => item.source !== "ФСТЭК" && !item.id.startsWith("fstec:"));
        if (seeded && toastable.length) {
          const newest = [...toastable].sort((a, b) => Date.parse(b.at) - Date.parse(a.at))[0];
          if (newest) {
            showToast({
              title: toastable.length > 1 ? `${newest.source}: ${toastable.length} новых` : `${newest.source}: новое`,
              body: newest.kind === "cve" ? `${newest.title}${newest.body ? ` — ${newest.body}` : ""}` : newest.title,
              href: newest.href.startsWith("/") ? undefined : newest.href
            });
          }
        }
      } finally {
        inFlight = false;
        if (!cancelled) markNoticesReady();
      }
    };

    void poll();
    const id = window.setInterval(() => void poll(), 60_000);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, [enabled]);

  if (!enabled || !toast) return null;

  return (
    <div className="vc-shell pointer-events-none fixed inset-x-0 top-16 z-[70] flex justify-end px-4">
      <div className="vc-notice-in pointer-events-auto w-[min(380px,calc(100vw-2rem))]">
        <div className="rounded-xl border border-[var(--vc-border)] bg-[var(--vc-surface)] px-3 py-2.5 shadow-lg">
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <div className="text-[12px] font-semibold text-[var(--vc-text)]">{toast.title}</div>
              {toast.body ? <div className="mt-0.5 line-clamp-2 text-[11px] leading-snug text-[var(--vc-muted)]">{toast.body}</div> : null}
              {toast.href ? (
                <a
                  href={toast.href}
                  target="_blank"
                  rel="noreferrer"
                  className="mt-1.5 inline-flex items-center gap-1.5 text-[11px] font-medium text-[#2f6bff] hover:underline"
                >
                  Открыть источник
                  <ExternalLink className="h-3 w-3" aria-hidden />
                </a>
              ) : null}
            </div>
            <button
              type="button"
              onClick={() => setToast(null)}
              className="rounded-md border border-[var(--vc-border)] p-1 text-[var(--vc-muted)] hover:bg-[var(--vc-hover)]"
              aria-label="Закрыть"
            >
              <X className="h-3.5 w-3.5" aria-hidden />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
