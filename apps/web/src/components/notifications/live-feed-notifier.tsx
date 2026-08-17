"use client";

import { useAuth } from "@/contexts/auth-context";
import { useEffect, useRef, useState } from "react";
import { ExternalLink, Loader2, Volume2, X } from "lucide-react";
import { apiFetch } from "@/lib/api-fetch";
import { cn } from "@/components/ui/cn";

type Toast = {
  title: string;
  body?: string;
  href?: string;
};

function beepWithCtx(ctx: AudioContext, freq = 880) {
  try {
    const o = ctx.createOscillator();
    const g = ctx.createGain();
    o.type = "sine";
    o.frequency.value = freq;
    g.gain.value = 0.0001;
    o.connect(g);
    g.connect(ctx.destination);
    o.start();
    const now = ctx.currentTime;
    g.gain.setValueAtTime(0.0001, now);
    g.gain.linearRampToValueAtTime(0.12, now + 0.02);
    g.gain.exponentialRampToValueAtTime(0.0001, now + 0.16);
    o.stop(now + 0.18);
  } catch {
    // ignore
  }
}

function safeGet(key: string): string {
  try {
    return localStorage.getItem(key) ?? "";
  } catch {
    return "";
  }
}

function safeSet(key: string, value: string) {
  try {
    localStorage.setItem(key, value);
  } catch {
    // ignore
  }
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
  const [busy, setBusy] = useState(false);
  const timer = useRef<number | null>(null);
  const audioCtxRef = useRef<AudioContext | null>(null);
  const [audioUnlocked, setAudioUnlocked] = useState(false);

  const soundKey = "vip:live:sound";
  const [soundEnabled, setSoundEnabled] = useState(() => safeGet(soundKey) !== "0");
  const enabled = Boolean(user) && !loading;

  useEffect(() => {
    if (!enabled) return;
    safeSet("vip:live:global", "1");
    return () => {
      try {
        localStorage.removeItem("vip:live:global");
      } catch {
        // ignore
      }
    };
  }, [enabled]);

  // Browsers block sound until a user gesture. Unlock once on first interaction.
  useEffect(() => {
    if (!enabled) return;
    const Ctx = (window.AudioContext ||
      (window as Window & { webkitAudioContext?: typeof AudioContext }).webkitAudioContext) as
      | typeof AudioContext
      | undefined;
    if (!Ctx) return;

    const unlock = async () => {
      try {
        if (!audioCtxRef.current) audioCtxRef.current = new Ctx();
        if (audioCtxRef.current.state === "suspended") await audioCtxRef.current.resume();
        setAudioUnlocked(true);
      } catch {
        // ignore
      }
    };

    window.addEventListener("pointerdown", unlock, { once: true, passive: true });
    window.addEventListener("keydown", unlock, { once: true, passive: true });
    return () => {
      window.removeEventListener("pointerdown", unlock);
      window.removeEventListener("keydown", unlock);
    };
  }, [enabled]);

  useEffect(() => {
    safeSet(soundKey, soundEnabled ? "1" : "0");
  }, [soundEnabled, audioUnlocked]);

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

    const poll = async () => {
      if (cancelled) return;
      setBusy(true);
      try {
        // FSTEC
        const fstec = await fetchJson<{ items?: Array<{ id: string; title?: string; link?: string }> }>("/api/fstec/feed");
        const fstecNewest = fstec?.items?.[0];
        if (fstecNewest?.id) {
          const key = "vip:fstec:lastSeenId";
          const last = safeGet(key);
          if (last) {
            if (last !== fstecNewest.id) {
              safeSet(key, fstecNewest.id);
              showToast({
                title: "ФСТЭК: новая публикация",
                body: fstecNewest.title || "Новая запись в ленте",
                href: fstecNewest.link
              });
              if (soundEnabled && audioCtxRef.current && audioUnlocked) beepWithCtx(audioCtxRef.current, 880);
            }
          } else {
            safeSet(key, fstecNewest.id);
          }
        }

        // Patch telegram aggregator
        const patch = await fetchJson<{ items?: Array<{ id: string; title?: string; link?: string; channel?: { slug: string } }> }>("/api/patch/feed");
        const patchNewest = patch?.items?.[0];
        if (patchNewest?.id) {
          const key = "vip:patch:lastSeenId";
          const last = safeGet(key);
          if (last) {
            if (last !== patchNewest.id) {
              safeSet(key, patchNewest.id);
              showToast({
                title: "Patch: новая публикация",
                body: patchNewest.title || (patchNewest.channel?.slug ? `@${patchNewest.channel.slug}` : "Новая запись"),
                href: patchNewest.link
              });
              if (soundEnabled && audioCtxRef.current && audioUnlocked) beepWithCtx(audioCtxRef.current, 740);
            }
          } else {
            safeSet(key, patchNewest.id);
          }
        }
      } finally {
        setBusy(false);
      }
    };

    void poll();
    const id = window.setInterval(() => void poll(), 60_000);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, [enabled, soundEnabled, audioUnlocked]);

  if (!enabled) return null;

  return (
    <div className="fixed bottom-4 right-4 z-[70]">
      <div className="mb-2 flex justify-end gap-2">
        <button
          type="button"
          onClick={() => {
            if (!audioCtxRef.current) return;
            if (!audioUnlocked) return;
            beepWithCtx(audioCtxRef.current, 880);
          }}
          disabled={!audioUnlocked}
          className={cn(
            "inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white/90 px-2.5 py-1.5 text-[11px] text-fg/85 shadow-sm backdrop-blur",
            "hover:bg-white disabled:opacity-50 dark:border-white/[0.08] dark:bg-black/50 dark:hover:bg-black/65"
          )}
          title={
            audioUnlocked
              ? "Тест звука"
              : "Браузер блокирует звук до первого клика/нажатия клавиши в странице"
          }
        >
          Тест
        </button>
        <button
          type="button"
          onClick={() => setSoundEnabled((v) => !v)}
          className={cn(
            "inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white/90 px-2.5 py-1.5 text-[11px] text-fg/85 shadow-sm backdrop-blur",
            "hover:bg-white dark:border-white/[0.08] dark:bg-black/50 dark:hover:bg-black/65"
          )}
          title={soundEnabled ? "Звук уведомлений: включён" : "Звук уведомлений: выключен"}
        >
          {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden /> : null}
          <Volume2 className={cn("h-3.5 w-3.5", !soundEnabled && "opacity-40")} aria-hidden />
          {soundEnabled ? "Звук" : "Без звука"}
        </button>
      </div>

      {toast ? (
        <div className="w-[min(420px,calc(100vw-2rem))]">
          <div className="rounded-2xl border border-slate-200/80 bg-white/95 p-4 shadow-2xl backdrop-blur dark:border-white/[0.08] dark:bg-black/70">
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="text-xs font-semibold text-fg/95">{toast.title}</div>
                {toast.body ? <div className="mt-1 line-clamp-2 text-[11px] leading-snug text-muted">{toast.body}</div> : null}
                {toast.href ? (
                  <a
                    href={toast.href}
                    target="_blank"
                    rel="noreferrer"
                    className="mt-2 inline-flex items-center gap-1.5 text-[11px] font-medium text-accent hover:underline"
                  >
                    Открыть источник
                    <ExternalLink className="h-3 w-3" aria-hidden />
                  </a>
                ) : null}
              </div>
              <button
                type="button"
                onClick={() => setToast(null)}
                className="rounded-lg border border-slate-200 bg-white p-1.5 text-muted hover:bg-slate-50 dark:border-border dark:bg-black/20 dark:hover:bg-black/35"
                aria-label="Закрыть"
              >
                <X className="h-4 w-4" aria-hidden />
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}

