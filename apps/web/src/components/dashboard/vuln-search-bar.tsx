"use client";

import { useCallback, useEffect, useId, useMemo, useRef, useState } from "react";
import { Loader2, Search, Sparkles, X } from "lucide-react";
import { cn } from "../ui/cn";

const HISTORY_KEY = "vip:vulnSearchRecent";
const MAX_HISTORY = 8;

type VendorRow = { vendor: string; count: number };
type ProductRow = { vendor: string; product: string; count: number };

export type VulnSearchHints = {
  vendors: VendorRow[];
  products: ProductRow[];
} | null;

type Suggestion =
  | { kind: "phrase"; label: string; value: string; sub?: string }
  | { kind: "vendor"; label: string; value: string; count: number }
  | { kind: "product"; label: string; value: string; count: number; vendor: string };

function readHistory(): string[] {
  try {
    const raw = localStorage.getItem(HISTORY_KEY);
    if (!raw) return [];
    const p = JSON.parse(raw) as unknown;
    if (!Array.isArray(p)) return [];
    return p.filter((x): x is string => typeof x === "string").slice(0, MAX_HISTORY);
  } catch {
    return [];
  }
}

function writeHistory(items: string[]) {
  try {
    localStorage.setItem(HISTORY_KEY, JSON.stringify(items.slice(0, MAX_HISTORY)));
  } catch {
    // ignore
  }
}

function normalizeNeedle(s: string): string {
  return s.trim().toLowerCase();
}

export function VulnSearchBar({
  value,
  onChange,
  hints,
  hintsLoading,
  listLoading,
  onClearFilters
}: {
  value: string;
  onChange: (next: string) => void;
  hints: VulnSearchHints;
  hintsLoading: boolean;
  listLoading: boolean;
  /** Сбросить фильтры вендор/продукт — при смене запроса с подсказки */
  onClearFilters: () => void;
}) {
  const id = useId();
  const inputRef = useRef<HTMLInputElement>(null);
  const rootRef = useRef<HTMLDivElement>(null);
  const [open, setOpen] = useState(false);
  const [recent, setRecent] = useState<string[]>([]);

  useEffect(() => {
    setRecent(readHistory());
  }, []);

  const needle = normalizeNeedle(value);

  const suggestions = useMemo((): Suggestion[] => {
    const out: Suggestion[] = [];
    const vList = hints?.vendors ?? [];
    const pList = hints?.products ?? [];
    if (needle.length < 1) return out;

    out.push({
      kind: "phrase",
      label: `Искать «${value.trim()}» везде`,
      value: value.trim(),
      sub: "CVE id, NVD, вендор, продукт, ИИ‑сводка"
    });
    for (const v of vList) {
      if (normalizeNeedle(v.vendor).includes(needle)) {
        out.push({ kind: "vendor", label: v.vendor, value: v.vendor, count: v.count });
      }
    }
    for (const p of pList) {
      const blob = `${p.vendor} ${p.product}`;
      if (normalizeNeedle(blob).includes(needle)) {
        out.push({
          kind: "product",
          label: p.product || blob,
          value: blob.trim(),
          count: p.count,
          vendor: p.vendor
        });
      }
    }
    return out.slice(0, 14);
  }, [hints, needle, value]);

  const hasEmptyHelp =
    needle.length === 0 && (recent.length > 0 || (hints?.vendors?.length ?? 0) > 0 || hintsLoading);
  const showPanel =
    open && (hasEmptyHelp || needle.length >= 1 || hintsLoading);

  const applyValue = useCallback(
    (next: string) => {
      const t = next.trim();
      onClearFilters();
      onChange(t);
      if (t) {
        const h = [t, ...readHistory().filter((x) => x !== t)].slice(0, MAX_HISTORY);
        writeHistory(h);
        setRecent(h);
      }
      setOpen(false);
      inputRef.current?.blur();
    },
    [onChange, onClearFilters]
  );

  useEffect(() => {
    const onDoc = (e: MouseEvent) => {
      if (!rootRef.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, []);

  const busy = listLoading && Boolean(value.trim());

  return (
    <div ref={rootRef} className="relative z-30 mb-4 w-full">
      <label htmlFor={id} className="mb-2 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wide text-fg/80">
        <Search className="h-3.5 w-3.5 text-accent" aria-hidden />
        Поиск по уязвимостям
      </label>

      <div
        role="combobox"
        aria-expanded={showPanel}
        aria-controls={`${id}-panel`}
        aria-haspopup="listbox"
        className={cn(
          "pointer-events-auto flex min-h-[48px] w-full items-center gap-3 rounded-2xl border-2 px-3 py-2 shadow-sm transition-colors",
          "border-slate-200 bg-white dark:border-white/[0.14] dark:bg-zinc-950/85",
          "focus-within:border-accent/45 focus-within:ring-2 focus-within:ring-accent/15"
        )}
      >
        <Search className="h-5 w-5 shrink-0 text-accent/80" aria-hidden />
        <input
          ref={inputRef}
          id={id}
          type="search"
          autoComplete="off"
          autoCorrect="off"
          spellCheck={false}
          enterKeyHint="search"
          placeholder="CVE-2024-…, BDU:2026-…, вендор, продукт, текст…"
          title="Полнотекстовый поиск: id CVE, JSON NVD, индекс вендор/продукт, текст ИИ-обогащения"
          aria-autocomplete="list"
          value={value}
          onChange={(e) => {
            onChange(e.target.value);
            setOpen(true);
          }}
          onFocus={() => setOpen(true)}
          onKeyDown={(e) => {
            if (e.key === "Escape") setOpen(false);
          }}
          className={cn(
            "min-h-[40px] min-w-0 flex-1 border-0 bg-transparent text-sm text-fg outline-none",
            "placeholder:text-muted"
          )}
        />
        {busy ? <Loader2 className="h-4 w-4 shrink-0 animate-spin text-accent" aria-label="Загрузка" /> : null}
        {value ? (
          <button
            type="button"
            className="shrink-0 rounded-lg p-1.5 text-muted hover:bg-slate-100 hover:text-fg dark:hover:bg-white/[0.08]"
            onClick={() => {
              onChange("");
              onClearFilters();
              inputRef.current?.focus();
            }}
            aria-label="Очистить поиск"
          >
            <X className="h-4 w-4" />
          </button>
        ) : null}
      </div>

      <p className="mt-2 text-[11px] leading-relaxed text-muted">
        Ищем по <span className="text-fg/80">CVE</span>, описанию{" "}
        <span className="text-fg/80">NVD</span>, полям <span className="text-fg/80">вендор / продукт</span> и тексту{" "}
        <span className="text-fg/80">ИИ‑сводки</span>. Ниже — подсказки из топа за 24ч и недавние запросы.
      </p>

      {showPanel ? (
        <div
          id={`${id}-panel`}
          role="listbox"
          className={cn(
            "absolute left-0 right-0 top-full z-[100] mt-2 max-h-[min(70vh,320px)] overflow-auto rounded-xl border py-1 shadow-xl",
            "border-slate-200 bg-white dark:border-white/[0.12] dark:bg-zinc-950"
          )}
        >
          {hintsLoading && needle.length >= 1 ? (
            <div className="flex items-center gap-2 px-3 py-2 text-xs text-muted">
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
              Подгружаем подсказки…
            </div>
          ) : null}

          {needle.length === 0 && recent.length > 0 ? (
            <div className="border-b border-slate-100 px-2 py-2 dark:border-white/[0.06]">
              <div className="px-2 pb-1 text-[10px] font-medium uppercase tracking-wide text-muted">Недавние</div>
              <div className="flex flex-wrap gap-1.5">
                {recent.map((r) => (
                  <button
                    key={r}
                    type="button"
                    className="rounded-full border border-slate-200 bg-slate-50 px-2.5 py-1 text-[11px] text-fg/90 hover:bg-slate-100 dark:border-white/[0.1] dark:bg-white/[0.05] dark:hover:bg-white/[0.09]"
                    onMouseDown={(e) => e.preventDefault()}
                    onClick={() => applyValue(r)}
                  >
                    {r.length > 42 ? `${r.slice(0, 40)}…` : r}
                  </button>
                ))}
              </div>
            </div>
          ) : null}

          {needle.length === 0 && !hintsLoading && (hints?.vendors?.length ?? 0) > 0 ? (
            <div className="border-b border-slate-100 px-2 py-2 dark:border-white/[0.06]">
              <div className="flex items-center gap-1.5 px-2 pb-1 text-[10px] font-medium uppercase tracking-wide text-muted">
                <Sparkles className="h-3 w-3 text-accent/80" />
                Частые вендоры (24 ч)
              </div>
              <div className="flex flex-wrap gap-1.5">
                {(hints?.vendors ?? []).slice(0, 10).map((v) => (
                  <button
                    key={v.vendor}
                    type="button"
                    className="rounded-full border border-slate-200 bg-slate-50 px-2.5 py-1 text-[11px] text-fg/90 hover:border-accent/30 hover:bg-accent/5 dark:border-white/[0.1] dark:bg-white/[0.05]"
                    onMouseDown={(e) => e.preventDefault()}
                    onClick={() => applyValue(v.vendor)}
                  >
                    {v.vendor}
                    <span className="ml-1 tabular-nums text-muted">({v.count})</span>
                  </button>
                ))}
              </div>
            </div>
          ) : null}

          {suggestions.map((s, idx) => (
            <button
              key={`${s.kind}-${idx}-${s.label}`}
              type="button"
              role="option"
              aria-selected={false}
              className={cn(
                "flex w-full items-start gap-2 px-3 py-2.5 text-left text-sm hover:bg-slate-50 dark:hover:bg-white/[0.06]",
                s.kind === "phrase" && "border-b border-slate-100 font-medium dark:border-white/[0.06]"
              )}
              onMouseDown={(e) => e.preventDefault()}
              onClick={() => applyValue(s.value)}
            >
              <span className="min-w-0 flex-1">
                <span className="block text-fg/95">{s.label}</span>
                {"sub" in s && s.sub ? <span className="mt-0.5 block text-[11px] text-muted">{s.sub}</span> : null}
                {s.kind === "vendor" ? (
                  <span className="mt-0.5 block text-[11px] text-muted">Вендор · {s.count} CVE в окне</span>
                ) : null}
                {s.kind === "product" ? (
                  <span className="mt-0.5 block text-[11px] text-muted">
                    {s.vendor} · {s.count} CVE
                  </span>
                ) : null}
              </span>
            </button>
          ))}

          {needle.length >= 1 && suggestions.length <= 1 && !hintsLoading ? (
            <div className="border-t border-slate-100 px-3 py-2 text-[11px] text-muted dark:border-white/[0.06]">
              Нет совпадений в топе вендоров/продуктов — по Enter выполняется полнотекстовый поиск по всем полям.
            </div>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}
