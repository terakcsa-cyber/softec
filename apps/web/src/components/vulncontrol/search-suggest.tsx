"use client";

import { useEffect, useMemo, useRef, useState, type KeyboardEvent as ReactKeyboardEvent, type ReactNode } from "react";
import type { Route } from "next";
import { usePathname, useRouter } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { Search } from "lucide-react";
import { cn } from "@/components/ui/cn";
import { apiFetch } from "@/lib/api-fetch";
import type { LiveCve, LiveTask } from "@/lib/vulncontrol/live";
import { taskIssueKey } from "../dashboard/vuln-task-ui";
import { rememberTask, stashCatalogFilter, stashVcPage, useVc, vulnerabilityPath } from "./vc-context";
import { useAnchoredStyle } from "./vc-pop";

const CVE_LIMIT = 8;
const TASK_LIMIT = 5;
const CATALOG_LIMIT = 5;

type CveHit = { kind: "cve"; cveId: string; subtitle: string };
type TaskHit = { kind: "task"; id: string; issueKey: string; title: string; meta: string; viaKey: boolean };
type ProductHit = { kind: "product"; product: string; vendor: string };
type VendorHit = { kind: "vendor"; vendor: string };
type SuggestHit = CveHit | TaskHit | ProductHit | VendorHit;

type ProductRow = {
  vendor?: string | null;
  product?: string | null;
  vendor_key?: string | null;
  product_key_norm?: string | null;
};

async function getJson<T>(url: string): Promise<T> {
  const res = await apiFetch(url, { cache: "no-store" });
  if (!res.ok) throw new Error(`Запрос не выполнен (${res.status})`);
  return (await res.json()) as T;
}

function looksLikeIssueKey(value: string) {
  const compact = value.replace(/\s+/g, "");
  return /^vt-/i.test(compact) && /^vt-?[0-9a-f]*$/i.test(compact);
}

/** Любой фрагмент CVE (CVE-2025-353 / 2025-353 / cve_2025_353) → нормализованный id для API. */
function cveApiQuery(value: string) {
  const compact = value.replace(/\s+/g, "");
  const shaped = /^(?:cve[_-]?)?(\d{4})[_-](\d{1,})$/i.exec(compact);
  if (shaped?.[1] && shaped[2]) return `CVE-${shaped[1]}-${shaped[2]}`;
  return value.trim();
}

function includesNeedle(value: string | null | undefined, needle: string) {
  if (!value || !needle) return false;
  return value.toLowerCase().includes(needle.toLowerCase());
}

function cveSubtitle(row: LiveCve) {
  const title = (row.short_ru || row.short_description || "").trim();
  const where = [row.vp_vendor, row.vp_product].filter(Boolean).join(" / ");
  if (where && title) return `${where} — ${title}`;
  return title || where;
}

function Highlight({ text, query }: { text: string; query: string }) {
  const needles = highlightNeedles(query);
  if (!text) return null;
  if (!needles.length) return <>{text}</>;
  const lower = text.toLowerCase();
  const out: ReactNode[] = [];
  let cursor = 0;
  let guard = 0;
  while (cursor < text.length && guard < 24) {
    let bestAt = -1;
    let bestLen = 0;
    for (const n of needles) {
      const at = lower.indexOf(n, cursor);
      if (at < 0) continue;
      if (bestAt < 0 || at < bestAt || (at === bestAt && n.length > bestLen)) {
        bestAt = at;
        bestLen = n.length;
      }
    }
    if (bestAt < 0 || bestLen === 0) break;
    if (bestAt > cursor) out.push(text.slice(cursor, bestAt));
    out.push(
      <mark key={`${bestAt}-${guard}`} className="rounded-[2px] bg-[#f5c451]/45 px-0.5 font-semibold text-inherit">
        {text.slice(bestAt, bestAt + bestLen)}
      </mark>
    );
    cursor = bestAt + bestLen;
    guard += 1;
  }
  if (cursor < text.length) out.push(text.slice(cursor));
  return <>{out}</>;
}

function highlightNeedles(query: string) {
  const raw = query.trim().toLowerCase();
  if (!raw) return [] as string[];
  const shaped = cveApiQuery(query).toLowerCase();
  const out = new Set<string>([raw]);
  if (shaped && shaped !== raw) out.add(shaped);
  const bare = shaped.replace(/^cve-/, "");
  if (bare) out.add(bare);
  return [...out].filter(Boolean).sort((a, b) => b.length - a.length);
}

export function SearchSuggest() {
  const router = useRouter();
  const pathname = usePathname();
  const { setQuery, setPage, openTask } = useVc();
  const boxRef = useRef<HTMLDivElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const [draft, setDraft] = useState("");
  const [debounced, setDebounced] = useState("");
  const needle = draft.trim();

  useEffect(() => {
    const handle = window.setTimeout(() => setDebounced(needle), 160);
    return () => window.clearTimeout(handle);
  }, [needle]);

  const keyMode = looksLikeIssueKey(debounced);
  const catalogMode = !keyMode && debounced.length >= 2 && !/^(?:cve[_-]?)?\d{4}[_-]\d*$/i.test(debounced.replace(/\s+/g, ""));
  const enabled = debounced.length > 0;

  const cveQ = cveApiQuery(debounced);
  const cves = useQuery({
    queryKey: ["vc", "suggest", "cves", cveQ],
    enabled,
    queryFn: () => getJson<{ items: LiveCve[] }>(`/api/cves?limit=12&sort=risk&q=${encodeURIComponent(cveQ)}`),
    staleTime: 30_000
  });

  const tasks = useQuery({
    queryKey: ["vc", "suggest", "tasks", keyMode ? "issue-key" : debounced],
    enabled,
    queryFn: () =>
      getJson<{ items: LiveTask[] }>(
        keyMode
          ? "/api/vuln-tasks?limit=200&sort=score"
          : `/api/vuln-tasks?limit=8&sort=score&q=${encodeURIComponent(debounced)}`
      ),
    staleTime: 30_000
  });

  const products = useQuery({
    queryKey: ["vc", "suggest", "products", debounced],
    enabled: catalogMode,
    queryFn: () =>
      getJson<{ items: ProductRow[] }>(
        `/api/products?band=all&limit=8&q=${encodeURIComponent(debounced)}`
      ),
    staleTime: 30_000
  });

  const inSync = needle.length > 0 && needle === debounced;
  const pending =
    !inSync ||
    cves.isLoading ||
    tasks.isLoading ||
    (catalogMode && products.isLoading);

  const hits = useMemo(() => {
    if (!inSync) return [] as SuggestHit[];
    const found: SuggestHit[] = [];
    const cveItems = cves.data?.items ?? [];
    const seenCve = new Set<string>();
    for (const row of cveItems) {
      if (!row.cve_id || seenCve.has(row.cve_id)) continue;
      seenCve.add(row.cve_id);
      found.push({ kind: "cve", cveId: row.cve_id, subtitle: cveSubtitle(row) });
      if (found.filter((hit) => hit.kind === "cve").length >= CVE_LIMIT) break;
    }

    const taskItems = tasks.data?.items ?? [];
    let taskCount = 0;
    const seenTask = new Set<string>();
    for (const task of taskItems) {
      if (!task.id || seenTask.has(task.id)) continue;
      const issueKey = taskIssueKey(task.id);
      if (keyMode && !includesNeedle(issueKey, debounced)) continue;
      seenTask.add(task.id);
      const meta = [task.product_display, task.vendor_display].filter(Boolean).join(" · ");
      found.push({
        kind: "task",
        id: task.id,
        issueKey,
        title: task.title || "",
        meta,
        viaKey: keyMode
      });
      taskCount += 1;
      if (taskCount >= TASK_LIMIT) break;
    }

    const productHits: ProductHit[] = [];
    const vendorHits: VendorHit[] = [];
    const seenProduct = new Set<string>();
    const seenVendor = new Set<string>();
    const addProduct = (product: string | null | undefined, vendor: string | null | undefined) => {
      const name = product?.trim();
      if (!name) return;
      const key = `${(vendor ?? "").trim().toLowerCase()}|${name.toLowerCase()}`;
      if (seenProduct.has(key) || productHits.length >= CATALOG_LIMIT) return;
      seenProduct.add(key);
      productHits.push({ kind: "product", product: name, vendor: vendor?.trim() || "" });
    };
    const addVendor = (vendor: string | null | undefined) => {
      const name = vendor?.trim();
      if (!name) return;
      const key = name.toLowerCase();
      if (seenVendor.has(key) || vendorHits.length >= CATALOG_LIMIT) return;
      seenVendor.add(key);
      vendorHits.push({ kind: "vendor", vendor: name });
    };

    for (const row of products.data?.items ?? []) {
      addProduct(row.product, row.vendor);
      addVendor(row.vendor);
    }
    for (const row of cveItems) {
      addProduct(row.vp_product, row.vp_vendor);
      addVendor(row.vp_vendor);
    }
    for (const task of taskItems) {
      if (keyMode && !includesNeedle(taskIssueKey(task.id), debounced)) continue;
      addProduct(task.product_display, task.vendor_display);
      addVendor(task.vendor_display);
    }
    return [...found, ...productHits, ...vendorHits];
  }, [cves.data?.items, debounced, inSync, keyMode, products.data?.items, tasks.data?.items]);

  useEffect(() => {
    setActive(0);
  }, [debounced]);

  useEffect(() => {
    if (!open) return;
    const onDoc = (event: PointerEvent) => {
      if (!boxRef.current?.contains(event.target as Node)) setOpen(false);
    };
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
    };
    document.addEventListener("pointerdown", onDoc);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("pointerdown", onDoc);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const show = open && needle.length > 0;
  const listStyle = useAnchoredStyle(show, boxRef, listRef, "start", "anchor", 440, `${hits.length}:${needle}:${pending}`);
  const settled = inSync && !cves.isLoading && !tasks.isLoading && (!catalogMode || !products.isLoading);
  const failed = settled && (cves.isError || tasks.isError || (catalogMode && products.isError)) && hits.length === 0;

  function goVulns(vendor: string, product: string, text = "") {
    setOpen(false);
    setDraft("");
    const patch = {
      q: text,
      vendor: vendor || "all",
      product: product || "all",
      tab: "all" as const,
      severity: "all" as const,
      status: "all" as const
    };
    const here = pathname === "/" || pathname === "/vulnerabilities";
    if (here) {
      setQuery(patch);
      setPage("vulns");
      return;
    }
    stashCatalogFilter({ vendor: patch.vendor, product: patch.product, q: text });
    router.push("/vulnerabilities" as Route);
  }

  function applyTextSearch() {
    const text = needle;
    if (!text) return;
    if (hits[0]) {
      choose(hits[Math.min(active, hits.length - 1)] ?? hits[0]!);
      return;
    }
    const shaped = cveApiQuery(text);
    if (/^CVE-\d{4}-\d{4,}$/i.test(shaped)) {
      setOpen(false);
      setDraft("");
      router.push(vulnerabilityPath(shaped.toUpperCase()));
      return;
    }
    goVulns("all", "all", text);
  }

  function choose(hit: SuggestHit) {
    setOpen(false);
    setDraft("");
    if (hit.kind === "cve") {
      router.push(vulnerabilityPath(hit.cveId));
      return;
    }
    if (hit.kind === "task") {
      if (pathname === "/") {
        openTask(hit.id);
        return;
      }
      rememberTask(hit.id);
      stashVcPage("tasks");
      router.push("/" as Route);
      return;
    }
    if (hit.kind === "product") {
      goVulns(hit.vendor, hit.product);
      return;
    }
    goVulns(hit.vendor, "");
  }

  function onKeyDown(event: ReactKeyboardEvent<HTMLInputElement>) {
    if (event.key === "Escape") {
      if (open) {
        event.preventDefault();
        event.stopPropagation();
        setOpen(false);
      }
      return;
    }
    if (event.key === "Enter") {
      event.preventDefault();
      if (show && hits.length) {
        const hit = hits[Math.min(active, hits.length - 1)];
        if (hit) choose(hit);
        return;
      }
      if (needle) applyTextSearch();
      return;
    }
    if (!show || !hits.length) return;
    if (event.key === "ArrowDown") {
      event.preventDefault();
      setActive((index) => (index + 1) % hits.length);
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      setActive((index) => (index - 1 + hits.length) % hits.length);
    }
  }

  let cursor = 0;
  const cveHits = hits.filter((hit): hit is CveHit => hit.kind === "cve");
  const taskHits = hits.filter((hit): hit is TaskHit => hit.kind === "task");
  const productHits = hits.filter((hit): hit is ProductHit => hit.kind === "product");
  const vendorHits = hits.filter((hit): hit is VendorHit => hit.kind === "vendor");

  function row(hit: SuggestHit, index: number) {
    const on = index === active;
    return (
      <button
        key={hit.kind === "cve" ? hit.cveId : hit.kind === "task" ? hit.id : hit.kind === "product" ? `p:${hit.vendor}:${hit.product}` : `v:${hit.vendor}`}
        type="button"
        role="option"
        aria-selected={on}
        onMouseEnter={() => setActive(index)}
        onMouseDown={(event) => event.preventDefault()}
        onClick={() => choose(hit)}
        className={cn("block w-full px-3 py-1.5 text-left", on ? "bg-[color-mix(in_srgb,var(--vc-primary)_20%,transparent)]" : "hover:bg-[var(--vc-hover)]")}
      >
        {hit.kind === "cve" ? (
          <>
            <span className="block font-mono text-[12px] font-semibold text-[var(--vc-link)]">
              <Highlight text={hit.cveId} query={needle} />
            </span>
            {hit.subtitle ? (
              <span className="mt-0.5 line-clamp-1 block text-[11px] text-[var(--vc-muted)]">
                <Highlight text={hit.subtitle} query={needle} />
              </span>
            ) : null}
          </>
        ) : null}
        {hit.kind === "task" ? (
          <>
            <span className="flex min-w-0 items-baseline gap-2">
              <span className="shrink-0 font-mono text-[12px] font-semibold text-[var(--vc-link)]">
                <Highlight text={hit.issueKey} query={needle} />
              </span>
              <span className="min-w-0 truncate text-[12px] text-[var(--vc-text)]">
                <Highlight text={hit.title} query={needle} />
              </span>
            </span>
            {hit.meta ? (
              <span className="mt-0.5 line-clamp-1 block text-[11px] text-[var(--vc-muted)]">
                <Highlight text={hit.meta} query={needle} />
              </span>
            ) : null}
          </>
        ) : null}
        {hit.kind === "product" ? (
          <>
            <span className="block truncate text-[12px] text-[var(--vc-text)]">
              <Highlight text={hit.product} query={needle} />
            </span>
            {hit.vendor ? (
              <span className="mt-0.5 block truncate text-[11px] text-[var(--vc-muted)]">
                <Highlight text={hit.vendor} query={needle} />
              </span>
            ) : null}
          </>
        ) : null}
        {hit.kind === "vendor" ? (
          <span className="block truncate text-[12px] text-[var(--vc-text)]">
            <Highlight text={hit.vendor} query={needle} />
          </span>
        ) : null}
      </button>
    );
  }

  function section(label: string, items: SuggestHit[]) {
    if (!items.length) return null;
    const start = cursor;
    cursor += items.length;
    return (
      <div>
        <div className="px-3 pb-1 pt-2 text-[10px] font-semibold uppercase tracking-wide text-[var(--vc-muted)]">{label}</div>
        {items.map((hit, index) => row(hit, start + index))}
      </div>
    );
  }

  return (
    <div ref={boxRef} className="relative min-w-0 flex-1">
      <label className="flex h-9 w-full items-center gap-2 rounded-lg border border-[var(--vc-border)] bg-[var(--vc-inset)] px-3 text-[var(--vc-muted)]">
        <Search className="h-3.5 w-3.5 shrink-0" />
        <input
          id="vc-search"
          value={draft}
          role="combobox"
          aria-expanded={show}
          aria-controls="vc-search-results"
          aria-autocomplete="list"
          autoComplete="off"
          autoCorrect="off"
          spellCheck={false}
          onChange={(event) => {
            const next = event.target.value;
            setDraft(next);
            setOpen(next.trim().length > 0);
          }}
          onFocus={() => {
            if (needle) setOpen(true);
          }}
          onKeyDown={onKeyDown}
          placeholder="CVE-2025-353, продукт, вендор, VT-…"
          className="min-w-0 flex-1 bg-transparent text-[13px] text-[var(--vc-text)] outline-none placeholder:text-[var(--vc-muted)]"
        />
        <span className="hidden rounded border border-[var(--vc-border)] px-1.5 py-0.5 text-[10px] sm:inline">⌘ K</span>
      </label>
      {show ? (
        <div
          ref={listRef}
          id="vc-search-results"
          role="listbox"
          className="vc-pop overflow-x-hidden overflow-y-auto rounded-lg border border-[var(--vc-border)] bg-[var(--vc-surface)] py-1 shadow-xl"
          style={listStyle}
        >
          {pending && hits.length === 0 ? <p className="px-3 py-3 text-[12px] text-[var(--vc-muted)]">Ищу…</p> : null}
          {failed ? <p className="px-3 py-3 text-[12px] text-[var(--vc-muted)]">Не удалось выполнить поиск</p> : null}
          {settled && !failed && hits.length === 0 ? (
            <p className="px-3 py-3 text-[12px] text-[var(--vc-muted)]">Ничего не найдено. Enter — поиск по каталогу.</p>
          ) : null}
          {section("Уязвимости", cveHits)}
          {section("Задачи", taskHits)}
          {section("Продукты", productHits)}
          {section("Вендоры", vendorHits)}
        </div>
      ) : null}
    </div>
  );
}
