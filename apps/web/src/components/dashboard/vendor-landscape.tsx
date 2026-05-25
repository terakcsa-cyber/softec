"use client";

import { useId, useMemo } from "react";
import { motion } from "framer-motion";
import { Factory, Layers } from "lucide-react";
import { cn } from "../ui/cn";

const VENDOR_COLORS = [
  "rgb(99, 102, 241)",
  "rgb(236, 72, 153)",
  "rgb(34, 197, 94)",
  "rgb(245, 158, 11)",
  "rgb(56, 189, 248)",
  "rgb(167, 139, 250)",
  "rgb(251, 113, 133)",
  "rgb(52, 211, 153)"
];

type VendorRow = { vendor: string; count: number };
type ProductRow = { vendor: string; product: string; count: number };

function buildDonutSegments(vendors: VendorRow[], maxSlices = 7) {
  const sorted = [...vendors].sort((a, b) => b.count - a.count);
  const top = sorted.slice(0, maxSlices);
  const rest = sorted.slice(maxSlices);
  const restSum = rest.reduce((s, v) => s + v.count, 0);
  const rows: { label: string; value: number; color: string }[] = top.map((v, i) => ({
    label: v.vendor,
    value: v.count,
    color: VENDOR_COLORS[i % VENDOR_COLORS.length]!
  }));
  if (restSum > 0) {
    rows.push({
      label: "Прочие",
      value: restSum,
      color: "rgba(148, 163, 184, 0.85)"
    });
  }
  const total = rows.reduce((s, r) => s + r.value, 0);
  return { rows, total };
}

function VendorDonut({
  donut
}: {
  donut: { rows: { label: string; value: number; color: string }[]; total: number };
}) {
  const uid = useId();
  const { rows, total } = donut;
  const gradId = `donut-grad-${uid}`;

  let acc = 0;
  const arcs = rows.map((r) => {
    const start = acc;
    const frac = total > 0 ? r.value / total : 0;
    acc += frac;
    return { ...r, start, frac };
  });

  return (
    <div className="flex flex-col items-center gap-4 sm:flex-row sm:items-center sm:justify-center sm:gap-8">
      <div className="relative h-[200px] w-[200px] shrink-0">
        <svg viewBox="0 0 100 100" className="h-full w-full -rotate-90">
          <defs>
            <filter id={`${gradId}-g`} x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur stdDeviation="1.2" result="b" />
              <feMerge>
                <feMergeNode in="b" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>
          {total <= 0 ? (
            <circle cx="50" cy="50" r="38" fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="14" />
          ) : (
            arcs.map((a, i) => {
              const startAngle = a.start * Math.PI * 2;
              const endAngle = (a.start + a.frac) * Math.PI * 2;
              const r = 38;
              const cx = 50;
              const cy = 50;
              const x1 = cx + r * Math.cos(startAngle);
              const y1 = cy + r * Math.sin(startAngle);
              const x2 = cx + r * Math.cos(endAngle);
              const y2 = cy + r * Math.sin(endAngle);
              const large = a.frac > 0.5 ? 1 : 0;
              const d = `M ${cx} ${cy} L ${x1} ${y1} A ${r} ${r} 0 ${large} 1 ${x2} ${y2} Z`;
              return (
                <motion.path
                  key={`${a.label}-${i}`}
                  d={d}
                  fill={a.color}
                  fillOpacity={0.88}
                  stroke="rgba(0,0,0,0.35)"
                  strokeWidth={0.35}
                  filter={`url(#${gradId}-g)`}
                  initial={{ opacity: 0, scale: 0.92 }}
                  animate={{ opacity: 1, scale: 1 }}
                  transition={{ delay: 0.04 * i, type: "spring", stiffness: 120, damping: 18 }}
                />
              );
            })
          )}
          <circle cx="50" cy="50" r="22" fill="rgb(9, 9, 12)" stroke="rgba(255,255,255,0.08)" strokeWidth={0.5} />
        </svg>
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center pt-0.5">
          <div className="text-[10px] font-medium uppercase tracking-wider text-muted">всего</div>
          <div className="text-xl font-semibold tabular-nums text-fg/95">{total.toLocaleString()}</div>
          <div className="text-[9px] text-muted">упоминаний</div>
        </div>
      </div>

      <ul className="min-w-0 flex-1 space-y-2 text-[11px]">
        {rows.length === 0 ? (
          <li className="text-muted">Нет данных по вендорам за окно.</li>
        ) : (
          rows.map((r) => (
            <li key={r.label} className="flex items-center justify-between gap-2">
              <span className="flex min-w-0 items-center gap-2">
                <span className="h-2 w-2 shrink-0 rounded-sm" style={{ background: r.color }} />
                <span className="truncate text-fg/90">{r.label}</span>
              </span>
              <span className="shrink-0 tabular-nums text-muted">
                {r.value}
                <span className="ml-1 text-fg/70">
                  ({total > 0 ? ((r.value / total) * 100).toFixed(0) : 0}%)
                </span>
              </span>
            </li>
          ))
        )}
      </ul>
    </div>
  );
}

function VendorBars({ vendors }: { vendors: VendorRow[] }) {
  const max = Math.max(1, ...vendors.map((v) => v.count));
  const top = useMemo(() => [...vendors].sort((a, b) => b.count - a.count).slice(0, 10), [vendors]);

  return (
    <div className="space-y-2.5">
      {top.length === 0 ? (
        <div className="text-[11px] text-muted">—</div>
      ) : (
        top.map((v, i) => {
          const w = (v.count / max) * 100;
          return (
            <div key={v.vendor}>
              <div className="mb-0.5 flex items-center justify-between gap-2 text-[11px]">
                <span className="min-w-0 truncate font-medium text-fg/90">{v.vendor}</span>
                <span className="shrink-0 tabular-nums text-muted">{v.count}</span>
              </div>
              <div className="h-2 overflow-hidden rounded-full bg-white/[0.06] ring-1 ring-white/[0.05]">
                <motion.div
                  className="h-full rounded-full bg-gradient-to-r from-indigo-500/90 via-violet-500/70 to-fuchsia-500/50"
                  initial={{ width: 0 }}
                  animate={{ width: `${w}%` }}
                  transition={{ type: "spring", stiffness: 80, damping: 20, delay: 0.03 * i }}
                />
              </div>
            </div>
          );
        })
      )}
    </div>
  );
}

function ProductCards({ products }: { products: ProductRow[] }) {
  const top = useMemo(() => [...products].sort((a, b) => b.count - a.count).slice(0, 8), [products]);
  if (!top.length) {
    return <div className="text-[11px] text-muted">—</div>;
  }
  return (
    <div className="grid gap-2 sm:grid-cols-2">
      {top.map((p, i) => (
        <motion.div
          key={`${p.vendor}|${p.product}`}
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.03 * i }}
          className="rounded-xl border border-slate-200 bg-white px-3 py-2.5 shadow-sm ring-1 ring-slate-200/60 dark:border-white/[0.07] dark:bg-black/30 dark:shadow-none dark:ring-white/[0.04]"
        >
          <div className="text-[10px] text-muted">{p.vendor}</div>
          <div className="truncate text-[12px] font-medium text-fg/90">{p.product}</div>
          <div className="mt-1 text-[11px] tabular-nums text-muted">{p.count} CVE</div>
        </motion.div>
      ))}
    </div>
  );
}

export function VendorLandscape({
  windowHours,
  sampledCves,
  sampledBdu,
  sampledTotal,
  method,
  usedCpe,
  usedFallback,
  usedBdu,
  vendors,
  products,
  onVendorSelect,
  onProductSelect
}: {
  windowHours: number;
  sampledCves: number;
  sampledBdu?: number;
  sampledTotal?: number;
  method?: string;
  usedCpe?: number;
  usedFallback?: number;
  usedBdu?: number;
  vendors: VendorRow[];
  products: ProductRow[];
  onVendorSelect?: (vendor: string) => void;
  onProductSelect?: (vendor: string, product: string) => void;
}) {
  const donut = useMemo(() => buildDonutSegments(vendors), [vendors]);

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <div className="flex items-center gap-2 text-sm font-semibold tracking-tight text-fg/95">
            <Factory className="h-4 w-4 text-muted" />
            Ландшафт вендоров за {windowHours}ч
          </div>
          <p className="mt-1 max-w-2xl text-[12px] text-muted">
            Доля по CVE (NVD/CPE) и записям БДУ ФСТЭК за окно публикации. Клик — фильтр списка CVE.
          </p>
        </div>
        <div className="text-right text-[10px] text-muted">
          <div>
            выборка:{" "}
            {(sampledTotal ?? sampledCves).toLocaleString()}
            {typeof sampledBdu === "number" && sampledBdu > 0
              ? ` (CVE ${sampledCves.toLocaleString()} + БДУ ${sampledBdu.toLocaleString()})`
              : ` CVE`}
          </div>
          {method ? (
            <div className="text-muted/80">
              {method}
              {typeof usedCpe === "number" ? ` · CPE ${usedCpe}` : ""}
              {typeof usedFallback === "number" ? ` · fb ${usedFallback}` : ""}
              {typeof usedBdu === "number" && usedBdu > 0 ? ` · БДУ ${usedBdu}` : ""}
            </div>
          ) : null}
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <div className="rounded-2xl border border-slate-200/90 bg-gradient-to-br from-white via-slate-50 to-indigo-100/35 p-5 shadow-sm ring-1 ring-slate-200/70 dark:border-border dark:from-black/50 dark:via-black/30 dark:to-indigo-950/15 dark:shadow-none dark:ring-white/[0.06]">
          <div className="mb-4 text-xs font-medium text-fg/90">Доля по вендорам</div>
          <VendorDonut donut={donut} />
          <div className="mt-6 space-y-2 border-t border-slate-200/90 pt-4 dark:border-white/[0.06]">
            <div className="text-[10px] font-medium uppercase tracking-wider text-muted">Топ по объёму</div>
            <VendorBars vendors={vendors} />
          </div>
          {vendors.length ? (
            <div className="mt-4 flex flex-wrap gap-2 border-t border-slate-200/90 pt-4 dark:border-white/[0.06]">
              {vendors.slice(0, 6).map((v) => (
                <button
                  key={v.vendor}
                  type="button"
                  onClick={() => onVendorSelect?.(v.vendor)}
                  className={cn(
                    "rounded-full border border-slate-200 bg-white px-3 py-1 text-[11px] text-fg/85 shadow-sm transition hover:border-accent/35 hover:bg-accent/10 dark:border-white/10 dark:bg-white/[0.04] dark:shadow-none",
                    !onVendorSelect && "cursor-default hover:border-slate-200 hover:bg-white dark:hover:border-white/10 dark:hover:bg-white/[0.04]"
                  )}
                >
                  {v.vendor}
                </button>
              ))}
            </div>
          ) : null}
        </div>

        <div className="rounded-2xl border border-slate-200/90 bg-white p-5 shadow-sm ring-1 ring-slate-200/60 dark:border-border dark:bg-black/20 dark:shadow-none dark:ring-white/[0.05]">
          <div className="mb-3 flex items-center gap-2 text-xs font-medium text-fg/90">
            <Layers className="h-3.5 w-3.5 text-muted" />
            Топ продуктов
          </div>
          <ProductCards products={products} />
          {products.length ? (
            <div className="mt-4 flex flex-wrap gap-2 border-t border-slate-200/90 pt-4 dark:border-white/[0.06]">
              {products.slice(0, 6).map((p) => (
                <button
                  key={`${p.vendor}|${p.product}`}
                  type="button"
                  onClick={() => onProductSelect?.(p.vendor, p.product)}
                  className={cn(
                    "max-w-full truncate rounded-full border border-slate-200 bg-white px-3 py-1 text-left text-[11px] text-fg/85 shadow-sm transition hover:border-accent/35 hover:bg-accent/10 dark:border-white/10 dark:bg-white/[0.04] dark:shadow-none",
                    !onProductSelect && "cursor-default hover:border-slate-200 hover:bg-white dark:hover:border-white/10 dark:hover:bg-white/[0.04]"
                  )}
                >
                  {p.vendor} / {p.product}
                </button>
              ))}
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );
}
