"use client";

import { useMemo, useState } from "react";
import { formatNum, SEVERITY_COLORS } from "@/lib/vulncontrol/metrics";

export function Donut({
  slices,
  colors,
  center,
  sub,
  onPick,
  svgClassName = "h-[132px] w-[132px]"
}: {
  slices: Array<{ key: string; label: string; value: number; pct: number }>;
  colors: string[];
  center: string;
  sub: string;
  onPick?: (key: string) => void;
  svgClassName?: string;
}) {
  const [active, setActive] = useState<number | null>(null);
  const sum = slices.reduce((acc, slice) => acc + slice.value, 0);
  const total = sum || 1;
  const radius = 52;
  const circ = 2 * Math.PI * radius;
  let offset = 0;
  const arcs = slices.map((slice, index) => {
    const length = (slice.value / total) * circ;
    const arc = { slice, index, length, offset };
    offset += length;
    return arc;
  });

  return (
    <div className="flex min-w-0 items-center gap-3">
      <svg viewBox="0 0 140 140" className={`${svgClassName} shrink-0`}>
        <circle cx="70" cy="70" r={radius} fill="none" stroke="var(--vc-donut-track)" strokeWidth="14" />
        {arcs.map((arc) => (
          <circle
            key={arc.slice.key}
            cx="70"
            cy="70"
            r={radius}
            fill="none"
            stroke={colors[arc.index] ?? "#64748b"}
            strokeWidth={active === arc.index ? 18 : 14}
            strokeDasharray={`${arc.length} ${circ - arc.length}`}
            strokeDashoffset={-arc.offset}
            strokeLinecap="butt"
            transform="rotate(-90 70 70)"
            opacity={active == null || active === arc.index ? 1 : 0.35}
            className={onPick ? "cursor-pointer" : undefined}
            onMouseEnter={() => setActive(arc.index)}
            onMouseLeave={() => setActive(null)}
            onClick={() => onPick?.(arc.slice.key)}
          />
        ))}
        <text x="70" y="66" textAnchor="middle" fill="var(--vc-text)" fontSize="18" fontWeight="700">
          {center}
        </text>
        <text x="70" y="84" textAnchor="middle" fill="var(--vc-muted)" fontSize="11">
          {sub}
        </text>
      </svg>
      <ul className="min-w-0 flex-1 space-y-1.5">
        {slices.map((slice, index) => (
          <li
            key={slice.key}
            onMouseEnter={() => setActive(index)}
            onMouseLeave={() => setActive(null)}
            onClick={() => onPick?.(slice.key)}
            className={`grid grid-cols-[10px_minmax(0,1fr)_auto_auto] items-center gap-2 text-[11px] ${onPick ? "cursor-pointer" : ""}`}
          >
            <span className="h-2 w-2 rounded-full" style={{ background: colors[index] }} />
            <span className="truncate text-[var(--vc-muted)]">{slice.label}</span>
            <span className="tabular-nums text-[var(--vc-text)]">{formatNum(slice.value)}</span>
            <span className="w-10 text-right tabular-nums text-[var(--vc-muted)]">{(sum ? (slice.value / sum) * 100 : 0).toFixed(1)}%</span>
          </li>
        ))}
      </ul>
      {active != null ? (
        <span className="sr-only">
          {slices[active]?.label}: {formatNum(slices[active]?.value ?? 0)}
        </span>
      ) : null}
    </div>
  );
}

type TrendPoint = { label: string; critical: number; high: number; medium: number; low: number };

export function TrendChart({ points }: { points: TrendPoint[] }) {
  const [hover, setHover] = useState<number | null>(null);
  const width = 640;
  const height = 210;
  const pad = { l: 32, r: 8, t: 12, b: 26 };
  const max = 200;
  const innerW = width - pad.l - pad.r;
  const innerH = height - pad.t - pad.b;
  const x = (index: number) => pad.l + (points.length <= 1 ? innerW / 2 : (index / (points.length - 1)) * innerW);
  const y = (value: number) => pad.t + innerH - (Math.min(value, max) / max) * innerH;

  const path = (key: keyof Omit<TrendPoint, "label">) => {
    if (!points.length) return "";
    return points
      .map((point, index) => {
        const px = x(index);
        const py = y(point[key]);
        if (index === 0) return `M ${px} ${py}`;
        const prev = points[index - 1]!;
        const cx = (x(index - 1) + px) / 2;
        return `C ${cx} ${y(prev[key])}, ${cx} ${py}, ${px} ${py}`;
      })
      .join(" ");
  };

  const area = (key: keyof Omit<TrendPoint, "label">) => {
    if (!points.length) return "";
    const line = path(key);
    return `${line} L ${x(points.length - 1)} ${y(0)} L ${x(0)} ${y(0)} Z`;
  };

  const series = [
    { key: "low" as const, color: SEVERITY_COLORS.low, label: "Низкие" },
    { key: "medium" as const, color: SEVERITY_COLORS.medium, label: "Средние" },
    { key: "high" as const, color: SEVERITY_COLORS.high, label: "Высокие" },
    { key: "critical" as const, color: SEVERITY_COLORS.critical, label: "Критические" }
  ];

  return (
    <div>
      <svg
        viewBox={`0 0 ${width} ${height}`}
        className="h-[210px] w-full"
        onMouseLeave={() => setHover(null)}
        onMouseMove={(event) => {
          const rect = event.currentTarget.getBoundingClientRect();
          const rel = ((event.clientX - rect.left) / rect.width) * width;
          let best = 0;
          let dist = Infinity;
          points.forEach((_, index) => {
            const gap = Math.abs(x(index) - rel);
            if (gap < dist) {
              dist = gap;
              best = index;
            }
          });
          setHover(best);
        }}
      >
        <defs>
          {series.map((item) => (
            <linearGradient key={item.key} id={`vc-fill-${item.key}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={item.color} stopOpacity="0.28" />
              <stop offset="100%" stopColor={item.color} stopOpacity="0" />
            </linearGradient>
          ))}
        </defs>
        {[0, 50, 100, 150, 200].map((tick) => (
          <g key={tick}>
            <line x1={pad.l} x2={width - pad.r} y1={y(tick)} y2={y(tick)} stroke="var(--vc-grid)" />
            <text x={pad.l - 6} y={y(tick) + 3} textAnchor="end" fill="var(--vc-muted)" fontSize="10">
              {tick}
            </text>
          </g>
        ))}
        {series.map((item) => (
          <path key={`${item.key}-area`} d={area(item.key)} fill={`url(#vc-fill-${item.key})`} />
        ))}
        {series.map((item) => (
          <path key={item.key} d={path(item.key)} fill="none" stroke={item.color} strokeWidth="2" />
        ))}
        {hover != null && points[hover] ? (
          <line x1={x(hover)} x2={x(hover)} y1={pad.t} y2={height - pad.b} stroke="var(--vc-crosshair)" />
        ) : null}
        {points.map((point, index) => (
          <text key={point.label} x={x(index)} y={height - 6} textAnchor="middle" fill="var(--vc-muted)" fontSize="10">
            {point.label}
          </text>
        ))}
      </svg>
      <div className="mt-1 flex flex-wrap gap-3 text-[11px] text-[var(--vc-muted)]">
        {series.map((item) => (
          <span key={item.key} className="inline-flex items-center gap-1.5">
            <span className="h-1.5 w-3 rounded-full" style={{ background: item.color }} />
            {item.label}
          </span>
        ))}
      </div>
      {hover != null && points[hover] ? (
        <div className="mt-2 grid grid-cols-4 gap-2 rounded-lg border border-[var(--vc-border)] bg-[var(--vc-well)] px-2 py-1.5 text-[10px]">
          {series.map((item) => (
            <div key={item.key}>
              <div className="text-[var(--vc-muted)]">{item.label}</div>
              <div className="font-semibold tabular-nums" style={{ color: item.color }}>
                {points[hover]![item.key]}
              </div>
            </div>
          ))}
        </div>
      ) : null}
    </div>
  );
}

export function FlowChart({
  points,
  direction
}: {
  points: Array<{ label: string; published: number; critical: number }>;
  direction: "up" | "down" | "flat";
}) {
  const [hover, setHover] = useState<number | null>(null);
  const width = 720;
  const height = 230;
  const pad = { l: 36, r: 18, t: 16, b: 28 };
  const max = Math.max(...points.map((point) => point.published), 1);
  const innerW = width - pad.l - pad.r;
  const innerH = height - pad.t - pad.b;
  const x = (index: number) => pad.l + (points.length <= 1 ? innerW / 2 : (index / (points.length - 1)) * innerW);
  const y = (value: number) => pad.t + innerH - (value / max) * innerH;
  const line = (key: "published" | "critical") => {
    if (!points.length) return "";
    return points
      .map((point, index) => {
        const px = x(index);
        const py = y(point[key]);
        if (index === 0) return `M ${px} ${py}`;
        const prev = points[index - 1]!;
        const cx = (x(index - 1) + px) / 2;
        return `C ${cx} ${y(prev[key])}, ${cx} ${py}, ${px} ${py}`;
      })
      .join(" ");
  };
  const area = `${line("published")} L ${x(Math.max(points.length - 1, 0))} ${y(0)} L ${x(0)} ${y(0)} Z`;
  const arrowFrom = Math.max(points.length - 4, 0);
  const arrowColor = direction === "up" ? "var(--vc-critical)" : direction === "down" ? "var(--vc-success)" : "var(--vc-muted)";
  const ticks = [0, Math.round(max / 2), max];

  if (!points.length) return <p className="text-[12px] text-[var(--vc-muted)]">Нет публикаций за этот период</p>;

  return (
    <div>
      <svg
        viewBox={`0 0 ${width} ${height}`}
        className="h-[230px] w-full"
        onMouseLeave={() => setHover(null)}
        onMouseMove={(event) => {
          const rect = event.currentTarget.getBoundingClientRect();
          const rel = ((event.clientX - rect.left) / rect.width) * width;
          let best = 0;
          let dist = Infinity;
          points.forEach((_, index) => {
            const gap = Math.abs(x(index) - rel);
            if (gap < dist) {
              dist = gap;
              best = index;
            }
          });
          setHover(best);
        }}
      >
        <defs>
          <linearGradient id="vc-flow-pub" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="var(--vc-primary)" stopOpacity="0.35" />
            <stop offset="100%" stopColor="var(--vc-primary)" stopOpacity="0" />
          </linearGradient>
          <marker id="vc-flow-arrow" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
            <path d="M0 0 L7 3 L0 6 Z" fill={arrowColor} />
          </marker>
        </defs>
        {ticks.map((tick) => (
          <g key={tick}>
            <line x1={pad.l} x2={width - pad.r} y1={y(tick)} y2={y(tick)} stroke="var(--vc-grid)" />
            <text x={pad.l - 6} y={y(tick) + 3} textAnchor="end" fill="var(--vc-muted)" fontSize="10">
              {tick}
            </text>
          </g>
        ))}
        <path d={area} fill="url(#vc-flow-pub)" />
        <path d={line("published")} fill="none" stroke="var(--vc-primary)" strokeWidth="2.4" />
        <path d={line("critical")} fill="none" stroke="var(--vc-critical)" strokeWidth="2" />
        {points.length > 1 ? (
          <line
            x1={x(arrowFrom)}
            y1={y(points[arrowFrom]!.published)}
            x2={x(points.length - 1)}
            y2={y(points[points.length - 1]!.published)}
            stroke={arrowColor}
            strokeWidth="2.2"
            markerEnd="url(#vc-flow-arrow)"
          />
        ) : null}
        {hover != null && points[hover] ? (
          <line x1={x(hover)} x2={x(hover)} y1={pad.t} y2={height - pad.b} stroke="var(--vc-crosshair)" />
        ) : null}
        {points.map((point, index) => (
          index % Math.ceil(points.length / 6) === 0 ? (
            <text key={point.label} x={x(index)} y={height - 8} textAnchor="middle" fill="var(--vc-muted)" fontSize="10">
              {point.label.slice(5)}
            </text>
          ) : null
        ))}
      </svg>
      <div className="mt-1 flex flex-wrap gap-3 text-[11px] text-[var(--vc-muted)]">
        <span className="inline-flex items-center gap-1.5"><span className="h-1.5 w-3 rounded-full bg-[var(--vc-primary)]" />Публикации</span>
        <span className="inline-flex items-center gap-1.5"><span className="h-1.5 w-3 rounded-full" style={{ background: "var(--vc-critical)" }} />CVSS ≥ 9</span>
        <span className="inline-flex items-center gap-1.5"><span className="h-1.5 w-3 rounded-full" style={{ background: arrowColor }} />Наклон хвоста ряда</span>
      </div>
      {hover != null && points[hover] ? (
        <div className="mt-2 flex flex-wrap gap-4 rounded-lg border border-[var(--vc-border)] bg-[var(--vc-well)] px-2 py-1.5 text-[11px]">
          <span className="text-[var(--vc-muted)]">{points[hover]!.label}</span>
          <span>Публикации <b className="tabular-nums">{points[hover]!.published}</b></span>
          <span>CVSS ≥ 9 <b className="tabular-nums">{points[hover]!.critical}</b></span>
        </div>
      ) : null}
    </div>
  );
}

export function CountBars({
  points,
  onPick
}: {
  points: Array<{ label: string; count: number }>;
  onPick?: (label: string, count: number) => void;
}) {
  const max = Math.max(...points.map((point) => point.count), 1);
  if (!points.length) return <p className="text-[12px] text-[var(--vc-muted)]">Нет публикаций за этот период</p>;
  return (
    <div className="flex h-[148px] items-end gap-1">
      {points.map((point) => {
        const clickable = Boolean(onPick && point.count > 0);
        const inner = (
          <>
            <span className="text-[9px] tabular-nums text-[var(--vc-muted)]">{point.count}</span>
            <div
              className={`w-full rounded-sm ${clickable ? "bg-[var(--vc-high)]" : "bg-[var(--vc-low)]"}`}
              style={{ height: `${Math.max(4, (point.count / max) * 112)}px` }}
            />
            <span className="w-full truncate text-center text-[9px] text-[var(--vc-muted)]">{point.label.slice(5)}</span>
          </>
        );
        if (!clickable) {
          return (
            <div key={point.label} className="flex min-w-0 flex-1 flex-col items-center justify-end gap-1" title={`${point.label}: ${point.count}`}>
              {inner}
            </div>
          );
        }
        return (
          <button
            key={point.label}
            type="button"
            title={`${point.label}: ${point.count} — открыть список`}
            onClick={() => onPick?.(point.label, point.count)}
            className="flex min-w-0 flex-1 flex-col items-center justify-end gap-1 rounded-sm hover:bg-[var(--vc-hover)]"
          >
            {inner}
          </button>
        );
      })}
    </div>
  );
}

export function HBars({
  rows,
  color,
  onPick
}: {
  rows: Array<{ name: string; value: number }>;
  color: string;
  onPick?: (name: string) => void;
}) {
  const max = Math.max(...rows.map((row) => row.value), 1);
  return (
    <div className="space-y-2.5">
      {rows.map((row) => (
        <button
          key={row.name}
          type="button"
          onClick={() => onPick?.(row.name)}
          className="block w-full text-left"
        >
          <div className="mb-1 flex items-center justify-between gap-2 text-[12px]">
            <span className="truncate">{row.name}</span>
            <span className="tabular-nums text-[var(--vc-muted)]">{formatNum(row.value)}</span>
          </div>
          <div className="h-1.5 overflow-hidden rounded-full bg-[var(--vc-track)]">
            <div className="h-full rounded-full" style={{ width: `${(row.value / max) * 100}%`, background: color }} />
          </div>
        </button>
      ))}
    </div>
  );
}

export function Spark({ values, color }: { values: number[]; color: string }) {
  const d = useMemo(() => {
    const max = Math.max(...values, 1);
    return values
      .map((value, index) => {
        const x = (index / Math.max(values.length - 1, 1)) * 78;
        const y = 28 - (value / max) * 24;
        return `${index === 0 ? "M" : "L"}${x.toFixed(1)} ${y.toFixed(1)}`;
      })
      .join(" ");
  }, [values]);
  return (
    <svg viewBox="0 0 78 32" className="h-8 w-[78px]">
      <path d={d} fill="none" stroke={color} strokeWidth="1.6" />
    </svg>
  );
}

export function Ring({ pct, color }: { pct: number; color: string }) {
  const r = 16;
  const c = 2 * Math.PI * r;
  return (
    <svg viewBox="0 0 42 42" className="h-10 w-10">
      <circle cx="21" cy="21" r={r} fill="none" stroke="var(--vc-track)" strokeWidth="4" />
      <circle
        cx="21"
        cy="21"
        r={r}
        fill="none"
        stroke={color}
        strokeWidth="4"
        strokeDasharray={`${(pct / 100) * c} ${c}`}
        strokeLinecap="round"
        transform="rotate(-90 21 21)"
      />
    </svg>
  );
}
