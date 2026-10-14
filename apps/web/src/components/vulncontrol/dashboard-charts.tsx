"use client";

import { useId, useState } from "react";
import { formatInt } from "@/lib/vulncontrol/live";

const MONTHS = ["янв", "фев", "мар", "апр", "мая", "июн", "июл", "авг", "сен", "окт", "ноя", "дек"];

const RANK_COLORS = [
  "var(--vc-low)",
  "var(--vc-success)",
  "var(--vc-high)",
  "var(--vc-medium)",
  "var(--vc-purple)",
  "var(--vc-critical)",
  "var(--vc-info)",
  "var(--vc-kev)"
];

export function utcTodayKey(now = new Date()) {
  return now.toISOString().slice(0, 10);
}

function shiftKey(key: string, deltaDays: number) {
  const date = new Date(`${key}T00:00:00.000Z`);
  date.setUTCDate(date.getUTCDate() + deltaDays);
  return date.toISOString().slice(0, 10);
}

/** Календарные сутки UTC. День без строки в ряде — 0 публикаций, не пропуск. */
export function fillUtcDays(source: Array<{ day: string; count: number }>, span: number, endKey = utcTodayKey()) {
  const map = new Map<string, number>();
  for (const row of source) {
    const day = String(row.day).slice(0, 10);
    const count = Number(row.count);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(day) || !Number.isFinite(count)) continue;
    map.set(day, (map.get(day) ?? 0) + count);
  }
  const points: Array<{ day: string; count: number }> = [];
  const safeSpan = Math.max(1, span);
  for (let offset = safeSpan - 1; offset >= 0; offset -= 1) {
    const day = shiftKey(endKey, -offset);
    points.push({ day, count: map.get(day) ?? 0 });
  }
  return points;
}

/** Последние 7 календарных дней ряда против предыдущих 7. Процент только если предыдущее окно > 0. */
export function publicationWeekDelta(source: Array<{ day: string; count: number }>) {
  const days = fillUtcDays(source, 14);
  const previous = days.slice(0, 7).reduce((sum, row) => sum + row.count, 0);
  const recent = days.slice(7).reduce((sum, row) => sum + row.count, 0);
  const pct = previous > 0 ? Math.round(((recent - previous) / previous) * 100) : null;
  return { recent, previous, pct };
}

function axisScale(value: number) {
  if (!Number.isFinite(value) || value <= 0) return { max: 4, ticks: [0, 1, 2, 3, 4] };
  const exp = Math.pow(10, Math.floor(Math.log10(value)));
  const steps = [1, 2, 2.5, 5, 10].flatMap((base) => [base * exp / 10, base * exp, base * exp * 10]);
  let best: { max: number; step: number; score: number } | null = null;
  for (const step of steps) {
    if (!(step > 0)) continue;
    const max = Math.ceil((value * 1.02) / step) * step;
    const count = Math.round(max / step);
    if (count < 3 || count > 6) continue;
    const headroom = max / value;
    if (headroom > 1.45) continue;
    const score = Math.abs(count - 4) + (headroom - 1) * 3;
    if (!best || score < best.score) best = { max, step, score };
  }
  if (!best) return { max: value, ticks: [0, value / 2, value] };
  const ticks: number[] = [];
  for (let tick = 0; tick <= best.max + best.step * 0.001; tick += best.step) {
    ticks.push(Math.round(tick * 1000) / 1000);
  }
  return { max: best.max, ticks };
}

function dayLabel(day: string) {
  const month = Number(day.slice(5, 7));
  const date = Number(day.slice(8, 10));
  return `${date} ${MONTHS[month - 1] ?? ""}`.trim();
}

function tickLabel(value: number) {
  if (Number.isInteger(value)) return formatInt(value);
  return new Intl.NumberFormat("ru-RU", { maximumFractionDigits: 1 }).format(value);
}

export function DashPublicationTrend({ points }: { points: Array<{ day: string; count: number }> }) {
  const [hover, setHover] = useState<number | null>(null);
  const gradId = `dash-pub-${useId().replace(/:/g, "")}`;
  const width = 720;
  const height = 220;
  const pad = { l: 52, r: 14, t: 14, b: 28 };
  if (!points.length) return <p className="text-[12px] text-[var(--vc-muted)]">Нет публикаций за этот период</p>;

  const rawMax = Math.max(...points.map((point) => point.count), 0);
  const scale = axisScale(rawMax);
  const max = scale.max;
  const innerW = width - pad.l - pad.r;
  const innerH = height - pad.t - pad.b;
  const x = (index: number) => pad.l + (points.length <= 1 ? innerW / 2 : (index / (points.length - 1)) * innerW);
  const y = (value: number) => pad.t + innerH - (value / max) * innerH;
  const coords = points.map((point, index) => ({ x: x(index), y: y(point.count) }));
  const line = coords.map((point, index) => `${index === 0 ? "M" : "L"}${point.x.toFixed(1)} ${point.y.toFixed(1)}`).join(" ");
  const area = `${line} L ${coords[coords.length - 1]!.x.toFixed(1)} ${y(0).toFixed(1)} L ${coords[0]!.x.toFixed(1)} ${y(0).toFixed(1)} Z`;
  const ticks = scale.ticks;
  const labelStep = points.length <= 8 ? 1 : points.length <= 16 ? 3 : 5;
  const active = hover != null ? points[hover] : null;

  return (
    <div className="min-w-0">
      <svg
        viewBox={`0 0 ${width} ${height}`}
        className="h-[210px] w-full"
        role="img"
        aria-label={`Публикации NVD по суткам UTC. Максимум за сутки ${formatInt(rawMax)}.`}
        onMouseLeave={() => setHover(null)}
        onMouseMove={(event) => {
          const rect = event.currentTarget.getBoundingClientRect();
          const rel = ((event.clientX - rect.left) / Math.max(rect.width, 1)) * width;
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
          <linearGradient id={gradId} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="var(--vc-primary)" stopOpacity="0.55" />
            <stop offset="100%" stopColor="var(--vc-primary)" stopOpacity="0.02" />
          </linearGradient>
        </defs>
        {ticks.map((tick) => (
          <g key={tick}>
            <line x1={pad.l} x2={width - pad.r} y1={y(tick)} y2={y(tick)} stroke="var(--vc-grid)" />
            <text x={pad.l - 8} y={y(tick) + 3} textAnchor="end" fill="var(--vc-muted)" fontSize="11">
              {tickLabel(tick)}
            </text>
          </g>
        ))}
        <path d={area} fill={`url(#${gradId})`} />
        <path d={line} fill="none" stroke="var(--vc-primary)" strokeWidth="2.4" />
        {hover != null ? (
          <line x1={x(hover)} x2={x(hover)} y1={pad.t} y2={height - pad.b} stroke="var(--vc-crosshair)" />
        ) : null}
        {coords.map((point, index) => (
          <circle
            key={points[index]!.day}
            cx={point.x}
            cy={point.y}
            r={hover === index ? 4 : points.length <= 8 ? 2.4 : 0}
            fill="var(--vc-primary)"
          />
        ))}
        {points.map((point, index) => {
          if (index % labelStep !== 0 && index !== points.length - 1) return null;
          const anchor = index === 0 ? "start" : index === points.length - 1 ? "end" : "middle";
          return (
            <text key={point.day} x={x(index)} y={height - 8} textAnchor={anchor} fill="var(--vc-muted)" fontSize="11">
              {dayLabel(point.day)}
            </text>
          );
        })}
      </svg>
      <div className="mt-1 flex flex-wrap items-center justify-between gap-2 text-[11px]">
        <span className="inline-flex items-center gap-1.5 text-[var(--vc-muted)]">
          <span className="h-1.5 w-3 rounded-full bg-[var(--vc-primary)]" />
          Публикации за сутки, UTC
        </span>
        <span className="min-h-4 tabular-nums text-[var(--vc-text)]">
          {active ? `${dayLabel(active.day)} · ${formatInt(active.count)}` : "Наведите на точку ряда"}
        </span>
      </div>
    </div>
  );
}

export function DashRankBars({
  rows
}: {
  rows: Array<{ key: string; name: string; value: number; onPick?: () => void }>;
}) {
  const max = Math.max(...rows.map((row) => row.value), 1);
  if (!rows.length) return <p className="text-[12px] text-[var(--vc-muted)]">Нет данных</p>;
  return (
    <div className="space-y-2.5">
      {rows.map((row, index) => {
        const color = RANK_COLORS[index % RANK_COLORS.length]!;
        const width = row.value <= 0 ? 0 : Math.max((row.value / max) * 100, 1.5);
        const body = (
          <>
            <span className="mt-1 h-2 w-2 shrink-0 rounded-full" style={{ background: color }} />
            <span className="min-w-0 flex-1">
              <span className="mb-1 flex items-center justify-between gap-2 text-[12px]">
                <span className="truncate">{row.name}</span>
                <span className="shrink-0 tabular-nums font-medium" style={{ color }}>{formatInt(row.value)}</span>
              </span>
              <span className="block h-2 overflow-hidden rounded-full bg-[var(--vc-track)]">
                <span className="block h-full rounded-full" style={{ width: `${width}%`, background: color }} />
              </span>
            </span>
          </>
        );
        if (!row.onPick) {
          return (
            <div key={row.key} className="flex items-start gap-2" title={`${row.name}: ${formatInt(row.value)}`}>
              {body}
            </div>
          );
        }
        return (
          <button
            key={row.key}
            type="button"
            onClick={row.onPick}
            title={`${row.name}: ${formatInt(row.value)}`}
            className="flex w-full items-start gap-2 text-left hover:opacity-90"
          >
            {body}
          </button>
        );
      })}
    </div>
  );
}
