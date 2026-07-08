import type { VocPriority } from "./triage.js";
import { vocPriorityFromScore, type VocScoreResult } from "./scoring.js";

export const VOC_WATCHLIST_KINDS = ["vendor", "product", "keyword"] as const;
export type VocWatchlistKind = (typeof VOC_WATCHLIST_KINDS)[number];

export type VocWatchlistRule = {
  id: string;
  kind: VocWatchlistKind;
  value: string;
  label: string;
  active: boolean;
};

function norm(s: string): string {
  return s.trim().toLowerCase();
}

export function watchlistKindLabel(kind: VocWatchlistKind): string {
  if (kind === "vendor") return "Вендор";
  if (kind === "product") return "Продукт";
  return "Ключевое слово";
}

export function applyWatchlistBoost(
  base: VocScoreResult,
  ctx: {
    vendor?: string | null;
    product?: string | null;
    text?: string | null;
  },
  rules: VocWatchlistRule[]
): VocScoreResult {
  const active = rules.filter((r) => r.active && r.value.trim());
  if (!active.length) return base;

  let bonus = 0;
  const reasons = [...base.reasons];
  const vendor = norm(ctx.vendor ?? "");
  const product = norm(ctx.product ?? "");
  const text = norm(ctx.text ?? "");
  const vendorProduct = vendor && product ? `${vendor}/${product}` : product || vendor;

  for (const rule of active) {
    const needle = norm(rule.value);
    if (!needle) continue;
    const tag = rule.label?.trim() || rule.value;

    if (rule.kind === "vendor" && vendor && (vendor === needle || vendor.includes(needle))) {
      bonus += 15;
      reasons.push(`watchlist: ${tag}`);
      continue;
    }
    if (
      rule.kind === "product" &&
      (product === needle || vendorProduct.includes(needle) || product.includes(needle))
    ) {
      bonus += 12;
      reasons.push(`watchlist: ${tag}`);
      continue;
    }
    if (rule.kind === "keyword" && text.includes(needle)) {
      bonus += 10;
      reasons.push(`watchlist: ${tag}`);
    }
  }

  if (bonus <= 0) return base;
  const score = Math.min(100, base.score + bonus);
  const priority: VocPriority = vocPriorityFromScore(score);
  return { score, priority, reasons: [...new Set(reasons)].slice(0, 10) };
}
