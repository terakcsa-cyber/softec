import type { VocPriority } from "./voc-api";
import type { VocWatchlistRule } from "./voc-watchlist-api";

function norm(s: string): string {
  return s.trim().toLowerCase();
}

function priorityFromScore(score: number): VocPriority {
  if (score >= 85) return "p1";
  if (score >= 65) return "p2";
  if (score >= 40) return "p3";
  return "p4";
}

/** Client copy — без barrel `@vuln-intel/shared`. */
export function applyWatchlistBoostClient(
  base: { score: number; priority: VocPriority; reasons: string[] },
  ctx: { vendor?: string | null; product?: string | null; text?: string | null },
  rules: VocWatchlistRule[]
) {
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
    } else if (
      rule.kind === "product" &&
      (product === needle || vendorProduct.includes(needle) || product.includes(needle))
    ) {
      bonus += 12;
      reasons.push(`watchlist: ${tag}`);
    } else if (rule.kind === "keyword" && text.includes(needle)) {
      bonus += 10;
      reasons.push(`watchlist: ${tag}`);
    }
  }

  if (bonus <= 0) return base;
  const score = Math.min(100, base.score + bonus);
  return { score, priority: priorityFromScore(score), reasons: [...new Set(reasons)].slice(0, 10) };
}

export function hasWatchlistHit(item: { vocReasons: string[] }): boolean {
  return item.vocReasons.some((r) => r.startsWith("watchlist:"));
}

export function watchlistKindLabel(kind: VocWatchlistRule["kind"]): string {
  if (kind === "vendor") return "Вендор";
  if (kind === "product") return "Продукт";
  return "Ключевое слово";
}
