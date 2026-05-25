/** Скользящее окно «новые CVE на дашборде» — по дате публикации в NVD, не по lastModified. */
export const CVE_HOT_WINDOW_HOURS = 24;

export function parseNvdTimestampIso(value: string | null | undefined): string | undefined {
  if (!value || typeof value !== "string") return undefined;
  const d = new Date(value.trim());
  if (Number.isNaN(d.getTime())) return undefined;
  return d.toISOString();
}

/** Дата публикации из NVD CVE 2.0 JSON (поле `published` на корне записи). */
export function extractNvdPublishedIso(raw: unknown): string | undefined {
  if (raw == null || typeof raw !== "object" || Array.isArray(raw)) return undefined;
  const published = (raw as Record<string, unknown>).published;
  if (typeof published !== "string") return undefined;
  return parseNvdTimestampIso(published);
}

export function isPublishedWithinHours(
  publishedAtIso: string | null | undefined,
  hours: number = CVE_HOT_WINDOW_HOURS,
  nowMs: number = Date.now()
): boolean {
  if (!publishedAtIso) return false;
  const t = new Date(publishedAtIso).getTime();
  if (Number.isNaN(t)) return false;
  return t >= nowMs - hours * 60 * 60 * 1000;
}

/** SQL: эффективная дата публикации (колонка + паспорт NVD в raw). */
export const SQL_EFFECTIVE_PUBLISHED_AT = `COALESCE(
  c.published_at,
  (NULLIF(TRIM(BOTH FROM c.raw->>'published'), ''))::timestamptz
)`;

/** Окно pubStart/pubEnd для NVD 2.0: скользящие часы + догон после простоя ingest. */
export function resolveNvdPubSyncWindow(opts: {
  now?: Date;
  maxPublishedAt?: Date | null;
  hotHours?: number;
  maxGapBackfillDays?: number;
  overlapMs?: number;
}): { pubStartIso: string; pubEndIso: string; reason: string } {
  const now = opts.now ?? new Date();
  const hotHours = Math.max(1, Math.min(72, opts.hotHours ?? 27));
  const maxGapDays = Math.max(1, Math.min(120, opts.maxGapBackfillDays ?? 21));
  const overlapMs = opts.overlapMs ?? 3_600_000;

  const pubEndIso = now.toISOString();
  const slidingStart = new Date(now.getTime() - hotHours * 60 * 60 * 1000);
  let pubStart = slidingStart;
  let reason = `sliding_${hotHours}h`;

  const maxPub = opts.maxPublishedAt;
  if (maxPub && !Number.isNaN(maxPub.getTime())) {
    const gapStart = new Date(maxPub.getTime() - overlapMs);
    const minGapStart = new Date(now.getTime() - maxGapDays * 24 * 60 * 60 * 1000);
    if (gapStart < pubStart) {
      pubStart = gapStart > minGapStart ? gapStart : minGapStart;
      reason = gapStart > minGapStart ? "gap_from_max_published" : `gap_capped_${maxGapDays}d`;
    }
  }

  return { pubStartIso: pubStart.toISOString(), pubEndIso, reason };
}
