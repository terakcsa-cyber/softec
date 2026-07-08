const TWENTY_FOUR_H_MS = 24 * 60 * 60 * 1000;

/** DD.MM.YYYY в полях publication_date / last_upd_date БДУ. */
export const BDU_DD_MM_YYYY_SQL_REGEX = "^\\d{2}\\.\\d{2}\\.\\d{4}$";

/**
 * Запись попала в «ленту ФСТЭК» за последние N часов: дата публикации или обновления в выгрузке.
 * Используется для дашборда и API (не путать с updated_at синка в нашей БД).
 */
export function sqlBduFstecAttentionWithinHours(alias: string, hours: number): string {
  const h = Math.max(1, Math.min(168, Math.floor(hours)));
  return `(
    (${alias}.publication_date ~ '${BDU_DD_MM_YYYY_SQL_REGEX}'
      AND to_timestamp(${alias}.publication_date, 'DD.MM.YYYY') >= now() - interval '${h} hours')
    OR (${alias}.last_upd_date ~ '${BDU_DD_MM_YYYY_SQL_REGEX}'
      AND to_timestamp(${alias}.last_upd_date, 'DD.MM.YYYY') >= now() - interval '${h} hours')
  )`;
}

/** Парсинг publication_date из БДУ (DD.MM.YYYY). */
export function parseBduPublicationMs(publicationDate: string | null | undefined): number | null {
  if (!publicationDate) return null;
  const m = /^(\d{2})\.(\d{2})\.(\d{4})$/.exec(publicationDate.trim());
  if (!m) return null;
  const t = Date.UTC(Number(m[3]), Number(m[2]) - 1, Number(m[1]));
  return Number.isFinite(t) ? t : null;
}

export function parseBduLastUpdMs(lastUpdDate: string | null | undefined): number | null {
  return parseBduPublicationMs(lastUpdDate);
}

export function isBduPublicationInLast24h(publicationDate: string | null | undefined): boolean {
  const t = parseBduPublicationMs(publicationDate);
  if (t == null) return false;
  return t >= Date.now() - TWENTY_FOUR_H_MS;
}

/** Публикация или last_upd_date ФСТЭК в скользящем окне (часы). */
export function isBduFstecAttentionWithinHours(
  publicationDate: string | null | undefined,
  lastUpdDate: string | null | undefined,
  hours = 24
): boolean {
  const windowMs = hours * 60 * 60 * 1000;
  const cutoff = Date.now() - windowMs;
  const pub = parseBduPublicationMs(publicationDate);
  const upd = parseBduLastUpdMs(lastUpdDate);
  return (pub != null && pub >= cutoff) || (upd != null && upd >= cutoff);
}
