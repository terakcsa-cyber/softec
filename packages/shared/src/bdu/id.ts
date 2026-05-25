/** Номер БДУ без префикса «BDU:», например `2025-10277`. */
export const BDU_ID_RE = /^\d{4}-\d+$/;

export const CVE_ID_RE = /^CVE-\d{4}-\d+$/i;

/** Нормализует `BDU:2025-10277`, `бду:2025-10277` или `2025-10277`. */
export function normalizeBduId(raw: string): string | null {
  const s = raw.trim();
  if (!s) return null;
  const prefixed = /^bdu\s*:\s*(\d{4}-\d+)$/i.exec(s);
  if (prefixed?.[1]) return prefixed[1];
  if (BDU_ID_RE.test(s)) return s;
  return null;
}

export function normalizeCveId(raw: string): string | null {
  const s = raw.trim().toUpperCase();
  return CVE_ID_RE.test(s) ? s : null;
}

/** Публичная карточка уязвимости на портале ФСТЭК. */
export function bduFstecUrl(bduId: string): string {
  const id = normalizeBduId(bduId) ?? bduId;
  return `https://bdu.fstec.ru/vul/${encodeURIComponent(id)}`;
}
