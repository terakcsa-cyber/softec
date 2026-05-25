/** Экранирование для `LIKE ... ESCAPE '\\'` (литеральные `%`, `_`, `\`). */
export function escapePgLikePattern(s: string): string {
  return s.replace(/\\/g, "\\\\").replace(/%/g, "\\%").replace(/_/g, "\\_");
}
