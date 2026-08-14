/** Нормализация статуса ФСТЭК: NBSP, регистр, пробелы. */
function norm(s: string): string {
  return s.toLowerCase().replace(/\u00a0/g, " ").replace(/\s+/g, " ").trim();
}

/**
 * Статус исправления БДУ.
 * Нельзя искать подстроку «имеется» — «не имеется» и формулировки без «имеется»
 * («Официальное исправление») дают ложный ответ.
 * true = исправление есть, false = подтверждённо нет, null = неизвестно.
 */
export function interpretBduFixStatus(fixStatus: string | null | undefined): boolean | null {
  const t = norm(fixStatus ?? "");
  if (!t) return null;

  if (
    /не\s+имеется|отсутств|недоступн|unavailable|нет\s+(официальн[а-яё]*\s+)?исправлен|исправление\s+не/.test(
      t
    )
  ) {
    return false;
  }

  if (
    /имеется|официальн[а-яё]*\s+исправлен|временн[а-яё]*\s+(исправлен|решен)|обходн|workaround|official|temporary|патч|исправлен[оаы]|доступн[оа]\s+(обновлен|исправлен|патч)/.test(
      t
    )
  ) {
    return true;
  }

  return null;
}

/**
 * Статус эксплуатации БДУ.
 * Нельзя искать «существует» через includes: «существование эксплойта не подтверждено»
 * содержит эту подстроку.
 */
export function interpretBduExploitStatus(exploitStatus: string | null | undefined): boolean | null {
  const t = norm(exploitStatus ?? "");
  if (!t) return null;

  if (/не\s+подтвержд|отсутств|не\s+существует|unproven|неизвестн/.test(t)) {
    return false;
  }

  if (
    /(^|[^а-яёa-z])существует([^а-яёa-z]|$)|эксплуатация\s+существу|functional|poc|proof[-\s]?of[-\s]?concept|эксплойт\s+(есть|известен)/.test(
      t
    )
  ) {
    return true;
  }

  return null;
}

export function resolveBduHasFix(opts: {
  fixStatus?: string | null;
  hasFix?: boolean | null;
}): boolean | null {
  const fromText = interpretBduFixStatus(opts.fixStatus);
  if (fromText != null) return fromText;
  if (typeof opts.hasFix === "boolean") return opts.hasFix;
  return null;
}

export function resolveBduHasExploit(opts: {
  exploitStatus?: string | null;
  hasExploit?: boolean | null;
}): boolean | null {
  const fromText = interpretBduExploitStatus(opts.exploitStatus);
  if (fromText != null) return fromText;
  if (typeof opts.hasExploit === "boolean") return opts.hasExploit;
  return null;
}
