function dedupePairs(pairs: { bduId: string; cveId: string }[]): { bduId: string; cveId: string }[] {
  const seen = new Set<string>();
  const out: typeof pairs = [];
  for (const p of pairs) {
    const k = `${p.cveId}|${p.bduId}`;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(p);
  }
  return out;
}

function extractPairsFromLine(line: string): { bduId: string; cveId: string }[] {
  const pairs: { bduId: string; cveId: string }[] = [];
  const reForward = /(?:BDU|bdu):\s*(\d{4}-\d+)\s*[,\s;|]+\s*(CVE-\d{4}-\d+)/gi;
  const reBackward = /(CVE-\d{4}-\d+)\s*[,\s;|]+\s*(?:BDU|bdu):\s*(\d{4}-\d+)/gi;
  let m: RegExpExecArray | null;
  while ((m = reForward.exec(line)) !== null) {
    const bdu = m[1];
    const cve = m[2];
    if (bdu && cve) pairs.push({ bduId: bdu, cveId: cve.toUpperCase() });
  }
  while ((m = reBackward.exec(line)) !== null) {
    const cve = m[1];
    const bdu = m[2];
    if (bdu && cve) pairs.push({ bduId: bdu, cveId: cve.toUpperCase() });
  }
  const bdus = [...line.matchAll(/(?:BDU|bdu):\s*(\d{4}-\d+)/gi)].map((x) => x[1]);
  const cves = [...line.matchAll(/CVE-\d{4}-\d+/gi)].map((x) => x[0].toUpperCase());
  if (pairs.length === 0 && bdus.length === 1 && cves.length === 1) {
    const b0 = bdus[0];
    const c0 = cves[0];
    if (b0 !== undefined && c0 !== undefined) pairs.push({ bduId: b0, cveId: c0 });
  }
  if (pairs.length === 0 && bdus.length === cves.length && bdus.length > 1) {
    for (let i = 0; i < bdus.length; i++) {
      const b = bdus[i];
      const c = cves[i];
      if (b !== undefined && c !== undefined) pairs.push({ bduId: b, cveId: c });
    }
  }
  return pairs;
}

/**
 * Извлекает пары BDU id + CVE из текста поста ФСТЭК (одна строка или весь текст).
 * Форматы: `BDU:2025-10277 CVE-2025-54502`, с запятой, обратный порядок и т.д.
 */
export function extractBduCvePairs(text: string): { bduId: string; cveId: string }[] {
  const lines = text.split(/\r?\n/);
  const pairs: { bduId: string; cveId: string }[] = [];
  for (const line of lines) {
    pairs.push(...extractPairsFromLine(line));
  }
  let out = dedupePairs(pairs);
  const allBdus = [...text.matchAll(/(?:BDU|bdu):\s*(\d{4}-\d+)/gi)].map((x) => x[1]);
  const allCves = [...text.matchAll(/CVE-\d{4}-\d+/gi)].map((x) => x[0].toUpperCase());
  if (allBdus.length === 1 && allCves.length === 1) {
    const b0 = allBdus[0];
    const c0 = allCves[0];
    if (b0 !== undefined && c0 !== undefined) {
      const p = { bduId: b0, cveId: c0 };
      if (!out.some((x) => x.cveId === p.cveId && x.bduId === p.bduId)) {
        out = dedupePairs([...out, p]);
      }
    }
  }
  return out;
}
