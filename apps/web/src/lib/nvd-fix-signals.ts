/** Клиентская копия логики из packages/shared/src/cve/nvd-fix-signals.ts */

export type NvdFixPatchLink = { label: string; url: string };

export type NvdFixSignals = {
  upgrade: string[];
  fixedIn: string[];
  mitigation: string[];
  remediation: string[];
  nextSteps: string[];
  patchLinks: NvdFixPatchLink[];
};

function asRecord(v: unknown): Record<string, unknown> | null {
  return v != null && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}

function str(v: unknown): string {
  return typeof v === "string" ? v.trim() : "";
}

function uniq(xs: string[], limit = 12): string[] {
  const out: string[] = [];
  for (const x of xs) {
    const v = x.replace(/\s+/g, " ").trim();
    if (!v) continue;
    if (out.some((y) => y.toLowerCase() === v.toLowerCase())) continue;
    out.push(v);
    if (out.length >= limit) break;
  }
  return out;
}

function productLabelFromCpe(criteria: string): string {
  const parts = criteria.split(":");
  if (parts.length < 5) return "компонент";
  const vendorRaw = parts[3] ?? "";
  const productRaw = parts[4] ?? "";
  const vendor = vendorRaw === "*" ? "" : vendorRaw.replace(/_/g, " ");
  const product = productRaw === "*" ? "" : productRaw.replace(/_/g, " ");
  if (vendor === "linux" && product === "linux kernel") return "Linux kernel";
  if (product && vendor) return `${vendor} ${product}`;
  return product || vendor || "компонент";
}

function extractVersionRanges(raw: Record<string, unknown>): string[] {
  const out: string[] = [];
  const configs = raw.configurations;
  const nodes: unknown[] = [];
  if (Array.isArray(configs)) {
    for (const cfg of configs) {
      const c = asRecord(cfg);
      if (c?.nodes && Array.isArray(c.nodes)) nodes.push(...c.nodes);
    }
  }

  for (const node of nodes) {
    const n = asRecord(node);
    const matches = n?.cpeMatch;
    if (!Array.isArray(matches)) continue;
    for (const m of matches) {
      const match = asRecord(m);
      if (!match || match.vulnerable === false) continue;
      const criteria = str(match.criteria);
      if (!criteria.startsWith("cpe:2.3:")) continue;
      const label = productLabelFromCpe(criteria);
      const start = str(match.versionStartIncluding) || str(match.versionStartExcluding);
      const end = str(match.versionEndExcluding) || str(match.versionEndIncluding);
      if (end) {
        out.push(
          start
            ? `Обновить ${label} до версии ${end} или новее (уязвимы ${start} – ${end})`
            : `Обновить ${label} до версии ${end} или новее`
        );
        out.push(`Исправлено в ${label} начиная с версии ${end}`);
      } else if (start) {
        out.push(`Проверить ${label}: уязвимы версии начиная с ${start}`);
      }
    }
  }
  return out;
}

function extractReferenceFixes(raw: Record<string, unknown>): {
  patchLinks: NvdFixPatchLink[];
  fixedIn: string[];
  mitigation: string[];
} {
  const patchLinks: NvdFixPatchLink[] = [];
  const fixedIn: string[] = [];
  const mitigation: string[] = [];
  const refs = raw.references;
  if (!Array.isArray(refs)) return { patchLinks, fixedIn, mitigation };

  let kernelPatch = 0;
  for (const item of refs) {
    const ref = asRecord(item);
    const url = str(ref?.url);
    if (!url) continue;
    const tags = Array.isArray(ref?.tags) ? ref!.tags.map((t) => String(t).toLowerCase()) : [];
    const isPatch = tags.includes("patch") || /git\.kernel\.org\/stable\/c\//i.test(url);
    if (isPatch) {
      kernelPatch++;
      patchLinks.push({
        label: kernelPatch === 1 ? "Патч Linux kernel (stable)" : `Патч Linux kernel #${kernelPatch}`,
        url
      });
      fixedIn.push(`Применить официальный патч ядра: ${url}`);
    }
    if (/msrc\.microsoft\.com/i.test(url)) {
      mitigation.push("Сверить рекомендации Microsoft Security Update Guide по этому CVE");
    }
  }

  if (kernelPatch > 0) {
    mitigation.push(
      "Обновить пакеты linux-image / linux-headers (или эквивалент) на хостах с уязвимым ядром и перезагрузить систему"
    );
  }

  return { patchLinks, fixedIn, mitigation };
}

export function extractFixSignalsFromNvdRaw(raw: unknown): NvdFixSignals {
  const o = asRecord(raw);
  if (!o) {
    return { upgrade: [], fixedIn: [], mitigation: [], remediation: [], nextSteps: [], patchLinks: [] };
  }

  const versionLines = extractVersionRanges(o);
  const { patchLinks, fixedIn: refFixed, mitigation: refMit } = extractReferenceFixes(o);

  const upgrade = versionLines.filter((l) => /^обновить/i.test(l));
  const fixedIn = [...versionLines.filter((l) => /^исправлено/i.test(l)), ...refFixed];
  const remediation = uniq([...upgrade, ...fixedIn, ...refMit], 10);
  const nextSteps: string[] = [];
  if (versionLines.length > 0) {
    nextSteps.push("Определить фактические версии уязвимого ПО на серверах и рабочих станциях");
    nextSteps.push("Сверить инвентарь с затронутыми диапазонами версий из NVD (CPE)");
  }
  if (patchLinks.length > 0) {
    nextSteps.push("Запланировать установку патчей ядра / обновление пакетов ОС в ближайшее окно обслуживания");
  }

  return {
    upgrade: uniq(upgrade, 8),
    fixedIn: uniq(fixedIn, 8),
    mitigation: uniq(refMit, 6),
    remediation,
    nextSteps: uniq(nextSteps, 6),
    patchLinks
  };
}

export function augmentEnrichmentWithNvdFixes(
  output: Record<string, unknown>,
  raw: unknown
): Record<string, unknown> {
  const signals = extractFixSignalsFromNvdRaw(raw);
  const hasContent =
    signals.upgrade.length +
      signals.fixedIn.length +
      signals.remediation.length +
      signals.patchLinks.length >
    0;
  if (!hasContent) return output;

  const remediation = Array.isArray(output.remediation)
    ? output.remediation.map(String).filter(Boolean)
    : [];
  const nextSteps = Array.isArray(output.nextSteps) ? output.nextSteps.map(String).filter(Boolean) : [];

  const mergedRemediation = uniq([...remediation, ...signals.remediation, ...signals.mitigation], 12);
  const mergedNext = uniq(
    [
      ...nextSteps,
      ...signals.nextSteps,
      ...(mergedRemediation.length > 0 ? [] : ["Проверить применимость CVE к вашему окружению"])
    ],
    8
  );

  const sources = Array.isArray(output.sources) ? [...output.sources] : [];
  for (const p of signals.patchLinks) {
    if (sources.some((s) => asRecord(s)?.url === p.url)) continue;
    sources.push({ url: p.url, label: p.label, kind: "patch" });
  }

  return {
    ...output,
    remediation: mergedRemediation.length > 0 ? mergedRemediation : remediation,
    nextSteps: mergedNext,
    sources: sources.length > 0 ? sources : output.sources,
    _nvd_fix_augmented: true
  };
}
