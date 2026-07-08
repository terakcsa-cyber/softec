/** Форматирование суточного Threat digest для Telegram (HTML). */

export type ThreatDigestHotCve = {
  cve_id: string;
  threat_score: number;
  signal_count: number;
  epss: number | null;
  cvss_base: number | null;
  risk_score: number | null;
  vckev_only: boolean;
  epss_spike: boolean;
  has_poc: boolean;
  has_public_exploit: boolean;
  cisa_kev: boolean;
  epss_delta_7d: number | null;
  vendor: string | null;
  product: string | null;
  signal_types: string[];
  /**
   * Короткая русская сводка (из enrichment_ai, если есть; иначе fallback).
   * Для PDF/оперативных отчётов.
   */
  summary_ru?: string | null;
  /** NVD description (может быть EN), компактно. */
  description?: string | null;
  /** CVSS v3.1 поля (для трендов по векторам). */
  cvss_av?: string | null;
  cvss_pr?: string | null;
  cvss_ui?: string | null;
  cvss_ac?: string | null;
  /** Последний сигнал за окно (UTC ISO). */
  latest_signal_at?: string | null;
  /** Примеры источников/рефов по сигналам. */
  sources?: Array<{
    signal_type: string;
    source: string;
    title: string | null;
    url: string | null;
    last_seen_at: string | null;
  }>;
  /** Рекомендации/меры (из enrichment_ai, если доступны). */
  remediation?: string[];
  next_steps?: string[];
  /** Класс уязвимости (CWE/категория) — если модель/базовый анализ смогли. */
  vuln_class?: string | null;
};

export type ThreatDigestCriticalEvent = {
  cve_id: string;
  priority: "P0" | "P1" | "P2";
  threat_score: number;
  epss: number | null;
  cvss_base: number | null;
  vendor: string | null;
  product: string | null;
  tags: string[];
  why: string;
  summary_ru: string | null;
};

export type ThreatDigestPayload = {
  generatedAt: string;
  windowHours: number;
  pulse: {
    signals: number;
    newSignals: number;
    updatedSignals: number;
    distinctCves: number;
    hotCves: number;
    vckevOnly: number;
    epssSpikes: number;
    cisaKev: number;
    withPoc: number;
    withPublicExploit: number;
    watchlistHits: number;
    newVckev24h: number;
    cvesPublished24h: number;
  };
  byType: Array<{ signal_type: string; count: number }>;
  vendors: Array<{ vendor: string; signal_count: number; cve_count: number; hot_count: number }>;
  hourly: Array<{ hour: string; count: number }>;
  hotCves: ThreatDigestHotCve[];
  /** Критические события за сутки (оперативка), отсортировано по P0->P2, затем threat_score. */
  criticalEvents?: ThreatDigestCriticalEvent[];
  /** Тренды по CVSS векторам (для PDF, рассчитано по hotCves/critical). */
  trends?: {
    attackVector: Array<{ key: string; label: string; count: number }>;
    privilegesRequired: Array<{ key: string; label: string; count: number }>;
    userInteraction: Array<{ key: string; label: string; count: number }>;
  };
  newVckev: Array<{ cve_id: string; cvss_base: number | null; epss: number | null; vckev_only: boolean }>;
  epssSpikeLeaders: Array<{ cve_id: string; epss: number | null; epss_delta_7d: number | null; cvss_base: number | null }>;
  watchlistCves: Array<{ cve_id: string; threat_score: number; vendor: string | null; label: string }>;
};

export const THREAT_SIGNAL_EMOJI: Record<string, string> = {
  vulncheck_kev: "🎯",
  metasploit: "💣",
  exploit_db: "🧨",
  nvd_exploit_tag: "🏷",
  poc_github: "🐙",
  poc_public: "🧪",
  nuclei: "⚡"
};

export const THREAT_SIGNAL_LABEL: Record<string, string> = {
  vulncheck_kev: "VulnCheck KEV",
  metasploit: "Metasploit",
  exploit_db: "Exploit-DB",
  nvd_exploit_tag: "NVD exploit",
  poc_github: "GitHub PoC",
  poc_public: "Public PoC",
  nuclei: "Nuclei"
};

const TG_MAX = 3900;

export function escapeTelegramHtml(raw: string): string {
  return String(raw ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function signalLabel(type: string): string {
  const emoji = THREAT_SIGNAL_EMOJI[type] ?? "📌";
  const label = THREAT_SIGNAL_LABEL[type] ?? type;
  return `${emoji} ${label}`;
}

function fmtPct(n?: number | null): string {
  if (typeof n !== "number" || !Number.isFinite(n)) return "—";
  return `${(n * 100).toFixed(1)}%`;
}

function fmtDelta(n?: number | null): string {
  if (typeof n !== "number" || !Number.isFinite(n)) return "";
  const sign = n > 0 ? "+" : "";
  return `${sign}${(n * 100).toFixed(1)}pp`;
}

function cvssEmoji(score: number | null): string {
  if (score == null) return "⚪";
  if (score >= 9) return "🔴";
  if (score >= 7) return "🟠";
  if (score >= 4) return "🟡";
  return "🟢";
}

function threatEmoji(score: number): string {
  if (score >= 75) return "🚨";
  if (score >= 55) return "🔥";
  if (score >= 35) return "⚠️";
  return "📍";
}

function nvdLink(cveId: string): string {
  const id = escapeTelegramHtml(cveId);
  const url = `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cveId)}`;
  return `<a href="${url}">${id}</a>`;
}

function barChart(counts: number[], width = 12): string {
  if (!counts.length) return "—";
  const max = Math.max(...counts, 1);
  const blocks = "▁▂▃▄▅▆▇█";
  return counts
    .map((c) => {
      const idx = Math.min(blocks.length - 1, Math.round((c / max) * (blocks.length - 1)));
      return blocks[idx] ?? "▁";
    })
    .join("");
}

function splitChunks(parts: string[], maxLen = TG_MAX): string[] {
  const out: string[] = [];
  let cur = "";
  for (const part of parts) {
    if (!part) continue;
    const next = cur ? `${cur}\n\n${part}` : part;
    if (next.length <= maxLen) {
      cur = next;
      continue;
    }
    if (cur) out.push(cur);
    if (part.length <= maxLen) {
      cur = part;
      continue;
    }
    // hard split long part by lines
    const lines = part.split("\n");
    cur = "";
    for (const line of lines) {
      const attempt = cur ? `${cur}\n${line}` : line;
      if (attempt.length > maxLen) {
        if (cur) out.push(cur);
        cur = line;
      } else {
        cur = attempt;
      }
    }
  }
  if (cur) out.push(cur);
  return out;
}

function formatHeader(payload: ThreatDigestPayload): string {
  const d = new Date(payload.generatedAt);
  const when = Number.isNaN(d.getTime())
    ? payload.generatedAt
    : d.toLocaleString("ru-RU", {
        day: "2-digit",
        month: "long",
        year: "numeric",
        hour: "2-digit",
        minute: "2-digit",
        timeZone: "Europe/Moscow"
      });
  return [
    "🛡️ <b>THREAT DIGEST · 24 часа</b>",
    `📅 ${escapeTelegramHtml(when)} MSK`,
    "━━━━━━━━━━━━━━━━━━━━"
  ].join("\n");
}

function formatPulse(payload: ThreatDigestPayload): string {
  const p = payload.pulse;
  const lines = [
    "📊 <b>PULSE</b>",
    `🔥 Сигналов: <b>${p.signals}</b> · CVE: <b>${p.distinctCves}</b>`,
    `🆕 Новых: <b>${p.newSignals}</b> · ♻️ Обновлённых: <b>${p.updatedSignals}</b>`,
    `🚨 Hot CVE: <b>${p.hotCves}</b> · 🎯 VCK-only: <b>${p.vckevOnly}</b>`,
    `📈 EPSS spike: <b>${p.epssSpikes}</b> · 🧨 Exploit: <b>${p.withPublicExploit}</b> · 🧪 PoC: <b>${p.withPoc}</b>`,
    `🇺🇸 CISA KEV: <b>${p.cisaKev}</b> · 🆕 VCK за сутки: <b>${p.newVckev24h}</b>`,
    `👁 Watchlist: <b>${p.watchlistHits}</b> · 📦 CVE опубликовано: <b>${p.cvesPublished24h}</b>`
  ];
  if (payload.hourly.length) {
    lines.push("");
    lines.push(`⏱ Активность (24ч): <code>${barChart(payload.hourly.map((h) => h.count))}</code>`);
  }
  return lines.join("\n");
}

function formatByType(payload: ThreatDigestPayload): string {
  if (!payload.byType.length) return "";
  const lines = ["🧭 <b>СИГНАЛЫ ПО ТИПАМ</b>"];
  for (const row of payload.byType.slice(0, 10)) {
    lines.push(`  ${signalLabel(row.signal_type)} · <b>${row.count}</b>`);
  }
  return lines.join("\n");
}

function formatVendors(payload: ThreatDigestPayload): string {
  if (!payload.vendors.length) return "";
  const lines = ["🏭 <b>TOP VENDORS</b>"];
  payload.vendors.slice(0, 10).forEach((v, i) => {
    const hot = v.hot_count > 0 ? ` · 🔥${v.hot_count}` : "";
    lines.push(
      `${i + 1}. <b>${escapeTelegramHtml(v.vendor)}</b> — ${v.signal_count} sig / ${v.cve_count} CVE${hot}`
    );
  });
  return lines.join("\n");
}

function formatHotCveBlock(title: string, rows: ThreatDigestHotCve[]): string {
  if (!rows.length) return "";
  const lines = [title];
  rows.forEach((row, i) => {
    const tags: string[] = [];
    if (row.cisa_kev) tags.push("🇺🇸 KEV");
    if (row.vckev_only) tags.push("🎯 VCK-only");
    if (row.epss_spike) tags.push("📈 EPSS↑");
    if (row.has_public_exploit) tags.push("🧨 Exploit");
    else if (row.has_poc) tags.push("🧪 PoC");
    const types = row.signal_types.slice(0, 3).map((t) => THREAT_SIGNAL_EMOJI[t] ?? "📌").join("");
    const epssLine =
      typeof row.epss === "number"
        ? `EPSS <b>${fmtPct(row.epss)}</b>${row.epss_delta_7d != null ? ` (${fmtDelta(row.epss_delta_7d)})` : ""}`
        : "EPSS —";
    lines.push("");
    lines.push(
      `${threatEmoji(row.threat_score)} <b>${i + 1}.</b> ${nvdLink(row.cve_id)} <code>[${row.threat_score}]</code>`
    );
    lines.push(`   ${cvssEmoji(row.cvss_base)} CVSS <b>${row.cvss_base ?? "—"}</b> · ${epssLine} · Risk <b>${row.risk_score ?? "—"}</b>`);
    if (tags.length) lines.push(`   ${tags.join("  ")}`);
    if (types) lines.push(`   ${types} · ${row.signal_count} сигн.`);
    if (row.vendor) {
      lines.push(`   🏢 ${escapeTelegramHtml(row.vendor)}${row.product ? ` / ${escapeTelegramHtml(row.product)}` : ""}`);
    }
  });
  return lines.join("\n");
}

function formatNewVck(payload: ThreatDigestPayload): string {
  if (!payload.newVckev.length) return "";
  const lines = ["🎯 <b>НОВЫЕ VULNCHECK KEV (24ч)</b>"];
  for (const row of payload.newVckev.slice(0, 12)) {
    lines.push(
      `• ${nvdLink(row.cve_id)} · CVSS ${row.cvss_base ?? "—"} · EPSS ${fmtPct(row.epss)}${row.vckev_only ? " · VCK-only" : ""}`
    );
  }
  return lines.join("\n");
}

function formatEpssLeaders(payload: ThreatDigestPayload): string {
  if (!payload.epssSpikeLeaders.length) return "";
  const lines = ["📈 <b>EPSS SPIKE LEADERS</b>"];
  for (const row of payload.epssSpikeLeaders.slice(0, 8)) {
    lines.push(
      `• ${nvdLink(row.cve_id)} · EPSS <b>${fmtPct(row.epss)}</b> (${fmtDelta(row.epss_delta_7d)}) · CVSS ${row.cvss_base ?? "—"}`
    );
  }
  return lines.join("\n");
}

function formatWatchlist(payload: ThreatDigestPayload): string {
  if (!payload.watchlistCves.length) return "";
  const lines = ["👁 <b>WATCHLIST HITS</b>"];
  for (const row of payload.watchlistCves.slice(0, 10)) {
    lines.push(
      `• ${nvdLink(row.cve_id)} <code>[${row.threat_score}]</code> · ${escapeTelegramHtml(row.label)}${row.vendor ? ` · ${escapeTelegramHtml(row.vendor)}` : ""}`
    );
  }
  return lines.join("\n");
}

function footer(part: number, total: number): string {
  return `\n<i>— Vuln Intel Platform · часть ${part}/${total}</i>`;
}

/** Собрать HTML-сообщения для Telegram (≤3900 символов каждое). */
export function formatThreatDailyDigestMessages(payload: ThreatDigestPayload): string[] {
  const hot = payload.hotCves;
  const mid = Math.ceil(hot.length / 2);
  const sections = [
    [formatHeader(payload), formatPulse(payload), formatByType(payload), formatVendors(payload)].filter(Boolean).join("\n\n"),
    formatHotCveBlock("🔥 <b>HOT CVE · TOP</b>", hot.slice(0, mid)),
    [
      hot.length > mid ? formatHotCveBlock("🔥 <b>HOT CVE · продолжение</b>", hot.slice(mid)) : "",
      formatNewVck(payload),
      formatEpssLeaders(payload),
      formatWatchlist(payload)
    ]
      .filter(Boolean)
      .join("\n\n")
  ].filter(Boolean);

  const chunks = splitChunks(sections);
  const total = chunks.length;
  return chunks.map((body, i) => `${body}${footer(i + 1, total)}`);
}

/** Plain-text fallback (без HTML). */
export function formatThreatDailyDigestPlain(payload: ThreatDigestPayload): string {
  return formatThreatDailyDigestMessages(payload)
    .join("\n\n---\n\n")
    .replace(/<[^>]+>/g, "")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">");
}
