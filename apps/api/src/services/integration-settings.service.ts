import { BadRequestException, Injectable } from "@nestjs/common";
import { randomUUID } from "node:crypto";
import {
  defaultNvdCatalogDoc,
  fingerprintNvdApiKey,
  getVulnContextLlmConfigFromEnv,
  getTextEngineSettingsFromEnv,
  mergeVulnContextLlmConfig,
  mergeTextEngineSettings,
  MPVM_DEFAULT_PDQL,
  MPVM_DEFAULT_INVENTORY_PDQL,
  NVD_CATALOG_SCAN_MODE,
  NVD_CATALOG_SETTINGS_KEY,
  normalizeNvdCatalogDoc,
  parseNvdCatalogDoc,
  catalogScanHeadIso,
  probeBduSourceReachability,
  resolveBduVulxmlUrl,
  verifyMpvmConnection,
  type MpvmClientConfig,
  type NvdCatalogDoc,
  type TextEngineSettings,
  type VulnContextLlmConfig
} from "@vuln-intel/shared";
import { DbService } from "./db.service.js";

type LlmProfileRow = {
  id: string;
  name: string;
  endpoint: string;
  apiKey?: string;
  model: string;
  promptVersion?: string;
};

type LlmDoc = { profiles: LlmProfileRow[]; activeId: string | null };
type TextEngineDoc = Partial<TextEngineSettings>;
type NvdDoc = { apiKey?: string };
type VulncheckDoc = { apiToken?: string };
type MpvmDoc = {
  enabled?: boolean;
  baseUrl?: string;
  username?: string;
  apiToken?: string;
  password?: string;
  clientSecret?: string;
  authPort?: number;
  tlsInsecure?: boolean;
  pdql?: string;
};
type TelegramDoc = {
  enabled?: boolean;
  botToken?: string;
  chatId?: string;
};

function isRecord(x: unknown): x is Record<string, unknown> {
  return Boolean(x) && typeof x === "object" && !Array.isArray(x);
}

@Injectable()
export class IntegrationSettingsService {
  constructor(private readonly db: DbService) {}

  private async readJson(key: string): Promise<Record<string, unknown>> {
    const r = await this.db.query<{ value: unknown }>(
      `SELECT value FROM app_integration_settings WHERE key = $1 LIMIT 1`,
      [key]
    );
    const v = r.rows[0]?.value;
    return isRecord(v) ? v : {};
  }

  private async writeJson(key: string, value: object): Promise<void> {
    await this.db.query(
      `INSERT INTO app_integration_settings (key, value, updated_at)
       VALUES ($1, $2::jsonb, now())
       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
      [key, JSON.stringify(value)]
    );
  }

  async getNvdCatalogDoc(): Promise<NvdCatalogDoc | null> {
    const raw = await this.readJson(NVD_CATALOG_SETTINGS_KEY);
    return parseNvdCatalogDoc(raw);
  }

  /** Запуск/продолжение каталога: всегда today→1999; pending — с текущего дня. */
  async requestNvdCatalogBackfill(apiKey: string): Promise<NvdCatalogDoc> {
    const fp = fingerprintNvdApiKey(apiKey);
    const existingRaw = await this.getNvdCatalogDoc();
    const existing = existingRaw ? normalizeNvdCatalogDoc(existingRaw) : null;
    const keyChanged = Boolean(existing?.keyFingerprint && existing.keyFingerprint !== fp);
    const continueDeep = !keyChanged && existing?.status === "running";

    const doc = defaultNvdCatalogDoc({
      status: continueDeep ? "running" : "pending",
      scanMode: NVD_CATALOG_SCAN_MODE,
      pubCursor: continueDeep ? existing!.pubCursor : catalogScanHeadIso(),
      requestedAt: new Date().toISOString(),
      keyFingerprint: fp,
      totalUpserted: keyChanged ? 0 : (existing?.totalUpserted ?? 0),
      startedAt: keyChanged ? undefined : existing?.startedAt,
      completedAt: undefined,
      lastWindowEnd: undefined,
      lastWindowStart: undefined
    });

    await this.writeJson(NVD_CATALOG_SETTINGS_KEY, doc);
    return doc;
  }

  private async getNvdCatalogProgress(): Promise<{
    status: NvdCatalogDoc["status"] | "idle";
    pubCursor: string | null;
    completedAt: string | null;
    totalUpserted: number | null;
    cveCount: number;
  }> {
    const doc = await this.getNvdCatalogDoc();
    const countR = await this.db.query<{ n: string }>(`SELECT count(*)::text AS n FROM cve`);
    const cveCount = Number(countR.rows[0]?.n ?? 0);
    if (!doc) {
      return { status: "idle", pubCursor: null, completedAt: null, totalUpserted: null, cveCount };
    }
    return {
      status: doc.status,
      pubCursor: doc.pubCursor ?? null,
      completedAt: doc.completedAt ?? null,
      totalUpserted: doc.totalUpserted ?? null,
      cveCount
    };
  }

  async getEffectiveLlmConfig(): Promise<VulnContextLlmConfig> {
    const base = getVulnContextLlmConfigFromEnv();
    const doc = (await this.readJson("llm")) as unknown as LlmDoc;
    const profiles = Array.isArray(doc.profiles) ? doc.profiles : [];
    const activeId = doc.activeId ? String(doc.activeId) : null;
    const pick = activeId ? profiles.find((p) => p && String(p.id) === activeId) : null;
    if (!pick || !String(pick.endpoint ?? "").trim() || !String(pick.model ?? "").trim()) return base;
    const patch: Partial<VulnContextLlmConfig> = {
      endpoint: String(pick.endpoint).trim(),
      model: String(pick.model).trim(),
      promptVersion: pick.promptVersion?.trim() || base.promptVersion
    };
    if (pick.apiKey !== undefined) patch.apiKey = pick.apiKey;
    return mergeVulnContextLlmConfig(base, patch);
  }

  async getTextEngineSettings(): Promise<TextEngineSettings> {
    const base = getTextEngineSettingsFromEnv();
    const doc = (await this.readJson("textEngine")) as unknown as TextEngineDoc;
    return mergeTextEngineSettings(base, doc);
  }

  async resolveNvdApiKey(): Promise<string | undefined> {
    const { key } = await this.getNvdKeyResolution();
    return key;
  }

  /** Приоритет как у ingest: ключ из UI (БД) → NVD_API_KEY в .env. */
  async getNvdKeyResolution(): Promise<{
    key: string | undefined;
    source: "db" | "env" | "none";
    hasDbKey: boolean;
    hasEnvKey: boolean;
  }> {
    const nvd = (await this.readJson("nvd")) as unknown as NvdDoc;
    const fromDb = typeof nvd.apiKey === "string" ? nvd.apiKey.trim() : "";
    const fromEnv = process.env.NVD_API_KEY?.trim() ?? "";
    if (fromDb) {
      return { key: fromDb, source: "db", hasDbKey: true, hasEnvKey: Boolean(fromEnv) };
    }
    if (fromEnv) {
      return { key: fromEnv, source: "env", hasDbKey: false, hasEnvKey: true };
    }
    return { key: undefined, source: "none", hasDbKey: false, hasEnvKey: false };
  }

  /** Проверка ключа NVD (переданный, из БД или .env). */
  async verifyNvdApiKey(apiKeyOverride?: string): Promise<{
    ok: boolean;
    status: number | null;
    apiKeyRejected: boolean;
    ms: number;
    error: string | null;
    keySource: "override" | "db" | "env" | "none";
    hasApiKey: boolean;
  }> {
    const resolution = await this.getNvdKeyResolution();
    const key =
      apiKeyOverride?.trim() ||
      resolution.key ||
      undefined;
    const keySource: "override" | "db" | "env" | "none" = apiKeyOverride?.trim()
      ? "override"
      : resolution.source;

    const endpoint =
      process.env.NVD_API_BASE?.trim() || "https://services.nvd.nist.gov/rest/json/cves/2.0";
    const started = Date.now();
    const ac = new AbortController();
    const timeoutMs = Math.max(3000, Math.min(25_000, Number(process.env.NVD_HEALTH_TIMEOUT_MS ?? 12_000)));
    const t = setTimeout(() => ac.abort(), timeoutMs);

    let status: number | null = null;
    let apiKeyRejected = false;
    let error: string | null = null;

    try {
      const url = new URL(endpoint);
      const end = new Date();
      const start = new Date(end.getTime() - 60 * 60 * 1000);
      url.searchParams.set("lastModStartDate", start.toISOString());
      url.searchParams.set("lastModEndDate", end.toISOString());
      url.searchParams.set("resultsPerPage", "1");
      url.searchParams.set("startIndex", "0");

      const headers: Record<string, string> = { accept: "application/json" };
      if (key) headers.apiKey = key;
      let res = await fetch(url.toString(), { method: "GET", headers, signal: ac.signal });
      status = res.status;
      if (res.status === 404 && key) {
        apiKeyRejected = true;
        res = await fetch(url.toString(), {
          method: "GET",
          headers: { accept: "application/json" },
          signal: ac.signal
        });
        status = res.status;
      }
      const ok = res.status === 200;
      if (!ok) error = `HTTP ${res.status}`;
      else if (apiKeyRejected) {
        error =
          "Ключ отклонён NVD (HTTP 404). Запрос без ключа прошёл — замените ключ (https://nvd.nist.gov/developers/request-an-api-key).";
      }
      return {
        ok,
        status,
        apiKeyRejected,
        ms: Date.now() - started,
        error,
        keySource,
        hasApiKey: Boolean(key)
      };
    } catch (e) {
      return {
        ok: false,
        status,
        apiKeyRejected,
        ms: Date.now() - started,
        error: e instanceof Error ? e.message : String(e),
        keySource,
        hasApiKey: Boolean(key)
      };
    } finally {
      clearTimeout(t);
    }
  }

  private async getNvdWatermarkMeta(): Promise<{
    ts: string | null;
    processed: number | null;
    modifiedStart: string | null;
    modifiedEnd: string | null;
    partial: boolean;
  }> {
    const r = await this.db.query<{ ts: string | null; metadata: unknown }>(
      `SELECT to_char(ts AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS ts, metadata
         FROM audit_log
        WHERE action = 'nvd.watermark'
          AND NULLIF(TRIM(metadata->>'modifiedEnd'), '') IS NOT NULL
          AND COALESCE(metadata->>'reason', '') NOT IN ('bootstrap after fix')
     ORDER BY (metadata->>'modifiedEnd')::timestamptz DESC, ts DESC
        LIMIT 1`
    );
    const row = r.rows[0];
    const meta = isRecord(row?.metadata) ? row.metadata : {};
    const processed = typeof meta.processed === "number" ? meta.processed : Number(meta.processed);
    return {
      ts: row?.ts ?? null,
      processed: Number.isFinite(processed) ? processed : null,
      modifiedStart:
        typeof meta.modifiedStart === "string" && meta.modifiedStart.trim()
          ? meta.modifiedStart.trim()
          : null,
      modifiedEnd:
        typeof meta.modifiedEnd === "string" && meta.modifiedEnd.trim()
          ? meta.modifiedEnd.trim()
          : null,
      partial: meta.partial === true
    };
  }

  private async getNvdLastAttempt(): Promise<{ processed: number | null; at: string | null }> {
    const r = await this.db.query<{ ts: string | null; metadata: unknown }>(
      `SELECT to_char(ts AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS ts, metadata
         FROM audit_log
        WHERE action = 'nvd.watermark'
     ORDER BY ts DESC
        LIMIT 1`
    );
    const meta = isRecord(r.rows[0]?.metadata) ? r.rows[0].metadata : {};
    const processed = typeof meta.processed === "number" ? meta.processed : Number(meta.processed);
    return {
      at: r.rows[0]?.ts ?? null,
      processed: Number.isFinite(processed) ? processed : null
    };
  }

  private async getNvdLastIngestActivity(): Promise<{ at: string | null }> {
    const r = await this.db.query<{ ts: string | null }>(
      `SELECT to_char(MAX(ts) AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS ts
         FROM audit_log
        WHERE action IN ('nvd.watermark', 'nvd.pub_sync', 'nvd.pub_catchup', 'nvd.catalog_backfill', 'nvd.catalog_complete')`
    );
    return { at: r.rows[0]?.ts ?? null };
  }

  /** Lightweight NVD API probe (same surface as LLM in GET /stats/queue). */
  async probeNvdHealth() {
    const resolution = await this.getNvdKeyResolution();
    const verify = await this.verifyNvdApiKey();
    const endpoint =
      process.env.NVD_API_BASE?.trim() || "https://services.nvd.nist.gov/rest/json/cves/2.0";
    const watermark = await this.getNvdWatermarkMeta();
    const catalog = await this.getNvdCatalogProgress();
    const lastAttempt = await this.getNvdLastAttempt();
    const lastActivity = await this.getNvdLastIngestActivity();
    const pollMs = Number(process.env.NVD_POLL_INTERVAL_MS ?? 15 * 60 * 1000);
    const staleMs = Math.max(pollMs * 2, 30 * 60 * 1000);

    let ingestStale = true;
    const activityAt = lastActivity.at ?? lastAttempt.at;
    if (activityAt) {
      const age = Date.now() - new Date(activityAt).getTime();
      ingestStale = !Number.isFinite(age) || age > staleMs;
    }
    const ingestHealthy = !ingestStale;
    const catalogActive = catalog.status === "pending" || catalog.status === "running";

    const apiProbeOk = verify.ok;
    const apiStatus = verify.status;
    const apiError = verify.error;
    const apiKeyRejected = verify.apiKeyRejected;
    const ms = verify.ms;
    const ok = apiProbeOk || ingestHealthy;
    let error: string | null = null;
    if (!apiProbeOk) {
      error = apiError;
      if (ingestHealthy) {
        error = `${apiError ?? "API недоступен"} (ingest активен — проверка API по таймауту, это не блокирует синхронизацию)`;
      }
    }

    return {
      configured: true,
      ok,
      apiProbeOk,
      endpoint,
      ms,
      status: apiStatus,
      hasApiKey: Boolean(resolution.key),
      activeKeySource: resolution.source,
      apiKeyRejected,
      watermarkTs: watermark.ts,
      lastProcessed: watermark.processed,
      lastAttemptProcessed: lastAttempt.processed,
      watermarkStart: watermark.modifiedStart,
      watermarkEnd: watermark.modifiedEnd,
      watermarkPartial: watermark.partial,
      ingestStale,
      ingestStaleHint: ingestStale
        ? "Долго нет записи watermark ingest — проверьте apps/ingest (docker + NVD_PAGE_SLEEP_MS=6500)."
        : null,
      catalogStatus: catalog.status,
      catalogActive,
      catalogPubCursor: catalog.pubCursor,
      catalogCveCount: catalog.cveCount,
      catalogTotalUpserted: catalog.totalUpserted,
      catalogCompletedAt: catalog.completedAt,
      error: ok ? (apiProbeOk ? null : error) : error ?? ingestStale ? "Ingest устарел" : "NVD недоступен"
    };
  }

  private async getBduLastIngest(): Promise<{
    at: string | null;
    records: number | null;
    maxBduId: string | null;
    sourceUrl: string | null;
    usedFallback: boolean | null;
  }> {
    const r = await this.db.query<{ ts: string | null; metadata: unknown }>(
      `SELECT to_char(ts AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS ts, metadata
         FROM audit_log
        WHERE action = 'bdu.ingest'
     ORDER BY ts DESC
        LIMIT 1`
    );
    const meta = isRecord(r.rows[0]?.metadata) ? r.rows[0].metadata : {};
    const records = typeof meta.records === "number" ? meta.records : Number(meta.records);
    return {
      at: r.rows[0]?.ts ?? null,
      records: Number.isFinite(records) ? records : null,
      maxBduId: typeof meta.maxBduId === "string" ? meta.maxBduId : null,
      sourceUrl: typeof meta.sourceUrl === "string" ? meta.sourceUrl : null,
      usedFallback: meta.usedFallback === true
    };
  }

  /** Доступность bdu.fstec.ru и свежесть ingest (аналог NVD в GET /stats/queue). */
  async probeBduHealth() {
    const sourceUrl = resolveBduVulxmlUrl();
    const timeoutMs = Math.max(800, Math.min(15_000, Number(process.env.BDU_HEALTH_TIMEOUT_MS ?? 6000)));
    const probe = await probeBduSourceReachability(timeoutMs);
    const lastIngest = await this.getBduLastIngest();

    const stats = await this.db.query<{
      n: string;
      updated: string | null;
      max_id: string | null;
      max_pub: string | null;
    }>(
      `SELECT
         COUNT(*)::text AS n,
         to_char(MAX(updated_at) AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated,
         MAX(bdu_id) AS max_id,
         to_char(
           MAX(to_timestamp(publication_date, 'DD.MM.YYYY')) AT TIME ZONE 'UTC',
           'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
         ) AS max_pub
       FROM bdu_vuln
      WHERE publication_date ~ '^\\d{2}\\.\\d{2}\\.\\d{4}$'`
    );
    const links = await this.db.query<{ n: string }>(`SELECT COUNT(*)::text AS n FROM cve_bdu_link`);

    const pollMs = Number(process.env.BDU_POLL_INTERVAL_MS ?? 30 * 60 * 1000);
    const staleMs = Math.max(pollMs * 2, 6 * 60 * 60 * 1000);

    let ingestStale = true;
    const ingestAt = lastIngest.at ?? stats.rows[0]?.updated ?? null;
    if (ingestAt) {
      const age = Date.now() - new Date(ingestAt).getTime();
      ingestStale = !Number.isFinite(age) || age > staleMs;
    }
    const ingestHealthy = !ingestStale && Number(stats.rows[0]?.n ?? 0) > 0;
    const ok = (probe.ok || ingestHealthy) && Number(stats.rows[0]?.n ?? 0) > 0;

    let error: string | null = null;
    if (!probe.ok) {
      error = probe.error;
      if (ingestHealthy) {
        error = `${probe.error ?? "Источник недоступен"} (в БД есть свежие данные — проверка URL не блокирует работу)`;
      }
    }
    if (Number(stats.rows[0]?.n ?? 0) === 0) {
      error = error ?? "Таблица bdu_vuln пуста — запустите ingest (BDU_TLS_INSECURE=true при ошибке TLS)";
    }

    return {
      configured: true,
      ok,
      sourceProbeOk: probe.ok,
      endpoint: sourceUrl,
      ms: probe.ms,
      status: probe.status,
      tlsInsecure: probe.tlsInsecure,
      recordCount: Number(stats.rows[0]?.n ?? 0),
      cveLinkCount: Number(links.rows[0]?.n ?? 0),
      maxBduId: stats.rows[0]?.max_id ?? null,
      maxPublicationAt: stats.rows[0]?.max_pub ?? null,
      dbUpdatedAt: stats.rows[0]?.updated ?? null,
      lastIngestAt: lastIngest.at,
      lastIngestRecords: lastIngest.records,
      lastIngestMaxBduId: lastIngest.maxBduId,
      lastIngestSourceUrl: lastIngest.sourceUrl,
      lastIngestUsedFallback: lastIngest.usedFallback,
      ingestStale,
      ingestStaleHint: ingestStale
        ? "Долго нет bdu.ingest в audit_log — проверьте apps/ingest (BDU_INGEST_ENABLED, BDU_TLS_INSECURE, сеть до bdu.fstec.ru)."
        : null,
      error: ok ? (probe.ok ? null : error) : error ?? (ingestStale ? "BDU ingest устарел" : "BDU недоступен")
    };
  }

  async getUiState() {
    const base = getVulnContextLlmConfigFromEnv();
    const doc = (await this.readJson("llm")) as unknown as LlmDoc;
    const profilesRaw = Array.isArray(doc.profiles) ? doc.profiles : [];
    const profiles = profilesRaw
      .filter((p) => p && typeof p === "object")
      .map((p) => {
        const row = p as LlmProfileRow;
        const key = typeof row.apiKey === "string" ? row.apiKey.trim() : "";
        return {
          id: String(row.id ?? ""),
          name: String(row.name ?? ""),
          endpoint: String(row.endpoint ?? ""),
          hasApiKey: key.length > 0,
          model: String(row.model ?? ""),
          promptVersion: String(row.promptVersion ?? "v1")
        };
      })
      .filter((p) => p.id);

    const resolution = await this.getNvdKeyResolution();
    const catalog = await this.getNvdCatalogProgress();
    const mpvm = await this.getMpvmUiState();
    const telegram = await this.getTelegramUiState();
    const vulncheck = await this.getVulncheckUiState();
    const textEngine = await this.getTextEngineSettings();

    return {
      textEngine,
      llm: {
        profiles,
        activeId: doc.activeId ? String(doc.activeId) : null,
        envFallback: {
          endpoint: base.endpoint,
          model: base.model,
          hasApiKey: Boolean(base.apiKey?.trim())
        }
      },
      nvd: {
        hasDbKey: resolution.hasDbKey,
        hasEnvKey: resolution.hasEnvKey,
        activeKeySource: resolution.source,
        catalogStatus: catalog.status,
        catalogCveCount: catalog.cveCount,
        catalogPubCursor: catalog.pubCursor
      },
      vulncheck,
      mpvm,
      telegram
    };
  }

  async getVulncheckUiState() {
    const doc = (await this.readJson("vulncheck")) as unknown as VulncheckDoc;
    const fromDb = typeof doc.apiToken === "string" ? doc.apiToken.trim() : "";
    const fromEnv = process.env.VULNCHECK_API_TOKEN?.trim() ?? "";
    const last = await this.db.query<{ ts: string | null; metadata: unknown }>(
      `SELECT to_char(ts AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS ts, metadata
         FROM audit_log WHERE action = 'vulncheck.kev.ingest' ORDER BY ts DESC LIMIT 1`
    );
    const meta = isRecord(last.rows[0]?.metadata) ? last.rows[0].metadata : {};
    const kevCount = await this.db.query<{ n: string }>(`SELECT count(*)::text AS n FROM vulncheck_kev`);
    return {
      hasDbToken: fromDb.length > 0,
      hasEnvToken: fromEnv.length > 0,
      activeTokenSource: fromDb ? ("db" as const) : fromEnv ? ("env" as const) : ("none" as const),
      kevCount: Number(kevCount.rows[0]?.n ?? 0),
      lastIngestAt: last.rows[0]?.ts ?? null,
      lastIngestItems: typeof meta.items === "number" ? meta.items : Number(meta.items) || null
    };
  }

  async getTelegramDoc(): Promise<TelegramDoc> {
    return (await this.readJson("telegram")) as unknown as TelegramDoc;
  }

  async getTelegramUiState() {
    const doc = await this.getTelegramDoc();
    const token = typeof doc.botToken === "string" ? doc.botToken.trim() : "";
    const chatId = typeof doc.chatId === "string" ? doc.chatId.trim() : "";
    const last = await this.db.query<{ ts: string | null; metadata: unknown }>(
      `SELECT to_char(ts AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS ts, metadata
         FROM audit_log WHERE action = 'telegram.post' ORDER BY ts DESC LIMIT 1`
    );
    const meta = isRecord(last.rows[0]?.metadata) ? last.rows[0].metadata : {};
    return {
      enabled: doc.enabled !== false && Boolean(token && chatId),
      hasBotToken: token.length > 0,
      chatId: chatId.length > 0 ? chatId : "",
      lastPostAt: last.rows[0]?.ts ?? null,
      lastPostIdentifier: typeof meta.identifier === "string" ? meta.identifier : null
    };
  }

  private async getMpvmLastSync(): Promise<{
    at: string | null;
    fetched: number | null;
    error: string | null;
  }> {
    const r = await this.db.query<{ ts: string | null; metadata: unknown }>(
      `SELECT to_char(ts AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS ts, metadata
         FROM audit_log
        WHERE action = 'mpvm.sync'
     ORDER BY ts DESC
        LIMIT 1`
    );
    const meta = isRecord(r.rows[0]?.metadata) ? r.rows[0].metadata : {};
    const fetched = typeof meta.fetched === "number" ? meta.fetched : Number(meta.fetched);
    return {
      at: r.rows[0]?.ts ?? null,
      fetched: Number.isFinite(fetched) ? fetched : null,
      error: typeof meta.error === "string" ? meta.error : null
    };
  }

  async getMpvmUiState() {
    const doc = (await this.readJson("mpvm")) as unknown as MpvmDoc;
    const baseUrl = typeof doc.baseUrl === "string" ? doc.baseUrl.trim() : "";
    const token = typeof doc.apiToken === "string" ? doc.apiToken.trim() : "";
    const password = typeof doc.password === "string" ? doc.password.trim() : "";
    const clientSecret = typeof doc.clientSecret === "string" ? doc.clientSecret.trim() : "";
    const countR = await this.db.query<{ n: string }>(`SELECT COUNT(*)::text AS n FROM mpvm_asset`);
    const softwareR = await this.db.query<{ n: string }>(`SELECT COUNT(*)::text AS n FROM mpvm_asset_software`);
    const vulnR = await this.db.query<{ n: string }>(`SELECT COUNT(*)::text AS n FROM mpvm_asset_vulnerability`);
    const last = await this.getMpvmLastSync();
    return {
      enabled: doc.enabled !== false && Boolean(baseUrl),
      baseUrl,
      username: typeof doc.username === "string" ? doc.username : "",
      hasApiToken: token.length > 0,
      hasPassword: password.length > 0,
      hasClientSecret: clientSecret.length > 0,
      authPort: typeof doc.authPort === "number" ? doc.authPort : 3334,
      tlsInsecure: doc.tlsInsecure === true,
      pdql:
        typeof doc.pdql === "string" && doc.pdql.trim() && doc.pdql.trim() !== MPVM_DEFAULT_PDQL
          ? doc.pdql.trim()
          : MPVM_DEFAULT_INVENTORY_PDQL,
      assetCount: Number(countR.rows[0]?.n ?? 0),
      softwareCount: Number(softwareR.rows[0]?.n ?? 0),
      vulnerabilityCount: Number(vulnR.rows[0]?.n ?? 0),
      lastSyncAt: last.at,
      lastSyncFetched: last.fetched,
      lastSyncError: last.error
    };
  }

  async getMpvmClientConfig(): Promise<MpvmClientConfig | null> {
    const doc = (await this.readJson("mpvm")) as unknown as MpvmDoc;
    const baseUrl = typeof doc.baseUrl === "string" ? doc.baseUrl.trim() : "";
    if (!baseUrl || doc.enabled === false) return null;
    const apiToken = typeof doc.apiToken === "string" ? doc.apiToken.trim() : "";
    const password = typeof doc.password === "string" ? doc.password.trim() : "";
    const clientSecret = typeof doc.clientSecret === "string" ? doc.clientSecret.trim() : "";
    const username = typeof doc.username === "string" ? doc.username.trim() : "";
    if (!apiToken && !(username && password && clientSecret)) return null;
    return {
      baseUrl,
      username: username || undefined,
      apiToken: apiToken || undefined,
      password: password || undefined,
      clientSecret: clientSecret || undefined,
      authPort: typeof doc.authPort === "number" ? doc.authPort : 3334,
      tlsInsecure: doc.tlsInsecure === true,
      pdql:
        typeof doc.pdql === "string" && doc.pdql.trim() && doc.pdql.trim() !== MPVM_DEFAULT_PDQL
          ? doc.pdql.trim()
          : MPVM_DEFAULT_INVENTORY_PDQL,
      timeoutMs: Math.max(10_000, Math.min(120_000, Number(process.env.MPVM_HTTP_TIMEOUT_MS ?? 90_000)))
    };
  }

  async verifyMpvm(overrides?: Partial<MpvmClientConfig>) {
    const saved = await this.getMpvmClientConfig();
    const doc = (await this.readJson("mpvm")) as unknown as MpvmDoc;
    const baseUrl =
      overrides?.baseUrl?.trim() ||
      saved?.baseUrl ||
      (typeof doc.baseUrl === "string" ? doc.baseUrl.trim() : "");
    const apiToken =
      overrides?.apiToken?.trim() ||
      saved?.apiToken ||
      (typeof doc.apiToken === "string" ? doc.apiToken.trim() : "");
    if (!baseUrl) {
      return { ok: false, ms: 0, error: "Укажите URL MP VM", assetSample: 0, pdql: MPVM_DEFAULT_PDQL };
    }
    if (!apiToken && !overrides?.password && !saved?.password) {
      return { ok: false, ms: 0, error: "Укажите API-токен", assetSample: 0, pdql: MPVM_DEFAULT_PDQL };
    }
    const cfg: MpvmClientConfig = {
      baseUrl,
      username: overrides?.username ?? saved?.username ?? doc.username,
      apiToken: overrides?.apiToken ?? saved?.apiToken,
      password: overrides?.password ?? saved?.password,
      clientSecret: overrides?.clientSecret ?? saved?.clientSecret,
      authPort: overrides?.authPort ?? saved?.authPort ?? 3334,
      tlsInsecure: overrides?.tlsInsecure ?? saved?.tlsInsecure ?? doc.tlsInsecure === true,
      pdql: overrides?.pdql ?? saved?.pdql,
      timeoutMs: saved?.timeoutMs
    };
    return verifyMpvmConnection(cfg);
  }

  async updateFromUi(body: unknown) {
    if (!isRecord(body)) throw new BadRequestException("Invalid body");

    if ("llm" in body) {
      const llmIn = body.llm;
      if (llmIn != null && !isRecord(llmIn)) throw new BadRequestException("llm must be an object");
      if (isRecord(llmIn)) {
        const profilesIn = llmIn.profiles;
        const activeIdIn = llmIn.activeId;
        if (profilesIn != null && !Array.isArray(profilesIn)) throw new BadRequestException("llm.profiles must be an array");
        if (activeIdIn != null && typeof activeIdIn !== "string" && activeIdIn !== null) {
          throw new BadRequestException("llm.activeId must be a string or null");
        }

        const existing = (await this.readJson("llm")) as unknown as LlmDoc;
        const existingById = new Map<string, LlmProfileRow>();
        for (const p of Array.isArray(existing.profiles) ? existing.profiles : []) {
          if (p && typeof p === "object" && String((p as LlmProfileRow).id)) {
            existingById.set(String((p as LlmProfileRow).id), p as LlmProfileRow);
          }
        }

        let nextProfiles: LlmProfileRow[] = Array.isArray(existing.profiles)
          ? existing.profiles.filter((p) => p && typeof p === "object").map((p) => ({ ...(p as LlmProfileRow) }))
          : [];

        if (Array.isArray(profilesIn)) {
          if (profilesIn.length > 24) throw new BadRequestException("Too many LLM profiles (max 24)");
          nextProfiles = [];
          for (const raw of profilesIn) {
            if (!isRecord(raw)) continue;
            const id = typeof raw.id === "string" && raw.id.trim() ? raw.id.trim() : randomUUID();
            const name = typeof raw.name === "string" ? raw.name.trim() : "";
            const endpoint = typeof raw.endpoint === "string" ? raw.endpoint.trim() : "";
            const model = typeof raw.model === "string" ? raw.model.trim() : "";
            const promptVersion =
              typeof raw.promptVersion === "string" && raw.promptVersion.trim()
                ? raw.promptVersion.trim()
                : "v1";
            if (!name) throw new BadRequestException("Each LLM profile needs a name");
            if (!endpoint) throw new BadRequestException("Each LLM profile needs an endpoint");
            if (!model) throw new BadRequestException("Each LLM profile needs a model");

            const prev = existingById.get(id);
            let apiKey: string | undefined;
            if ("apiKey" in raw) {
              if (raw.apiKey === null || raw.apiKey === undefined) apiKey = prev?.apiKey ?? "";
              else if (typeof raw.apiKey === "string") apiKey = raw.apiKey;
              else throw new BadRequestException("llm profile apiKey must be a string");
            } else {
              apiKey = prev?.apiKey ?? "";
            }

            nextProfiles.push({ id, name, endpoint, apiKey, model, promptVersion });
          }
        }

        let activeId: string | null =
          typeof existing.activeId === "string" && existing.activeId.trim() ? String(existing.activeId).trim() : null;
        if (nextProfiles.length === 0) activeId = null;
        else if (activeIdIn === null) activeId = null;
        else if (typeof activeIdIn === "string" && activeIdIn.trim()) {
          activeId = activeIdIn.trim();
          if (!nextProfiles.some((p) => p.id === activeId)) {
            throw new BadRequestException("llm.activeId must match one of the profiles");
          }
        }

        const doc: LlmDoc = { profiles: nextProfiles, activeId };
        await this.writeJson("llm", doc as object);
      }
    }

    if ("textEngine" in body) {
      const textIn = body.textEngine;
      if (textIn != null && !isRecord(textIn)) throw new BadRequestException("textEngine must be an object");
      if (isRecord(textIn)) {
        const current = await this.getTextEngineSettings();
        const next: TextEngineSettings = mergeTextEngineSettings(current, {
          textEngine: textIn.textEngine as TextEngineSettings["textEngine"],
          translateEndpoint:
            typeof textIn.translateEndpoint === "string"
              ? textIn.translateEndpoint.trim()
              : current.translateEndpoint
        });
        await this.writeJson("textEngine", next);
      }
    }

    let nvdVerification: Awaited<ReturnType<IntegrationSettingsService["verifyNvdApiKey"]>> | undefined;

    if ("nvd" in body) {
      const nvdIn = body.nvd;
      if (nvdIn != null && !isRecord(nvdIn)) throw new BadRequestException("nvd must be an object");
      if (isRecord(nvdIn) && "apiKey" in nvdIn) {
        const k = nvdIn.apiKey;
        if (k === null || k === undefined) {
          await this.db.query(`DELETE FROM app_integration_settings WHERE key = 'nvd'`);
          nvdVerification = await this.verifyNvdApiKey();
        } else if (typeof k === "string") {
          const trimmed = k.trim();
          if (!trimmed) {
            await this.db.query(`DELETE FROM app_integration_settings WHERE key = 'nvd'`);
            nvdVerification = await this.verifyNvdApiKey();
          } else {
            await this.writeJson("nvd", { apiKey: trimmed });
            nvdVerification = await this.verifyNvdApiKey(trimmed);
            if (nvdVerification.ok && !nvdVerification.apiKeyRejected) {
              await this.requestNvdCatalogBackfill(trimmed);
            }
          }
        } else throw new BadRequestException("nvd.apiKey must be a string or null");
      }
    }

    if ("vulncheck" in body) {
      const vcIn = body.vulncheck;
      if (vcIn != null && !isRecord(vcIn)) throw new BadRequestException("vulncheck must be an object");
      if (isRecord(vcIn) && "apiToken" in vcIn) {
        const t = vcIn.apiToken;
        if (t === null || t === undefined) {
          await this.db.query(`DELETE FROM app_integration_settings WHERE key = 'vulncheck'`);
        } else if (typeof t === "string") {
          const trimmed = t.trim();
          if (!trimmed) await this.db.query(`DELETE FROM app_integration_settings WHERE key = 'vulncheck'`);
          else await this.writeJson("vulncheck", { apiToken: trimmed });
        } else throw new BadRequestException("vulncheck.apiToken must be a string or null");
      }
    }

    if ("mpvm" in body) {
      const mpvmIn = body.mpvm;
      if (mpvmIn != null && !isRecord(mpvmIn)) throw new BadRequestException("mpvm must be an object");
      if (isRecord(mpvmIn)) {
        const existing = (await this.readJson("mpvm")) as unknown as MpvmDoc;
        const next: MpvmDoc = { ...existing };

        if ("enabled" in mpvmIn) next.enabled = mpvmIn.enabled !== false;
        if (typeof mpvmIn.baseUrl === "string") next.baseUrl = mpvmIn.baseUrl.trim();
        if (typeof mpvmIn.username === "string") next.username = mpvmIn.username.trim();
        if (typeof mpvmIn.pdql === "string") next.pdql = mpvmIn.pdql.trim();
        if (typeof mpvmIn.authPort === "number") next.authPort = mpvmIn.authPort;
        if ("tlsInsecure" in mpvmIn) next.tlsInsecure = mpvmIn.tlsInsecure === true;

        if ("apiToken" in mpvmIn) {
          if (mpvmIn.apiToken === null || mpvmIn.apiToken === undefined) delete next.apiToken;
          else if (typeof mpvmIn.apiToken === "string") {
            const t = mpvmIn.apiToken.trim();
            if (t) next.apiToken = t;
            else delete next.apiToken;
          } else throw new BadRequestException("mpvm.apiToken must be a string or null");
        }
        if ("password" in mpvmIn) {
          if (mpvmIn.password === null) delete next.password;
          else if (typeof mpvmIn.password === "string") {
            const p = mpvmIn.password.trim();
            if (p) next.password = p;
            else delete next.password;
          }
        }
        if ("clientSecret" in mpvmIn) {
          if (mpvmIn.clientSecret === null) delete next.clientSecret;
          else if (typeof mpvmIn.clientSecret === "string") {
            const s = mpvmIn.clientSecret.trim();
            if (s) next.clientSecret = s;
            else delete next.clientSecret;
          }
        }

        if (!next.baseUrl?.trim()) {
          await this.db.query(`DELETE FROM app_integration_settings WHERE key = 'mpvm'`);
        } else {
          await this.writeJson("mpvm", next as object);
        }
      }
    }

    if ("telegram" in body) {
      const tgIn = body.telegram;
      if (tgIn != null && !isRecord(tgIn)) throw new BadRequestException("telegram must be an object");
      if (isRecord(tgIn)) {
        const existing = await this.getTelegramDoc();
        const next: TelegramDoc = { ...existing };
        if ("enabled" in tgIn) next.enabled = tgIn.enabled !== false;
        if (typeof tgIn.chatId === "string") next.chatId = tgIn.chatId.trim();
        if ("botToken" in tgIn) {
          if (tgIn.botToken === null || tgIn.botToken === undefined) delete next.botToken;
          else if (typeof tgIn.botToken === "string") {
            const t = tgIn.botToken.trim();
            if (t) next.botToken = t;
            else delete next.botToken;
          } else throw new BadRequestException("telegram.botToken must be a string or null");
        }
        if (!next.botToken?.trim() && !next.chatId?.trim()) {
          await this.db.query(`DELETE FROM app_integration_settings WHERE key = 'telegram'`);
        } else {
          await this.writeJson("telegram", next as object);
        }
      }
    }

    const state = await this.getUiState();
    return nvdVerification ? { ...state, nvdVerification } : state;
  }
}
