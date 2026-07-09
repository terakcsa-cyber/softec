import { createHash } from "node:crypto";
import { Inject, Injectable, OnModuleInit } from "@nestjs/common";
import { v4 as uuidv4 } from "uuid";
import {
  QueueEventType,
  SQL_EFFECTIVE_PUBLISHED_AT,
  buildScoreEventsForCveIds,
  catalogBackfillActive,
  catalogReverseFloorReached,
  catalogScanHeadIso,
  defaultNvdCatalogDoc,
  extractNvdPublishedIso,
  extractVendorProductPairsFromCveRaw,
  fingerprintNvdApiKey,
  hot24ScoreHourBucket,
  hot24ScoreIdempotencyKey,
  initialReverseCatalogCursor,
  isPublishedWithinHours,
  listHot24CvesNeedingScore,
  publishScoreEvents,
  NVD_CATALOG_FLOOR_ISO,
  NVD_CATALOG_SCAN_MODE,
  NVD_CATALOG_SETTINGS_KEY,
  NVD_PUB_MAX_WINDOW_DAYS,
  normalizeNvdCatalogDoc,
  parseNvdCatalogDoc,
  parseNvdTimestampIso,
  resolveCatalogDeepEndMs,
  resolveNvdPubSyncWindow,
  resolveNvdCatalogTurboParams,
  stableJsonStringify,
  sha256Hex,
  type NvdCatalogDoc
} from "@vuln-intel/shared";
import { DbService } from "../services/db.service.js";
import { QueueService } from "../services/queue.service.js";

type NvdApiItem = {
  cve: any;
};

@Injectable()
export class NvdIngestJob implements OnModuleInit {
  /** Сериализуем запросы к NVD (pub-hot и lastMod не бьют rate limit параллельно). */
  private nvdApiChain: Promise<unknown> = Promise.resolve();
  /** После HTTP 404 с apiKey — не слать ключ снова, пока ключ не сменился (БД / .env). */
  private nvdApiKeyRejected = false;
  private nvdApiKeyFingerprint: string | null = null;

  constructor(
    @Inject(DbService) private readonly db: DbService,
    @Inject(QueueService) private readonly queue: QueueService
  ) {}

  private isNvdInvalidApiKeyResponse(status: number, text: string, messageHeader: string | null): boolean {
    if (status !== 404) return false;
    const detail = `${messageHeader ?? ""} ${text}`.toLowerCase();
    return detail.includes("invalid apikey") || detail.includes("invalid api key");
  }

  private withNvdApiLock<T>(fn: () => Promise<T>): Promise<T> {
    const next = this.nvdApiChain.then(fn, fn);
    this.nvdApiChain = next.catch(() => undefined);
    return next;
  }

  async onModuleInit() {
    if (!process.env.NVD_API_KEY?.trim()) {
      // eslint-disable-next-line no-console
      console.warn(
        "[ingest:nvd] NVD_API_KEY пуст — запросы к NVD 2.0 возможны, но лимиты жёстче. Ключ: https://nvd.nist.gov/developers/request-an-api-key"
      );
    }

    const intervalMs = Number(process.env.NVD_POLL_INTERVAL_MS ?? 15 * 60 * 1000);
    const initialDelayMs = Number(process.env.NVD_INITIAL_DELAY_MS ?? 12_000);

    setTimeout(() => {
      void this.bootstrapCatalogBackfill();
    }, Math.min(initialDelayMs, 8000));

    setTimeout(() => {
      this.runForever(intervalMs).catch((e) => {
        // eslint-disable-next-line no-console
        console.error("[ingest:nvd] runForever crashed — restarting loop in 30s", e);
        setTimeout(() => {
          this.runForever(intervalMs).catch((err) => {
            // eslint-disable-next-line no-console
            console.error("[ingest:nvd] runForever crashed again", err);
          });
        }, 30_000);
      });
    }, initialDelayMs);

    const pubHotOnStartMs = Number(process.env.NVD_PUB_HOT_SYNC_ON_START_MS ?? 0);
    if (pubHotOnStartMs > 0 && process.env.NVD_PUB_HOT_SYNC !== "false") {
      setTimeout(() => {
        this.syncPublishedHotWindow()
          .then(() => this.sweepHotWindowPipelines())
          .catch((e) => {
            // eslint-disable-next-line no-console
            console.error("[ingest:nvd] published hot-window sync on start failed", e);
          });
      }, pubHotOnStartMs);
    }

    const sweepOnStartMs = Number(process.env.HOT24_AI_SWEEP_ON_START_MS ?? 8_000);
    if (sweepOnStartMs > 0 && (process.env.HOT24_AI_SWEEP !== "false" || process.env.HOT24_SCORE_SWEEP !== "false")) {
      setTimeout(() => {
        this.sweepHotWindowPipelines().catch((e) => {
          // eslint-disable-next-line no-console
          console.error("[ingest:nvd] hot24h sweep on start failed", e);
        });
      }, sweepOnStartMs);
    }

    const sweepIntervalMs = Number(process.env.HOT24_AI_SWEEP_INTERVAL_MS ?? 0);
    if (sweepIntervalMs > 0 && (process.env.HOT24_AI_SWEEP !== "false" || process.env.HOT24_SCORE_SWEEP !== "false")) {
      setInterval(() => {
        this.sweepHotWindowPipelines().catch((e) => {
          // eslint-disable-next-line no-console
          console.error("[ingest:nvd] hot24h sweep interval failed", e);
        });
      }, sweepIntervalMs);
    }

    // Старше 24ч: по умолчанию не догоняем в фоне — только по открытию CVE в UI. Включить: BACKLOG_AI_SWEEP=true
    const backlogOnStartMs = Number(process.env.BACKLOG_AI_SWEEP_ON_START_MS ?? 20_000);
    if (backlogOnStartMs > 0 && process.env.BACKLOG_AI_SWEEP === "true") {
      setTimeout(() => {
        this.sweepBacklogEnrich().catch((e) => {
          // eslint-disable-next-line no-console
          console.error("[ingest:nvd] backlog AI sweep on start failed", e);
        });
      }, backlogOnStartMs);
    }

    const backlogIntervalMs = Number(process.env.BACKLOG_AI_SWEEP_INTERVAL_MS ?? 30_000);
    if (backlogIntervalMs > 0 && process.env.BACKLOG_AI_SWEEP === "true") {
      setInterval(() => {
        this.sweepBacklogEnrich().catch((e) => {
          // eslint-disable-next-line no-console
          console.error("[ingest:nvd] backlog AI sweep interval failed", e);
        });
      }, backlogIntervalMs);
    }
  }

  private async runForever(intervalMs: number) {
    // eslint-disable-next-line no-constant-condition
    while (true) {
      const startedAt = Date.now();
      let skipPollSleep = false;
      try {
        const catalogRemaining = await this.runCatalogBackfillBurst();
        if (catalogRemaining) {
          skipPollSleep = true;
          const turbo = await this.resolveCatalogTurboParams();
          if (turbo.burstPauseMs > 0) {
            await new Promise((r) => setTimeout(r, turbo.burstPauseMs));
          }
          continue;
        }

        // eslint-disable-next-line no-console
        console.log("[ingest:nvd] cycle started");
        await this.runOnce();
        // eslint-disable-next-line no-console
        console.log("[ingest:nvd] cycle completed");
      } catch (e) {
        // eslint-disable-next-line no-console
        console.error("NVD ingest failed", e);
      }
      if (!skipPollSleep) {
        const sleep = Math.max(5_000, intervalMs - (Date.now() - startedAt));
        await new Promise((r) => setTimeout(r, sleep));
      }
    }
  }

  private catalogTurboEnabled(): boolean {
    return process.env.NVD_CATALOG_TURBO !== "false";
  }

  private async resolveCatalogTurboParams() {
    const apiKey = await this.resolveNvdApiKey();
    const hasEffectiveApiKey = Boolean(this.effectiveNvdApiKey(apiKey));
    const base = resolveNvdCatalogTurboParams({
      turboEnabled: this.catalogTurboEnabled(),
      hasEffectiveApiKey
    });
    return {
      ...base,
      windowDays: Math.min(
        NVD_PUB_MAX_WINDOW_DAYS,
        Math.max(1, Number(process.env.NVD_CATALOG_WINDOW_DAYS ?? base.windowDays))
      ),
      windowsPerBurst: Math.max(
        1,
        Number(process.env.NVD_CATALOG_WINDOWS_PER_BURST ?? base.windowsPerBurst)
      ),
      burstPauseMs: Math.max(
        0,
        Number(process.env.NVD_CATALOG_BURST_PAUSE_MS ?? base.burstPauseMs)
      ),
      pageSleepMs: Math.max(
        0,
        Number(process.env.NVD_CATALOG_PAGE_SLEEP_MS ?? base.pageSleepMs)
      ),
      resultsPerPage: Math.max(
        20,
        Math.min(2000, Number(process.env.NVD_CATALOG_RESULTS_PER_PAGE ?? base.resultsPerPage))
      )
    };
  }

  private scoreFanoutHotOnly(): boolean {
    return process.env.NVD_FANOUT_SCORE_HOT_ONLY !== "false";
  }

  private fingerprintNvdApiKey(key?: string): string | null {
    if (!key?.trim()) return null;
    return createHash("sha256").update(key.trim()).digest("hex").slice(0, 16);
  }

  private async resolveNvdApiKey(): Promise<string | undefined> {
    let fromDb: string | undefined;
    try {
      const r = await this.db.query<{ value: unknown }>(
        `SELECT value FROM app_integration_settings WHERE key = 'nvd' LIMIT 1`
      );
      const v = r.rows[0]?.value as { apiKey?: string } | undefined;
      const k = v?.apiKey;
      if (typeof k === "string" && k.trim()) fromDb = k.trim();
    } catch {
      // table may not exist on very first boot before API migrations
    }
    const key = fromDb ?? process.env.NVD_API_KEY?.trim() ?? undefined;
    const fp = this.fingerprintNvdApiKey(key);
    if (fp !== this.nvdApiKeyFingerprint) {
      this.nvdApiKeyFingerprint = fp;
      this.nvdApiKeyRejected = false;
    }
    return key;
  }

  private effectiveNvdApiKey(apiKey?: string): string | undefined {
    return apiKey && !this.nvdApiKeyRejected ? apiKey : undefined;
  }

  private async runOnce() {
    const catalog = await this.readCatalogState();
    if (catalogBackfillActive(catalog)) {
      // eslint-disable-next-line no-console
      console.log("[ingest:nvd] skip incremental — catalog backfill in progress");
      return;
    }

    await this.repairPublishedAtFromRaw();

    const apiKey = await this.resolveNvdApiKey();
    const baseUrl = process.env.NVD_API_BASE ?? "https://services.nvd.nist.gov/rest/json/cves/2.0";

    const overlapMs = Number(process.env.NVD_WATERMARK_OVERLAP_MS ?? 120_000);
    const lastEnd = await this.getLatestWatermarkModifiedEnd();

    const sinceIso = lastEnd
      ? new Date(Math.max(0, new Date(lastEnd).getTime() - overlapMs)).toISOString()
      : new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString();

    const nowIso = new Date().toISOString();
    const maxWindowHours = Math.max(
      1,
      Math.min(168, Number(process.env.NVD_WATERMARK_MAX_WINDOW_HOURS ?? 24))
    );
    const windowEndMs = Math.min(
      new Date(nowIso).getTime(),
      new Date(sinceIso).getTime() + maxWindowHours * 60 * 60 * 1000
    );
    const modEndIso = new Date(windowEndMs).toISOString();
    const windowChunked = windowEndMs < new Date(nowIso).getTime() - 60_000;

    if (new Date(sinceIso).getTime() >= windowEndMs) {
      // eslint-disable-next-line no-console
      console.log(`[ingest:nvd] skip: watermark window empty (${sinceIso} >= ${modEndIso})`);
      if (process.env.NVD_PUB_HOT_SYNC !== "false") {
        await this.syncPublishedHotWindow();
      }
      return;
    }

    let startIndex = 0;
    const resultsPerPage = Math.max(
      20,
      Math.min(2000, Number(process.env.NVD_RESULTS_PER_PAGE ?? 100))
    );
    let processed = 0;
    let syncComplete = true;
    let partialSync = false;
    const pageSleepMs = this.resolveNvdPageSleepMs(apiKey);
    const maxEmptyRetries = Number(process.env.NVD_EMPTY_PAGE_RETRIES ?? 12);
    let emptyRetries = 0;

    for (;;) {
      if (startIndex > 0 || emptyRetries > 0) {
        await new Promise((r) => setTimeout(r, pageSleepMs));
      }

      const url = new URL(baseUrl);
      url.searchParams.set("lastModStartDate", sinceIso);
      url.searchParams.set("lastModEndDate", modEndIso);
      url.searchParams.set("startIndex", String(startIndex));
      url.searchParams.set("resultsPerPage", String(resultsPerPage));

      const page: any = await this.withNvdApiLock(() => this.fetchJson(url.toString(), apiKey));
      const vulnerabilities = (page?.vulnerabilities ?? []) as NvdApiItem[];
      const totalResults = Number(page?.totalResults ?? vulnerabilities.length);

      if (vulnerabilities.length === 0 && startIndex < totalResults) {
        emptyRetries++;
        if (emptyRetries > maxEmptyRetries) {
          if (processed > 0) {
            partialSync = true;
            // eslint-disable-next-line no-console
            console.warn(
              `[ingest:nvd] partial sync: NVD returned empty at startIndex=${startIndex} totalResults=${totalResults} after ${processed} upserts — advancing watermark (API cap or rate limit)`
            );
            break;
          }
          if (startIndex === 0) {
            // eslint-disable-next-line no-console
            console.warn(
              `[ingest:nvd] empty incremental window (total=${totalResults}) after retries — advancing watermark with processed=0`
            );
            break;
          }
          syncComplete = false;
          // eslint-disable-next-line no-console
          console.error(
            `[ingest:nvd] empty page at startIndex=${startIndex} totalResults=${totalResults} — watermark not advanced`
          );
          break;
        }
        const emptySleepMs = Number(process.env.NVD_EMPTY_PAGE_SLEEP_MS ?? Math.max(pageSleepMs, 6000));
        // eslint-disable-next-line no-console
        console.warn(
          `[ingest:nvd] empty page (NVD rate limit?) startIndex=${startIndex} total=${totalResults} retry=${emptyRetries}/${maxEmptyRetries} sleep=${emptySleepMs}ms`
        );
        await new Promise((r) => setTimeout(r, emptySleepMs));
        continue;
      }
      emptyRetries = 0;

      for (const item of vulnerabilities) {
        const cveId = String(item?.cve?.id ?? "");
        if (!cveId.startsWith("CVE-")) continue;
        try {
          await this.upsertCveAndFanout({
            cveId,
            source: "nvd",
            raw: item.cve,
            publishedAt: item?.cve?.published,
            modifiedAt: item?.cve?.lastModified
          });
          processed++;
        } catch (e) {
          // eslint-disable-next-line no-console
          console.error(`[ingest:nvd] failed cve=${cveId}`, e);
        }
      }

      startIndex += vulnerabilities.length;
      if (startIndex >= totalResults) break;
    }

    if (partialSync && processed > 0) syncComplete = true;
    if (windowChunked && processed >= 0) syncComplete = true;

    // eslint-disable-next-line no-console
    console.log(
      `[ingest:nvd] processed=${processed} complete=${syncComplete} partial=${partialSync || windowChunked} window=${sinceIso}..${modEndIso}`
    );

    await this.backfillCvssBase();
    await this.sweepHotWindowPipelines();

    if (syncComplete) {
      await this.db.query(
        `INSERT INTO audit_log(actor_type, action, metadata)
         VALUES ('system', 'nvd.watermark', $1)`,
        [
          JSON.stringify({
            modifiedStart: sinceIso,
            modifiedEnd: modEndIso,
            processed,
            partial: partialSync || windowChunked
          })
        ]
      );
    }

    if (process.env.NVD_PUB_HOT_SYNC !== "false") {
      await this.syncPublishedHotWindow();
      await this.syncPublishedCatchUpFromWatermark();
    }
  }

  /** Последний modifiedEnd watermark (включая processed=0 — иначе ingest застревает на одном окне). */
  private async getLatestWatermarkModifiedEnd(): Promise<string | null> {
    const last = await this.db.query<{ modified_end: string | null }>(
      `SELECT NULLIF(TRIM(metadata->>'modifiedEnd'), '') AS modified_end
         FROM audit_log
        WHERE action = 'nvd.watermark'
          AND NULLIF(TRIM(metadata->>'modifiedEnd'), '') IS NOT NULL
     ORDER BY (metadata->>'modifiedEnd')::timestamptz DESC, ts DESC
        LIMIT 1`
    );
    return last.rows[0]?.modified_end ?? null;
  }

  /** NVD: без apiKey — 5 req / 30s; с ключом — 50 req / 30s. */
  private resolveNvdPageSleepMs(apiKey?: string): number {
    const configured = Number(process.env.NVD_PAGE_SLEEP_MS);
    if (Number.isFinite(configured) && configured > 0) return configured;
    return apiKey ? 6500 : 6000;
  }

  private async readCatalogState(): Promise<NvdCatalogDoc | null> {
    try {
      const r = await this.db.query<{ value: unknown }>(
        `SELECT value FROM app_integration_settings WHERE key = $1 LIMIT 1`,
        [NVD_CATALOG_SETTINGS_KEY]
      );
      const parsed = parseNvdCatalogDoc(r.rows[0]?.value);
      if (!parsed) return null;
      const normalized = normalizeNvdCatalogDoc(parsed);
      const migrated =
        parsed.scanMode !== normalized.scanMode ||
        parsed.pubCursor !== normalized.pubCursor ||
        parsed.status !== normalized.status;
      if (migrated) {
        await this.writeCatalogState(normalized);
        // eslint-disable-next-line no-console
        console.log(
          `[ingest:nvd] catalog state migrated to newest_first backEdge=${normalized.pubCursor}`
        );
      }
      return normalized;
    } catch {
      return null;
    }
  }

  private async writeCatalogState(doc: NvdCatalogDoc): Promise<void> {
    await this.db.query(
      `INSERT INTO app_integration_settings (key, value, updated_at)
       VALUES ($1, $2::jsonb, now())
       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
      [NVD_CATALOG_SETTINGS_KEY, JSON.stringify(doc)]
    );
  }

  private async catalogCompleteMinCve(): Promise<number> {
    return Math.max(10_000, Number(process.env.NVD_CATALOG_COMPLETE_MIN_CVE ?? 150_000));
  }

  private async bootstrapCatalogBackfill(): Promise<void> {
    if (process.env.NVD_CATALOG_BACKFILL === "false") return;
    const apiKey = await this.resolveNvdApiKey();

    const minComplete = Math.max(
      10_000,
      Number(process.env.NVD_CATALOG_COMPLETE_MIN_CVE ?? 150_000)
    );
    const countR = await this.db.query<{ n: string }>(`SELECT count(*)::text AS n FROM cve`);
    const cveCount = Number(countR.rows[0]?.n ?? 0);
    const doc = await this.readCatalogState();
    const fp = apiKey ? fingerprintNvdApiKey(apiKey) : "none";

    if (doc?.status === "complete" && cveCount >= minComplete) return;

    if (doc?.status === "complete" && cveCount < minComplete) {
      // eslint-disable-next-line no-console
      console.log(
        `[ingest:nvd] catalog reset (cve=${cveCount} < ${minComplete}) — restarting full backfill`
      );
      await this.writeCatalogState(
        defaultNvdCatalogDoc({
          status: "pending",
          pubCursor: initialReverseCatalogCursor(),
          keyFingerprint: fp,
          requestedAt: new Date().toISOString()
        })
      );
      return;
    }

    if (!doc && cveCount < minComplete) {
      await this.writeCatalogState(
        defaultNvdCatalogDoc({
          status: "pending",
          keyFingerprint: fp,
          requestedAt: new Date().toISOString()
        })
      );
      // eslint-disable-next-line no-console
      console.log(`[ingest:nvd] catalog bootstrap pending (cve=${cveCount})`);
    }
  }

  /** Полная загрузка каталога по pubStart/pubEnd (newest_first: от now() к 1999). */
  private async runCatalogBackfillBurst(): Promise<boolean> {
    if (process.env.NVD_CATALOG_BACKFILL === "false") return false;

    const apiKey = await this.resolveNvdApiKey();

    let doc = await this.readCatalogState();
    if (!catalogBackfillActive(doc)) {
      await this.bootstrapCatalogBackfill();
      doc = await this.readCatalogState();
    }
    if (!catalogBackfillActive(doc) || !doc) return false;

    const fp = apiKey ? fingerprintNvdApiKey(apiKey) : "none";
    if (doc.keyFingerprint && doc.keyFingerprint !== fp) {
      doc = defaultNvdCatalogDoc({
        status: "pending",
        pubCursor: initialReverseCatalogCursor(),
        keyFingerprint: fp,
        requestedAt: new Date().toISOString()
      });
      await this.writeCatalogState(doc);
    } else if (!doc.keyFingerprint) {
      doc.keyFingerprint = fp;
    }

    if (doc.status === "pending") {
      doc.status = "running";
      doc.startedAt = doc.startedAt ?? new Date().toISOString();
      doc.scanMode = NVD_CATALOG_SCAN_MODE;
      doc.pubCursor = catalogScanHeadIso();
      await this.writeCatalogState(doc);
      const turbo = await this.resolveCatalogTurboParams();
      // eslint-disable-next-line no-console
      console.log(
        `[ingest:nvd] catalog backfill started (today→1999) turbo=${turbo.turbo} windowDays=${turbo.windowDays} windowsPerBurst=${turbo.windowsPerBurst}`
      );
    }

    const turbo = await this.resolveCatalogTurboParams();
    const windowDays = turbo.windowDays;
    const windowsPerBurst = turbo.windowsPerBurst;
    const floorMs = new Date(NVD_CATALOG_FLOOR_ISO).getTime();
    const dayMs = 24 * 60 * 60 * 1000;
    const nowMs = Date.now();
    const syncOpts = {
      resultsPerPage: turbo.resultsPerPage,
      pageSleepMs: turbo.pageSleepMs
    };

    let burstUpserted = 0;

    // Пока deep-scan идёт вглубь — каждый burst подтягивает «голову» с текущего дня.
    if (doc.status === "running") {
      const headHours = Math.max(6, Number(process.env.NVD_CATALOG_HEAD_HOURS ?? 48));
      const headStartMs = nowMs - headHours * 60 * 60 * 1000;
      const headProcessed = await this.syncPublishedWindow(
        new Date(headStartMs).toISOString(),
        new Date(nowMs).toISOString(),
        `catalog_head_${headHours}h`,
        "nvd.catalog_backfill",
        syncOpts
      );
      burstUpserted += headProcessed;
    }

    let cursorEndMs = resolveCatalogDeepEndMs(doc);
    doc.scanMode = NVD_CATALOG_SCAN_MODE;

    for (let w = 0; w < windowsPerBurst && cursorEndMs > floorMs; w++) {
      const windowStartMs = Math.max(floorMs, cursorEndMs - windowDays * dayMs);
      const pubStartIso = new Date(windowStartMs).toISOString();
      const pubEndIso = new Date(cursorEndMs).toISOString();
      const processed = await this.syncPublishedWindow(
        pubStartIso,
        pubEndIso,
        `catalog_rev_${windowDays}d`,
        "nvd.catalog_backfill",
        syncOpts
      );
      burstUpserted += processed;
      doc.totalUpserted = (doc.totalUpserted ?? 0) + processed;
      doc.pubCursor = pubStartIso;
      doc.lastWindowStart = pubStartIso;
      doc.lastWindowEnd = pubEndIso;
      doc.scanMode = NVD_CATALOG_SCAN_MODE;
      doc.status = "running";
      cursorEndMs = windowStartMs;
      await this.writeCatalogState(doc);
    }

    if (catalogReverseFloorReached(doc.pubCursor)) {
      const countR = await this.db.query<{ n: string }>(`SELECT count(*)::text AS n FROM cve`);
      const cveCount = Number(countR.rows[0]?.n ?? 0);
      const minComplete = await this.catalogCompleteMinCve();
      if (cveCount < minComplete) {
        // eslint-disable-next-line no-console
        console.warn(
          `[ingest:nvd] catalog reached 1999 but cve=${cveCount} < ${minComplete} — finishing anyway (pub walk done)`
        );
      }

      doc.status = "complete";
      doc.completedAt = new Date().toISOString();
      await this.writeCatalogState(doc);
      await this.db.query(
        `INSERT INTO audit_log(actor_type, action, metadata)
         VALUES ('system', 'nvd.catalog_complete', $1)`,
        [
          JSON.stringify({
            totalUpserted: doc.totalUpserted ?? 0,
            completedAt: doc.completedAt,
            scanMode: NVD_CATALOG_SCAN_MODE
          })
        ]
      );
      // eslint-disable-next-line no-console
      console.log(`[ingest:nvd] catalog backfill complete total=${doc.totalUpserted ?? 0}`);
      return false;
    }

    doc.status = "running";
    await this.writeCatalogState(doc);
    // eslint-disable-next-line no-console
    console.log(
      `[ingest:nvd] catalog burst upserted=${burstUpserted} backEdge=${doc.pubCursor} total=${doc.totalUpserted ?? 0} turbo=${turbo.turbo}`
    );
    return true;
  }

  private async upsertCveAndFanout(input: {
    cveId: string;
    source: string;
    raw: any;
    publishedAt?: string;
    modifiedAt?: string;
  }) {
    const publishedAtIso =
      parseNvdTimestampIso(input.publishedAt) ?? extractNvdPublishedIso(input.raw);
    const modifiedAtIso = parseNvdTimestampIso(input.modifiedAt);
    const cvss = this.extractCvssBaseScore(input.raw);

    const inserted = await this.db.query(
      `INSERT INTO cve(cve_id, source, published_at, modified_at, cvss_base, raw)
       VALUES ($1,$2,$3,$4,$5,$6)
       ON CONFLICT (cve_id)
       DO UPDATE SET raw = EXCLUDED.raw,
                     source = EXCLUDED.source,
                     published_at = CASE
                       WHEN EXCLUDED.published_at IS NOT NULL THEN EXCLUDED.published_at
                       ELSE cve.published_at
                     END,
                     modified_at = COALESCE(EXCLUDED.modified_at, cve.modified_at),
                     cvss_base = COALESCE(EXCLUDED.cvss_base, cve.cvss_base),
                     updated_at = now()
       RETURNING cve_id`,
      [
        input.cveId,
        input.source,
        publishedAtIso ? new Date(publishedAtIso) : null,
        modifiedAtIso ? new Date(modifiedAtIso) : null,
        cvss ?? null,
        JSON.stringify(input.raw)
      ]
    );

    if (inserted.rowCount === 0) return;

    // Pipeline-level vendor/product index: always keep it in sync with CVE raw.
    await this.upsertVendorProductIndex(input.cveId, input.raw);

    const idempotencyKey = await sha256Hex(
      stableJsonStringify({
        t: "ingest",
        cveId: input.cveId,
        modifiedAt: input.modifiedAt ?? null
      })
    );

    // Фоновое ИИ: только CVE за последние 24ч (как view=last24h). Остальные — по открытию в UI (POST /enrich).
    // Отключить весь fanout: NVD_FANOUT_ENRICH=false.
    if (process.env.NVD_FANOUT_ENRICH !== "false" && isPublishedWithinHours(publishedAtIso)) {
      this.queue.publish(
        "vuln.events",
        "vuln.enrich.requested.v1",
        {
          id: uuidv4(),
          type: QueueEventType.EnrichCveRequested,
          ts: new Date().toISOString(),
          producer: { service: "ingest", version: "0.0.1" },
          idempotencyKey: `enrich:${idempotencyKey}`,
          payload: {
            cveId: input.cveId,
            source: input.source,
            raw: input.raw
          }
        },
        { priority: 9 }
      );
    }

    // Score: по умолчанию только CVE из окна 24ч по published (не весь catch-up lastModified).
    const scoreHotOnly = this.scoreFanoutHotOnly();
    if (!scoreHotOnly || isPublishedWithinHours(publishedAtIso)) {
      this.queue.publish("vuln.events", "vuln.score.requested.v1", {
        id: uuidv4(),
        type: QueueEventType.ScoreCveRequested,
        ts: new Date().toISOString(),
        producer: { service: "ingest", version: "0.0.1" },
        idempotencyKey: `score:${idempotencyKey}`,
        payload: {
          cveId: input.cveId,
          cvss,
          publishedAt: publishedAtIso,
          modifiedAt: modifiedAtIso
        }
      });
    }
  }

  /**
   * Отдельный проход NVD по pubStart/pubEnd — только реально опубликованные за окно.
   * Не смешивается с watermark lastModified (после простоя не «заливает» блок 24ч).
   */
  private async syncPublishedHotWindow() {
    if (catalogBackfillActive(await this.readCatalogState())) return;

    const maxRow = await this.db.query<{ max_pub: Date | null }>(
      `SELECT MAX(published_at) AS max_pub FROM cve`
    );
    const maxPublishedAt = maxRow.rows[0]?.max_pub ?? null;
    const { pubStartIso, pubEndIso, reason } = resolveNvdPubSyncWindow({
      maxPublishedAt,
      hotHours: Number(process.env.NVD_PUB_HOT_HOURS ?? 27),
      maxGapBackfillDays: Number(process.env.NVD_PUB_GAP_BACKFILL_DAYS ?? 21),
      overlapMs: Number(process.env.NVD_PUB_HOT_OVERLAP_MS ?? 3_600_000)
    });

    await this.syncPublishedWindow(pubStartIso, pubEndIso, reason, "nvd.pub_sync");
  }

  /**
   * Догон по дате публикации от watermark lastModified: закрывает дыры, когда max(published_at)
   * уже «свежий», но часть CVE в середине пропущена (типичный кейс после простоя ingest).
   */
  private async syncPublishedCatchUpFromWatermark() {
    if (process.env.NVD_PUB_CATCHUP === "false") return;
    if (catalogBackfillActive(await this.readCatalogState())) return;

    const watermarkEnd = await this.getLatestWatermarkModifiedEnd();
    if (!watermarkEnd) return;

    const lagHours = Math.max(1, Number(process.env.NVD_PUB_CATCHUP_LAG_HOURS ?? 6));
    const chunkDays = Math.max(1, Math.min(30, Number(process.env.NVD_PUB_CATCHUP_CHUNK_DAYS ?? 7)));
    const overlapMs = Number(process.env.NVD_PUB_CATCHUP_OVERLAP_MS ?? 3_600_000);

    const endMs = new Date(watermarkEnd).getTime();
    if (Number.isNaN(endMs)) return;
    const nowMs = Date.now();
    if (nowMs - endMs < lagHours * 60 * 60 * 1000) return;

    const pubStartIso = new Date(Math.max(0, endMs - overlapMs)).toISOString();
    const chunkEndMs = Math.min(nowMs, endMs + chunkDays * 24 * 60 * 60 * 1000);
    if (chunkEndMs <= new Date(pubStartIso).getTime()) return;
    const pubEndIso = new Date(chunkEndMs).toISOString();

    await this.syncPublishedWindow(
      pubStartIso,
      pubEndIso,
      `catchup_watermark_${chunkDays}d`,
      "nvd.pub_catchup"
    );
  }

  private async syncPublishedWindow(
    pubStartIso: string,
    pubEndIso: string,
    reason: string,
    auditAction: "nvd.pub_sync" | "nvd.pub_catchup" | "nvd.catalog_backfill",
    opts?: { resultsPerPage?: number; pageSleepMs?: number }
  ): Promise<number> {
    const apiKey = await this.resolveNvdApiKey();
    const baseUrl = process.env.NVD_API_BASE ?? "https://services.nvd.nist.gov/rest/json/cves/2.0";
    const resultsPerPage =
      opts?.resultsPerPage ??
      Math.max(20, Math.min(2000, Number(process.env.NVD_RESULTS_PER_PAGE ?? 100)));
    const pageSleepMs = opts?.pageSleepMs ?? this.resolveNvdPageSleepMs(apiKey);
    let startIndex = 0;
    let processed = 0;
    const maxEmptyRetries = Number(process.env.NVD_EMPTY_PAGE_RETRIES ?? 12);
    let emptyRetries = 0;

    const logTag =
      auditAction === "nvd.pub_catchup"
        ? "pub-catchup"
        : auditAction === "nvd.catalog_backfill"
          ? "catalog"
          : "pub-hot";

    // eslint-disable-next-line no-console
    console.log(`[ingest:nvd] ${logTag} window=${pubStartIso}..${pubEndIso} reason=${reason}`);

    for (;;) {
      if (startIndex > 0 || emptyRetries > 0) {
        await new Promise((r) => setTimeout(r, pageSleepMs));
      }

      const url = new URL(baseUrl);
      url.searchParams.set("pubStartDate", pubStartIso);
      url.searchParams.set("pubEndDate", pubEndIso);
      url.searchParams.set("startIndex", String(startIndex));
      url.searchParams.set("resultsPerPage", String(resultsPerPage));

      const page: any = await this.withNvdApiLock(() => this.fetchJson(url.toString(), apiKey));
      const vulnerabilities = (page?.vulnerabilities ?? []) as NvdApiItem[];
      const totalResults = Number(page?.totalResults ?? vulnerabilities.length);

      if (vulnerabilities.length === 0 && startIndex < totalResults) {
        emptyRetries++;
        if (emptyRetries <= maxEmptyRetries) {
          // eslint-disable-next-line no-console
          console.warn(
            `[ingest:nvd] ${logTag} empty page startIndex=${startIndex} total=${totalResults} retry=${emptyRetries}/${maxEmptyRetries}`
          );
          continue;
        }
        // eslint-disable-next-line no-console
        console.error(
          `[ingest:nvd] ${logTag} giving up empty page startIndex=${startIndex} total=${totalResults}`
        );
        break;
      }
      emptyRetries = 0;
      if (vulnerabilities.length === 0) break;

      for (const item of vulnerabilities) {
        const cveId = String(item?.cve?.id ?? "");
        if (!cveId.startsWith("CVE-")) continue;
        try {
          await this.upsertCveAndFanout({
            cveId,
            source: "nvd",
            raw: item.cve,
            publishedAt: item?.cve?.published,
            modifiedAt: item?.cve?.lastModified
          });
          processed++;
        } catch (e) {
          // eslint-disable-next-line no-console
          console.error(`[ingest:nvd] ${logTag} failed cve=${cveId}`, e);
        }
      }

      startIndex += vulnerabilities.length;
      if (startIndex >= totalResults) break;
    }

    await this.db.query(
      `INSERT INTO audit_log(actor_type, action, metadata)
       VALUES ('system', $1, $2)`,
      [
        auditAction,
        JSON.stringify({
          pubStart: pubStartIso,
          pubEnd: pubEndIso,
          processed,
          reason
        })
      ]
    );

    // eslint-disable-next-line no-console
    console.log(`[ingest:nvd] ${logTag} processed=${processed}`);
    return processed;
  }

  /** Заполнить published_at из паспорта NVD, если колонка пустая. */
  private async repairPublishedAtFromRaw() {
    const limit = Math.max(1, Math.min(5000, Number(process.env.NVD_PUBLISHED_REPAIR_LIMIT ?? 500)));
    const r = await this.db.query(
      `WITH pick AS (
         SELECT cve_id
           FROM cve
          WHERE published_at IS NULL
            AND raw->>'published' IS NOT NULL
            AND (NULLIF(TRIM(BOTH FROM raw->>'published'), ''))::timestamptz IS NOT NULL
          LIMIT $1
       )
       UPDATE cve c
          SET published_at = (NULLIF(TRIM(BOTH FROM c.raw->>'published'), ''))::timestamptz,
              updated_at = now()
         FROM pick
        WHERE c.cve_id = pick.cve_id`,
      [limit]
    );
    const n = r.rowCount ?? 0;
    if (n > 0) {
      // eslint-disable-next-line no-console
      console.log(`[ingest:nvd] published_at repair updated=${n}`);
    }
  }

  private async upsertVendorProductIndex(cveId: string, raw: any) {
    const pairsRaw = extractVendorProductPairsFromCveRaw(raw);
    // Dedupe within one CVE: duplicate constrained rows in a single INSERT break Postgres ON CONFLICT.
    const dedup = new Map<string, (typeof pairsRaw)[number]>();
    for (const p of pairsRaw) {
      const productKeyNorm = p.product ?? "";
      const key = `${p.vendor}\0${productKeyNorm}`;
      if (!dedup.has(key)) dedup.set(key, p);
    }
    const pairs = Array.from(dedup.values());
    // Replace the index rows for this CVE deterministically.
    await this.db.query(`DELETE FROM cve_vendor_product WHERE cve_id = $1`, [cveId]);
    if (pairs.length === 0) return;

    const values: string[] = [];
    const params: any[] = [];
    for (const p of pairs) {
      const vendorKey = p.vendor;
      const productKey = p.product;
      const productKeyNorm = productKey ?? "";
      params.push(cveId, vendorKey, vendorKey, productKey, productKey, productKeyNorm, p.source);
      const base = params.length - 6;
      values.push(
        `($${base}, $${base + 1}, $${base + 2}, $${base + 3}, $${base + 4}, $${base + 5}, $${base + 6})`
      );
    }

    await this.db.query(
      `INSERT INTO cve_vendor_product (cve_id, vendor_key, vendor, product_key, product, product_key_norm, source)
       VALUES ${values.join(", ")}
       ON CONFLICT (cve_id, vendor_key, product_key_norm)
       DO UPDATE SET source = EXCLUDED.source,
                     product_key = EXCLUDED.product_key,
                     product = EXCLUDED.product,
                     vendor = EXCLUDED.vendor,
                     updated_at = now()`,
      params
    );
  }

  private extractCvssBaseScore(raw: any): number | undefined {
    const metrics = raw?.metrics;
    if (!metrics || typeof metrics !== "object") return undefined;
    const candidates: unknown[] = [];
    for (const k of Object.keys(metrics)) {
      const v = (metrics as any)[k];
      if (Array.isArray(v)) candidates.push(...v);
    }
    for (const c of candidates) {
      const score = (c as any)?.cvssData?.baseScore;
      if (typeof score === "number" && score >= 0 && score <= 10) return score;
    }
    return undefined;
  }

  private async backfillCvssBase() {
    const limit = Number(process.env.CVSS_BACKFILL_LIMIT ?? 500);
    const batch = await this.db.query<{ cve_id: string; raw: any }>(
      `SELECT cve_id, raw
         FROM cve
        WHERE cvss_base IS NULL
        ORDER BY published_at DESC NULLS LAST
        LIMIT $1`,
      [limit]
    );
    if ((batch.rowCount ?? 0) === 0) return;

    let updated = 0;
    for (const row of batch.rows) {
      const cvss = this.extractCvssBaseScore(row.raw);
      if (cvss == null) continue;
      // eslint-disable-next-line no-await-in-loop
      await this.db.query(`UPDATE cve SET cvss_base = $2, updated_at = now() WHERE cve_id = $1 AND cvss_base IS NULL`, [
        row.cve_id,
        cvss
      ]);
      updated++;
    }

    if (updated > 0) {
      // eslint-disable-next-line no-console
      console.log(`[ingest:nvd] cvss_backfill updated=${updated}`);
    }
  }

  /** Догон enrich + score для CVE за 24ч (после каждого цикла NVD и по таймеру). */
  private async sweepHotWindowPipelines() {
    await Promise.all([this.sweepHotWindowEnrich(), this.sweepHotWindowScore()]);
  }

  /**
   * Догоняем risk_score для CVE из окна 24ч без свежего score.
   * Ключ idempotency `score:hot24h:…` — один прогон в час на CVE.
   */
  private async sweepHotWindowScore() {
    if (process.env.HOT24_SCORE_SWEEP === "false") return;

    const limit = Math.max(1, Math.min(2000, Number(process.env.HOT24_SCORE_SWEEP_LIMIT ?? 500)));
    const staleHours = Math.max(0, Math.min(168, Number(process.env.HOT24_SCORE_STALE_HOURS ?? 6)));
    const bucket = hot24ScoreHourBucket();
    const rows = await listHot24CvesNeedingScore(this.db, { limit, staleHours, bucket });
    if (!rows.length) return;

    const events = await buildScoreEventsForCveIds(
      rows.map((r) => r.cve_id),
      {
        producer: { service: "ingest", version: "0.0.1" },
        tag: "hot24-sweep",
        idempotencyKeyFor: (cveId) => hot24ScoreIdempotencyKey(cveId, bucket)
      }
    );
    const n = publishScoreEvents((ex, rk, payload) => this.queue.publish(ex, rk, payload), events);
    if (n > 0) {
      // eslint-disable-next-line no-console
      console.log(`[ingest:nvd] hot24h score sweep enqueued=${n} (limit=${limit}, bucket=${bucket})`);
    }
  }

  /**
   * Догоняем ИИ для CVE из окна 24ч, у которых нет успешной записи в enrichment_ai:
   * бэкфилл без fanout, сбой до фикса LLM, «LLM not configured», последняя строка — enrich_error.
   * Ключ idempotency отдельный от ingest (`enrich:hot24h:…`), чтобы после настройки Llama повторить обработку.
   */
  private async sweepHotWindowEnrich() {
    if (process.env.HOT24_AI_SWEEP === "false") return;

    const limit = Math.max(1, Math.min(500, Number(process.env.HOT24_AI_SWEEP_LIMIT ?? 200)));
    const hourBucket = new Date();
    hourBucket.setMinutes(0, 0, 0);
    const bucket = hourBucket.toISOString().slice(0, 13);

    const r = await this.db.query<{ cve_id: string; raw: unknown }>(
      `SELECT c.cve_id, c.raw
         FROM cve c
    LEFT JOIN LATERAL (
          SELECT output_text, output_json
            FROM enrichment_ai
           WHERE cve_id = c.cve_id
        ORDER BY created_at DESC
           LIMIT 1
         ) latest ON true
        WHERE ${SQL_EFFECTIVE_PUBLISHED_AT} >= now() - interval '24 hours'
          AND NOT EXISTS (
            SELECT 1
              FROM idempotency_key k
             WHERE k.scope = 'ai.enrich'
               AND k.key = ('enrich:hot24h:' || c.cve_id || ':' || $2::text)
          )
          AND (
            latest.output_text IS NULL
            OR latest.output_text = 'LLM not configured.'
            OR COALESCE(latest.output_json->>'summary', '') LIKE 'LLM not configured%'
            OR (latest.output_json @> '{"_enrich_error": true}'::jsonb)
          )
     ORDER BY ${SQL_EFFECTIVE_PUBLISHED_AT} DESC NULLS LAST
        LIMIT $1`,
      [limit, bucket]
    );

    let n = 0;
    for (const row of r.rows) {
      const publishedIso = extractNvdPublishedIso(row.raw);
      if (!isPublishedWithinHours(publishedIso)) continue;

      const raw = row.raw;
      const rawObj =
        raw != null && typeof raw === "object" && !Array.isArray(raw) ? (raw as Record<string, unknown>) : {};
      this.queue.publish(
        "vuln.events",
        "vuln.enrich.requested.v1",
        {
          id: uuidv4(),
          type: QueueEventType.EnrichCveRequested,
          ts: new Date().toISOString(),
          producer: { service: "ingest", version: "0.0.1" },
          idempotencyKey: `enrich:hot24h:${row.cve_id}:${bucket}`,
          payload: {
            cveId: row.cve_id,
            // VulnerabilitySourceSchema: nvd | mitre | other — sweep не отдельный enum
            source: "other",
            raw: rawObj
          }
        },
        { priority: 9 }
      );
      n++;
    }
    if (n > 0) {
      // eslint-disable-next-line no-console
      console.log(`[ingest:nvd] hot24h AI sweep enqueued=${n} (limit=${limit}, bucket=${bucket})`);
    }
  }

  /**
   * Опционально: догон CVE старше 24ч в фоне. По умолчанию выкл.; включить BACKLOG_AI_SWEEP=true.
   */
  private async sweepBacklogEnrich() {
    if (process.env.BACKLOG_AI_SWEEP !== "true") return;

    const limit = Math.max(1, Math.min(2000, Number(process.env.BACKLOG_AI_SWEEP_LIMIT ?? 400)));
    const d = new Date();
    const dayBucket = d.toISOString().slice(0, 10);

    const r = await this.db.query<{ cve_id: string; raw: unknown }>(
      `SELECT c.cve_id, c.raw
         FROM cve c
    LEFT JOIN LATERAL (
          SELECT output_text, output_json
            FROM enrichment_ai
           WHERE cve_id = c.cve_id
        ORDER BY created_at DESC
           LIMIT 1
         ) latest ON true
        WHERE (c.published_at IS NULL OR c.published_at < now() - interval '24 hours')
          AND (
            latest.output_text IS NULL
            OR latest.output_text = 'LLM not configured.'
            OR COALESCE(latest.output_json->>'summary', '') LIKE 'LLM not configured%'
            OR (latest.output_json @> '{"_enrich_error": true}'::jsonb)
          )
     ORDER BY c.published_at DESC NULLS LAST
        LIMIT $1`,
      [limit]
    );

    let n = 0;
    for (const row of r.rows) {
      const raw = row.raw;
      const rawObj =
        raw != null && typeof raw === "object" && !Array.isArray(raw) ? (raw as Record<string, unknown>) : {};
      this.queue.publish(
        "vuln.events",
        "vuln.enrich.requested.v1",
        {
          id: uuidv4(),
          type: QueueEventType.EnrichCveRequested,
          ts: new Date().toISOString(),
          producer: { service: "ingest", version: "0.0.1" },
          idempotencyKey: `enrich:backlog:${row.cve_id}:${dayBucket}`,
          payload: {
            cveId: row.cve_id,
            source: "other",
            raw: rawObj
          }
        },
        { priority: 6 }
      );
      n++;
    }
    if (n > 0) {
      // eslint-disable-next-line no-console
      console.log(`[ingest:nvd] backlog AI sweep enqueued=${n} (limit=${limit}, day=${dayBucket})`);
    }
  }

  private async fetchJson(url: string, apiKey?: string) {
    const effectiveKey = this.effectiveNvdApiKey(apiKey);
    try {
      return await this.fetchJsonWithKey(url, effectiveKey);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      if (effectiveKey && this.isNvdInvalidApiKeyResponse(404, msg, null)) {
        this.nvdApiKeyRejected = true;
        // eslint-disable-next-line no-console
        console.warn(
          "[ingest:nvd] NVD API key rejected — falling back to unauthenticated requests"
        );
        return await this.fetchJsonWithKey(url, undefined);
      }
      throw e;
    }
  }

  private async fetchJsonWithKey(url: string, apiKey?: string): Promise<any> {
    const headers: Record<string, string> = { accept: "application/json" };
    if (apiKey) headers["apiKey"] = apiKey;

    const maxAttempts = Number(process.env.NVD_FETCH_RETRIES ?? 6);
    const timeoutMs = Number(process.env.NVD_FETCH_TIMEOUT_MS ?? 120_000);
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      const ac = new AbortController();
      const t = setTimeout(() => ac.abort(), timeoutMs);
      try {
        const res = await fetch(url, { headers, signal: ac.signal });
        if (res.ok) return res.json();
        const text = await res.text().catch(() => "");
        const messageHeader = res.headers.get("message");
        if (apiKey && this.isNvdInvalidApiKeyResponse(res.status, text, messageHeader)) {
          this.nvdApiKeyRejected = true;
          // eslint-disable-next-line no-console
          console.warn("[ingest:nvd] NVD API key rejected — retrying without apiKey");
          return await this.fetchJsonWithKey(url, undefined);
        }
        if (res.status === 404) {
          throw new Error(
            `NVD fetch failed: 404 ${messageHeader ?? (text || "not found")} url=${url}`
          );
        }
        const retryAfter = res.headers.get("retry-after");
        const backoffMs = retryAfter
          ? Number(retryAfter) * 1000
          : Math.min(60_000, 2000 * attempt * attempt);
        if (attempt === maxAttempts) {
          throw new Error(`NVD fetch failed: ${res.status} ${res.statusText} ${text} url=${url}`);
        }
        // eslint-disable-next-line no-console
        console.warn(
          `[ingest:nvd] fetch retry ${attempt}/${maxAttempts} status=${res.status} sleep=${backoffMs}ms`
        );
        await new Promise((r) => setTimeout(r, backoffMs));
      } catch (e) {
        if (attempt === maxAttempts) throw e;
        const backoffMs = Math.min(60_000, 2000 * attempt * attempt);
        // eslint-disable-next-line no-console
        console.warn(`[ingest:nvd] fetch error retry ${attempt}/${maxAttempts} sleep=${backoffMs}ms`, e);
        await new Promise((r) => setTimeout(r, backoffMs));
      } finally {
        clearTimeout(t);
      }
    }
    throw new Error("unreachable");
  }
}

