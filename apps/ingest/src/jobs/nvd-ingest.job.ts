import { createHash } from "node:crypto";
import { Inject, Injectable, OnModuleInit } from "@nestjs/common";
import { v4 as uuidv4 } from "uuid";
import {
  QueueEventType,
  SQL_EFFECTIVE_PUBLISHED_AT,
  extractNvdPublishedIso,
  extractVendorProductPairsFromCveRaw,
  isPublishedWithinHours,
  parseNvdTimestampIso,
  resolveNvdPubSyncWindow,
  stableJsonStringify,
  sha256Hex
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

    const pubHotOnStartMs = Number(process.env.NVD_PUB_HOT_SYNC_ON_START_MS ?? 2_000);
    if (pubHotOnStartMs > 0 && process.env.NVD_PUB_HOT_SYNC !== "false") {
      setTimeout(() => {
        this.syncPublishedHotWindow()
          .then(() => this.sweepHotWindowEnrich())
          .catch((e) => {
            // eslint-disable-next-line no-console
            console.error("[ingest:nvd] published hot-window sync on start failed", e);
          });
      }, pubHotOnStartMs);
    }

    const sweepOnStartMs = Number(process.env.HOT24_AI_SWEEP_ON_START_MS ?? 45_000);
    if (sweepOnStartMs > 0 && process.env.HOT24_AI_SWEEP !== "false") {
      setTimeout(() => {
        this.sweepHotWindowEnrich().catch((e) => {
          // eslint-disable-next-line no-console
          console.error("[ingest:nvd] hot24h sweep on start failed", e);
        });
      }, sweepOnStartMs);
    }

    const sweepIntervalMs = Number(process.env.HOT24_AI_SWEEP_INTERVAL_MS ?? 0);
    if (sweepIntervalMs > 0 && process.env.HOT24_AI_SWEEP !== "false") {
      setInterval(() => {
        this.sweepHotWindowEnrich().catch((e) => {
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
      try {
        // eslint-disable-next-line no-console
        console.log("[ingest:nvd] cycle started");
        await this.runOnce();
        // eslint-disable-next-line no-console
        console.log("[ingest:nvd] cycle completed");
      } catch (e) {
        // eslint-disable-next-line no-console
        console.error("NVD ingest failed", e);
      } finally {
        const sleep = Math.max(5_000, intervalMs - (Date.now() - startedAt));
        await new Promise((r) => setTimeout(r, sleep));
      }
    }
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
    if (this.nvdApiKeyRejected) return undefined;
    return key;
  }

  private async runOnce() {
    await this.repairPublishedAtFromRaw();

    if (process.env.NVD_PUB_HOT_SYNC !== "false") {
      await this.syncPublishedHotWindow();
    }

    const apiKey = await this.resolveNvdApiKey();
    const baseUrl = process.env.NVD_API_BASE ?? "https://services.nvd.nist.gov/rest/json/cves/2.0";

    const overlapMs = Number(process.env.NVD_WATERMARK_OVERLAP_MS ?? 120_000);
    const last = await this.db.query<{ metadata: any }>(
      `SELECT metadata FROM audit_log
        WHERE action = 'nvd.watermark'
          AND COALESCE((metadata->>'processed')::int, 0) > 0
     ORDER BY ts DESC
        LIMIT 1`
    );

    const lastEnd =
      (last.rowCount ?? 0) > 0 && last.rows[0]?.metadata?.modifiedEnd
        ? String(last.rows[0].metadata.modifiedEnd)
        : null;

    const sinceIso = lastEnd
      ? new Date(Math.max(0, new Date(lastEnd).getTime() - overlapMs)).toISOString()
      : new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString();

    const nowIso = new Date().toISOString();
    if (new Date(sinceIso).getTime() >= new Date(nowIso).getTime()) {
      // eslint-disable-next-line no-console
      console.log(`[ingest:nvd] skip: watermark window empty (${sinceIso} >= ${nowIso})`);
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
      url.searchParams.set("lastModEndDate", nowIso);
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

    // eslint-disable-next-line no-console
    console.log(
      `[ingest:nvd] processed=${processed} complete=${syncComplete} partial=${partialSync} window=${sinceIso}..${nowIso}`
    );

    await this.backfillCvssBase();
    await this.sweepHotWindowEnrich();

    if (syncComplete) {
      await this.db.query(
        `INSERT INTO audit_log(actor_type, action, metadata)
         VALUES ('system', 'nvd.watermark', $1)`,
        [
          JSON.stringify({
            modifiedStart: sinceIso,
            modifiedEnd: nowIso,
            processed,
            partial: partialSync
          })
        ]
      );
    }
  }

  /** NVD: без apiKey — 5 req / 30s; с ключом — 50 req / 30s. */
  private resolveNvdPageSleepMs(apiKey?: string): number {
    const configured = Number(process.env.NVD_PAGE_SLEEP_MS);
    if (Number.isFinite(configured) && configured > 0) return configured;
    return apiKey ? 6500 : 6000;
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

    const apiKey = await this.resolveNvdApiKey();
    const baseUrl = process.env.NVD_API_BASE ?? "https://services.nvd.nist.gov/rest/json/cves/2.0";
    const resultsPerPage = Math.max(
      20,
      Math.min(2000, Number(process.env.NVD_RESULTS_PER_PAGE ?? 100))
    );
    const pageSleepMs = this.resolveNvdPageSleepMs(apiKey);
    let startIndex = 0;
    let processed = 0;
    const maxEmptyRetries = Number(process.env.NVD_EMPTY_PAGE_RETRIES ?? 12);
    let emptyRetries = 0;

    // eslint-disable-next-line no-console
    console.log(
      `[ingest:nvd] pub-hot sync window=${pubStartIso}..${pubEndIso} reason=${reason} maxPublished=${maxPublishedAt?.toISOString() ?? "none"}`
    );

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
            `[ingest:nvd] pub-hot empty page startIndex=${startIndex} total=${totalResults} retry=${emptyRetries}/${maxEmptyRetries}`
          );
          continue;
        }
        // eslint-disable-next-line no-console
        console.error(
          `[ingest:nvd] pub-hot giving up empty page startIndex=${startIndex} total=${totalResults}`
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
          console.error(`[ingest:nvd] pub-hot failed cve=${cveId}`, e);
        }
      }

      startIndex += vulnerabilities.length;
      if (startIndex >= totalResults) break;
    }

    await this.db.query(
      `INSERT INTO audit_log(actor_type, action, metadata)
       VALUES ('system', 'nvd.pub_sync', $1)`,
      [
        JSON.stringify({
          pubStart: pubStartIso,
          pubEnd: pubEndIso,
          processed,
          reason,
          maxPublishedBefore: maxPublishedAt?.toISOString() ?? null
        })
      ]
    );

    if (processed > 0) {
      // eslint-disable-next-line no-console
      console.log(`[ingest:nvd] pub-hot sync processed=${processed}`);
    } else {
      // eslint-disable-next-line no-console
      console.log(`[ingest:nvd] pub-hot sync processed=0 (NVD returned no rows in window)`);
    }
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

  /**
   * Догоняем ИИ для CVE из окна 24ч, у которых нет успешной записи в enrichment_ai:
   * бэкфилл без fanout, сбой до фикса LLM, «LLM not configured», последняя строка — enrich_error.
   * Ключ idempotency отдельный от ingest (`enrich:hot24h:…`), чтобы после настройки Llama повторить обработку.
   */
  private async sweepHotWindowEnrich() {
    if (process.env.NVD_FANOUT_ENRICH === "false" || process.env.HOT24_AI_SWEEP === "false") return;

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
          AND (
            latest.output_text IS NULL
            OR latest.output_text = 'LLM not configured.'
            OR COALESCE(latest.output_json->>'summary', '') LIKE 'LLM not configured%'
            OR (latest.output_json @> '{"_enrich_error": true}'::jsonb)
          )
     ORDER BY ${SQL_EFFECTIVE_PUBLISHED_AT} DESC NULLS LAST
        LIMIT $1`,
      [limit]
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
    try {
      return await this.fetchJsonWithKey(url, apiKey);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      if (apiKey && /\b404\b/.test(msg)) {
        this.nvdApiKeyRejected = true;
        // eslint-disable-next-line no-console
        console.warn(
          "[ingest:nvd] NVD API key rejected (HTTP 404) — falling back to unauthenticated requests (check NVD_API_KEY)"
        );
        return await this.fetchJsonWithKey(url, undefined);
      }
      throw e;
    }
  }

  private async fetchJsonWithKey(url: string, apiKey?: string) {
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
        const retryAfter = res.headers.get("retry-after");
        const backoffMs = retryAfter
          ? Number(retryAfter) * 1000
          : Math.min(60_000, 2000 * attempt * attempt);
        if (attempt === maxAttempts) {
          const text = await res.text().catch(() => "");
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

