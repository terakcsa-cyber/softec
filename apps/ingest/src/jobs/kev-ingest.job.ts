import { Inject, Injectable, OnModuleInit } from "@nestjs/common";
import {
  applyRiskScoresForCveIds,
  buildScoreEventsForCveIds,
  isAiScoreEnabled,
  publishScoreEvents,
  shouldScoreViaQueue
} from "@vuln-intel/shared";
import { DbService } from "../services/db.service.js";
import { QueueService } from "../services/queue.service.js";

type KevItem = {
  cveID?: string;
  vendorProject?: string;
  product?: string;
  vulnerabilityName?: string;
  dateAdded?: string;
  dueDate?: string;
  requiredAction?: string;
  knownRansomwareCampaignUse?: string;
  notes?: string;
};

@Injectable()
export class KevIngestJob implements OnModuleInit {
  constructor(
    @Inject(DbService) private readonly db: DbService,
    @Inject(QueueService) private readonly queue: QueueService
  ) {}

  async onModuleInit() {
    const intervalMs = Number(process.env.KEV_POLL_INTERVAL_MS ?? 6 * 60 * 60 * 1000); // 6h
    const initialDelayMs = Number(process.env.KEV_INITIAL_DELAY_MS ?? 8_000);
    setTimeout(() => {
      this.runForever(intervalMs).catch((e) => {
        // eslint-disable-next-line no-console
        console.error(e);
        process.exit(1);
      });
    }, initialDelayMs);
  }

  private async runForever(intervalMs: number) {
    // eslint-disable-next-line no-constant-condition
    while (true) {
      const startedAt = Date.now();
      try {
        await this.ensureSchema();
        await this.runOnce();
      } catch (e) {
        // eslint-disable-next-line no-console
        console.error("KEV ingest failed", e);
      } finally {
        const sleep = Math.max(30_000, intervalMs - (Date.now() - startedAt));
        await new Promise((r) => setTimeout(r, sleep));
      }
    }
  }

  private async ensureSchema() {
    await this.db.query(
      `CREATE TABLE IF NOT EXISTS kev (
        cve_id TEXT PRIMARY KEY,
        vendor_project TEXT,
        product TEXT,
        vulnerability_name TEXT,
        date_added DATE,
        due_date DATE,
        required_action TEXT,
        ransomware_use TEXT,
        notes TEXT,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )`
    );
    await this.db.query(`CREATE INDEX IF NOT EXISTS kev_date_added_idx ON kev (date_added DESC)`);
  }

  private async runOnce() {
    const url =
      process.env.KEV_FEED_URL ??
      "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
    const res = await fetch(url, { headers: { accept: "application/json" } });
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new Error(`KEV fetch failed: ${res.status} ${res.statusText} ${text}`);
    }
    const data = (await res.json()) as { vulnerabilities?: KevItem[] };
    const items = (data?.vulnerabilities ?? []) as KevItem[];
    if (!Array.isArray(items) || items.length === 0) return;

    const nowIso = new Date().toISOString();
    let touched = 0;
    const toScore: string[] = [];
    for (const it of items) {
      const cveId = String(it?.cveID ?? "");
      if (!/^CVE-\d{4}-\d+$/.test(cveId)) continue;

      await this.db.query(
        `INSERT INTO kev(cve_id, vendor_project, product, vulnerability_name, date_added, due_date, required_action, ransomware_use, notes, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9, now())
         ON CONFLICT (cve_id)
         DO UPDATE SET vendor_project = EXCLUDED.vendor_project,
                       product = EXCLUDED.product,
                       vulnerability_name = EXCLUDED.vulnerability_name,
                       date_added = EXCLUDED.date_added,
                       due_date = EXCLUDED.due_date,
                       required_action = EXCLUDED.required_action,
                       ransomware_use = EXCLUDED.ransomware_use,
                       notes = EXCLUDED.notes,
                       updated_at = now()`,
        [
          cveId,
          it.vendorProject ?? null,
          it.product ?? null,
          it.vulnerabilityName ?? null,
          it.dateAdded ? new Date(it.dateAdded) : null,
          it.dueDate ? new Date(it.dueDate) : null,
          it.requiredAction ?? null,
          it.knownRansomwareCampaignUse ?? null,
          it.notes ?? null
        ]
      );
      touched++;

      const present = await this.db.query<{ cve_id: string }>(
        `SELECT cve_id FROM cve WHERE cve_id = $1 LIMIT 1`,
        [cveId]
      );
      if ((present.rowCount ?? 0) === 0) continue;
      if (!isAiScoreEnabled()) continue;
      toScore.push(cveId);
    }

    let rescored = 0;
    if (toScore.length) {
      rescored = await applyRiskScoresForCveIds(this.db, toScore, {
        concurrency: Number(process.env.AI_SCORE_INLINE_CONCURRENCY ?? 32),
        buildQueueEvents: () =>
          buildScoreEventsForCveIds(toScore, {
            producer: { service: "ingest", version: "0.0.1" },
            tag: "kev",
            tsBucket: "iso"
          }),
        publishViaQueue: (events) =>
          publishScoreEvents((ex, rk, payload) => this.queue.publish(ex, rk, payload), events)
      });
    }

    await this.db.query(
      `INSERT INTO audit_log(actor_type, action, metadata)
       VALUES ('system', 'kev.ingest', $1)`,
      [
        JSON.stringify({
          url,
          items: items.length,
          touched,
          rescored,
          mode: shouldScoreViaQueue() ? "queue" : "inline",
          ts: nowIso
        })
      ]
    );
  }
}
