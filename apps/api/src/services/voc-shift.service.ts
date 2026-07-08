import { BadRequestException, Injectable, NotFoundException } from "@nestjs/common";
import {
  vocAlertConditionLabel,
  type VocAlertChannel,
  type VocAlertCondition,
  type VocHandoverReport,
  type VocKpiSnapshot
} from "@vuln-intel/shared";
import type { AuthUser } from "../auth/jwt.strategy.js";
import { DbService } from "./db.service.js";
import { TelegramPostService } from "./telegram-post.service.js";
import { VocService } from "./voc.service.js";

export type VocAlertRuleRow = {
  id: string;
  name: string;
  active: boolean;
  condition: VocAlertCondition;
  channel: VocAlertChannel;
  webhookUrl: string | null;
  createdAt: string;
  updatedAt: string;
};

const ALERT_COOLDOWN_MS = 4 * 3_600_000;

@Injectable()
export class VocShiftService {
  constructor(
    private readonly db: DbService,
    private readonly voc: VocService,
    private readonly telegram: TelegramPostService
  ) {}

  async kpis(windowHours = 8): Promise<VocKpiSnapshot> {
    const hours = Math.max(1, Math.min(72, windowHours));
    const generatedAt = new Date().toISOString();

    const triageR = await this.db.query<{ status: string; n: string }>(
      `SELECT status, count(*)::text AS n FROM voc_triage GROUP BY status`
    );
    const triage = { open: 0, claimed: 0, done: 0, dismissed: 0 };
    for (const row of triageR.rows) {
      if (row.status === "open") triage.open = Number(row.n);
      else if (row.status === "claimed") triage.claimed = Number(row.n);
      else if (row.status === "done") triage.done = Number(row.n);
      else if (row.status === "dismissed") triage.dismissed = Number(row.n);
    }

    const casesR = await this.db.query<{
      active: string;
      sla_breached: string;
      resolved: string;
      avg_hours: number | null;
    }>(
      `SELECT
         (SELECT count(*)::text FROM voc_case WHERE status IN ('open','in_progress')) AS active,
         (SELECT count(*)::text FROM voc_case
           WHERE status IN ('open','in_progress') AND sla_due_at IS NOT NULL AND sla_due_at < now()) AS sla_breached,
         (SELECT count(*)::text FROM voc_case
           WHERE status = 'resolved' AND resolved_at >= now() - ($1::text || ' hours')::interval) AS resolved,
         (SELECT avg(EXTRACT(EPOCH FROM (resolved_at - created_at)) / 3600.0)
            FROM voc_case
           WHERE status = 'resolved'
             AND resolved_at >= now() - ($1::text || ' hours')::interval) AS avg_hours`,
      [String(hours)]
    );
    const cr = casesR.rows[0];

    const outcomesR = await this.db.query<{ outcome: string; n: string }>(
      `SELECT outcome, count(*)::text AS n
         FROM voc_case
        WHERE outcome IS NOT NULL
          AND resolved_at >= now() - ($1::text || ' hours')::interval
        GROUP BY outcome`,
      [String(hours)]
    );
    const outcomes: Record<string, number> = {};
    for (const row of outcomesR.rows) outcomes[row.outcome] = Number(row.n);

    const queue = await this.voc.queue({ source: "all", status: "active", limit: 300 });
    const p1Open = queue.items.filter((i) => i.vocPriority === "p1" && i.status === "open").length;
    const p2Open = queue.items.filter((i) => i.vocPriority === "p2" && i.status === "open").length;
    const watchlistHits = queue.stats.watchlist_hits ?? 0;

    const tgR = await this.db.query<{ total: string; dismissed: string }>(
      `SELECT
         count(*)::text AS total,
         count(*) FILTER (WHERE status = 'dismissed')::text AS dismissed
       FROM voc_triage
       WHERE source = 'tg'
         AND updated_at >= now() - interval '24 hours'`
    );
    const tgTotal = Number(tgR.rows[0]?.total ?? 0);
    const tgDismissed = Number(tgR.rows[0]?.dismissed ?? 0);

    return {
      windowHours: hours,
      generatedAt,
      triage,
      cases: {
        active: Number(cr?.active ?? 0),
        slaBreached: Number(cr?.sla_breached ?? 0),
        resolvedInWindow: Number(cr?.resolved ?? 0),
        avgResolutionHours:
          typeof cr?.avg_hours === "number" && Number.isFinite(cr.avg_hours)
            ? Math.round(cr.avg_hours * 10) / 10
            : null
      },
      outcomes,
      queue: { p1Open, p2Open, watchlistHits },
      tg: {
        total24h: tgTotal,
        dismissed: tgDismissed,
        noiseRatio: tgTotal > 0 ? Math.round((tgDismissed / tgTotal) * 100) : null
      }
    };
  }

  async handover(user: AuthUser | null, windowHours = 8, notes?: string | null): Promise<VocHandoverReport> {
    const hours = Math.max(1, Math.min(72, windowHours));
    const kpi = await this.kpis(hours);

    const openHot = await this.db.query<{
      title: string;
      primary_ref_key: string;
      voc_priority: string;
      sla_due_at: Date | null;
    }>(
      `SELECT title, primary_ref_key, voc_priority, sla_due_at
         FROM voc_case
        WHERE status IN ('open','in_progress')
        ORDER BY
          CASE voc_priority WHEN 'p1' THEN 0 WHEN 'p2' THEN 1 WHEN 'p3' THEN 2 ELSE 3 END,
          sla_due_at ASC NULLS LAST
        LIMIT 15`
    );

    const resolved = await this.db.query<{
      title: string;
      outcome: string;
      resolved_at: Date;
    }>(
      `SELECT title, outcome, resolved_at
         FROM voc_case
        WHERE status = 'resolved'
          AND resolved_at >= now() - ($1::text || ' hours')::interval
        ORDER BY resolved_at DESC
        LIMIT 20`,
      [String(hours)]
    );

    const openHotItems = openHot.rows.map((r) => ({
      title: r.title,
      refKey: r.primary_ref_key,
      priority: r.voc_priority,
      slaDueAt: r.sla_due_at?.toISOString?.() ?? null
    }));

    const resolvedItems = resolved.rows.map((r) => ({
      title: r.title,
      outcome: r.outcome,
      resolvedAt: r.resolved_at.toISOString()
    }));

    const lines = [
      `# VOC Handover · ${hours}ч`,
      ``,
      `Сгенерировано: ${new Date().toLocaleString("ru-RU")}`,
      user?.email ? `Смена: ${user.email}` : null,
      ``,
      `## KPI`,
      `- Очередь: open ${kpi.triage.open} · в работе ${kpi.triage.claimed} · готово ${kpi.triage.done}`,
      `- Кейсы активные: ${kpi.cases.active} · SLA просрочен: ${kpi.cases.slaBreached}`,
      `- Закрыто за окно: ${kpi.cases.resolvedInWindow}${kpi.cases.avgResolutionHours != null ? ` · ср. ${kpi.cases.avgResolutionHours}ч` : ""}`,
      `- P1 в очереди: ${kpi.queue.p1Open} · P2: ${kpi.queue.p2Open} · Watchlist: ${kpi.queue.watchlistHits}`,
      kpi.tg.noiseRatio != null ? `- TG шум 24ч: ${kpi.tg.noiseRatio}% dismissed (${kpi.tg.dismissed}/${kpi.tg.total24h})` : null,
      ``,
      `## Исходы (${hours}ч)`,
      Object.keys(kpi.outcomes).length
        ? Object.entries(kpi.outcomes)
            .map(([k, v]) => `- ${k}: ${v}`)
            .join("\n")
        : "- нет закрытых кейсов",
      ``,
      `## Открытые hot-кейсы`,
      openHotItems.length
        ? openHotItems.map((i) => `- [${i.priority}] ${i.title}${i.slaDueAt ? ` · SLA ${i.slaDueAt}` : ""}`).join("\n")
        : "- нет",
      ``,
      `## Закрыто за смену`,
      resolvedItems.length
        ? resolvedItems.map((i) => `- ${i.outcome}: ${i.title}`).join("\n")
        : "- нет",
      notes?.trim() ? `\n## Заметки смены\n${notes.trim()}` : null
    ].filter(Boolean);

    const markdown = lines.join("\n");
    const report: VocHandoverReport = {
      windowHours: hours,
      generatedAt: new Date().toISOString(),
      authorEmail: user?.email ?? null,
      kpi,
      markdown,
      openHotItems,
      resolvedItems
    };

    await this.db.query(
      `INSERT INTO voc_handover (author_email, window_hours, snapshot, notes, markdown)
       VALUES ($1,$2,$3::jsonb,$4,$5)`,
      [user?.email ?? null, hours, JSON.stringify(report), notes?.trim() || null, markdown]
    );

    return report;
  }

  async listAlertRules(): Promise<VocAlertRuleRow[]> {
    const r = await this.db.query<{
      id: string;
      name: string;
      active: boolean;
      condition: VocAlertCondition;
      channel: VocAlertChannel;
      webhook_url: string | null;
      created_at: Date;
      updated_at: Date;
    }>(`SELECT * FROM voc_alert_rule ORDER BY updated_at DESC`);
    return r.rows.map((row) => ({
      id: row.id,
      name: row.name,
      active: row.active,
      condition: row.condition,
      channel: row.channel,
      webhookUrl: row.webhook_url,
      createdAt: row.created_at.toISOString(),
      updatedAt: row.updated_at.toISOString()
    }));
  }

  async addAlertRule(input: {
    name?: string;
    condition?: VocAlertCondition;
    channel?: VocAlertChannel;
    webhookUrl?: string | null;
  }) {
    const name = String(input.name ?? "").trim();
    const condition = input.condition ?? "p1_open";
    if (!name) throw new BadRequestException("name required");
    const r = await this.db.query<{ id: string }>(
      `INSERT INTO voc_alert_rule (name, condition, channel, webhook_url)
       VALUES ($1,$2,$3,$4)
       RETURNING id`,
      [name, condition, input.channel ?? "telegram", input.webhookUrl?.trim() || null]
    );
    const rules = await this.listAlertRules();
    return { ok: true, id: r.rows[0]!.id, rules };
  }

  async patchAlertRule(
    id: string,
    input: { active?: boolean; name?: string; webhookUrl?: string | null }
  ) {
    const sets = ["updated_at = now()"];
    const params: unknown[] = [];
    const add = (col: string, val: unknown) => {
      params.push(val);
      sets.push(`${col} = $${params.length}`);
    };
    if (input.active !== undefined) add("active", input.active);
    if (input.name?.trim()) add("name", input.name.trim());
    if (input.webhookUrl !== undefined) add("webhook_url", input.webhookUrl?.trim() || null);
    if (sets.length === 1) throw new BadRequestException("nothing to update");
    params.push(id);
    const r = await this.db.query(`UPDATE voc_alert_rule SET ${sets.join(", ")} WHERE id = $${params.length} RETURNING id`, params);
    if (!r.rows[0]) throw new NotFoundException("rule not found");
    return { ok: true, rules: await this.listAlertRules() };
  }

  async removeAlertRule(id: string) {
    await this.db.query(`DELETE FROM voc_alert_rule WHERE id = $1`, [id]);
    return { ok: true, rules: await this.listAlertRules() };
  }

  async evaluateAlerts(): Promise<{ fired: number; results: Array<{ ruleId: string; dedupKey: string; ok: boolean; error?: string }> }> {
    const rules = (await this.listAlertRules()).filter((r) => r.active);
    const kpi = await this.kpis(8);
    const queue = await this.voc.queue({ source: "all", status: "active", limit: 200 });
    const results: Array<{ ruleId: string; dedupKey: string; ok: boolean; error?: string }> = [];
    let fired = 0;

    for (const rule of rules) {
      const hits = this.collectAlertHits(rule.condition, kpi, queue.items);
      for (const hit of hits) {
        const can = await this.canFire(rule.id, hit.dedupKey);
        if (!can) continue;
        const text = `🔔 VOC · ${rule.name}\n${vocAlertConditionLabel(rule.condition)}\n\n${hit.message}`;
        const send = await this.dispatchAlert(rule, text);
        results.push({ ruleId: rule.id, dedupKey: hit.dedupKey, ok: send.ok, error: send.error ?? undefined });
        if (send.ok) {
          fired += 1;
          await this.markFired(rule.id, hit.dedupKey);
        }
      }
    }

    return { fired, results };
  }

  async fireCaseExposedAlert(caseTitle: string, caseId: string) {
    const rules = (await this.listAlertRules()).filter(
      (r) => r.active && r.condition === "case_exposed"
    );
    for (const rule of rules) {
      const dedupKey = `case_exposed:${caseId}`;
      if (!(await this.canFire(rule.id, dedupKey))) continue;
      const text = `🔴 VOC · ${rule.name}\nИсход: экспозиция подтверждена\n\n${caseTitle}`;
      const send = await this.dispatchAlert(rule, text);
      if (send.ok) await this.markFired(rule.id, dedupKey);
    }
  }

  private collectAlertHits(
    condition: VocAlertCondition,
    kpi: VocKpiSnapshot,
    items: Awaited<ReturnType<VocService["queue"]>>["items"]
  ): Array<{ dedupKey: string; message: string }> {
    const hits: Array<{ dedupKey: string; message: string }> = [];

    if (condition === "p1_open") {
      for (const item of items.filter((i) => i.vocPriority === "p1" && i.status === "open")) {
        hits.push({
          dedupKey: `p1:${item.refKey}`,
          message: `${item.title}\n${item.refKey} · score ${item.vocScore}`
        });
      }
    }

    if (condition === "sla_breach" && kpi.cases.slaBreached > 0) {
      hits.push({
        dedupKey: `sla_breach:${kpi.cases.slaBreached}`,
        message: `Просрочено кейсов: ${kpi.cases.slaBreached}`
      });
    }

    if (condition === "watchlist_p1") {
      for (const item of items.filter(
        (i) =>
          (i.vocPriority === "p1" || i.vocPriority === "p2") &&
          i.vocReasons.some((r) => r.startsWith("watchlist:"))
      )) {
        hits.push({
          dedupKey: `wl:${item.refKey}`,
          message: `${item.title}\n${item.refKey} · ${item.vocPriority}`
        });
      }
    }

    return hits;
  }

  private async canFire(ruleId: string, dedupKey: string): Promise<boolean> {
    const r = await this.db.query<{ fired_at: Date }>(
      `SELECT fired_at FROM voc_alert_fired WHERE rule_id = $1 AND dedup_key = $2`,
      [ruleId, dedupKey]
    );
    const t = r.rows[0]?.fired_at?.getTime();
    if (!t) return true;
    return Date.now() - t >= ALERT_COOLDOWN_MS;
  }

  private async markFired(ruleId: string, dedupKey: string) {
    await this.db.query(
      `INSERT INTO voc_alert_fired (rule_id, dedup_key, fired_at)
       VALUES ($1,$2,now())
       ON CONFLICT (rule_id, dedup_key) DO UPDATE SET fired_at = now()`,
      [ruleId, dedupKey]
    );
  }

  private async dispatchAlert(
    rule: VocAlertRuleRow,
    text: string
  ): Promise<{ ok: boolean; error?: string | null }> {
    if (rule.channel === "webhook") {
      const url = rule.webhookUrl?.trim();
      if (!url) return { ok: false, error: "webhook_url missing" };
      try {
        const res = await fetch(url, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ text, source: "voc", rule: rule.name }),
          signal: AbortSignal.timeout(15_000)
        });
        return { ok: res.ok, error: res.ok ? null : `HTTP ${res.status}` };
      } catch (e) {
        return { ok: false, error: e instanceof Error ? e.message : String(e) };
      }
    }
    const r = await this.telegram.sendTelegramMessage(text);
    return { ok: r.ok, error: r.error };
  }
}
