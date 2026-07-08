import { BadRequestException, Injectable, Logger, NotFoundException } from "@nestjs/common";
import {
  bduFstecUrl,
  buildVulnPostFromAiJson,
  EXPLOIT_INTEL_UPSERT_SQL,
  extractNvdCveDescription,
  extractNvdExploitationHint,
  extractNvdVulnerabilityClass,
  formatVulnTelegramPost,
  normalizeTelegramUserStatus,
  parseAiOutputJsonLoose,
  resolveBduCardEnrichment,
  resolveCveCardEnrichment
} from "@vuln-intel/shared";
import { DbService } from "./db.service.js";
import { IntegrationSettingsService } from "./integration-settings.service.js";

@Injectable()
export class TelegramPostService {
  private readonly logger = new Logger(TelegramPostService.name);

  constructor(
    private readonly db: DbService,
    private readonly integration: IntegrationSettingsService
  ) {}

  private async resolveCredentials(overrides?: { botToken?: string; chatId?: string }) {
    const doc = await this.integration.getTelegramDoc();
    const botToken = overrides?.botToken?.trim() || doc.botToken?.trim() || "";
    const chatId = overrides?.chatId?.trim() || doc.chatId?.trim() || "";
    if (!botToken) throw new BadRequestException("Telegram bot token не задан");
    if (!chatId) throw new BadRequestException("Telegram chat id не задан");
    return { botToken, chatId };
  }

  async sendTelegramMessage(
    text: string,
    creds?: { botToken: string; chatId: string },
    opts?: { parseMode?: "HTML" | "Markdown" }
  ): Promise<{ ok: boolean; messageId: number | null; error: string | null }> {
    const { botToken, chatId } = creds ?? (await this.resolveCredentials());
    const url = `https://api.telegram.org/bot${encodeURIComponent(botToken)}/sendMessage`;
    try {
      const bodyPayload: Record<string, unknown> = {
        chat_id: chatId,
        text,
        disable_web_page_preview: true
      };
      if (opts?.parseMode) bodyPayload.parse_mode = opts.parseMode;

      const res = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify(bodyPayload),
        signal: AbortSignal.timeout(30_000)
      });
      const body = (await res.json().catch(() => ({}))) as {
        ok?: boolean;
        description?: string;
        result?: { message_id?: number };
      };
      if (!res.ok || body.ok === false) {
        return {
          ok: false,
          messageId: null,
          error: body.description ?? `HTTP ${res.status}`
        };
      }
      return {
        ok: true,
        messageId: body.result?.message_id ?? null,
        error: null
      };
    } catch (e) {
      return {
        ok: false,
        messageId: null,
        error: e instanceof Error ? e.message : String(e)
      };
    }
  }

  async sendTelegramMessages(
    texts: string[],
    opts?: { parseMode?: "HTML" | "Markdown" }
  ): Promise<{ ok: boolean; sent: number; messageIds: number[]; error: string | null }> {
    const creds = await this.resolveCredentials();
    const messageIds: number[] = [];
    for (const text of texts) {
      const r = await this.sendTelegramMessage(text, creds, opts);
      if (!r.ok) {
        return { ok: false, sent: messageIds.length, messageIds, error: r.error };
      }
      if (r.messageId != null) messageIds.push(r.messageId);
      await new Promise((resolve) => setTimeout(resolve, 350));
    }
    return { ok: true, sent: messageIds.length, messageIds, error: null };
  }

  async sendTelegramDocument(input: {
    buffer: Buffer;
    filename: string;
    caption?: string;
    parseMode?: "HTML" | "Markdown";
  }): Promise<{ ok: boolean; messageId: number | null; error: string | null }> {
    const creds = await this.resolveCredentials();
    const url = `https://api.telegram.org/bot${encodeURIComponent(creds.botToken)}/sendDocument`;
    try {
      const form = new FormData();
      form.append("chat_id", creds.chatId);
      form.append("document", new Blob([input.buffer], { type: "application/pdf" }), input.filename);
      if (input.caption) form.append("caption", input.caption);
      if (input.parseMode) form.append("parse_mode", input.parseMode);

      const res = await fetch(url, {
        method: "POST",
        body: form,
        signal: AbortSignal.timeout(60_000)
      });
      const body = (await res.json().catch(() => ({}))) as {
        ok?: boolean;
        description?: string;
        result?: { message_id?: number };
      };
      if (!res.ok || body.ok === false) {
        return { ok: false, messageId: null, error: body.description ?? `HTTP ${res.status}` };
      }
      return { ok: true, messageId: body.result?.message_id ?? null, error: null };
    } catch (e) {
      return { ok: false, messageId: null, error: e instanceof Error ? e.message : String(e) };
    }
  }

  async verify(overrides?: { botToken?: string; chatId?: string }) {
    const creds = await this.resolveCredentials(overrides);
    const text = "✅ Vuln Intel: тест подключения Telegram-бота";
    const r = await this.sendTelegramMessage(text, creds);
    return { ...r, chatId: creds.chatId };
  }

  private resolveAiRow(rows: { output_json: unknown }[]): Record<string, unknown> | null {
    for (const row of rows) {
      const parsed = parseAiOutputJsonLoose(row.output_json);
      if (parsed && !parsed._enrich_error) return parsed;
    }
    return null;
  }

  async postCve(cveId: string, userStatus: string) {
    const status = normalizeTelegramUserStatus(userStatus);
    const id = cveId.trim().toUpperCase();
    const cve = await this.db.query<{
      cve_id: string;
      raw: unknown;
      cvss_base: number | null;
      exploit_known: boolean;
      epss: number | null;
    }>(
      `SELECT c.cve_id, c.raw, c.cvss_base, (k.cve_id IS NOT NULL) AS exploit_known, es.score AS epss
         FROM cve c
         LEFT JOIN kev k ON k.cve_id = c.cve_id
         LEFT JOIN epss_score es ON es.cve_id = c.cve_id
        WHERE c.cve_id = $1 LIMIT 1`,
      [id]
    );
    if ((cve.rowCount ?? 0) === 0) throw new NotFoundException("CVE not found");
    const row = cve.rows[0]!;

    const aiR = await this.db.query<{ output_json: unknown }>(
      `SELECT output_json FROM enrichment_ai WHERE cve_id = $1
         AND output_text IS DISTINCT FROM 'LLM not configured.'
       ORDER BY created_at DESC LIMIT 5`,
      [id]
    );
    const ai = resolveCveCardEnrichment(this.resolveAiRow(aiR.rows), id, row.raw) as Record<
      string,
      unknown
    >;

    const products = await this.db.query<{ vendor: string; product: string | null }>(
      `SELECT vendor, product FROM cve_vendor_product WHERE cve_id = $1 ORDER BY vendor, product LIMIT 8`,
      [id]
    );
    const productHint =
      products.rows.length > 0
        ? products.rows
            .map((p) => [p.vendor, p.product].filter(Boolean).join(" / "))
            .slice(0, 4)
            .join("; ")
        : null;

    const advisories = await this.db.query<{ link: string; title: string; summary: string | null }>(
      `SELECT link, title, summary FROM vendor_advisory
        WHERE $1::text = ANY(cve_ids)
        ORDER BY published_at DESC NULLS LAST
        LIMIT 5`,
      [id]
    );

    const links: string[] = [`https://nvd.nist.gov/vuln/detail/${id}`];
    if (row.exploit_known) {
      links.push(`https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search=${id}`);
    }

    const bduLinks = await this.db.query<{ bdu_id: string; name: string | null }>(
      `SELECT l.bdu_id, b.name FROM cve_bdu_link l
         LEFT JOIN bdu_vuln b ON b.bdu_id = l.bdu_id
        WHERE l.cve_id = $1 ORDER BY l.bdu_id LIMIT 5`,
      [id]
    );
    for (const b of bduLinks.rows) links.push(bduFstecUrl(b.bdu_id));
    for (const a of advisories.rows) {
      if (a.link?.startsWith("http") && !links.includes(a.link)) links.push(a.link);
    }

    const extraRemediation: string[] = [];
    for (const a of advisories.rows) {
      const s = a.summary?.trim();
      if (s && s.length > 12 && s.length < 400) extraRemediation.push(`${a.title}: ${s}`);
    }

    const input = buildVulnPostFromAiJson(id, ai, {
      userStatus: status,
      cvssScore: row.cvss_base,
      exploitKnown: row.exploit_known,
      epssScore: row.epss,
      fallbackDescription: extractNvdCveDescription(row.raw),
      fallbackTitle: productHint ? `${id} — ${productHint}` : null,
      fallbackVulnerabilityClass: extractNvdVulnerabilityClass(row.raw),
      fallbackAttackFlow: Array.isArray(ai.attackFlow) ? ai.attackFlow.map(String) : [],
      fallbackExploitation: extractNvdExploitationHint(row.raw, row.exploit_known),
      extraLinks: links,
      extraRemediation
    });
    return this.publish(input);
  }

  async postBdu(bduId: string, userStatus: string) {
    const status = normalizeTelegramUserStatus(userStatus);
    const id = bduId.replace(/^BDU:/i, "").trim();
    const bdu = await this.db.query<{
      bdu_id: string;
      name: string;
      description: string | null;
      solution: string | null;
      software_names: string | null;
      severity: string | null;
      exploit_status: string | null;
      cvss_score: number | null;
      has_exploit: boolean;
      cve_ids: string[];
    }>(
      `SELECT bdu_id, name, description, solution, software_names, severity, exploit_status,
              cvss_score, has_exploit, cve_ids
         FROM bdu_vuln WHERE bdu_id = $1 LIMIT 1`,
      [id]
    );
    if ((bdu.rowCount ?? 0) === 0) throw new NotFoundException("BDU not found");

    const row = bdu.rows[0]!;
    const linkedCve = await this.db.query<{ raw: unknown; cve_id: string }>(
      `SELECT cve_id, raw FROM cve
        WHERE cve_id = ANY($1::text[]) AND raw IS NOT NULL
        ORDER BY cvss_base DESC NULLS LAST
        LIMIT 1`,
      [row.cve_ids ?? []]
    );
    const linkedRaw = linkedCve.rows[0]?.raw ?? null;

    const aiR = await this.db.query<{ output_json: unknown }>(
      `SELECT output_json FROM enrichment_bdu WHERE bdu_id = $1
         AND output_text IS DISTINCT FROM 'LLM not configured.'
       ORDER BY created_at DESC LIMIT 5`,
      [id]
    );
    const ai = resolveBduCardEnrichment(
      this.resolveAiRow(aiR.rows),
      id,
      {
        name: row.name,
        description: row.description,
        solution: row.solution,
        software_names: row.software_names,
        severity: row.severity,
        exploit_status: row.exploit_status,
        has_exploit: row.has_exploit
      },
      linkedRaw
    ) as Record<string, unknown>;

    const links = [bduFstecUrl(id)];
    for (const cve of row.cve_ids ?? []) {
      if (typeof cve === "string" && cve.startsWith("CVE-")) {
        links.push(`https://nvd.nist.gov/vuln/detail/${cve}`);
      }
    }

    const extraRemediation: string[] = [];
    if (row.solution?.trim()) {
      for (const line of row.solution.split(/\n+/).map((s) => s.trim()).filter(Boolean).slice(0, 8)) {
        extraRemediation.push(line);
      }
    }

    const input = buildVulnPostFromAiJson(`BDU:${id}`, ai, {
      userStatus: status,
      cvssScore: row.cvss_score,
      exploitKnown: row.has_exploit,
      fallbackDescription: row.description ?? row.name,
      fallbackTitle: row.name?.trim() || `БДУ ${id}`,
      fallbackVulnerabilityClass:
        row.severity?.trim() ||
        (linkedRaw ? extractNvdVulnerabilityClass(linkedRaw) : null),
      fallbackAttackFlow: Array.isArray(ai.attackFlow) ? ai.attackFlow.map(String) : [],
      fallbackExploitation:
        row.exploit_status?.trim() ||
        (linkedRaw ? extractNvdExploitationHint(linkedRaw, row.has_exploit) : null),
      extraLinks: links,
      extraRemediation
    });

    return this.publish(input);
  }

  private async publish(input: ReturnType<typeof buildVulnPostFromAiJson>) {
    const text = formatVulnTelegramPost(input);
    const sent = await this.sendTelegramMessage(text);
    try {
      await this.db.query(
        `INSERT INTO audit_log (actor_type, action, metadata)
         VALUES ('user', 'telegram.post', $1::jsonb)`,
        [
          JSON.stringify({
            ok: sent.ok,
            identifier: input.identifier,
            cveId: /^CVE-\d{4}-\d+$/i.test(input.identifier) ? input.identifier.toUpperCase() : null,
            messageId: sent.messageId,
            error: sent.error
          })
        ]
      );
      const cveId = /^CVE-\d{4}-\d+$/i.test(input.identifier) ? input.identifier.toUpperCase() : null;
      if (sent.ok && cveId) {
        await this.db.query(EXPLOIT_INTEL_UPSERT_SQL, [[cveId]]);
      }
    } catch (e) {
      this.logger.warn(`telegram.post audit write failed: ${e instanceof Error ? e.message : String(e)}`);
    }
    if (!sent.ok) throw new BadRequestException(sent.error ?? "Telegram send failed");
    return {
      ok: true,
      identifier: input.identifier,
      messageId: sent.messageId,
      previewLength: text.length
    };
  }
}
