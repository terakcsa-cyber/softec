import { Injectable, OnModuleInit } from "@nestjs/common";
import type { ConsumeMessage } from "amqplib";
import { createHash, randomUUID } from "node:crypto";
import { QueueService } from "../services/queue.service.js";
import { DbService } from "../services/db.service.js";
import { getVulnContextLlmConfigFromEnv, sha256Hex, stableJsonStringify } from "@vuln-intel/shared";

type Envelope = {
  id?: string;
  type?: string;
  ts?: string;
  idempotencyKey?: string;
  payload?: {
    findingId?: string;
  };
};

function extractTextFromChatCompletions(data: any): string | null {
  const choices = data?.choices;
  if (!Array.isArray(choices) || !choices.length) return null;
  const msg = choices[0]?.message?.content;
  if (typeof msg === "string" && msg.trim()) return msg.trim();
  return null;
}

@Injectable()
export class AsvTriageWorker implements OnModuleInit {
  constructor(
    private readonly db: DbService,
    private readonly queue: QueueService
  ) {}

  async onModuleInit() {
    await this.queue.ensureTopology();
    const ch = this.queue.channel!;
    ch.prefetch(2);

    await ch.consume("ai.asv-triage", async (msg: ConsumeMessage | null) => {
      if (!msg) return;
      const raw = msg.content.toString("utf8");
      let env: Envelope;
      try {
        env = JSON.parse(raw) as Envelope;
      } catch {
        this.queue.ack(msg);
        return;
      }

      const findingId = env?.payload?.findingId;
      if (!findingId || typeof findingId !== "string") {
        this.queue.ack(msg);
        return;
      }

      try {
        const fr = await this.db.query<{
          id: string;
          asset_id: string;
          tool: string;
          title: string;
          severity: string;
          confidence: string;
          external_id: string | null;
          affected: any;
          evidence: any;
        }>(
          `SELECT id, asset_id, tool, title, severity, confidence, external_id, affected, evidence
             FROM asv_finding
            WHERE id = $1`,
          [findingId]
        );
        const f = fr.rows[0];
        if (!f) {
          this.queue.ack(msg);
          return;
        }

        const cfg = getVulnContextLlmConfigFromEnv();

        // Keep input bounded and stable.
        const input = {
          kind: "asv_finding_triage_v1",
          finding: {
            id: f.id,
            tool: f.tool,
            title: f.title,
            severity: f.severity,
            confidence: f.confidence,
            external_id: f.external_id,
            affected: f.affected,
            evidence: f.evidence
          }
        };
        const inputHash = await sha256Hex(stableJsonStringify(input));

        const system = [
          "Ты — опытный инженер по безопасности (AppSec/InfraSec), помогаешь в ASV (Attack Surface Visibility).",
          "Вывод ТОЛЬКО валидный JSON (никакого markdown, никаких пояснений вне JSON).",
          "Пиши по-русски. Будь максимально практичным: коротко, ясно, без воды.",
          "Будь консервативным: если доказательств мало — так и скажи, и укажи что нужно подтвердить.",
          "НЕЛЬЗЯ: эксплойт-код, инструкции по атаке, вредоносные payload'ы. Можно: безопасная верификация, хардениг, рекомендации.",
          "Оценивай приоритет с учётом влияния, экспозиции, простоты эксплуатации и достоверности."
        ].join("\n");

        const user = [
          "Сделай triage для этого finding и предложи следующие шаги.",
          "",
          "Верни JSON со следующими ключами (КЛЮЧИ строго такие же, значения — на русском):",
          "- summary: string (1-3 предложения: что найдено + где + почему важно)",
          "- why_it_matters: string[] (3-7 пунктов, ориентируйся на риск/влияние)",
          "- verification_steps: string[] (3-10 безопасных шагов проверки, без эксплуатации; если нужны доступы/логи — упомяни)",
          "- remediation: string[] (3-10 действий: быстрый фикс + правильный фикс + защитные меры)",
          "- false_positive_risks: string[] (что может быть FP и как отличить)",
          "- confidence: one of [\"low\",\"medium\",\"high\"] (насколько уверены в выводе по текущим данным)",
          "- priority: one of [\"p0\",\"p1\",\"p2\",\"p3\"] (p0=срочно/критично, p3=низкий)",
          "",
          "Важно:",
          "- Если это скорее 'surface' (инвентарь/инфо) — так и скажи, и дай полезные шаги.",
          "- Если есть CVE/KEV/EPSS в evidence — используй это в приоритизации.",
          "",
          "Finding payload:",
          JSON.stringify(input.finding, null, 2)
        ].join("\n");

        let outputText: string | null = null;
        let outputJson: any = {};
        let tokensInput: number | null = null;
        let tokensOutput: number | null = null;

        const headers: Record<string, string> = { "content-type": "application/json" };
        if (cfg.apiKey) headers.authorization = `Bearer ${cfg.apiKey}`;

        const body = {
          model: cfg.model,
          messages: [
            { role: "system", content: system },
            { role: "user", content: user }
          ],
          temperature: 0.2
        };

        try {
          const res = await fetch(cfg.endpoint, {
            method: "POST",
            headers,
            body: JSON.stringify(body)
          });
          const data: any = await res.json().catch(() => ({}));
          if (!res.ok) {
            outputText = JSON.stringify({ error: true, status: res.status, body: data });
            outputJson = { error: true, status: res.status, body: data };
          } else {
            outputText = extractTextFromChatCompletions(data) ?? "";
            try {
              outputJson = outputText ? JSON.parse(outputText) : {};
            } catch {
              outputJson = { summary: outputText };
            }
            tokensInput = typeof data?.usage?.prompt_tokens === "number" ? data.usage.prompt_tokens : null;
            tokensOutput = typeof data?.usage?.completion_tokens === "number" ? data.usage.completion_tokens : null;
          }
        } catch (e) {
          const msg = e instanceof Error ? e.message : String(e);
          outputText = `LLM call failed: ${msg}`;
          outputJson = { error: true, summary: "LLM call failed", message: msg };
        }

        await this.db.query(
          `INSERT INTO asv_ai_note (asset_id, finding_id, kind, model, prompt_version, input_hash, output_json, output_text, tokens_input, tokens_output, cost_usd)
           VALUES ($1,$2,'finding_triage',$3,$4,$5,$6::jsonb,$7,$8,$9,NULL)
           ON CONFLICT (kind, finding_id, input_hash)
           DO UPDATE SET output_json = EXCLUDED.output_json,
                         output_text = EXCLUDED.output_text,
                         tokens_input = EXCLUDED.tokens_input,
                         tokens_output = EXCLUDED.tokens_output,
                         cost_usd = EXCLUDED.cost_usd,
                         created_at = now()`,
          [
            f.asset_id,
            f.id,
            cfg.model,
            cfg.promptVersion,
            inputHash,
            JSON.stringify(outputJson ?? {}),
            outputText,
            tokensInput,
            tokensOutput
          ]
        );

        // optional event
        this.queue.publish("vuln.events", "asv.ai.triage.completed.v1", {
          id: randomUUID(),
          type: "asv.ai.triage.completed.v1",
          ts: new Date().toISOString(),
          payload: { findingId: f.id, assetId: f.asset_id, kind: "finding_triage" }
        });

        this.queue.ack(msg);
      } catch (err) {
        // eslint-disable-next-line no-console
        console.error("[ai:asv-triage] failed", err);
        this.queue.nack(msg, false);
      }
    });

    const cfg = getVulnContextLlmConfigFromEnv();
    // eslint-disable-next-line no-console
    console.log(`[ai:asv-triage] worker ready queue=ai.asv-triage model=${cfg.model} endpoint=${cfg.endpoint}`);
  }
}

