import { Injectable, OnModuleInit } from "@nestjs/common";
import type { ConsumeMessage } from "amqplib";
import { randomUUID } from "node:crypto";
import { QueueService } from "../services/queue.service.js";
import { DbService } from "../services/db.service.js";
import { LlmService } from "../services/llm.service.js";
import { sha256Hex, stableJsonStringify } from "@vuln-intel/shared";

type Envelope = {
  id?: string;
  type?: string;
  ts?: string;
  idempotencyKey?: string;
  payload?: {
    issueId?: string;
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
export class AsvPriorityWorker implements OnModuleInit {
  constructor(
    private readonly db: DbService,
    private readonly queue: QueueService,
    private readonly llm: LlmService
  ) {}

  async onModuleInit() {
    await this.queue.ensureTopology();
    const ch = this.queue.channel!;
    ch.prefetch(2);

    await ch.consume("ai.asv-priority", async (msg: ConsumeMessage | null) => {
      if (!msg) return;
      let env: Envelope;
      try {
        env = JSON.parse(msg.content.toString("utf8")) as Envelope;
      } catch {
        this.queue.ack(msg);
        return;
      }

      const issueId = env?.payload?.issueId;
      if (!issueId || typeof issueId !== "string") {
        this.queue.ack(msg);
        return;
      }

      try {
        const ir = await this.db.query<{
          id: string;
          asset_id: string;
          title: string;
          tool: string;
          external_id: string | null;
          endpoint_key: string | null;
          severity: string;
          confidence: string;
          status: string;
          occurrences: number;
          fix_guidance: any;
          first_seen: string;
          last_seen: string;
        }>(
          `SELECT id, asset_id, title, tool, external_id, endpoint_key, severity, confidence, status, occurrences, fix_guidance,
                  first_seen::text, last_seen::text
             FROM asv_issue
            WHERE id = $1`,
          [issueId]
        );
        const it = ir.rows[0];
        if (!it) {
          this.queue.ack(msg);
          return;
        }

        const cfg = await this.llm.getEffectiveLlmConfig();

        const input = {
          kind: "asv_issue_priority_v1",
          issue: it
        };
        const inputHash = await sha256Hex(stableJsonStringify(input));

        const system = [
          "You are a security analyst helping prioritize ASV issues.",
          "Output MUST be valid JSON only.",
          "Be conservative. Do not provide exploit code.",
          "Prioritize based on severity/confidence/exposure signal and operational impact."
        ].join("\n");

        const user = [
          "Given this ASV issue, output JSON keys:",
          "- summary: string",
          "- priority: one of [\"p0\",\"p1\",\"p2\",\"p3\"]",
          "- rationale: string[]",
          "- quick_actions: string[]",
          "- questions_to_answer: string[] (what to confirm next)",
          "",
          JSON.stringify(it, null, 2)
        ].join("\n");

        let outputText: string | null = null;
        let outputJson: any = {};
        let tokensInput: number | null = null;
        let tokensOutput: number | null = null;

        const headers: Record<string, string> = { "content-type": "application/json" };
        if (cfg.apiKey) headers.authorization = `Bearer ${cfg.apiKey}`;

        try {
          const res = await fetch(cfg.endpoint, {
            method: "POST",
            headers,
            body: JSON.stringify({
              model: cfg.model,
              messages: [
                { role: "system", content: system },
                { role: "user", content: user }
              ],
              temperature: 0.2
            })
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
          const msg2 = e instanceof Error ? e.message : String(e);
          outputText = `LLM call failed: ${msg2}`;
          outputJson = { error: true, summary: "LLM call failed", message: msg2 };
        }

        await this.db.query(
          `INSERT INTO asv_ai_note (asset_id, issue_id, kind, model, prompt_version, input_hash, output_json, output_text, tokens_input, tokens_output, cost_usd)
           VALUES ($1,$2,'issue_priority',$3,$4,$5,$6::jsonb,$7,$8,$9,NULL)
           ON CONFLICT (kind, issue_id, input_hash)
           DO UPDATE SET output_json = EXCLUDED.output_json,
                         output_text = EXCLUDED.output_text,
                         tokens_input = EXCLUDED.tokens_input,
                         tokens_output = EXCLUDED.tokens_output,
                         cost_usd = EXCLUDED.cost_usd,
                         created_at = now()`,
          [
            it.asset_id,
            it.id,
            cfg.model,
            cfg.promptVersion,
            inputHash,
            JSON.stringify(outputJson ?? {}),
            outputText,
            tokensInput,
            tokensOutput
          ]
        );

        this.queue.publish("vuln.events", "asv.ai.priority.completed.v1", {
          id: randomUUID(),
          type: "asv.ai.priority.completed.v1",
          ts: new Date().toISOString(),
          payload: { issueId: it.id, assetId: it.asset_id, kind: "issue_priority" }
        });

        this.queue.ack(msg);
      } catch (err) {
        // eslint-disable-next-line no-console
        console.error("[ai:asv-priority] failed", err);
        this.queue.nack(msg, false);
      }
    });

    const cfg = await this.llm.getEffectiveLlmConfig();
    // eslint-disable-next-line no-console
    console.log(`[ai:asv-priority] worker ready queue=ai.asv-priority model=${cfg.model} endpoint=${cfg.endpoint}`);
  }
}

