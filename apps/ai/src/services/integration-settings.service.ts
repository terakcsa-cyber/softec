import { Injectable, OnModuleInit } from "@nestjs/common";
import {
  getVulnContextLlmConfigFromEnv,
  mergeVulnContextLlmConfig,
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

function isRecord(x: unknown): x is Record<string, unknown> {
  return Boolean(x) && typeof x === "object" && !Array.isArray(x);
}

@Injectable()
export class IntegrationSettingsService implements OnModuleInit {
  private mem: { cfg: VulnContextLlmConfig; at: number } | null = null;
  private readonly ttlMs = Math.max(1000, Math.min(60_000, Number(process.env.INTEGRATION_SETTINGS_CACHE_MS ?? 5000)));

  constructor(private readonly db: DbService) {}

  async onModuleInit() {
    await this.refresh();
  }

  getPromptVersionCached(): string {
    return this.mem?.cfg.promptVersion ?? getVulnContextLlmConfigFromEnv().promptVersion;
  }

  async getEffectiveLlmConfig(): Promise<VulnContextLlmConfig> {
    const now = Date.now();
    if (this.mem && now - this.mem.at < this.ttlMs) return this.mem.cfg;
    await this.refresh();
    return this.mem!.cfg;
  }

  async refresh(): Promise<void> {
    const cfg = await this.loadMerged();
    this.mem = { cfg, at: Date.now() };
  }

  private async loadMerged(): Promise<VulnContextLlmConfig> {
    const base = getVulnContextLlmConfigFromEnv();
    try {
      const r = await this.db.query<{ value: unknown }>(
        `SELECT value FROM app_integration_settings WHERE key = 'llm' LIMIT 1`
      );
      const v = r.rows[0]?.value;
      const doc = (isRecord(v) ? v : {}) as unknown as LlmDoc;
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
    } catch {
      return base;
    }
  }
}
