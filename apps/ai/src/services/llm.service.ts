import { Injectable } from "@nestjs/common";
import { runCveTextEngine, runVulnContextLlm } from "@vuln-intel/shared";
import { IntegrationSettingsService } from "./integration-settings.service.js";

@Injectable()
export class LlmService {
  constructor(private readonly integration: IntegrationSettingsService) {}

  getPromptVersion() {
    return this.integration.getPromptVersionCached();
  }

  async getEffectiveLlmConfig() {
    return this.integration.getEffectiveLlmConfig();
  }

  async getTextEngineSettings() {
    return this.integration.getTextEngineSettings();
  }

  async generateVulnContext(input: {
    cveId: string;
    raw: Record<string, unknown>;
    skipTranslate?: boolean;
  }) {
    const text = await this.integration.getTextEngineSettings();
    if (text.textEngine !== "llm") {
      return runCveTextEngine(input.cveId, input.raw, text, { skipTranslate: input.skipTranslate });
    }
    const cfg = await this.integration.getEffectiveLlmConfig();
    return runVulnContextLlm(input.cveId, input.raw, cfg);
  }
}
