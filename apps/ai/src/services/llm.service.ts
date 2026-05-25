import { Injectable } from "@nestjs/common";
import { runVulnContextLlm } from "@vuln-intel/shared";
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

  async generateVulnContext(input: { cveId: string; raw: Record<string, unknown> }) {
    const cfg = await this.integration.getEffectiveLlmConfig();
    return runVulnContextLlm(input.cveId, input.raw, cfg);
  }
}
