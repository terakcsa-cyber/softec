import { Injectable } from "@nestjs/common";
import { getVulnContextLlmConfigFromEnv, runVulnContextLlm } from "@vuln-intel/shared";

@Injectable()
export class LlmService {
  /** Читаем env на каждый вызов: конфиг не должен «залипать» при старте до load-env / смене .env. */
  getPromptVersion() {
    return getVulnContextLlmConfigFromEnv().promptVersion;
  }

  async generateVulnContext(input: { cveId: string; raw: Record<string, unknown> }) {
    return runVulnContextLlm(input.cveId, input.raw, getVulnContextLlmConfigFromEnv());
  }
}
