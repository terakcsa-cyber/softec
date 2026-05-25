import { Injectable, OnModuleDestroy } from "@nestjs/common";
import { Redis } from "ioredis";

/**
 * Сбрасывает ключ `ai:enrich:*` в Redis после ручного enrich из API,
 * иначе воркер apps/ai может отдать старый кэш без HTTP к Ollama.
 */
@Injectable()
export class RedisEnrichCacheService implements OnModuleDestroy {
  private readonly client: Redis | null;

  constructor() {
    const url = process.env.REDIS_URL?.trim();
    this.client = url
      ? new Redis(url, {
          maxRetriesPerRequest: 2,
          enableOfflineQueue: false
        })
      : null;
  }

  async invalidateForCve(cveId: string, promptVersion: string): Promise<void> {
    if (!this.client || process.env.API_REDIS_ENRICH_INVALIDATE === "false") return;
    const key = `ai:enrich:${cveId}:${promptVersion}`;
    try {
      await this.client.del(key);
    } catch {
      // ignore — не блокируем ответ API
    }
  }

  async invalidateForBdu(bduId: string, promptVersion: string): Promise<void> {
    if (!this.client || process.env.API_REDIS_ENRICH_INVALIDATE === "false") return;
    const key = `ai:enrich:BDU:${bduId}:${promptVersion}`;
    try {
      await this.client.del(key);
    } catch {
      // ignore
    }
  }

  onModuleDestroy() {
    this.client?.disconnect();
  }
}
