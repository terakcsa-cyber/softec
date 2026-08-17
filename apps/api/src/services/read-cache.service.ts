import { Injectable, OnModuleDestroy } from "@nestjs/common";
import { Redis } from "ioredis";

type MemoryEntry = { exp: number; value: unknown };

/**
 * Short-lived JSON cache for heavy read endpoints (stats/summary, CVE first page).
 * Redis when REDIS_URL is set; otherwise in-process Map. Never throws to callers.
 */
@Injectable()
export class ReadCacheService implements OnModuleDestroy {
  private readonly redis: Redis | null;
  private readonly memory = new Map<string, MemoryEntry>();
  private readonly inflight = new Map<string, Promise<unknown>>();

  constructor() {
    const url = process.env.REDIS_URL?.trim();
    this.redis = url
      ? new Redis(url, {
          maxRetriesPerRequest: 1,
          enableOfflineQueue: false,
          lazyConnect: true
        })
      : null;
    void this.redis?.connect().catch(() => {
      // stay on memory fallback
    });
  }

  enabled(): boolean {
    const flag = (process.env.API_READ_CACHE ?? "").trim().toLowerCase();
    if (flag === "false" || flag === "0" || flag === "no") return false;
    return true;
  }

  ttlSec(kind: string, fallback: number): number {
    if (!this.enabled()) return 0;
    const specific = Number(process.env[`API_READ_CACHE_TTL_${kind.toUpperCase()}_SEC`]);
    if (Number.isFinite(specific) && specific >= 0) return Math.min(120, specific);
    const global = Number(process.env.API_READ_CACHE_TTL_SEC ?? fallback);
    if (!Number.isFinite(global) || global <= 0) return 0;
    return Math.min(120, Math.max(1, Math.floor(global)));
  }

  async getOrSet<T>(key: string, ttlSec: number, load: () => Promise<T>): Promise<T> {
    if (ttlSec <= 0) return load();
    const fullKey = `vip:read:${key}`;
    const hit = await this.get<T>(fullKey);
    if (hit !== undefined) return hit;
    const existing = this.inflight.get(fullKey);
    if (existing) return existing as Promise<T>;
    const pending = load()
      .then(async (value) => {
        await this.set(fullKey, value, ttlSec);
        return value;
      })
      .finally(() => {
        this.inflight.delete(fullKey);
      });
    this.inflight.set(fullKey, pending);
    return pending;
  }

  onModuleDestroy() {
    this.redis?.disconnect();
    this.memory.clear();
    this.inflight.clear();
  }

  private async get<T>(key: string): Promise<T | undefined> {
    const mem = this.memory.get(key);
    if (mem) {
      if (mem.exp > Date.now()) return mem.value as T;
      this.memory.delete(key);
    }
    if (!this.redis) return undefined;
    try {
      const raw = await this.redis.get(key);
      if (!raw) return undefined;
      const parsed = JSON.parse(raw) as T;
      this.memory.set(key, { exp: Date.now() + 2_000, value: parsed });
      return parsed;
    } catch {
      return undefined;
    }
  }

  private async set(key: string, value: unknown, ttlSec: number): Promise<void> {
    this.memory.set(key, { exp: Date.now() + ttlSec * 1000, value });
    if (!this.redis) return;
    try {
      await this.redis.set(key, JSON.stringify(value), "EX", ttlSec);
    } catch {
      // ignore
    }
  }
}
