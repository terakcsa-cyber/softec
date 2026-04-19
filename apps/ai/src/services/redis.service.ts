import { Injectable, OnModuleDestroy } from "@nestjs/common";
import { Redis } from "ioredis";

@Injectable()
export class RedisService implements OnModuleDestroy {
  readonly client: Redis;

  constructor() {
    const url = process.env.REDIS_URL ?? "redis://localhost:6379";
    this.client = new Redis(url, {
      maxRetriesPerRequest: 5,
      enableOfflineQueue: true
    });
  }

  async onModuleDestroy() {
    this.client.disconnect();
  }
}

