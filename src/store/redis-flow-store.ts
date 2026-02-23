import { randomUUID } from "node:crypto";

import RedisImport from "ioredis";

import type { FlowRecord, FlowStore } from "./flow-store.js";

const RELEASE_LOCK_SCRIPT = `
if redis.call("get", KEYS[1]) == ARGV[1] then
  return redis.call("del", KEYS[1])
else
  return 0
end
`;

export class RedisFlowStore implements FlowStore {
  private readonly redis: {
    get(key: string): Promise<string | null>;
    set(key: string, value: string, mode: "EX", seconds: number): Promise<unknown>;
    set(key: string, value: string, mode: "PX", milliseconds: number, condition: "NX"): Promise<unknown>;
    del(key: string): Promise<number>;
    eval(script: string, numkeys: number, ...args: string[]): Promise<unknown>;
    ping(): Promise<string>;
    quit(): Promise<string>;
  };

  constructor(
    redisUrl: string,
    private readonly ttlSeconds: number,
    private readonly keyPrefix = "asgardeo-authsignal-adapter"
  ) {
    const RedisConstructor = RedisImport as unknown as new (url: string) => RedisFlowStore["redis"];
    this.redis = new RedisConstructor(redisUrl);
  }

  async get(flowId: string): Promise<FlowRecord | undefined> {
    const payload = await this.redis.get(this.flowKey(flowId));
    if (!payload) {
      return undefined;
    }

    try {
      return JSON.parse(payload) as FlowRecord;
    } catch {
      return undefined;
    }
  }

  async save(record: FlowRecord): Promise<void> {
    await this.redis.set(this.flowKey(record.flowId), JSON.stringify(record), "EX", this.ttlSeconds);
  }

  async acquireLock(flowId: string, ttlMs: number): Promise<string | null> {
    const owner = randomUUID();
    const result = await this.redis.set(this.lockKey(flowId), owner, "PX", ttlMs, "NX");
    return result === "OK" ? owner : null;
  }

  async releaseLock(flowId: string, owner: string): Promise<void> {
    await this.redis.eval(RELEASE_LOCK_SCRIPT, 1, this.lockKey(flowId), owner);
  }

  async healthcheck(): Promise<void> {
    await this.redis.ping();
  }

  async close(): Promise<void> {
    await this.redis.quit();
  }

  private flowKey(flowId: string): string {
    return `${this.keyPrefix}:flow:${flowId}`;
  }

  private lockKey(flowId: string): string {
    return `${this.keyPrefix}:flow-lock:${flowId}`;
  }
}
