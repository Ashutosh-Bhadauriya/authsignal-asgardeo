import type { Logger } from "pino";

import type { AppConfig } from "../config.js";
import { MemoryFlowStore } from "./memory-flow-store.js";
import { RedisFlowStore } from "./redis-flow-store.js";
import type { FlowStore } from "./flow-store.js";

export function createFlowStore(config: AppConfig, logger: Logger): FlowStore {
  if (config.store.driver === "memory") {
    logger.warn("Using in-memory flow store. Use STORE_DRIVER=redis for production deployments.");
    return new MemoryFlowStore(config.store.flowTtlSeconds);
  }

  if (!config.store.redisUrl) {
    throw new Error("REDIS_URL is required when STORE_DRIVER=redis");
  }

  return new RedisFlowStore(config.store.redisUrl, config.store.flowTtlSeconds);
}
