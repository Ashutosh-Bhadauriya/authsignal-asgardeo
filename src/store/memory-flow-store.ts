import { randomUUID } from "node:crypto";

import type { FlowRecord, FlowStore } from "./flow-store.js";

interface MemoryRecord {
  flow: FlowRecord;
  expiresAt: number;
}

interface MemoryLock {
  owner: string;
  expiresAt: number;
}

export class MemoryFlowStore implements FlowStore {
  private readonly flows = new Map<string, MemoryRecord>();
  private readonly locks = new Map<string, MemoryLock>();

  constructor(private readonly ttlSeconds: number) {}

  async get(flowId: string): Promise<FlowRecord | undefined> {
    this.pruneExpired(flowId);
    return this.flows.get(flowId)?.flow;
  }

  async save(record: FlowRecord): Promise<void> {
    this.flows.set(record.flowId, {
      flow: record,
      expiresAt: Date.now() + this.ttlSeconds * 1000
    });
  }

  async acquireLock(flowId: string, ttlMs: number): Promise<string | null> {
    const now = Date.now();
    const existing = this.locks.get(flowId);
    if (existing && existing.expiresAt > now) {
      return null;
    }

    const owner = randomUUID();
    this.locks.set(flowId, { owner, expiresAt: now + ttlMs });
    return owner;
  }

  async releaseLock(flowId: string, owner: string): Promise<void> {
    const existing = this.locks.get(flowId);
    if (existing && existing.owner === owner) {
      this.locks.delete(flowId);
    }
  }

  async healthcheck(): Promise<void> {}

  async close(): Promise<void> {
    this.flows.clear();
    this.locks.clear();
  }

  private pruneExpired(flowId: string): void {
    const stored = this.flows.get(flowId);
    if (!stored) {
      return;
    }
    if (stored.expiresAt < Date.now()) {
      this.flows.delete(flowId);
    }
  }
}
