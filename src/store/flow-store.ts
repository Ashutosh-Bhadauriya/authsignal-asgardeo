export type FlowOutcome = "SUCCESS" | "FAILED";

interface BaseFlowRecord {
  flowId: string;
  userId: string;
  resumeUrl: string;
  tenantHint?: string;
  createdAt: string;
  updatedAt: string;
}

export interface PendingFlowRecord extends BaseFlowRecord {
  status: "PENDING";
  redirectUrl: string;
}

export interface CompletedFlowRecord extends BaseFlowRecord {
  status: "COMPLETED";
  outcome: FlowOutcome;
  failureReason?: string;
}

export type FlowRecord = PendingFlowRecord | CompletedFlowRecord;

export interface FlowStore {
  get(flowId: string): Promise<FlowRecord | undefined>;
  save(record: FlowRecord): Promise<void>;
  acquireLock(flowId: string, ttlMs: number): Promise<string | null>;
  releaseLock(flowId: string, owner: string): Promise<void>;
  healthcheck(): Promise<void>;
  close(): Promise<void>;
}
