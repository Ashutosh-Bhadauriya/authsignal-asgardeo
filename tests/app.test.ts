import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import pino from "pino";

import { createApp } from "../src/app.js";
import type { AuthsignalClient } from "../src/auth/authsignal-client.js";
import type { AppConfig } from "../src/config.js";
import { MemoryFlowStore } from "../src/store/memory-flow-store.js";

function baseConfig(): AppConfig {
  return {
    nodeEnv: "test",
    port: 3000,
    logLevel: "silent",
    trustProxy: true,
    asgardeo: {
      resumeUrlTemplate: "https://asgardeo.example.com/logincontext?flowId={flowId}",
      auth: { mode: "none" }
    },
    authsignal: {
      apiUrl: "https://signal.authsignal.com",
      secret: "secret"
    },
    store: {
      driver: "memory",
      flowTtlSeconds: 900
    }
  };
}

function createAuthsignalClientMock(overrides?: Partial<AuthsignalClient>): AuthsignalClient {
  return {
    trackAction: vi.fn(async () => ({ state: "ALLOW" })),
    getAction: vi.fn(async () => ({ state: "CHALLENGE_SUCCEEDED" })),
    ...overrides
  };
}

describe("Asgardeo/Authsignal adapter", () => {
  it("handles challenge-required flow and returns success after re-entry", async () => {
    const trackAction = vi.fn(async () => ({
      state: "CHALLENGE_REQUIRED",
      idempotencyKey: "action-id-123",
      url: "https://challenge.example.com/session/123"
    }));

    let getActionCallCount = 0;
    const getAction = vi.fn(async () => {
      getActionCallCount++;
      if (getActionCallCount === 1) {
        return { state: "CHALLENGE_REQUIRED" };
      }
      return { state: "CHALLENGE_SUCCEEDED" };
    });

    const authsignal = createAuthsignalClientMock({ trackAction, getAction });
    const app = createApp({
      config: baseConfig(),
      logger: pino({ enabled: false }),
      store: new MemoryFlowStore(900),
      authsignal
    });

    const authenticateRequest = {
      flowId: "flow-123",
      event: { user: { id: "user-1" } }
    };

    // First call: trackAction → CHALLENGE_REQUIRED → INCOMPLETE
    const firstAttempt = await request(app).post("/api/authenticate").send(authenticateRequest);
    expect(firstAttempt.status).toBe(200);
    expect(firstAttempt.body).toEqual({
      actionStatus: "INCOMPLETE",
      operations: [{ op: "redirect", url: "https://challenge.example.com/session/123" }]
    });

    // Second call: getAction → still CHALLENGE_REQUIRED → INCOMPLETE again
    const secondAttempt = await request(app).post("/api/authenticate").send(authenticateRequest);
    expect(secondAttempt.status).toBe(200);
    expect(secondAttempt.body.actionStatus).toBe("INCOMPLETE");
    expect(trackAction).toHaveBeenCalledTimes(1);
    expect(getAction).toHaveBeenCalledTimes(1);

    // Third call: getAction → CHALLENGE_SUCCEEDED → SUCCESS
    const thirdAttempt = await request(app).post("/api/authenticate").send(authenticateRequest);
    expect(thirdAttempt.status).toBe(200);
    expect(thirdAttempt.body).toEqual({ actionStatus: "SUCCESS" });
    expect(getAction).toHaveBeenCalledTimes(2);
    expect(getAction).toHaveBeenCalledWith("user-1", "login", "action-id-123");
  });

  it("returns FAILED when Authsignal blocks the action", async () => {
    const trackAction = vi.fn(async () => ({ state: "BLOCK" }));

    const app = createApp({
      config: baseConfig(),
      logger: pino({ enabled: false }),
      store: new MemoryFlowStore(900),
      authsignal: createAuthsignalClientMock({ trackAction })
    });

    const response = await request(app).post("/api/authenticate").send({
      flowId: "flow-block",
      event: { user: { id: "user-blocked" } }
    });

    expect(response.status).toBe(200);
    expect(response.body).toEqual({
      actionStatus: "FAILED",
      failureReason: "authsignal_block",
      failureDescription: "Authsignal denied the action"
    });
  });

  it("enforces bearer auth on authenticate endpoint when configured", async () => {
    const config = baseConfig();
    config.asgardeo.auth = { mode: "bearer", token: "top-secret" };

    const app = createApp({
      config,
      logger: pino({ enabled: false }),
      store: new MemoryFlowStore(900),
      authsignal: createAuthsignalClientMock()
    });

    const withoutToken = await request(app).post("/api/authenticate").send({
      flowId: "flow-auth",
      event: { user: { id: "user-auth" } }
    });
    expect(withoutToken.status).toBe(401);

    const withToken = await request(app)
      .post("/api/authenticate")
      .set("authorization", "Bearer top-secret")
      .send({
        flowId: "flow-auth",
        event: { user: { id: "user-auth" } }
      });
    expect(withToken.status).toBe(200);
    expect(withToken.body).toEqual({ actionStatus: "SUCCESS" });
  });

  it("returns FAILED when getAction reports challenge failed on re-entry", async () => {
    const trackAction = vi.fn(async () => ({
      state: "CHALLENGE_REQUIRED",
      idempotencyKey: "action-id-456",
      url: "https://challenge.example.com/session/456"
    }));
    const getAction = vi.fn(async () => ({ state: "CHALLENGE_FAILED" }));

    const authsignal = createAuthsignalClientMock({ trackAction, getAction });
    const app = createApp({
      config: baseConfig(),
      logger: pino({ enabled: false }),
      store: new MemoryFlowStore(900),
      authsignal
    });

    const req = { flowId: "flow-fail", event: { user: { id: "user-fail" } } };

    await request(app).post("/api/authenticate").send(req);

    const reentry = await request(app).post("/api/authenticate").send(req);
    expect(reentry.status).toBe(200);
    expect(reentry.body).toEqual({
      actionStatus: "FAILED",
      failureReason: "authsignal_challenge_failed",
      failureDescription: "Authentication challenge failed"
    });
  });

  it("returns INCOMPLETE when getAction call fails on re-entry", async () => {
    const trackAction = vi.fn(async () => ({
      state: "CHALLENGE_REQUIRED",
      idempotencyKey: "action-id-789",
      url: "https://challenge.example.com/session/789"
    }));
    const getAction = vi.fn(async () => { throw new Error("API timeout"); });

    const authsignal = createAuthsignalClientMock({ trackAction, getAction });
    const app = createApp({
      config: baseConfig(),
      logger: pino({ enabled: false }),
      store: new MemoryFlowStore(900),
      authsignal
    });

    const req = { flowId: "flow-err", event: { user: { id: "user-err" } } };

    await request(app).post("/api/authenticate").send(req);

    const reentry = await request(app).post("/api/authenticate").send(req);
    expect(reentry.status).toBe(200);
    expect(reentry.body.actionStatus).toBe("INCOMPLETE");
  });
});
