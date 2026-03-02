import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import pino from "pino";

import { createApp } from "../src/app.js";
import type { AuthsignalClient } from "../src/auth/authsignal-client.js";
import type { AppConfig } from "../src/config.js";
import { MemoryFlowStore } from "../src/store/memory-flow-store.js";

const TEST_PASSWORD = "test-password";
const TEST_AUTHSIGNAL_SECRET = "my-authsignal-secret";
const BASIC_AUTH_HEADER = "Basic " + Buffer.from(`${TEST_AUTHSIGNAL_SECRET}:${TEST_PASSWORD}`).toString("base64");

function baseConfig(): AppConfig {
  return {
    nodeEnv: "test",
    port: 3000,
    logLevel: "silent",
    trustProxy: true,
    asgardeo: {
      auth: { mode: "basic", password: TEST_PASSWORD }
    },
    authsignal: {
      apiUrl: "https://signal.authsignal.com"
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
      resolveAuthsignalClient: () => authsignal
    });

    const authenticateRequest = {
      flowId: "flow-123",
      event: { user: { id: "user-1" }, tenant: { name: "test-tenant" } }
    };

    // First call: trackAction → CHALLENGE_REQUIRED → INCOMPLETE
    const firstAttempt = await request(app)
      .post("/api/authenticate")
      .set("authorization", BASIC_AUTH_HEADER)
      .send(authenticateRequest);
    expect(firstAttempt.status).toBe(200);
    expect(firstAttempt.body).toEqual({
      actionStatus: "INCOMPLETE",
      operations: [{ op: "redirect", url: "https://challenge.example.com/session/123" }]
    });

    // Second call: getAction → still CHALLENGE_REQUIRED → INCOMPLETE again
    const secondAttempt = await request(app)
      .post("/api/authenticate")
      .set("authorization", BASIC_AUTH_HEADER)
      .send(authenticateRequest);
    expect(secondAttempt.status).toBe(200);
    expect(secondAttempt.body.actionStatus).toBe("INCOMPLETE");
    expect(trackAction).toHaveBeenCalledTimes(1);
    expect(getAction).toHaveBeenCalledTimes(1);

    // Third call: getAction → CHALLENGE_SUCCEEDED → SUCCESS
    const thirdAttempt = await request(app)
      .post("/api/authenticate")
      .set("authorization", BASIC_AUTH_HEADER)
      .send(authenticateRequest);
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
      resolveAuthsignalClient: () => createAuthsignalClientMock({ trackAction })
    });

    const response = await request(app)
      .post("/api/authenticate")
      .set("authorization", BASIC_AUTH_HEADER)
      .send({
        flowId: "flow-block",
        event: { user: { id: "user-blocked" }, tenant: { name: "test-tenant" } }
      });

    expect(response.status).toBe(200);
    expect(response.body).toEqual({
      actionStatus: "FAILED",
      failureReason: "authsignal_block",
      failureDescription: "Authsignal denied the action"
    });
  });

  it("rejects requests without valid Basic Auth", async () => {
    const app = createApp({
      config: baseConfig(),
      logger: pino({ enabled: false }),
      store: new MemoryFlowStore(900),
      resolveAuthsignalClient: () => createAuthsignalClientMock()
    });

    // No auth header
    const noAuth = await request(app).post("/api/authenticate").send({
      flowId: "flow-auth",
      event: { user: { id: "user-auth" } }
    });
    expect(noAuth.status).toBe(401);

    // Wrong password
    const wrongPassword = await request(app)
      .post("/api/authenticate")
      .set("authorization", "Basic " + Buffer.from("some-secret:wrong-password").toString("base64"))
      .send({
        flowId: "flow-auth",
        event: { user: { id: "user-auth" } }
      });
    expect(wrongPassword.status).toBe(401);

    // Correct password
    const correctAuth = await request(app)
      .post("/api/authenticate")
      .set("authorization", BASIC_AUTH_HEADER)
      .send({
        flowId: "flow-auth",
        event: { user: { id: "user-auth" }, tenant: { name: "test-tenant" } }
      });
    expect(correctAuth.status).toBe(200);
    expect(correctAuth.body).toEqual({ actionStatus: "SUCCESS" });
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
      resolveAuthsignalClient: () => authsignal
    });

    const req = { flowId: "flow-fail", event: { user: { id: "user-fail" }, tenant: { name: "test-tenant" } } };

    await request(app).post("/api/authenticate").set("authorization", BASIC_AUTH_HEADER).send(req);

    const reentry = await request(app).post("/api/authenticate").set("authorization", BASIC_AUTH_HEADER).send(req);
    expect(reentry.status).toBe(200);
    expect(reentry.body).toEqual({
      actionStatus: "FAILED",
      failureReason: "authsignal_challenge_failed",
      failureDescription: "Authentication challenge failed"
    });
  });

  it("extracts tenant from event.tenant.name and includes it in the resume URL", async () => {
    const trackAction = vi.fn(async () => ({
      state: "CHALLENGE_REQUIRED",
      idempotencyKey: "action-id-tenant",
      url: "https://challenge.example.com/session/tenant"
    }));

    const store = new MemoryFlowStore(900);
    const app = createApp({
      config: baseConfig(),
      logger: pino({ enabled: false }),
      store,
      resolveAuthsignalClient: () => createAuthsignalClientMock({ trackAction })
    });

    await request(app)
      .post("/api/authenticate")
      .set("authorization", BASIC_AUTH_HEADER)
      .send({
        flowId: "flow-tenant",
        event: {
          user: { id: "user-tenant" },
          tenant: { name: "acme-corp" },
          organization: { id: "org-123", orgHandle: "acme-corp" }
        }
      });

    const flow = await store.get("flow-tenant");
    expect(flow).toBeDefined();
    expect(flow!.tenantHint).toBe("acme-corp");
    expect(flow!.resumeUrl).toContain("/t/acme-corp/commonauth");
    expect(flow!.resumeUrl).toContain("flowId=flow-tenant");
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
      resolveAuthsignalClient: () => authsignal
    });

    const req = { flowId: "flow-err", event: { user: { id: "user-err" }, tenant: { name: "test-tenant" } } };

    await request(app).post("/api/authenticate").set("authorization", BASIC_AUTH_HEADER).send(req);

    const reentry = await request(app).post("/api/authenticate").set("authorization", BASIC_AUTH_HEADER).send(req);
    expect(reentry.status).toBe(200);
    expect(reentry.body.actionStatus).toBe("INCOMPLETE");
  });

  it("invokes the resolver with the Express request on each call", async () => {
    const mockClient = createAuthsignalClientMock();
    const resolver = vi.fn(() => mockClient);

    const app = createApp({
      config: baseConfig(),
      logger: pino({ enabled: false }),
      store: new MemoryFlowStore(900),
      resolveAuthsignalClient: resolver
    });

    await request(app)
      .post("/api/authenticate")
      .set("authorization", BASIC_AUTH_HEADER)
      .send({
        flowId: "flow-resolver",
        event: { user: { id: "user-1" }, tenant: { name: "test-tenant" } }
      });

    expect(resolver).toHaveBeenCalledTimes(1);
    expect(resolver.mock.calls[0]).toHaveLength(1);
    expect((resolver.mock.calls[0] as unknown[])[0]).toHaveProperty("headers");
  });
});
