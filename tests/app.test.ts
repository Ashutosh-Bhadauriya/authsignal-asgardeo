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
    publicBaseUrl: "https://adapter.example.com",
    callbackPath: "/api/callback",
    trustProxy: true,
    asgardeo: {
      resumeUrlTemplate: "https://asgardeo.example.com/logincontext?flowId={flowId}",
      auth: { mode: "none" }
    },
    authsignal: {
      apiUrl: "https://signal.authsignal.com",
      secret: "secret",
      action: "login",
      timeoutMs: 1000,
      maxRetries: 0
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
    validateChallenge: vi.fn(async () => ({ state: "CHALLENGE_SUCCEEDED", isValid: true })),
    ...overrides
  };
}

describe("Asgardeo/Authsignal adapter", () => {
  it("handles challenge-required flow and returns success after callback validation", async () => {
    const trackAction = vi.fn(async () => ({
      state: "CHALLENGE_REQUIRED",
      url: "https://challenge.example.com/session/123"
    }));
    const validateChallenge = vi.fn(async () => ({
      state: "CHALLENGE_SUCCEEDED",
      isValid: true
    }));

    const authsignal = createAuthsignalClientMock({ trackAction, validateChallenge });
    const app = createApp({
      config: baseConfig(),
      logger: pino({ enabled: false }),
      store: new MemoryFlowStore(900),
      authsignal
    });

    const authenticateRequest = {
      flowId: "flow-123",
      event: {
        user: {
          id: "user-1"
        }
      }
    };

    // First call: Authsignal returns CHALLENGE_REQUIRED → adapter returns INCOMPLETE with redirect
    const firstAttempt = await request(app).post("/api/authenticate").send(authenticateRequest);
    expect(firstAttempt.status).toBe(200);
    expect(firstAttempt.body).toEqual({
      actionStatus: "INCOMPLETE",
      operations: [{ op: "redirect", url: "https://challenge.example.com/session/123" }]
    });

    // Second call (same flowId): should return cached INCOMPLETE, no new trackAction
    const secondAttempt = await request(app).post("/api/authenticate").send(authenticateRequest);
    expect(secondAttempt.status).toBe(200);
    expect(secondAttempt.body.actionStatus).toBe("INCOMPLETE");
    expect(trackAction).toHaveBeenCalledTimes(1);

    // Callback from Authsignal: validates token and redirects to Asgardeo resume URL
    const callback = await request(app)
      .get("/api/callback")
      .query({ flowId: "flow-123", token: "authsignal-token" });

    expect(callback.status).toBe(302);
    expect(callback.headers.location).toBe("https://asgardeo.example.com/logincontext?flowId=flow-123");
    expect(validateChallenge).toHaveBeenCalledWith("authsignal-token");

    // Final call from Asgardeo (after resume): returns SUCCESS
    const finalAttempt = await request(app).post("/api/authenticate").send(authenticateRequest);
    expect(finalAttempt.status).toBe(200);
    expect(finalAttempt.body).toEqual({ actionStatus: "SUCCESS" });
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
      event: {
        user: {
          id: "user-blocked"
        }
      }
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

  it("redirects with failure when callback is missing token", async () => {
    const trackAction = vi.fn(async () => ({
      state: "CHALLENGE_REQUIRED",
      url: "https://challenge.example.com/session/abc"
    }));
    const validateChallenge = vi.fn(async () => ({
      state: "CHALLENGE_SUCCEEDED",
      isValid: true
    }));

    const app = createApp({
      config: baseConfig(),
      logger: pino({ enabled: false }),
      store: new MemoryFlowStore(900),
      authsignal: createAuthsignalClientMock({ trackAction, validateChallenge })
    });

    const authenticateRequest = {
      flowId: "flow-no-token",
      event: {
        user: {
          id: "user-1"
        }
      }
    };

    await request(app).post("/api/authenticate").send(authenticateRequest);
    const callback = await request(app).get("/api/callback").query({ flowId: "flow-no-token" });
    expect(callback.status).toBe(302);

    const finalAttempt = await request(app).post("/api/authenticate").send(authenticateRequest);
    expect(finalAttempt.status).toBe(200);
    expect(finalAttempt.body).toEqual({
      actionStatus: "FAILED",
      failureReason: "callback_token_missing",
      failureDescription: "Authentication challenge failed"
    });

    expect(validateChallenge).not.toHaveBeenCalled();
  });

  it("returns HTML 404 for expired or unknown flow callback", async () => {
    const app = createApp({
      config: baseConfig(),
      logger: pino({ enabled: false }),
      store: new MemoryFlowStore(900),
      authsignal: createAuthsignalClientMock()
    });

    const response = await request(app).get("/api/callback").query({
      flowId: "flow-does-not-exist",
      token: "token"
    });

    expect(response.status).toBe(404);
    expect(response.text).toContain("Flow not found");
  });
});
