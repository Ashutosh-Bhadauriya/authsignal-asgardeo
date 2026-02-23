import express, { type Request } from "express";
import helmet from "helmet";
import type { Logger } from "pino";

import type { AppConfig } from "./config.js";
import { createAsgardeoRequestAuth } from "./auth/asgardeo-request-auth.js";
import type { AuthsignalClient } from "./auth/authsignal-client.js";
import type { CompletedFlowRecord, FlowStore, PendingFlowRecord } from "./store/flow-store.js";
import { asgardeoAuthRequestSchema, type AsgardeoAuthRequest, type AsgardeoAuthResponse } from "./types/asgardeo.js";
import { buildCallbackUrl, buildResumeUrl, extractTenantHint, getClientIp, renderSimplePage, resolveUserId } from "./utils.js";

const LOCK_TTL_MS = 30_000;
const SUCCESS_STATES = new Set(["ALLOW", "CHALLENGE_SUCCEEDED", "REVIEW_SUCCEEDED"]);
const FAILED_STATES = new Set(["BLOCK", "CHALLENGE_FAILED", "REVIEW_FAILED"]);
const PENDING_STATES = new Set(["CHALLENGE_REQUIRED", "REVIEW_REQUIRED"]);

interface AppDependencies {
  config: AppConfig;
  logger: Logger;
  store: FlowStore;
  authsignal: AuthsignalClient;
}

function canRedirect(request: AsgardeoAuthRequest): boolean {
  if (!request.allowedOperations) {
    return true;
  }
  return request.allowedOperations.some((op) => op.op === "redirect");
}

function asgardeoSuccess(): AsgardeoAuthResponse {
  return { actionStatus: "SUCCESS" };
}

function asgardeoFailure(reason: string, description: string): AsgardeoAuthResponse {
  return { actionStatus: "FAILED", failureReason: reason, failureDescription: description };
}

function asgardeoIncomplete(redirectUrl: string): AsgardeoAuthResponse {
  return {
    actionStatus: "INCOMPLETE",
    operations: [{ op: "redirect", url: redirectUrl }]
  };
}

function asgardeoError(code: string, description: string): AsgardeoAuthResponse {
  return { actionStatus: "ERROR", errorCode: code, errorDescription: description };
}

function mapTrackState(
  state: string,
  response: { url?: string }
):
  | { kind: "success" }
  | { kind: "failed"; reason: string }
  | { kind: "pending"; redirectUrl: string }
  | { kind: "unknown" } {
  const normalized = state.toUpperCase();
  if (SUCCESS_STATES.has(normalized)) {
    return { kind: "success" };
  }
  if (FAILED_STATES.has(normalized)) {
    return { kind: "failed", reason: `authsignal_${normalized.toLowerCase()}` };
  }
  if (PENDING_STATES.has(normalized) && response.url) {
    return { kind: "pending", redirectUrl: response.url };
  }
  return { kind: "unknown" };
}

function mapValidateState(
  state?: string,
  isValid?: boolean
): { outcome: "SUCCESS" | "FAILED"; reason?: string } {
  const normalized = state?.toUpperCase();

  if (isValid === true || (normalized && SUCCESS_STATES.has(normalized))) {
    return { outcome: "SUCCESS" };
  }

  if (normalized && FAILED_STATES.has(normalized)) {
    return { outcome: "FAILED", reason: `authsignal_${normalized.toLowerCase()}` };
  }

  return { outcome: "FAILED", reason: "authsignal_validation_failed" };
}

export function createApp({ config, logger, store, authsignal }: AppDependencies): express.Express {
  const app = express();
  const authenticateAuthMiddleware = createAsgardeoRequestAuth(config);

  app.disable("x-powered-by");
  if (config.trustProxy) {
    app.set("trust proxy", true);
  }

  app.use((request, response, next) => {
    const startedAt = Date.now();
    response.on("finish", () => {
      const durationMs = Date.now() - startedAt;
      const statusCode = response.statusCode;
      const level = statusCode >= 500 ? "error" : statusCode >= 400 ? "warn" : "info";
      logger[level](
        {
          method: request.method,
          path: request.originalUrl,
          statusCode,
          durationMs
        },
        "HTTP request"
      );
    });
    next();
  });
  app.use(helmet());
  app.use(express.json({ limit: "100kb" }));

  app.get("/healthz", (_request, response) => {
    response.status(200).json({ status: "ok" });
  });

  app.get("/readyz", async (_request, response) => {
    try {
      await store.healthcheck();
      response.status(200).json({ status: "ok" });
    } catch (error) {
      logger.error({ err: error }, "Store readiness check failed");
      response.status(503).json({ status: "error" });
    }
  });

  app.post("/api/authenticate", authenticateAuthMiddleware, async (request, response) => {
    const parsedRequest = asgardeoAuthRequestSchema.safeParse(request.body);
    if (!parsedRequest.success) {
      response.status(400).json(asgardeoError("INVALID_REQUEST", "Invalid request payload"));
      return;
    }

    const asgardeoRequest = parsedRequest.data;
    const flowId = asgardeoRequest.flowId;

    try {
      const existingFlow = await store.get(flowId);
      if (existingFlow) {
        if (existingFlow.status === "PENDING") {
          if (!canRedirect(asgardeoRequest)) {
            response.status(200).json(asgardeoError("REDIRECT_NOT_ALLOWED", "Redirect operation not allowed"));
            return;
          }
          response.status(200).json(asgardeoIncomplete(existingFlow.redirectUrl));
          return;
        }

        response
          .status(200)
          .json(
            existingFlow.outcome === "SUCCESS"
              ? asgardeoSuccess()
              : asgardeoFailure(existingFlow.failureReason ?? "CHALLENGE_FAILED", "Authentication challenge failed")
          );
        return;
      }

      const lockOwner = await store.acquireLock(flowId, LOCK_TTL_MS);
      if (!lockOwner) {
        const lockRaceFlow = await store.get(flowId);
        if (lockRaceFlow) {
          if (lockRaceFlow.status === "PENDING") {
            if (!canRedirect(asgardeoRequest)) {
              response.status(200).json(asgardeoError("REDIRECT_NOT_ALLOWED", "Redirect operation not allowed"));
              return;
            }
            response.status(200).json(asgardeoIncomplete(lockRaceFlow.redirectUrl));
          } else {
            response
              .status(200)
              .json(
                lockRaceFlow.outcome === "SUCCESS"
                  ? asgardeoSuccess()
                  : asgardeoFailure(lockRaceFlow.failureReason ?? "CHALLENGE_FAILED", "Authentication challenge failed")
              );
          }
          return;
        }

        response.status(200).json(asgardeoError("FLOW_LOCKED", "Flow is being processed, retry shortly"));
        return;
      }

      try {
        const doubleCheckFlow = await store.get(flowId);
        if (doubleCheckFlow) {
          if (doubleCheckFlow.status === "PENDING") {
            if (!canRedirect(asgardeoRequest)) {
              response.status(200).json(asgardeoError("REDIRECT_NOT_ALLOWED", "Redirect operation not allowed"));
              return;
            }
            response.status(200).json(asgardeoIncomplete(doubleCheckFlow.redirectUrl));
            return;
          }
          response
            .status(200)
            .json(
              doubleCheckFlow.outcome === "SUCCESS"
                ? asgardeoSuccess()
                : asgardeoFailure(doubleCheckFlow.failureReason ?? "CHALLENGE_FAILED", "Authentication challenge failed")
            );
          return;
        }

        const userId = resolveUserId(asgardeoRequest);
        if (!userId) {
          response.status(200).json(asgardeoError("MISSING_USER", "No user identifier found in request"));
          return;
        }

        const tenantHint = extractTenantHint(asgardeoRequest);
        const resumeUrl = buildResumeUrl(config.asgardeo.resumeUrlTemplate, flowId, tenantHint);
        const callbackUrl = buildCallbackUrl(config.publicBaseUrl, config.callbackPath, flowId);

        const ipAddress = getClientIp(request);
        const userAgent = request.header("user-agent");
        const customPayload: Record<string, unknown> = {
          asgardeoFlowId: flowId
        };
        if (asgardeoRequest.actionType) {
          customPayload.asgardeoActionType = asgardeoRequest.actionType;
        }

        const action = asgardeoRequest.actionType ?? "login";

        const trackResult = await authsignal.trackAction({
          userId,
          action,
          redirectUrl: callbackUrl,
          ...(ipAddress ? { ipAddress } : {}),
          ...(userAgent ? { userAgent } : {}),
          custom: customPayload
        });

        const mappedTrackState = mapTrackState(trackResult.state, trackResult);
        if (mappedTrackState.kind === "pending") {
          if (!canRedirect(asgardeoRequest)) {
            response.status(200).json(asgardeoError("REDIRECT_NOT_ALLOWED", "Redirect operation not allowed"));
            return;
          }

          const now = new Date().toISOString();
          const pendingFlow: PendingFlowRecord = {
            flowId,
            userId,
            resumeUrl,
            status: "PENDING",
            redirectUrl: mappedTrackState.redirectUrl,
            createdAt: now,
            updatedAt: now,
            ...(tenantHint ? { tenantHint } : {})
          };
          await store.save(pendingFlow);
          response.status(200).json(asgardeoIncomplete(mappedTrackState.redirectUrl));
          return;
        }

        if (mappedTrackState.kind === "success") {
          const now = new Date().toISOString();
          await store.save({
            flowId, userId, resumeUrl, status: "COMPLETED", outcome: "SUCCESS",
            createdAt: now, updatedAt: now, ...(tenantHint ? { tenantHint } : {})
          });
          response.status(200).json(asgardeoSuccess());
          return;
        }

        if (mappedTrackState.kind === "failed") {
          const now = new Date().toISOString();
          await store.save({
            flowId, userId, resumeUrl, status: "COMPLETED", outcome: "FAILED",
            failureReason: mappedTrackState.reason,
            createdAt: now, updatedAt: now, ...(tenantHint ? { tenantHint } : {})
          });
          response.status(200).json(asgardeoFailure(mappedTrackState.reason, "Authsignal denied the action"));
          return;
        }

        logger.error({ flowId, trackResult }, "Unhandled Authsignal track state");
        response.status(200).json(asgardeoError("AUTHSIGNAL_ERROR", "Unexpected response from Authsignal"));
      } finally {
        try {
          await store.releaseLock(flowId, lockOwner);
        } catch (releaseError) {
          logger.error({ err: releaseError, flowId }, "Failed to release flow lock");
        }
      }
    } catch (error) {
      logger.error({ err: error, flowId }, "Failed to process Asgardeo authentication request");
      response.status(200).json(asgardeoError("INTERNAL_ERROR", "Internal adapter error"));
    }
  });

  app.get("/api/callback", async (request, response) => {
    let flowForFailure: PendingFlowRecord | undefined;
    let flowIdForLog: string | undefined;

    try {
      const flowId = getSingleQueryValue(request, "flowId");
      flowIdForLog = flowId;
      if (!flowId) {
        response
          .status(400)
          .type("html")
          .send(renderSimplePage("Missing flow ID", "The callback is missing flowId and cannot continue."));
        return;
      }

      const flow = await store.get(flowId);
      if (!flow) {
        response
          .status(404)
          .type("html")
          .send(renderSimplePage("Flow not found", "This authentication flow is expired or no longer available."));
        return;
      }

      if (flow.status === "COMPLETED") {
        response.redirect(302, flow.resumeUrl);
        return;
      }

      flowForFailure = flow;

      const token = getSingleQueryValue(request, "token");
      if (!token) {
        const completedAt = new Date().toISOString();
        await store.save(toCompletedFlow(flow, "FAILED", completedAt, "callback_token_missing"));
        response.redirect(302, flow.resumeUrl);
        return;
      }

      const validationResult = await authsignal.validateChallenge(token);
      const mapped = mapValidateState(validationResult.state, validationResult.isValid);

      await store.save(toCompletedFlow(flow, mapped.outcome, new Date().toISOString(), mapped.reason));

      response.redirect(302, flow.resumeUrl);
    } catch (error) {
      logger.error({ err: error, flowId: flowIdForLog }, "Failed to handle Authsignal callback");

      if (flowForFailure) {
        try {
          await store.save(
            toCompletedFlow(flowForFailure, "FAILED", new Date().toISOString(), "authsignal_validate_error")
          );
          if (!response.headersSent) {
            response.redirect(302, flowForFailure.resumeUrl);
            return;
          }
        } catch (saveError) {
          logger.error({ err: saveError, flowId: flowIdForLog }, "Failed to persist callback failure status");
        }
      }

      if (!response.headersSent) {
        response
          .status(500)
          .type("html")
          .send(renderSimplePage("Authentication error", "Could not complete callback processing."));
      }
    }
  });

  app.use((_request, response) => {
    response.status(404).json({ error: "not_found" });
  });

  return app;
}

function getSingleQueryValue(request: Request, key: string): string | undefined {
  const value = request.query[key];
  if (typeof value === "string") {
    const trimmed = value.trim();
    return trimmed === "" ? undefined : trimmed;
  }
  if (Array.isArray(value) && typeof value[0] === "string") {
    const trimmed = value[0].trim();
    return trimmed === "" ? undefined : trimmed;
  }
  return undefined;
}

function toCompletedFlow(
  flow: PendingFlowRecord,
  outcome: "SUCCESS" | "FAILED",
  updatedAt: string,
  failureReason?: string
): CompletedFlowRecord {
  return {
    flowId: flow.flowId,
    userId: flow.userId,
    resumeUrl: flow.resumeUrl,
    status: "COMPLETED",
    outcome,
    createdAt: flow.createdAt,
    updatedAt,
    ...(flow.tenantHint ? { tenantHint: flow.tenantHint } : {}),
    ...(failureReason ? { failureReason } : {})
  };
}
