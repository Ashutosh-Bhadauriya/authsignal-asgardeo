import express from "express";
import helmet from "helmet";
import type { Logger } from "pino";

import type { AppConfig } from "./config.js";
import { createAsgardeoRequestAuth } from "./auth/asgardeo-request-auth.js";
import type { AuthsignalClient, AuthsignalClientResolver } from "./auth/authsignal-client.js";
import type { CompletedFlowRecord, FlowStore, PendingFlowRecord } from "./store/flow-store.js";
import { asgardeoAuthRequestSchema, type AsgardeoAuthRequest, type AsgardeoAuthResponse } from "./types/asgardeo.js";
import { buildResumeUrl, extractTenantHint, getClientIp, resolveUserId } from "./utils.js";

const LOCK_TTL_MS = 30_000;
const SUCCESS_STATES = new Set(["ALLOW", "CHALLENGE_SUCCEEDED", "REVIEW_SUCCEEDED"]);
const FAILED_STATES = new Set(["BLOCK", "CHALLENGE_FAILED", "REVIEW_FAILED"]);
const PENDING_STATES = new Set(["CHALLENGE_REQUIRED", "REVIEW_REQUIRED"]);

interface AppDependencies {
  config: AppConfig;
  logger: Logger;
  store: FlowStore;
  resolveAuthsignalClient: AuthsignalClientResolver;
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

export function createApp({ config, logger, store, resolveAuthsignalClient }: AppDependencies): express.Express {
  const app = express();
  const authenticateAuthMiddleware = createAsgardeoRequestAuth(config);

  async function resolvePendingFlow(
    flow: PendingFlowRecord,
    asgardeoRequest: AsgardeoAuthRequest,
    authsignal: AuthsignalClient
  ): Promise<AsgardeoAuthResponse> {
    try {
      const actionResult = await authsignal.getAction(flow.userId, flow.action, flow.idempotencyKey);
      const actionState = actionResult.state.toUpperCase();

      if (SUCCESS_STATES.has(actionState)) {
        await store.save(toCompletedFlow(flow, "SUCCESS", new Date().toISOString()));
        return asgardeoSuccess();
      }

      if (FAILED_STATES.has(actionState)) {
        const reason = `authsignal_${actionState.toLowerCase()}`;
        await store.save(toCompletedFlow(flow, "FAILED", new Date().toISOString(), reason));
        return asgardeoFailure(reason, "Authentication challenge failed");
      }
    } catch (error) {
      logger.error({ err: error, flowId: flow.flowId }, "Failed to check action state via getAction");
    }

    // Still pending or getAction failed — bump updatedAt so TTL doesn't expire mid-challenge
    await store.save({ ...flow, updatedAt: new Date().toISOString() });

    if (!canRedirect(asgardeoRequest)) {
      return asgardeoError("REDIRECT_NOT_ALLOWED", "Redirect operation not allowed");
    }
    return asgardeoIncomplete(flow.redirectUrl);
  }

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
    const authsignal = resolveAuthsignalClient(request);

    try {
      const existingFlow = await store.get(flowId);
      if (existingFlow) {
        if (existingFlow.status === "PENDING") {
          response.status(200).json(await resolvePendingFlow(existingFlow, asgardeoRequest, authsignal));
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
            response.status(200).json(await resolvePendingFlow(lockRaceFlow, asgardeoRequest, authsignal));
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
            response.status(200).json(await resolvePendingFlow(doubleCheckFlow, asgardeoRequest, authsignal));
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
          redirectUrl: resumeUrl,
          ...(ipAddress ? { ipAddress } : {}),
          ...(userAgent ? { userAgent } : {}),
          custom: customPayload
        });

        const mappedTrackState = mapTrackState(trackResult.state, trackResult);
        if (mappedTrackState.kind === "pending") {
          if (!trackResult.idempotencyKey) {
            logger.error({ flowId, trackResult }, "trackAction returned CHALLENGE_REQUIRED without idempotencyKey");
            response.status(200).json(asgardeoError("AUTHSIGNAL_ERROR", "Missing idempotency key from Authsignal"));
            return;
          }

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
            idempotencyKey: trackResult.idempotencyKey,
            action,
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

  app.use((_request, response) => {
    response.status(404).json({ error: "not_found" });
  });

  return app;
}
