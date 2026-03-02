import type { Request } from "express";

import type { AsgardeoAuthRequest } from "./types/asgardeo.js";

function maybeString(value: unknown): string | undefined {
  if (typeof value !== "string") {
    return undefined;
  }
  const trimmed = value.trim();
  return trimmed === "" ? undefined : trimmed;
}

export function resolveUserId(request: AsgardeoAuthRequest): string | undefined {
  const user = request.event?.user;
  if (!user) {
    return undefined;
  }

  return (
    maybeString(user.id) ??
    maybeString(user.username) ??
    maybeString(user.email) ??
    maybeString(user.claims?.sub) ??
    maybeString(user.claims?.user_id)
  );
}

export function extractTenantHint(request: AsgardeoAuthRequest): string | undefined {
  // Prefer event.tenant.name (Asgardeo's actual payload structure)
  const tenantName = maybeString(request.event?.tenant?.name);
  if (tenantName) {
    return tenantName;
  }

  // Fall back to event.organization.orgHandle or id
  const org = request.event?.organization;
  const orgHandle = maybeString(org?.orgHandle);
  if (orgHandle) {
    return orgHandle;
  }

  const orgId = maybeString(org?.id);
  if (orgId) {
    return orgId;
  }

  return undefined;
}

export function buildResumeUrl(flowId: string, tenant: string): string {
  return `https://api.asgardeo.io/t/${encodeURIComponent(tenant)}/commonauth?flowId=${encodeURIComponent(flowId)}`;
}

export function getClientIp(request: Request): string | undefined {
  return request.ip || request.socket.remoteAddress || undefined;
}

export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
