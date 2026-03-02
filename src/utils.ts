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

export function buildResumeUrl(
  template: string,
  flowId: string,
  tenantHint?: string
): string {
  const replacements: Record<string, string> = {
    "{flowId}": encodeURIComponent(flowId),
    "{tenant}": tenantHint ? encodeURIComponent(tenantHint) : "",
    "{organization}": tenantHint ? encodeURIComponent(tenantHint) : ""
  };

  let resolved = template;
  for (const [placeholder, value] of Object.entries(replacements)) {
    resolved = resolved.replaceAll(placeholder, value);
  }

  const url = new URL(resolved);
  if (!url.searchParams.has("flowId")) {
    url.searchParams.set("flowId", flowId);
  }
  return url.toString();
}

export function getClientIp(request: Request): string | undefined {
  return request.ip || request.socket.remoteAddress || undefined;
}

export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
