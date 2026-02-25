import type { Request } from "express";

import type { AsgardeoAuthRequest } from "./types/asgardeo.js";

const TENANT_KEYS = ["tenant", "tenantDomain", "organization", "org", "organizationName"] as const;

function maybeString(value: unknown): string | undefined {
  if (typeof value !== "string") {
    return undefined;
  }
  const trimmed = value.trim();
  return trimmed === "" ? undefined : trimmed;
}

function readRecordValue(record: unknown, key: string): string | undefined {
  if (typeof record !== "object" || !record || Array.isArray(record)) {
    return undefined;
  }

  const value = (record as Record<string, unknown>)[key];
  return maybeString(value);
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
  for (const key of TENANT_KEYS) {
    const topLevel = readRecordValue(request, key);
    if (topLevel) {
      return topLevel;
    }
  }

  for (const key of TENANT_KEYS) {
    const inEvent = readRecordValue(request.event, key);
    if (inEvent) {
      return inEvent;
    }
  }

  const context = typeof request.event === "object" && request.event ? (request.event as Record<string, unknown>).context : undefined;
  for (const key of TENANT_KEYS) {
    const inContext = readRecordValue(context, key);
    if (inContext) {
      return inContext;
    }
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
