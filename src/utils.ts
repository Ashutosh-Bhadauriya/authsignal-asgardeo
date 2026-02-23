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

export function buildCallbackUrl(publicBaseUrl: string, callbackPath: string, flowId: string): string {
  const callback = new URL(callbackPath, publicBaseUrl);
  callback.searchParams.set("flowId", flowId);
  return callback.toString();
}

export function getClientIp(request: Request): string | undefined {
  return request.ip || request.socket.remoteAddress || undefined;
}

export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function escapeHtml(text: string): string {
  return text
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

export function renderSimplePage(title: string, message: string): string {
  const safeTitle = escapeHtml(title);
  const safeMessage = escapeHtml(message);
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${safeTitle}</title>
    <style>
      body {
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        margin: 0;
        padding: 40px 20px;
        background: #f8fafc;
        color: #0f172a;
      }
      main {
        max-width: 640px;
        margin: 0 auto;
        background: #ffffff;
        border-radius: 12px;
        box-shadow: 0 8px 24px rgba(15, 23, 42, 0.08);
        padding: 28px;
      }
      h1 {
        margin: 0 0 12px 0;
        font-size: 20px;
      }
      p {
        margin: 0;
        line-height: 1.5;
      }
    </style>
  </head>
  <body>
    <main>
      <h1>${safeTitle}</h1>
      <p>${safeMessage}</p>
    </main>
  </body>
</html>`;
}
