import { createHmac, timingSafeEqual } from "node:crypto";

import type { RequestHandler } from "express";

import type { AppConfig } from "../config.js";

const HMAC_KEY = "asgardeo-request-auth-compare";

function safeStringEquals(left: string, right: string): boolean {
  const leftDigest = createHmac("sha256", HMAC_KEY).update(left).digest();
  const rightDigest = createHmac("sha256", HMAC_KEY).update(right).digest();
  return timingSafeEqual(leftDigest, rightDigest);
}

function unauthorized(handlerResponse: Parameters<RequestHandler>[1]): void {
  handlerResponse.status(401).json({ error: "unauthorized" });
}

export function createAsgardeoRequestAuth(config: AppConfig): RequestHandler {
  const auth = config.asgardeo.auth;

  if (auth.mode === "none") {
    return (_request, _response, next) => next();
  }

  if (auth.mode === "basic") {
    return (request, response, next) => {
      const authorizationHeader = request.header("authorization");
      if (!authorizationHeader?.startsWith("Basic ")) {
        unauthorized(response);
        return;
      }

      let decoded: string;
      try {
        decoded = Buffer.from(authorizationHeader.slice("Basic ".length), "base64").toString("utf-8");
      } catch {
        unauthorized(response);
        return;
      }

      const splitIndex = decoded.indexOf(":");
      if (splitIndex < 0) {
        unauthorized(response);
        return;
      }

      const username = decoded.slice(0, splitIndex);
      const password = decoded.slice(splitIndex + 1);
      if (!safeStringEquals(username, auth.username) || !safeStringEquals(password, auth.password)) {
        unauthorized(response);
        return;
      }

      next();
    };
  }

  if (auth.mode === "bearer") {
    return (request, response, next) => {
      const authorizationHeader = request.header("authorization");
      if (!authorizationHeader?.startsWith("Bearer ")) {
        unauthorized(response);
        return;
      }

      const token = authorizationHeader.slice("Bearer ".length);
      if (!safeStringEquals(token, auth.token)) {
        unauthorized(response);
        return;
      }

      next();
    };
  }

  return (request, response, next) => {
    const headerValue = request.header(auth.headerName);
    if (typeof headerValue !== "string" || !safeStringEquals(headerValue, auth.value)) {
      unauthorized(response);
      return;
    }

    next();
  };
}
