import pino, { type Logger } from "pino";

import type { AppConfig } from "./config.js";

export function buildLogger(config: AppConfig): Logger {
  return pino({
    level: config.logLevel,
    redact: {
      paths: [
        "req.headers.authorization",
        "req.headers.cookie",
        "response.body.authData.additionalData.redirectUrl"
      ],
      censor: "[REDACTED]"
    }
  });
}
