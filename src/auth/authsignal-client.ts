import type { Logger } from "pino";

import type { AppConfig } from "../config.js";
import type { AuthsignalTrackResult, AuthsignalGetActionResult } from "../types/authsignal.js";
import { sleep } from "../utils.js";

const TIMEOUT_MS = 5000;
const MAX_RETRIES = 2;

interface TrackActionInput {
  userId: string;
  action: string;
  redirectUrl: string;
  ipAddress?: string;
  userAgent?: string;
  custom?: Record<string, unknown>;
}

export interface AuthsignalClient {
  trackAction(input: TrackActionInput): Promise<AuthsignalTrackResult>;
  getAction(userId: string, action: string, idempotencyKey: string): Promise<AuthsignalGetActionResult>;
}

export class HttpAuthsignalClient implements AuthsignalClient {
  private readonly baseUrl: string;
  private readonly serverApiAuthorizationHeader: string;

  constructor(
    private readonly authsignalConfig: AppConfig["authsignal"],
    private readonly logger: Logger
  ) {
    this.baseUrl = authsignalConfig.apiUrl.endsWith("/")
      ? authsignalConfig.apiUrl.slice(0, -1)
      : authsignalConfig.apiUrl;
    const encoded = Buffer.from(`${authsignalConfig.secret}:`, "utf-8").toString("base64");
    this.serverApiAuthorizationHeader = `Basic ${encoded}`;
  }

  async trackAction(input: TrackActionInput): Promise<AuthsignalTrackResult> {
    const requestBody = {
      redirectUrl: input.redirectUrl,
      ipAddress: input.ipAddress,
      userAgent: input.userAgent,
      custom: input.custom
    };

    return this.post<AuthsignalTrackResult>(
      `/v1/users/${encodeURIComponent(input.userId)}/actions/${encodeURIComponent(input.action)}`,
      requestBody
    );
  }

  async getAction(userId: string, action: string, idempotencyKey: string): Promise<AuthsignalGetActionResult> {
    return this.get<AuthsignalGetActionResult>(
      `/v1/users/${encodeURIComponent(userId)}/actions/${encodeURIComponent(action)}/${encodeURIComponent(idempotencyKey)}`
    );
  }

  private async post<T>(path: string, body: unknown): Promise<T> {
    return this.request<T>(path, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body)
    });
  }

  private async get<T>(path: string): Promise<T> {
    return this.request<T>(path, { method: "GET" });
  }

  private async request<T>(path: string, init: { method: string; headers?: Record<string, string>; body?: string }): Promise<T> {
    for (let attempt = 0; attempt <= MAX_RETRIES; attempt += 1) {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);

      try {
        const response = await fetch(`${this.baseUrl}${path}`, {
          method: init.method,
          headers: {
            ...init.headers,
            authorization: this.serverApiAuthorizationHeader
          },
          ...(init.body != null ? { body: init.body } : {}),
          signal: controller.signal
        });

        const responseText = await response.text();
        const parsedResponse = responseText ? (JSON.parse(responseText) as unknown) : {};

        if (!response.ok) {
          if (this.shouldRetryStatusCode(response.status) && attempt < MAX_RETRIES) {
            await sleep(this.retryDelay(attempt));
            continue;
          }

          throw new Error(
            `Authsignal request failed with status ${response.status}: ${JSON.stringify(parsedResponse)}`
          );
        }

        return parsedResponse as T;
      } catch (error) {
        if (this.isRetryableError(error) && attempt < MAX_RETRIES) {
          await sleep(this.retryDelay(attempt));
          continue;
        }
        throw error;
      } finally {
        clearTimeout(timeout);
      }
    }

    throw new Error("Authsignal request exhausted retries");
  }

  private shouldRetryStatusCode(statusCode: number): boolean {
    return statusCode === 429 || statusCode >= 500;
  }

  private isRetryableError(error: unknown): boolean {
    if (error instanceof Error && error.name === "AbortError") {
      return true;
    }
    if (error instanceof TypeError) {
      return true;
    }
    if (error instanceof Error) {
      this.logger.debug({ error: error.message }, "Non-retryable authsignal error");
    }
    return false;
  }

  private retryDelay(attempt: number): number {
    const base = 150;
    return base * 2 ** attempt;
  }
}
