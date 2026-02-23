import { z } from "zod";

const TRUE_VALUES = new Set(["1", "true", "yes", "on"]);
const FALSE_VALUES = new Set(["0", "false", "no", "off"]);

const optionalString = z.preprocess((value) => {
  if (typeof value !== "string") {
    return value;
  }

  const trimmed = value.trim();
  return trimmed === "" ? undefined : trimmed;
}, z.string().optional());

const booleanWithDefault = (defaultValue: boolean) =>
  z.preprocess((value) => {
    if (value === undefined) {
      return defaultValue;
    }
    if (typeof value === "boolean") {
      return value;
    }
    if (typeof value === "string") {
      const normalized = value.trim().toLowerCase();
      if (TRUE_VALUES.has(normalized)) {
        return true;
      }
      if (FALSE_VALUES.has(normalized)) {
        return false;
      }
    }
    return value;
  }, z.boolean());

const intWithDefault = (defaultValue: number) =>
  z.preprocess((value) => {
    if (value === undefined || value === "") {
      return defaultValue;
    }
    if (typeof value === "string") {
      return Number.parseInt(value, 10);
    }
    return value;
  }, z.number().int());

const envSchema = z
  .object({
    NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
    PORT: intWithDefault(3000).refine((value) => value > 0 && value < 65536, "PORT must be 1-65535"),
    LOG_LEVEL: z
      .enum(["fatal", "error", "warn", "info", "debug", "trace", "silent"])
      .default("info"),
    PUBLIC_BASE_URL: z.string().url(),
    CALLBACK_PATH: z.string().min(1).default("/api/callback"),
    TRUST_PROXY: booleanWithDefault(true),
    ASGARDEO_RESUME_URL_TEMPLATE: z.string().min(1),
    ASGARDEO_AUTH_MODE: z.enum(["none", "basic", "bearer", "api-key"]).default("none"),
    ASGARDEO_BASIC_USERNAME: optionalString,
    ASGARDEO_BASIC_PASSWORD: optionalString,
    ASGARDEO_BEARER_TOKEN: optionalString,
    ASGARDEO_API_KEY_HEADER: z.string().min(1).default("x-asgardeo-api-key"),
    ASGARDEO_API_KEY_VALUE: optionalString,
    AUTHSIGNAL_API_URL: z.string().url().default("https://api.authsignal.com"),
    AUTHSIGNAL_SECRET: z.string().min(1),
    STORE_DRIVER: z.enum(["memory", "redis"]).default("memory"),
    FLOW_TTL_SECONDS: intWithDefault(900).refine((value) => value >= 60, "FLOW_TTL_SECONDS must be >= 60"),
    REDIS_URL: optionalString
  })
  .superRefine((env, ctx) => {
    if (!env.ASGARDEO_RESUME_URL_TEMPLATE.includes("{flowId}")) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["ASGARDEO_RESUME_URL_TEMPLATE"],
        message: "ASGARDEO_RESUME_URL_TEMPLATE must include {flowId}"
      });
    }

    if (env.ASGARDEO_AUTH_MODE === "basic" && (!env.ASGARDEO_BASIC_USERNAME || !env.ASGARDEO_BASIC_PASSWORD)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["ASGARDEO_BASIC_USERNAME"],
        message: "ASGARDEO_BASIC_USERNAME and ASGARDEO_BASIC_PASSWORD are required for basic auth"
      });
    }

    if (env.ASGARDEO_AUTH_MODE === "bearer" && !env.ASGARDEO_BEARER_TOKEN) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["ASGARDEO_BEARER_TOKEN"],
        message: "ASGARDEO_BEARER_TOKEN is required for bearer auth"
      });
    }

    if (env.ASGARDEO_AUTH_MODE === "api-key" && !env.ASGARDEO_API_KEY_VALUE) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["ASGARDEO_API_KEY_VALUE"],
        message: "ASGARDEO_API_KEY_VALUE is required for api-key auth"
      });
    }

    if (env.STORE_DRIVER === "redis" && !env.REDIS_URL) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["REDIS_URL"],
        message: "REDIS_URL is required when STORE_DRIVER=redis"
      });
    }
  });

export interface AppConfig {
  nodeEnv: "development" | "test" | "production";
  port: number;
  logLevel: "fatal" | "error" | "warn" | "info" | "debug" | "trace" | "silent";
  publicBaseUrl: string;
  callbackPath: string;
  trustProxy: boolean;
  asgardeo: {
    resumeUrlTemplate: string;
    auth:
      | { mode: "none" }
      | { mode: "basic"; username: string; password: string }
      | { mode: "bearer"; token: string }
      | { mode: "api-key"; headerName: string; value: string };
  };
  authsignal: {
    apiUrl: string;
    secret: string;
  };
  store: {
    driver: "memory" | "redis";
    flowTtlSeconds: number;
    redisUrl?: string;
  };
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const parsed = envSchema.parse(env);
  const callbackPath = parsed.CALLBACK_PATH.startsWith("/")
    ? parsed.CALLBACK_PATH
    : `/${parsed.CALLBACK_PATH}`;

  let asgardeoAuth: AppConfig["asgardeo"]["auth"];
  switch (parsed.ASGARDEO_AUTH_MODE) {
    case "none":
      asgardeoAuth = { mode: "none" };
      break;
    case "basic":
      asgardeoAuth = {
        mode: "basic",
        username: parsed.ASGARDEO_BASIC_USERNAME as string,
        password: parsed.ASGARDEO_BASIC_PASSWORD as string
      };
      break;
    case "bearer":
      asgardeoAuth = { mode: "bearer", token: parsed.ASGARDEO_BEARER_TOKEN as string };
      break;
    case "api-key":
      asgardeoAuth = {
        mode: "api-key",
        headerName: parsed.ASGARDEO_API_KEY_HEADER.toLowerCase(),
        value: parsed.ASGARDEO_API_KEY_VALUE as string
      };
      break;
    default:
      throw new Error(`Unsupported ASGARDEO_AUTH_MODE: ${parsed.ASGARDEO_AUTH_MODE}`);
  }

  return {
    nodeEnv: parsed.NODE_ENV,
    port: parsed.PORT,
    logLevel: parsed.LOG_LEVEL,
    publicBaseUrl: parsed.PUBLIC_BASE_URL,
    callbackPath,
    trustProxy: parsed.TRUST_PROXY,
    asgardeo: {
      resumeUrlTemplate: parsed.ASGARDEO_RESUME_URL_TEMPLATE,
      auth: asgardeoAuth
    },
    authsignal: {
      apiUrl: parsed.AUTHSIGNAL_API_URL,
      secret: parsed.AUTHSIGNAL_SECRET
    },
    store: {
      driver: parsed.STORE_DRIVER,
      flowTtlSeconds: parsed.FLOW_TTL_SECONDS,
      ...(parsed.REDIS_URL ? { redisUrl: parsed.REDIS_URL } : {})
    }
  };
}
