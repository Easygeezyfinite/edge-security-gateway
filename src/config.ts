// Settings come from wrangler.toml [vars], which Workers always pass in as strings.
export interface Env {
  ORIGIN_URL: string;
  BLOCKED_PATH_PREFIXES?: string;
  ALLOWED_METHODS?: string;
  MAX_BODY_BYTES?: string;
  ORIGIN_TIMEOUT_MS?: string;
}

export interface GatewayConfig {
  originUrl: URL;
  blockedPathPrefixes: string[];
  allowedMethods: string[];
  maxBodyBytes: number;
  originTimeoutMs: number;
}

const DEFAULT_BLOCKED_PREFIXES = "/admin,/.env,/.git,/wp-admin";
const DEFAULT_ALLOWED_METHODS = "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS";
const DEFAULT_MAX_BODY_BYTES = 1024 * 1024;
const DEFAULT_ORIGIN_TIMEOUT_MS = 10_000;

function splitList(value: string): string[] {
  return value
    .split(",")
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
}

function parsePositiveInt(value: string | undefined, fallback: number, name: string): number {
  if (value === undefined || value.trim() === "") {
    return fallback;
  }
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new Error(`${name} must be a positive whole number, got "${value}"`);
  }
  return parsed;
}

export function loadConfig(env: Env): GatewayConfig {
  if (!env.ORIGIN_URL) {
    throw new Error("ORIGIN_URL is not set");
  }
  return {
    originUrl: new URL(env.ORIGIN_URL),
    // Prefixes are compared lowercase, so "/Admin" in the config still blocks "/admin".
    blockedPathPrefixes: splitList(env.BLOCKED_PATH_PREFIXES ?? DEFAULT_BLOCKED_PREFIXES).map((prefix) =>
      prefix.toLowerCase(),
    ),
    allowedMethods: splitList(env.ALLOWED_METHODS ?? DEFAULT_ALLOWED_METHODS).map((method) => method.toUpperCase()),
    maxBodyBytes: parsePositiveInt(env.MAX_BODY_BYTES, DEFAULT_MAX_BODY_BYTES, "MAX_BODY_BYTES"),
    originTimeoutMs: parsePositiveInt(env.ORIGIN_TIMEOUT_MS, DEFAULT_ORIGIN_TIMEOUT_MS, "ORIGIN_TIMEOUT_MS"),
  };
}
