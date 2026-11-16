import { loadConfig } from "./config.ts";
import type { Env, GatewayConfig } from "./config.ts";
import { isBlockedPath, normalizePath, readBodyWithLimit } from "./rules.ts";

// Hop-by-hop headers describe one connection, not the request, so a proxy must not pass them on.
const HOP_BY_HOP_HEADERS = [
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "proxy-connection",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
];

// Added to every response unless the origin already set its own value.
const SECURITY_HEADERS: Record<string, string> = {
  "strict-transport-security": "max-age=31536000; includeSubDomains",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "strict-origin-when-cross-origin",
};

// These advertise what the origin runs on, which only helps an attacker.
const HEADERS_TO_HIDE = ["server", "x-powered-by"];

const METHODS_WITHOUT_BODY = ["GET", "HEAD"];

type OriginFetch = (request: Request) => Promise<Response>;

// Reuse the caller's request id so logs line up across services, but only if it looks
// like an id. Anything else (newlines, huge strings) could be used to forge log lines.
const SAFE_REQUEST_ID = /^[A-Za-z0-9-]{1,64}$/;

export function pickRequestId(incomingId: string | null): string {
  if (incomingId !== null && SAFE_REQUEST_ID.test(incomingId)) {
    return incomingId;
  }
  return crypto.randomUUID();
}

function jsonError(status: number, message: string, requestId: string, extraHeaders: Record<string, string> = {}) {
  const response = new Response(JSON.stringify({ error: message, request_id: requestId }), {
    status,
    headers: { "content-type": "application/json", ...extraHeaders },
  });
  return finishResponse(response, requestId);
}

function buildOriginHeaders(incoming: Headers, requestId: string, clientIp: string | null, publicUrl: URL): Headers {
  const headers = new Headers(incoming);

  // The Connection header can name extra headers that are also hop-by-hop.
  const namedInConnection = (incoming.get("connection") ?? "")
    .split(",")
    .map((name) => name.trim().toLowerCase())
    .filter((name) => name.length > 0);
  for (const name of [...HOP_BY_HOP_HEADERS, ...namedInConnection]) {
    headers.delete(name);
  }

  // The client can send any X-Forwarded-For it likes, so we replace it instead of appending.
  // The edge is the first hop we trust, and Cloudflare tells us the real client IP.
  headers.delete("x-forwarded-for");
  if (clientIp) {
    headers.set("x-forwarded-for", clientIp);
  }
  headers.set("x-forwarded-proto", publicUrl.protocol.replace(":", ""));
  headers.set("x-forwarded-host", publicUrl.host);
  headers.set("x-request-id", requestId);
  return headers;
}

function finishResponse(originResponse: Response, requestId: string): Response {
  // Responses from fetch() have immutable headers, so copy into a new Response first.
  const response = new Response(originResponse.body, originResponse);
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
    if (!response.headers.has(name)) {
      response.headers.set(name, value);
    }
  }
  for (const name of HEADERS_TO_HIDE) {
    response.headers.delete(name);
  }
  response.headers.set("x-request-id", requestId);
  return response;
}

export async function handleRequest(
  request: Request,
  env: Env,
  fetchOrigin: OriginFetch = fetch,
): Promise<Response> {
  const requestId = pickRequestId(request.headers.get("x-request-id"));

  let config: GatewayConfig;
  try {
    config = loadConfig(env);
  } catch (error) {
    console.error("bad gateway config:", error);
    return jsonError(500, "gateway misconfigured", requestId);
  }

  const publicUrl = new URL(request.url);
  const method = request.method.toUpperCase();

  if (!config.allowedMethods.includes(method)) {
    return jsonError(405, "method not allowed", requestId, { allow: config.allowedMethods.join(", ") });
  }

  const normalizedPath = normalizePath(publicUrl.pathname);
  if (normalizedPath === null) {
    return jsonError(400, "malformed path", requestId);
  }
  if (isBlockedPath(normalizedPath, config.blockedPathPrefixes)) {
    return jsonError(403, "forbidden", requestId);
  }

  // Cheap early reject when the client tells us the size up front.
  const declaredLength = Number(request.headers.get("content-length") ?? "0");
  if (declaredLength > config.maxBodyBytes) {
    return jsonError(413, "request body too large", requestId);
  }

  let body: Uint8Array<ArrayBuffer> | null = null;
  if (!METHODS_WITHOUT_BODY.includes(method)) {
    body = await readBodyWithLimit(request, config.maxBodyBytes);
    if (body === null) {
      return jsonError(413, "request body too large", requestId);
    }
  }

  // Keep the original path and query; only the scheme and host change to the origin's.
  const targetUrl = new URL(publicUrl.pathname + publicUrl.search, config.originUrl);
  const originRequest = new Request(targetUrl, {
    method,
    headers: buildOriginHeaders(request.headers, requestId, request.headers.get("cf-connecting-ip"), publicUrl),
    body,
    // Pass redirects back to the client instead of following them at the edge.
    redirect: "manual",
    signal: AbortSignal.timeout(config.originTimeoutMs),
  });

  try {
    const originResponse = await fetchOrigin(originRequest);
    return finishResponse(originResponse, requestId);
  } catch (error) {
    if (error instanceof DOMException && error.name === "TimeoutError") {
      return jsonError(504, "origin timed out", requestId);
    }
    console.error("origin fetch failed:", error);
    return jsonError(502, "origin unreachable", requestId);
  }
}
