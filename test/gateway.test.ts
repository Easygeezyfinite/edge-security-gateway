import { test } from "node:test";
import assert from "node:assert/strict";
import { handleRequest, pickRequestId } from "../src/gateway.ts";
import type { Env } from "../src/config.ts";

const env: Env = {
  ORIGIN_URL: "https://origin.internal",
  BLOCKED_PATH_PREFIXES: "/admin,/.env",
  ALLOWED_METHODS: "GET,POST",
  MAX_BODY_BYTES: "16",
  ORIGIN_TIMEOUT_MS: "50",
};

// Fake origin that records what the gateway sent it.
function recordingOrigin(response: () => Response = () => new Response("hello from origin")) {
  const seen: Request[] = [];
  const fetchOrigin = async (request: Request) => {
    seen.push(request);
    return response();
  };
  return { seen, fetchOrigin };
}

test("forwards path and query to the origin and returns its response", async () => {
  const origin = recordingOrigin();
  const response = await handleRequest(new Request("https://edge.test/api/items?page=2"), env, origin.fetchOrigin);

  assert.equal(response.status, 200);
  assert.equal(await response.text(), "hello from origin");
  assert.equal(origin.seen.length, 1);
  assert.equal(origin.seen[0].url, "https://origin.internal/api/items?page=2");
});

test("blocks a hidden admin path without contacting the origin", async () => {
  const origin = recordingOrigin();
  for (const path of ["/admin", "/%61dmin/users", "//admin", "/static/%2e%2e/admin", "/.env"]) {
    const response = await handleRequest(new Request("https://edge.test" + path), env, origin.fetchOrigin);
    assert.equal(response.status, 403, `expected ${path} to be blocked`);
  }
  assert.equal(origin.seen.length, 0);
});

test("lets a path that only starts with a blocked word through", async () => {
  const origin = recordingOrigin();
  const response = await handleRequest(new Request("https://edge.test/administrator-guide"), env, origin.fetchOrigin);
  assert.equal(response.status, 200);
});

test("rejects malformed percent-encoding with 400", async () => {
  const origin = recordingOrigin();
  const response = await handleRequest(new Request("https://edge.test/%zz"), env, origin.fetchOrigin);
  assert.equal(response.status, 400);
  assert.equal(origin.seen.length, 0);
});

test("rejects methods that are not allowed with 405 and an Allow header", async () => {
  const origin = recordingOrigin();
  const response = await handleRequest(new Request("https://edge.test/api", { method: "DELETE" }), env, origin.fetchOrigin);
  assert.equal(response.status, 405);
  assert.equal(response.headers.get("allow"), "GET, POST");
  assert.equal(origin.seen.length, 0);
});

test("rejects a body that is too large with 413", async () => {
  const origin = recordingOrigin();
  const response = await handleRequest(
    new Request("https://edge.test/api", { method: "POST", body: "x".repeat(17) }),
    env,
    origin.fetchOrigin,
  );
  assert.equal(response.status, 413);
  assert.equal(origin.seen.length, 0);
});

test("forwards a small POST body unchanged", async () => {
  const origin = recordingOrigin();
  const response = await handleRequest(
    new Request("https://edge.test/api", { method: "POST", body: '{"a":1}' }),
    env,
    origin.fetchOrigin,
  );
  assert.equal(response.status, 200);
  assert.equal(await origin.seen[0].text(), '{"a":1}');
});

test("replaces a spoofed X-Forwarded-For with the real client IP", async () => {
  const origin = recordingOrigin();
  await handleRequest(
    new Request("https://edge.test/api", {
      headers: { "x-forwarded-for": "1.2.3.4", "cf-connecting-ip": "203.0.113.9" },
    }),
    env,
    origin.fetchOrigin,
  );
  const sentHeaders = origin.seen[0].headers;
  assert.equal(sentHeaders.get("x-forwarded-for"), "203.0.113.9");
  assert.equal(sentHeaders.get("x-forwarded-proto"), "https");
  assert.equal(sentHeaders.get("x-forwarded-host"), "edge.test");
});

test("drops a spoofed X-Forwarded-For even when the client IP is unknown", async () => {
  const origin = recordingOrigin();
  await handleRequest(
    new Request("https://edge.test/api", { headers: { "x-forwarded-for": "1.2.3.4" } }),
    env,
    origin.fetchOrigin,
  );
  assert.equal(origin.seen[0].headers.get("x-forwarded-for"), null);
});

test("strips hop-by-hop headers, including ones named in Connection", async () => {
  const origin = recordingOrigin();
  await handleRequest(
    new Request("https://edge.test/api", {
      headers: { connection: "keep-alive, x-internal-debug", "keep-alive": "timeout=5", "x-internal-debug": "1", accept: "text/html" },
    }),
    env,
    origin.fetchOrigin,
  );
  const sentHeaders = origin.seen[0].headers;
  assert.equal(sentHeaders.get("connection"), null);
  assert.equal(sentHeaders.get("keep-alive"), null);
  assert.equal(sentHeaders.get("x-internal-debug"), null);
  assert.equal(sentHeaders.get("accept"), "text/html");
});

test("adds security headers, keeps the origin's own values, and hides server details", async () => {
  const origin = recordingOrigin(
    () =>
      new Response("ok", {
        headers: { server: "nginx/1.18.0", "x-powered-by": "Express", "x-frame-options": "SAMEORIGIN" },
      }),
  );
  const response = await handleRequest(new Request("https://edge.test/"), env, origin.fetchOrigin);

  assert.equal(response.headers.get("x-content-type-options"), "nosniff");
  assert.match(response.headers.get("strict-transport-security") ?? "", /max-age=/);
  assert.equal(response.headers.get("x-frame-options"), "SAMEORIGIN");
  assert.equal(response.headers.get("server"), null);
  assert.equal(response.headers.get("x-powered-by"), null);
});

test("blocked responses get security headers too", async () => {
  const response = await handleRequest(new Request("https://edge.test/admin"), env, recordingOrigin().fetchOrigin);
  assert.equal(response.headers.get("x-content-type-options"), "nosniff");
  assert.equal(response.headers.get("content-type"), "application/json");
});

test("returns 502 when the origin can't be reached", async () => {
  const failingOrigin = async () => {
    throw new TypeError("connection refused");
  };
  const response = await handleRequest(new Request("https://edge.test/"), env, failingOrigin);
  assert.equal(response.status, 502);
});

test("returns 504 when the origin is slower than the timeout", async () => {
  // Answers after 1 s, far past the 50 ms timeout, unless the gateway aborts it first.
  // The 1 s timer also keeps Node's event loop alive, since AbortSignal.timeout doesn't.
  const slowOrigin = (request: Request) =>
    new Promise<Response>((resolve, reject) => {
      const lateAnswer = setTimeout(() => resolve(new Response("too late")), 1000);
      request.signal.addEventListener("abort", () => {
        clearTimeout(lateAnswer);
        reject(request.signal.reason);
      });
    });
  const response = await handleRequest(new Request("https://edge.test/"), env, slowOrigin);
  assert.equal(response.status, 504);
});

test("passes origin redirects back instead of following them", async () => {
  const origin = recordingOrigin();
  await handleRequest(new Request("https://edge.test/"), env, origin.fetchOrigin);
  assert.equal(origin.seen[0].redirect, "manual");
});

test("same request id goes to the origin and back to the client", async () => {
  const origin = recordingOrigin();
  const response = await handleRequest(
    new Request("https://edge.test/", { headers: { "x-request-id": "abc-123" } }),
    env,
    origin.fetchOrigin,
  );
  assert.equal(origin.seen[0].headers.get("x-request-id"), "abc-123");
  assert.equal(response.headers.get("x-request-id"), "abc-123");
});

test("pickRequestId refuses ids that could forge log lines", () => {
  assert.equal(pickRequestId("abc-123"), "abc-123");
  assert.notEqual(pickRequestId("abc\nFAKE LOG LINE"), "abc\nFAKE LOG LINE");
  assert.notEqual(pickRequestId("x".repeat(65)), "x".repeat(65));
  assert.match(pickRequestId(null), /^[0-9a-f-]{36}$/);
});

test("a missing ORIGIN_URL returns 500 instead of throwing", async () => {
  const response = await handleRequest(new Request("https://edge.test/"), { ORIGIN_URL: "" }, recordingOrigin().fetchOrigin);
  assert.equal(response.status, 500);
});
