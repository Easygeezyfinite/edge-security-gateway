import { test } from "node:test";
import assert from "node:assert/strict";
import { isBlockedPath, normalizePath, readBodyWithLimit } from "../src/rules.ts";

test("normalizePath undoes common tricks for hiding a blocked path", () => {
  const cases: Array<[string, string]> = [
    ["/admin", "/admin"],
    ["/%61dmin", "/admin"],
    ["//admin", "/admin"],
    ["/public/%2e%2e/admin", "/admin"],
    ["/public/..%2Fadmin", "/admin"],
    ["/public/./../ADMIN/", "/admin"],
    ["/public\\..\\admin", "/admin"],
    ["/../../admin", "/admin"],
    ["/", "/"],
  ];
  for (const [rawPath, expected] of cases) {
    assert.equal(normalizePath(rawPath), expected, `normalizing ${rawPath}`);
  }
});

test("normalizePath rejects broken encoding and null bytes", () => {
  assert.equal(normalizePath("/%zz"), null);
  assert.equal(normalizePath("/admin%00.png"), null);
});

test("isBlockedPath matches whole segments only", () => {
  const blocked = ["/admin", "/.git/"];
  assert.equal(isBlockedPath("/admin", blocked), true);
  assert.equal(isBlockedPath("/admin/users", blocked), true);
  assert.equal(isBlockedPath("/.git/config", blocked), true);
  assert.equal(isBlockedPath("/.git", blocked), true);
  assert.equal(isBlockedPath("/administrator", blocked), false);
  assert.equal(isBlockedPath("/public/admin", blocked), false);
});

function chunkedRequest(chunkSizes: number[]): Request {
  // No Content-Length here, like a chunked upload, so only counting while reading can catch it.
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      for (const size of chunkSizes) {
        controller.enqueue(new Uint8Array(size).fill(120));
      }
      controller.close();
    },
  });
  return new Request("https://edge.test/upload", {
    method: "POST",
    body: stream,
    duplex: "half",
  } as RequestInit);
}

test("readBodyWithLimit returns the whole body when under the limit", async () => {
  const body = await readBodyWithLimit(chunkedRequest([3, 4]), 10);
  assert.ok(body);
  assert.equal(body.byteLength, 7);
});

test("readBodyWithLimit allows a body exactly at the limit", async () => {
  const body = await readBodyWithLimit(chunkedRequest([5, 5]), 10);
  assert.ok(body);
  assert.equal(body.byteLength, 10);
});

test("readBodyWithLimit gives up once a chunked body passes the limit", async () => {
  assert.equal(await readBodyWithLimit(chunkedRequest([6, 6]), 10), null);
});

test("readBodyWithLimit cancels the stream after exceeding the limit", async () => {
  let cancelled = false;
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new Uint8Array(11));
    },
    cancel() {
      cancelled = true;
    },
  });
  const request = new Request("https://edge.test/upload", {
    method: "POST",
    body: stream,
    duplex: "half",
  } as RequestInit);

  assert.equal(await readBodyWithLimit(request, 10), null);
  assert.equal(cancelled, true);
});
