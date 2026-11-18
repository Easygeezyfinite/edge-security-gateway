# Edge Security Gateway

A reverse proxy that runs on Cloudflare Workers and sits in front of an origin server.
Every request is checked at the edge first. Bad requests get rejected before they
reach the origin, and good ones are forwarded with cleaned-up headers.

**Status:** milestone 1 of the TypeScript Worker is done (request filtering,
header handling, origin timeouts), with 24 unit tests. Not deployed yet, and there are
no performance numbers yet. Rate limiting at the edge and a Rust/WebAssembly rule
engine are next (see the roadmap).

## What it does to each request

```
client ──> [ edge worker ] ──> origin
              │
              ├─ method not allowed?        -> 405 + Allow header
              ├─ path broken / null byte?   -> 400
              ├─ path on the block list?    -> 403
              ├─ body over the size limit?  -> 413
              ├─ origin down?               -> 502
              └─ origin too slow?           -> 504
```

If the request passes, the worker forwards it to `ORIGIN_URL` with the same path and
query, and then:

- removes hop-by-hop headers (`Connection`, `Keep-Alive`, `Transfer-Encoding`, ...,
  plus any header the `Connection` header names)
- **replaces** `X-Forwarded-For` with Cloudflare's `CF-Connecting-IP` instead of
  appending to it, because the client can put anything in the header it sends
- sets `X-Forwarded-Proto`, `X-Forwarded-Host` and an `X-Request-Id`
- doesn't follow origin redirects, it passes them back to the client

On the way back it adds security headers (`Strict-Transport-Security`,
`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`) unless the origin set
its own value, and removes `Server` and `X-Powered-By`.

## Why path normalization matters

A block list that just checks `path.startsWith("/admin")` is easy to get around:

| request path | naive check | this gateway sees |
|---|---|---|
| `/admin` | blocked | `/admin` -> blocked |
| `/%61dmin` | **allowed** | `/admin` -> blocked |
| `//admin` | **allowed** | `/admin` -> blocked |
| `/static/%2e%2e/admin` | **allowed** | `/admin` -> blocked |
| `/ADMIN` | **allowed** | `/admin` -> blocked |
| `/administrator` | blocked (wrong) | `/administrator` -> allowed |

`normalizePath` in `src/rules.ts` decodes percent-encoding, turns `\` into `/`,
collapses repeated slashes, resolves `.` and `..`, and lowercases. Prefixes then match
on whole path segments only, so `/admin` doesn't block `/administrator`.

## Why the body is counted while reading

Checking `Content-Length` is a cheap first filter, but a chunked upload doesn't send
one. So the worker also reads the body itself, counts bytes as chunks arrive, and
stops with 413 as soon as it passes `MAX_BODY_BYTES`. The trade-off is that allowed
bodies are buffered in memory before forwarding (capped at 1 MB by default), instead
of being streamed straight through.

## Configuration

Set in `wrangler.toml` under `[vars]`:

| variable | default | meaning |
|---|---|---|
| `ORIGIN_URL` | (required) | where allowed requests go |
| `BLOCKED_PATH_PREFIXES` | `/admin,/.env,/.git,/wp-admin` | comma-separated, case-insensitive |
| `ALLOWED_METHODS` | `GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS` | everything else gets 405 |
| `MAX_BODY_BYTES` | `1048576` | larger bodies get 413 |
| `ORIGIN_TIMEOUT_MS` | `10000` | slower origins get 504 |

Set both numeric limits to positive whole numbers. Unset or blank limits use the
defaults in the table.

## Running it

Requires Node 22.18 or newer. Tests use Node's built-in test runner, which can run
TypeScript files directly, so there's no build step for tests.

```bash
npm install
npm test
npm run typecheck
```

Run the worker locally (forwards to httpbin.org by default):

```bash
npm run dev
```

Then in another terminal:

```bash
curl -i http://localhost:8787/get
curl -i http://localhost:8787/%61dmin
```

The first should return httpbin's response with the added security headers, and the
second should be `403`.

## Project layout

```
src/
  index.ts       Worker entry point
  gateway.ts     handleRequest: checks, header rewriting, forwarding, errors
  rules.ts       path normalization, block list matching, size-limited body read
  config.ts      reads and validates the [vars] settings
test/
  rules.test.ts
  gateway.test.ts   uses a fake origin, so no network is needed
wrangler.toml
```

`handleRequest` takes the origin fetch function as a parameter (the real `fetch` by
default), which is what lets the tests check exactly what would be sent to the origin.

## Roadmap

- [x] Reverse proxy to a configurable origin
- [x] Method allow list, path block list with normalization, body size limit
- [x] Hop-by-hop header removal, trusted `X-Forwarded-For`, request ids
- [x] Security response headers, hide `Server` / `X-Powered-By`
- [x] Origin timeout (504) and connection failure (502)
- [ ] Deploy to workers.dev and measure added latency
- [ ] Per-IP rate limiting at the edge (Durable Objects or Workers KV)
- [ ] Move rule matching into Rust compiled to WebAssembly
- [ ] WebSocket pass-through (the `Upgrade` header is stripped right now)

## Current limitations

- The origin gets the original path, not the normalized one, so an origin that decodes
  paths differently than `normalizePath` could still be a gap.
- Allowed request bodies are buffered in memory before forwarding.
- No WebSocket support yet.
- Not deployed or load tested yet, so there are no latency numbers.
