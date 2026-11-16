// Request checks that run before anything is sent to the origin.

// Turns a raw URL path into the form we compare against the block list.
// Attackers dodge naive prefix checks with tricks like:
//   /%61dmin            (%61 is "a")
//   //admin             (double slash)
//   /public/%2e%2e/admin (encoded "..")
// so we decode, collapse slashes, resolve "." and ".." and lowercase.
// Returns null if the path has broken percent-encoding, which we reject outright.
export function normalizePath(rawPath: string): string | null {
  let decoded: string;
  try {
    decoded = decodeURIComponent(rawPath);
  } catch {
    return null;
  }

  // A null byte has no business in a URL path and is a classic way to confuse backends.
  if (decoded.includes("\0")) {
    return null;
  }

  const resolvedSegments: string[] = [];
  for (const segment of decoded.replaceAll("\\", "/").split("/")) {
    if (segment === "" || segment === ".") {
      continue;
    }
    if (segment === "..") {
      // ".." at the root just stays at the root, same as a browser does.
      resolvedSegments.pop();
      continue;
    }
    resolvedSegments.push(segment);
  }
  return "/" + resolvedSegments.join("/").toLowerCase();
}

// "/admin" should block "/admin" and "/admin/users" but not "/administrator",
// so a prefix only matches on a whole path segment.
export function isBlockedPath(normalizedPath: string, blockedPrefixes: string[]): boolean {
  return blockedPrefixes.some((prefix) => {
    const trimmedPrefix = prefix.endsWith("/") ? prefix.slice(0, -1) : prefix;
    return normalizedPath === trimmedPrefix || normalizedPath.startsWith(trimmedPrefix + "/");
  });
}

// Reads the body while counting bytes, and gives up as soon as it passes the limit.
// Checking Content-Length alone isn't enough, because a chunked upload doesn't send one.
// Returns null when the body is too large.
export async function readBodyWithLimit(request: Request, maxBytes: number): Promise<Uint8Array<ArrayBuffer> | null> {
  if (request.body === null) {
    return new Uint8Array(0);
  }
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    totalBytes += value.byteLength;
    if (totalBytes > maxBytes) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }

  const body = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body;
}
