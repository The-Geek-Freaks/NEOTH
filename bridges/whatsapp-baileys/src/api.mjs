import { createHash, timingSafeEqual } from "node:crypto";
import http from "node:http";
import { CursorError } from "./state.mjs";

const MAX_REQUEST_BYTES = 16 * 1024 * 1024;

function json(response, status, body) {
  const encoded = Buffer.from(`${JSON.stringify(body)}\n`);
  response.writeHead(status, {
    "cache-control": "no-store",
    "content-type": "application/json; charset=utf-8",
    "content-length": encoded.length,
    "x-content-type-options": "nosniff",
  });
  response.end(encoded);
}

function tokenMatches(header, expectedDigest) {
  const supplied = typeof header === "string" && header.startsWith("Bearer ")
    ? header.slice("Bearer ".length)
    : "";
  const suppliedDigest = createHash("sha256").update(supplied).digest();
  return timingSafeEqual(suppliedDigest, expectedDigest);
}

async function readJson(request) {
  const declared = Number(request.headers["content-length"] ?? 0);
  if (Number.isFinite(declared) && declared > MAX_REQUEST_BYTES) {
    const error = new Error("request body exceeds 16 MiB");
    error.statusCode = 413;
    throw error;
  }
  const chunks = [];
  let bytes = 0;
  for await (const chunk of request) {
    bytes += chunk.length;
    if (bytes > MAX_REQUEST_BYTES) {
      const error = new Error("request body exceeds 16 MiB");
      error.statusCode = 413;
      throw error;
    }
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    const error = new Error("request body is not valid JSON");
    error.statusCode = 400;
    throw error;
  }
}

export async function createBridgeServer({ token, journal, runtime, host = "127.0.0.1", port = 9120 }) {
  if (typeof token !== "string" || !/^[A-Za-z0-9._~-]{32,}$/u.test(token)) {
    throw new Error("NEOTH_WA_BRIDGE_TOKEN must be 32+ URL-safe ASCII characters");
  }
  if (!["127.0.0.1", "::1", "localhost"].includes(host)) {
    throw new Error("Baileys bridge must bind loopback; expose it through an authenticated TLS proxy");
  }
  const expectedDigest = createHash("sha256").update(token).digest();

  const server = http.createServer(async (request, response) => {
    try {
      if (!tokenMatches(request.headers.authorization, expectedDigest)) {
        json(response, 401, { error: "unauthorized" });
        return;
      }
      const url = new URL(request.url ?? "/", "http://localhost");
      if (request.method === "GET" && url.pathname === "/v1/health") {
        json(response, 200, {
          ...runtime.health(),
          latest_cursor: journal.latestCursor(),
          capabilities: { text: true, media: true, cursor: true },
        });
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/messages") {
        const cursor = url.searchParams.get("cursor") ?? "0";
        const limit = url.searchParams.get("limit") ?? "50";
        let batch = journal.readAfter(cursor, limit);
        if (batch.messages.length === 0) {
          const requested = Number(url.searchParams.get("timeout_ms") ?? 25_000);
          const timeoutMs = Number.isFinite(requested)
            ? Math.max(0, Math.min(30_000, Math.floor(requested)))
            : 25_000;
          await journal.waitForEvents(timeoutMs);
          batch = journal.readAfter(cursor, limit);
        }
        json(response, 200, batch);
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/messages") {
        const result = await runtime.send(await readJson(request));
        json(response, 200, result);
        return;
      }
      json(response, 404, { error: "not_found" });
    } catch (error) {
      if (error instanceof CursorError) {
        json(response, 409, { error: error.code, message: error.message, ...error.details });
        return;
      }
      const status = Number.isInteger(error?.statusCode) ? error.statusCode : 500;
      json(response, status, {
        error: typeof error?.code === "string"
          ? error.code
          : status >= 500 ? "bridge_error" : "invalid_request",
        message: error.message,
      });
    }
  });
  server.headersTimeout = 5_000;
  server.requestTimeout = 35_000;
  server.keepAliveTimeout = 5_000;
  server.maxRequestsPerSocket = 100;

  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      server.off("error", reject);
      resolve();
    });
  });
  return {
    address: server.address(),
    close: () => new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve())),
  };
}
