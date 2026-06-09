#!/usr/bin/env node
/**
 * qproof MCP — hostable HTTP transport (Streamable-HTTP-style JSON-RPC).
 *
 * A zero-dependency {@link node:http} server that exposes the same
 * {@link McpServer} over HTTP so the qproof MCP can run as a remote service:
 *
 *   POST /mcp     — body is a single JSON-RPC 2.0 message; the JSON-RPC
 *                   response is returned as the 200 response body
 *                   (`application/json`). Notifications get HTTP 202 with no body.
 *   GET  /health  — liveness probe, returns `{ status: "ok", ... }`.
 *
 * This is the minimal-but-working core of the MCP Streamable HTTP transport.
 * The full spec also supports an SSE response (`text/event-stream`) for
 * server-initiated messages; this server speaks the JSON request/response half,
 * which is sufficient for stateless tool calls. See HOSTING.md for the
 * production design (auth, multi-tenant sessions, rate limiting, scaling).
 *
 * Run with `node dist/http.js` (PORT from env, default 3000).
 */

import { createServer } from "node:http";
import type { IncomingMessage, Server, ServerResponse } from "node:http";
import { randomUUID } from "node:crypto";
import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import process from "node:process";

import { createQproofServer } from "./index.js";
import { ErrorCode, makeFailure } from "./protocol.js";
import type { McpServer } from "./server.js";

/** Header carrying the MCP session id (per the Streamable HTTP transport). */
export const SESSION_HEADER = "mcp-session-id";

/** Maximum accepted request body size (1 MiB) — a basic abuse guard. */
const MAX_BODY_BYTES = 1024 * 1024;

export interface HttpServerOptions {
  /** Port to listen on. Defaults to env PORT or 3000. */
  port?: number;
  /** Host/interface to bind. Defaults to env HOST or "0.0.0.0". */
  host?: string;
}

/** Read a request body fully, enforcing the size cap. Resolves to the raw string. */
function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new Error("request body too large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

/** Write a JSON response with the given status and optional extra headers. */
function sendJson(
  res: ServerResponse,
  status: number,
  body: unknown,
  headers: Record<string, string> = {},
): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(payload).toString(),
    ...headers,
  });
  res.end(payload);
}

/**
 * Build (but do not start) the HTTP server wrapping an {@link McpServer}.
 * Exposed for testing and for embedding in a larger process.
 */
export function createHttpServer(server: McpServer): Server {
  return createServer((req, res) => {
    void handleRequest(server, req, res).catch((err: unknown) => {
      const messageText = err instanceof Error ? err.message : String(err);
      if (!res.headersSent) {
        sendJson(res, 500, makeFailure(null, ErrorCode.InternalError, messageText));
      } else {
        res.end();
      }
    });
  });
}

/** Route and handle a single HTTP request. */
async function handleRequest(
  server: McpServer,
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  const url = req.url ?? "/";
  const method = req.method ?? "GET";
  const path = url.split("?")[0];

  if (method === "GET" && path === "/health") {
    sendJson(res, 200, { status: "ok", server: "qproof", transport: "http" });
    return;
  }

  if (path === "/mcp") {
    if (method !== "POST") {
      // The full transport also allows GET for an SSE stream; we don't here.
      sendJson(res, 405, makeFailure(null, ErrorCode.InvalidRequest, "method not allowed"), {
        allow: "POST",
      });
      return;
    }
    await handleMcpPost(server, req, res);
    return;
  }

  sendJson(res, 404, makeFailure(null, ErrorCode.MethodNotFound, "not found"));
}

/** Handle `POST /mcp`: parse one JSON-RPC message, dispatch, return the result. */
async function handleMcpPost(
  server: McpServer,
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  // Session handling (stateless here): echo a provided session id, else mint one.
  // A production server would look this up in a session store — see HOSTING.md.
  const incomingSession = req.headers[SESSION_HEADER];
  const sessionId =
    (Array.isArray(incomingSession) ? incomingSession[0] : incomingSession) ?? randomUUID();
  const sessionHeaders = { [SESSION_HEADER]: sessionId };

  let raw: string;
  try {
    raw = await readBody(req);
  } catch (err) {
    const messageText = err instanceof Error ? err.message : String(err);
    sendJson(res, 413, makeFailure(null, ErrorCode.InvalidRequest, messageText), sessionHeaders);
    return;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    sendJson(res, 400, makeFailure(null, ErrorCode.ParseError, "parse error"), sessionHeaders);
    return;
  }

  const response = await server.handle(parsed);
  if (response === null) {
    // Notification — acknowledge with 202 and no body.
    res.writeHead(202, sessionHeaders);
    res.end();
    return;
  }
  sendJson(res, 200, response, sessionHeaders);
}

/** Start the HTTP server, resolving once it is listening. */
export function startHttpServer(options: HttpServerOptions = {}): Promise<Server> {
  const port = options.port ?? Number(process.env.PORT ?? 3000);
  const host = options.host ?? process.env.HOST ?? "0.0.0.0";
  const mcp = createQproofServer();
  const httpServer = createHttpServer(mcp);
  return new Promise((resolve) => {
    httpServer.listen(port, host, () => {
      process.stderr.write(`qproof MCP server (http) listening on http://${host}:${port}\n`);
      process.stderr.write(`  POST http://${host}:${port}/mcp   GET http://${host}:${port}/health\n`);
      resolve(httpServer);
    });
  });
}

/** Entry point when run directly. */
function main(): void {
  void startHttpServer();
}

/** True when this module is the program's entry point (handles symlinks). */
function isMainModule(): boolean {
  const argv1 = process.argv[1];
  if (!argv1) return false;
  const thisPath = fileURLToPath(import.meta.url);
  try {
    return realpathSync(argv1) === realpathSync(thisPath);
  } catch {
    return argv1 === thisPath;
  }
}

// Only auto-run when invoked as a script, not when imported by tests.
if (isMainModule()) {
  main();
}
