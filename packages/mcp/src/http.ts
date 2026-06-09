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
 * SAFE-BY-DEFAULT POSTURE (P0-1). Unlike the stdio transport — which trusts the
 * local user and stays fully featured — the HTTP transport is hardened because a
 * hosted endpoint is reachable by untrusted peers:
 *
 *   - Binds to 127.0.0.1 by default (NOT 0.0.0.0). Override with QPROOF_MCP_HOST.
 *   - Bearer-token auth: when QPROOF_MCP_TOKEN is set, every /mcp request must
 *     send `Authorization: Bearer <token>` (else 401). Binding to a non-loopback
 *     host WITHOUT a token is refused at startup (it would be an open relay).
 *   - The filesystem tools (scan_path, inventory_crypto, generate_cbom) read
 *     arbitrary server paths and are DISABLED over HTTP unless QPROOF_MCP_ALLOW_FS=1
 *     (security audit Q-01). The knowledge tools (explain_finding, suggest_hybrid,
 *     list_rules) are always available. Gating is enforced by registering only the
 *     permitted tools, so tools/list and tools/call both reflect it.
 *   - Per-request timeout (QPROOF_MCP_TIMEOUT_MS) and a response-size cap
 *     (QPROOF_MCP_MAX_RESPONSE_BYTES), in addition to the 1 MiB request-body cap.
 *
 * Run with `node dist/http.js` (PORT/QPROOF_MCP_* from env).
 */

import { createServer } from "node:http";
import type { IncomingMessage, Server, ServerResponse } from "node:http";
import { randomUUID } from "node:crypto";
import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import process from "node:process";

import { createQproofServer } from "./index.js";
import { ErrorCode, makeFailure } from "./protocol.js";
import type { JsonRpcResponse, ToolDefinition } from "./protocol.js";
import { qproofTools, FS_TOOL_NAMES } from "./tools.js";
import type { McpServer } from "./server.js";

/** Header carrying the MCP session id (per the Streamable HTTP transport). */
export const SESSION_HEADER = "mcp-session-id";

/** Maximum accepted request body size (1 MiB) — a basic abuse guard. */
const MAX_BODY_BYTES = 1024 * 1024;

/** Default per-request tool-execution deadline (ms). */
const DEFAULT_TIMEOUT_MS = 30_000;

/** Default cap on the serialized response body (4 MiB). */
const DEFAULT_MAX_RESPONSE_BYTES = 4 * 1024 * 1024;

/** Loopback hosts that are safe to bind without authentication. */
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "::1", "localhost"]);

export interface HttpServerOptions {
  /** Port to listen on. Defaults to env PORT or 3000. */
  port?: number;
  /** Host/interface to bind. Defaults to QPROOF_MCP_HOST / HOST or "127.0.0.1". */
  host?: string;
  /** Bearer token required on /mcp. Defaults to QPROOF_MCP_TOKEN (empty = none). */
  token?: string;
  /** Expose the filesystem tools over HTTP. Defaults to QPROOF_MCP_ALLOW_FS=1. */
  allowFs?: boolean;
  /** Per-request tool-execution timeout (ms). Defaults to QPROOF_MCP_TIMEOUT_MS. */
  timeoutMs?: number;
  /** Response-body size cap (bytes). Defaults to QPROOF_MCP_MAX_RESPONSE_BYTES. */
  maxResponseBytes?: number;
}

/* -------------------------------------------------------------------------- */
/* Pure policy (P0-1) — host/auth/tool-gating decisions, fully unit-testable.  */
/* -------------------------------------------------------------------------- */

/** A minimal env shape so the config resolver is pure and testable. */
export type HttpEnv = Record<string, string | undefined>;

/** Resolved, validated HTTP transport configuration. */
export interface HttpConfig {
  host: string;
  port: number;
  /** The bearer token, or "" when auth is disabled. */
  token: string;
  /** Whether the filesystem tools are exposed over HTTP. */
  allowFs: boolean;
  timeoutMs: number;
  maxResponseBytes: number;
  /** True when the host is a loopback interface (safe without auth). */
  loopback: boolean;
}

/**
 * Resolve the HTTP transport config from env + explicit overrides. Pure: does
 * no I/O and never reads `process` directly. Overrides win over env.
 */
export function resolveHttpConfig(env: HttpEnv, options: HttpServerOptions = {}): HttpConfig {
  const host = options.host ?? env.QPROOF_MCP_HOST ?? env.HOST ?? "127.0.0.1";
  const port = options.port ?? toInt(env.PORT, 3000);
  const token = (options.token ?? env.QPROOF_MCP_TOKEN ?? "").trim();
  const allowFs =
    options.allowFs ?? (env.QPROOF_MCP_ALLOW_FS === "1" || env.QPROOF_MCP_ALLOW_FS === "true");
  const timeoutMs = options.timeoutMs ?? toInt(env.QPROOF_MCP_TIMEOUT_MS, DEFAULT_TIMEOUT_MS);
  const maxResponseBytes =
    options.maxResponseBytes ??
    toInt(env.QPROOF_MCP_MAX_RESPONSE_BYTES, DEFAULT_MAX_RESPONSE_BYTES);
  return {
    host,
    port,
    token,
    allowFs,
    timeoutMs,
    maxResponseBytes,
    loopback: isLoopbackHost(host),
  };
}

/** Parse a positive integer from an env string, falling back on bad input. */
function toInt(value: string | undefined, fallback: number): number {
  if (value === undefined) return fallback;
  const n = Number(value);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback;
}

/** True when binding to `host` keeps the server private to this machine. */
export function isLoopbackHost(host: string): boolean {
  return LOOPBACK_HOSTS.has(host.trim().toLowerCase());
}

/**
 * Decide whether a non-loopback bind is permitted. A server reachable from the
 * network MUST require auth; binding wide-open without a token would be an open,
 * unauthenticated arbitrary-tool relay. Pure decision used at startup.
 */
export function startupDecision(config: HttpConfig): {
  ok: boolean;
  reason?: string;
} {
  if (!config.loopback && config.token.length === 0) {
    return {
      ok: false,
      reason:
        `refusing to bind to non-loopback host "${config.host}" without a token. ` +
        `Set QPROOF_MCP_TOKEN to require Bearer auth, or bind to 127.0.0.1.`,
    };
  }
  return { ok: true };
}

/** A request-authorization outcome. */
export interface AuthDecision {
  authorized: boolean;
  /** HTTP status to use when not authorized. */
  status?: number;
  message?: string;
}

/**
 * Decide whether a request is authorized given the configured token and the
 * incoming Authorization header. When no token is configured, all requests are
 * allowed (the loopback / trusted-edge case). Pure and testable.
 */
export function authorizeRequest(
  token: string,
  authorizationHeader: string | undefined,
): AuthDecision {
  if (token.length === 0) return { authorized: true };
  const header = (authorizationHeader ?? "").trim();
  const match = /^Bearer\s+(.+)$/i.exec(header);
  const presented = match?.[1]?.trim();
  if (!presented) {
    return { authorized: false, status: 401, message: "missing bearer token" };
  }
  if (!timingSafeEqualStr(presented, token)) {
    return { authorized: false, status: 401, message: "invalid bearer token" };
  }
  return { authorized: true };
}

/** Constant-time-ish string compare (length-independent short-circuit guarded). */
function timingSafeEqualStr(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/**
 * Select the tools to expose over HTTP for a given policy. The knowledge tools
 * are always returned; the filesystem tools are included only when
 * `allowFs` is true. Pure function of its inputs — the single source of truth
 * for HTTP tool gating, so tools/list and tools/call stay consistent.
 */
export function gateHttpTools(
  tools: readonly ToolDefinition[],
  allowFs: boolean,
): ToolDefinition[] {
  const fsNames = new Set(FS_TOOL_NAMES);
  return tools.filter((t) => allowFs || !fsNames.has(t.name));
}

/* -------------------------------------------------------------------------- */
/* HTTP plumbing                                                               */
/* -------------------------------------------------------------------------- */

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

/** Race a handler against a deadline; rejects with a timeout error if exceeded. */
function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  if (!(ms > 0)) return promise;
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("request timed out")), ms);
    timer.unref?.();
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (err: unknown) => {
        clearTimeout(timer);
        reject(err instanceof Error ? err : new Error(String(err)));
      },
    );
  });
}

/**
 * Build (but do not start) the HTTP server wrapping an {@link McpServer}.
 * Exposed for testing and for embedding in a larger process. The `config`
 * carries the resolved auth / timeout / response-cap policy.
 */
export function createHttpServer(server: McpServer, config: HttpConfig): Server {
  return createServer((req, res) => {
    void handleRequest(server, config, req, res).catch((err: unknown) => {
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
  config: HttpConfig,
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
    // Authenticate BEFORE reading the body or dispatching (Q-02).
    const auth = authorizeRequest(config.token, req.headers.authorization);
    if (!auth.authorized) {
      sendJson(
        res,
        auth.status ?? 401,
        makeFailure(null, ErrorCode.InvalidRequest, auth.message ?? "unauthorized"),
        { "www-authenticate": "Bearer" },
      );
      return;
    }
    await handleMcpPost(server, config, req, res);
    return;
  }

  sendJson(res, 404, makeFailure(null, ErrorCode.MethodNotFound, "not found"));
}

/** Handle `POST /mcp`: parse one JSON-RPC message, dispatch, return the result. */
async function handleMcpPost(
  server: McpServer,
  config: HttpConfig,
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

  let response: JsonRpcResponse | null;
  try {
    response = await withTimeout(server.handle(parsed), config.timeoutMs);
  } catch (err) {
    const messageText = err instanceof Error ? err.message : String(err);
    sendJson(res, 504, makeFailure(null, ErrorCode.InternalError, messageText), sessionHeaders);
    return;
  }

  if (response === null) {
    // Notification — acknowledge with 202 and no body.
    res.writeHead(202, sessionHeaders);
    res.end();
    return;
  }

  // Enforce the response-size cap (Q-03): never stream back an unbounded body.
  const serialized = JSON.stringify(response);
  if (Buffer.byteLength(serialized) > config.maxResponseBytes) {
    sendJson(
      res,
      500,
      makeFailure(null, ErrorCode.InternalError, "response too large"),
      sessionHeaders,
    );
    return;
  }
  sendJson(res, 200, response, sessionHeaders);
}

/**
 * Build the HTTP-facing {@link McpServer}: the same server used over stdio but
 * with the filesystem tools gated per policy. Exposed for tests.
 */
export function createHttpMcpServer(config: HttpConfig): McpServer {
  return createQproofServer({ tools: gateHttpTools(qproofTools, config.allowFs) });
}

/** Start the HTTP server, resolving once it is listening. */
export function startHttpServer(options: HttpServerOptions = {}): Promise<Server> {
  const config = resolveHttpConfig(process.env, options);

  const decision = startupDecision(config);
  if (!decision.ok) {
    return Promise.reject(new Error(decision.reason ?? "refusing to start"));
  }
  if (!config.loopback) {
    process.stderr.write(
      `qproof MCP (http): WARNING binding to non-loopback host ${config.host}; ` +
        `Bearer auth is required and active.\n`,
    );
  }

  const mcp = createHttpMcpServer(config);
  const httpServer = createHttpServer(mcp, config);
  return new Promise((resolve) => {
    httpServer.listen(config.port, config.host, () => {
      const auth = config.token ? "bearer-auth" : "no-auth";
      const fs = config.allowFs ? "fs-tools:on" : "fs-tools:off";
      process.stderr.write(
        `qproof MCP server (http) listening on http://${config.host}:${config.port} ` +
          `[${auth}, ${fs}]\n`,
      );
      process.stderr.write(
        `  POST http://${config.host}:${config.port}/mcp   ` +
          `GET http://${config.host}:${config.port}/health\n`,
      );
      resolve(httpServer);
    });
  });
}

/** Entry point when run directly. */
function main(): void {
  startHttpServer().catch((err: unknown) => {
    const messageText = err instanceof Error ? err.message : String(err);
    process.stderr.write(`qproof MCP (http) failed to start: ${messageText}\n`);
    process.exitCode = 1;
  });
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
