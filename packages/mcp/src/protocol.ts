/**
 * JSON-RPC 2.0 + Model Context Protocol (MCP) wire types.
 *
 * This module is pure type/shape definitions plus a few small helpers for
 * constructing valid JSON-RPC responses and errors. It has no runtime
 * dependencies and no I/O — the transport layers (stdio, http) and the
 * {@link McpServer} build on top of it.
 *
 * Reference: JSON-RPC 2.0 (https://www.jsonrpc.org/specification) and the
 * Model Context Protocol specification (https://modelcontextprotocol.io).
 */

/** The fixed JSON-RPC protocol marker. */
export const JSONRPC_VERSION = "2.0" as const;

/**
 * MCP protocol revision this server speaks. The `initialize` handshake echoes
 * the client's requested version when we support it, otherwise advertises this.
 */
export const MCP_PROTOCOL_VERSION = "2025-06-18" as const;

/** A JSON-RPC id: string or number per spec (we never originate notifications). */
export type JsonRpcId = string | number | null;

/** Any JSON value. Kept structural rather than `any` for strict mode. */
export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };

/** A JSON-RPC 2.0 request or notification (notifications omit `id`). */
export interface JsonRpcRequest {
  jsonrpc: typeof JSONRPC_VERSION;
  /** Absent for notifications. */
  id?: JsonRpcId;
  method: string;
  params?: Record<string, unknown> | unknown[];
}

/** A successful JSON-RPC response. */
export interface JsonRpcSuccess {
  jsonrpc: typeof JSONRPC_VERSION;
  id: JsonRpcId;
  result: unknown;
}

/** A JSON-RPC error object. */
export interface JsonRpcErrorObject {
  code: number;
  message: string;
  data?: unknown;
}

/** A failed JSON-RPC response. */
export interface JsonRpcFailure {
  jsonrpc: typeof JSONRPC_VERSION;
  id: JsonRpcId;
  error: JsonRpcErrorObject;
}

export type JsonRpcResponse = JsonRpcSuccess | JsonRpcFailure;

/** Standard JSON-RPC 2.0 error codes (plus MCP conventions). */
export const ErrorCode = {
  ParseError: -32700,
  InvalidRequest: -32600,
  MethodNotFound: -32601,
  InvalidParams: -32602,
  InternalError: -32603,
} as const;

/** An error that carries a JSON-RPC error code, thrown by tool handlers/dispatch. */
export class RpcError extends Error {
  readonly code: number;
  readonly data?: unknown;
  constructor(code: number, message: string, data?: unknown) {
    super(message);
    this.name = "RpcError";
    this.code = code;
    this.data = data;
  }
}

/** Build a successful response envelope. */
export function makeSuccess(id: JsonRpcId, result: unknown): JsonRpcSuccess {
  return { jsonrpc: JSONRPC_VERSION, id, result };
}

/** Build a failure response envelope. */
export function makeFailure(
  id: JsonRpcId,
  code: number,
  message: string,
  data?: unknown,
): JsonRpcFailure {
  const error: JsonRpcErrorObject = { code, message };
  if (data !== undefined) error.data = data;
  return { jsonrpc: JSONRPC_VERSION, id, error };
}

/** Narrow an unknown parsed value to something request-shaped enough to dispatch. */
export function isJsonRpcRequestLike(value: unknown): value is JsonRpcRequest {
  if (typeof value !== "object" || value === null) return false;
  const v = value as Record<string, unknown>;
  return v.jsonrpc === JSONRPC_VERSION && typeof v.method === "string";
}

/** True when a request is a notification (no `id` field present). */
export function isNotification(req: JsonRpcRequest): boolean {
  return !("id" in req) || req.id === undefined;
}

// ---------------------------------------------------------------------------
// MCP content + tool shapes
// ---------------------------------------------------------------------------

/** A single piece of MCP content. We only emit text content in this server. */
export interface TextContent {
  type: "text";
  text: string;
}

export type Content = TextContent;

/** The result envelope returned by a `tools/call`. */
export interface ToolResult {
  content: Content[];
  /** True when the tool ran but produced an error result (vs. a protocol error). */
  isError?: boolean;
}

/** A minimal JSON Schema object describing a tool's input. */
export interface JsonSchema {
  type: "object";
  properties?: Record<string, unknown>;
  required?: string[];
  additionalProperties?: boolean;
  [key: string]: unknown;
}

/** The public descriptor of a tool, as returned by `tools/list`. */
export interface ToolDescriptor {
  name: string;
  description: string;
  inputSchema: JsonSchema;
}

/**
 * Per-call context threaded from the transport into a tool handler. Carries the
 * cooperative-cancellation signal so a long-running tool (e.g. a filesystem
 * scan) can be aborted when the transport's request deadline fires, instead of
 * leaking unbounded background work after a 504/timeout.
 */
export interface ToolContext {
  /** Fires when the caller's request deadline elapses; abort in-flight work. */
  signal?: AbortSignal;
}

/** A registered tool: descriptor plus its async handler. */
export interface ToolDefinition extends ToolDescriptor {
  /**
   * Executes the tool with already-parsed arguments and an optional per-call
   * {@link ToolContext} (e.g. an `AbortSignal` for the request deadline).
   */
  handler: (
    args: Record<string, unknown>,
    context?: ToolContext,
  ) => Promise<ToolResult> | ToolResult;
}

/** Convenience: wrap one or more strings as a non-error text tool result. */
export function textResult(...parts: string[]): ToolResult {
  return { content: parts.map((text) => ({ type: "text", text })) };
}

/** Convenience: wrap a string as an error text tool result. */
export function errorResult(text: string): ToolResult {
  return { content: [{ type: "text", text }], isError: true };
}
