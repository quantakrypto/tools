/**
 * Transport-agnostic MCP server core.
 *
 * {@link McpServer} owns a tool registry and a single pure entry point,
 * {@link McpServer.handle}, that turns one JSON-RPC message into one JSON-RPC
 * response (or `null` for notifications, which get no reply). It performs no
 * I/O whatsoever — the stdio and http transports feed it parsed messages and
 * serialize whatever it returns. This makes the whole protocol surface
 * unit-testable by calling `handle` directly.
 *
 * The one concession to I/O is that unexpected (non-{@link RpcError}) throws are
 * logged to stderr with full detail and replaced with a generic message in the
 * response, so server internals (paths, ENOENT targets) never reach the remote
 * caller. The wire response remains a pure function of the inputs.
 */

import process from "node:process";

import {
  ErrorCode,
  MCP_PROTOCOL_VERSION,
  RpcError,
  isJsonRpcRequestLike,
  isNotification,
  makeFailure,
  makeSuccess,
} from "./protocol.js";
import type {
  JsonRpcRequest,
  JsonRpcResponse,
  ToolContext,
  ToolDefinition,
  ToolDescriptor,
  ToolResult,
} from "./protocol.js";

/** Identifying info advertised to clients during `initialize`. */
export interface ServerInfo {
  name: string;
  version: string;
}

export interface McpServerOptions {
  /** Server identity returned in the `initialize` handshake. */
  info: ServerInfo;
  /** Optional human-readable instructions surfaced to the client. */
  instructions?: string;
}

/**
 * A minimal, spec-faithful MCP server. Register tools with {@link registerTool}
 * and drive it one message at a time with {@link handle}.
 */
export class McpServer {
  private readonly tools = new Map<string, ToolDefinition>();
  private readonly info: ServerInfo;
  private readonly instructions?: string;
  /** Set once `initialize` has been received; informational only. */
  private initialized = false;

  constructor(options: McpServerOptions) {
    this.info = options.info;
    this.instructions = options.instructions;
  }

  /** Register a tool. Throws if a tool with the same name already exists. */
  registerTool(tool: ToolDefinition): this {
    if (this.tools.has(tool.name)) {
      throw new Error(`duplicate tool registration: ${tool.name}`);
    }
    this.tools.set(tool.name, tool);
    return this;
  }

  /** The public descriptors of all registered tools (sorted by name). */
  listTools(): ToolDescriptor[] {
    return [...this.tools.values()]
      .map(({ name, description, inputSchema }) => ({ name, description, inputSchema }))
      .sort((a, b) => a.name.localeCompare(b.name));
  }

  /** Whether the `initialize` handshake has completed. */
  get isInitialized(): boolean {
    return this.initialized;
  }

  /**
   * Process a single JSON-RPC message.
   *
   * @param message An already-parsed JSON value (the transport handles framing
   *   and `JSON.parse`). May be malformed; this method validates it.
   * @param context Optional per-call context (e.g. an `AbortSignal` for the
   *   transport's request deadline) forwarded to the invoked tool handler.
   * @returns The response to send back, or `null` when no reply is due
   *   (notifications, or an unparseable notification-shaped message).
   */
  async handle(message: unknown, context?: ToolContext): Promise<JsonRpcResponse | null> {
    if (!isJsonRpcRequestLike(message)) {
      // Not a valid request object. We can't know its id, so reply with null id.
      return makeFailure(null, ErrorCode.InvalidRequest, "invalid JSON-RPC request");
    }

    const req = message as JsonRpcRequest;
    const notification = isNotification(req);
    const id = notification ? null : (req.id ?? null);

    try {
      const result = await this.dispatch(req, context);
      // Notifications never receive a response, even on success.
      if (notification) return null;
      return makeSuccess(id, result);
    } catch (err) {
      if (notification) return null; // swallow errors from notifications
      if (err instanceof RpcError) {
        // RpcError messages are author-controlled validation strings, safe to return.
        return makeFailure(id, err.code, err.message, err.data);
      }
      // An unexpected throw may carry a server-side detail (a filesystem path, an
      // ENOENT for /etc/shadow, …). Log the detail locally; return a generic
      // message so the remote caller never learns server internals.
      const detail = err instanceof Error ? (err.stack ?? err.message) : String(err);
      process.stderr.write(`quantakrypto MCP: internal error handling request: ${detail}\n`);
      return makeFailure(id, ErrorCode.InternalError, "internal error");
    }
  }

  /** Route a request to the right handler. Throws {@link RpcError} on failure. */
  private async dispatch(req: JsonRpcRequest, context?: ToolContext): Promise<unknown> {
    switch (req.method) {
      case "initialize":
        return this.onInitialize();
      case "notifications/initialized":
        this.initialized = true;
        return {}; // notification → result ignored by handle()
      case "ping":
        return {};
      case "tools/list":
        return { tools: this.listTools() };
      case "tools/call":
        return this.onToolsCall(req.params, context);
      default:
        throw new RpcError(ErrorCode.MethodNotFound, `method not found: ${req.method}`);
    }
  }

  /** Build the `initialize` result. */
  private onInitialize(): unknown {
    this.initialized = true;
    const result: Record<string, unknown> = {
      protocolVersion: MCP_PROTOCOL_VERSION,
      capabilities: {
        // We expose tools; our list is static, so listChanged is false.
        tools: { listChanged: false },
      },
      serverInfo: { name: this.info.name, version: this.info.version },
    };
    if (this.instructions) result.instructions = this.instructions;
    return result;
  }

  /** Validate params and execute a tool for `tools/call`. */
  private async onToolsCall(params: unknown, context?: ToolContext): Promise<ToolResult> {
    if (typeof params !== "object" || params === null || Array.isArray(params)) {
      throw new RpcError(ErrorCode.InvalidParams, "tools/call requires an object params");
    }
    const { name, arguments: args } = params as {
      name?: unknown;
      arguments?: unknown;
    };
    if (typeof name !== "string" || name.length === 0) {
      throw new RpcError(ErrorCode.InvalidParams, "tools/call requires a 'name' string");
    }
    const tool = this.tools.get(name);
    if (!tool) {
      throw new RpcError(ErrorCode.InvalidParams, `unknown tool: ${name}`);
    }
    if (args !== undefined && (typeof args !== "object" || args === null || Array.isArray(args))) {
      throw new RpcError(ErrorCode.InvalidParams, "tool 'arguments' must be an object");
    }
    const toolArgs = (args ?? {}) as Record<string, unknown>;
    // Tool-level failures are reported as isError results, not protocol errors,
    // so the model can read and react to them. Only unexpected throws bubble up.
    return tool.handler(toolArgs, context);
  }
}
