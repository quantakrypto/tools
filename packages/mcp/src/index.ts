/**
 * @qproof/mcp — public API.
 *
 * Exports the transport-agnostic {@link McpServer}, the qproof tool set, and a
 * {@link createQproofServer} factory that wires them together. Transports
 * (stdio, http) consume the factory; tests drive the server's `handle` method
 * directly.
 */

import { VERSION } from "@qproof/core";

import { McpServer } from "./server.js";
import { qproofTools } from "./tools.js";

export { McpServer } from "./server.js";
export type { McpServerOptions, ServerInfo } from "./server.js";
export { qproofTools, CORE_VERSION } from "./tools.js";
export {
  MCP_PROTOCOL_VERSION,
  JSONRPC_VERSION,
  ErrorCode,
  RpcError,
  textResult,
  errorResult,
} from "./protocol.js";
export type {
  JsonRpcRequest,
  JsonRpcResponse,
  JsonRpcSuccess,
  JsonRpcFailure,
  ToolDefinition,
  ToolDescriptor,
  ToolResult,
  Content,
  TextContent,
  JsonSchema,
} from "./protocol.js";

/** The MCP server name advertised to clients. */
export const SERVER_NAME = "qproof";

/** The version reported by the server (kept in sync with @qproof/core). */
export const SERVER_VERSION = VERSION;

export interface CreateServerOptions {
  /** Override the advertised server version (defaults to @qproof/core VERSION). */
  version?: string;
  /** Override or extend the registered tool set (defaults to all qproof tools). */
  tools?: typeof qproofTools;
}

/**
 * Create a fully-wired qproof {@link McpServer} with all tools registered.
 *
 * @example
 * ```ts
 * const server = createQproofServer();
 * const res = await server.handle({ jsonrpc: "2.0", id: 1, method: "tools/list" });
 * ```
 */
export function createQproofServer(options: CreateServerOptions = {}): McpServer {
  const server = new McpServer({
    info: { name: SERVER_NAME, version: options.version ?? SERVER_VERSION },
    instructions:
      "qproof checks code for quantum-vulnerable cryptography and recommends " +
      "post-quantum (NIST PQC) migrations. Use scan_path / inventory_crypto to " +
      "assess a path, list_rules to see detectors, and explain_finding / " +
      "suggest_hybrid for remediation guidance.",
  });
  for (const tool of options.tools ?? qproofTools) {
    server.registerTool(tool);
  }
  return server;
}
