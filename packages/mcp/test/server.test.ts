/**
 * Protocol-level tests for the MCP server core.
 *
 * These drive {@link McpServer.handle} directly — no process spawning, no I/O —
 * exercising the JSON-RPC dispatch, the MCP handshake, and error handling.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { createQproofServer, SERVER_NAME } from "../src/index.js";
import { MCP_PROTOCOL_VERSION, ErrorCode } from "../src/protocol.js";
import type { JsonRpcSuccess, JsonRpcFailure } from "../src/protocol.js";

/** Assert a response is a success and return it narrowed. */
function expectSuccess(res: unknown): JsonRpcSuccess {
  assert.ok(res && typeof res === "object", "expected a response object");
  assert.ok("result" in (res as object), "expected a success response");
  return res as JsonRpcSuccess;
}

/** Assert a response is a failure and return it narrowed. */
function expectFailure(res: unknown): JsonRpcFailure {
  assert.ok(res && typeof res === "object", "expected a response object");
  assert.ok("error" in (res as object), "expected a failure response");
  return res as JsonRpcFailure;
}

test("initialize returns the expected handshake shape", async () => {
  const server = createQproofServer();
  const res = expectSuccess(
    await server.handle({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }),
  );

  assert.equal(res.jsonrpc, "2.0");
  assert.equal(res.id, 1);

  const result = res.result as Record<string, unknown>;
  assert.equal(result.protocolVersion, MCP_PROTOCOL_VERSION);

  const caps = result.capabilities as { tools?: { listChanged?: boolean } };
  assert.deepEqual(caps.tools, { listChanged: false });

  const info = result.serverInfo as { name?: string; version?: string };
  assert.equal(info.name, SERVER_NAME);
  assert.equal(typeof info.version, "string");
  assert.ok((info.version as string).length > 0);
});

test("notifications/initialized produces no response", async () => {
  const server = createQproofServer();
  // Notification: no id field present → handle() returns null.
  const res = await server.handle({ jsonrpc: "2.0", method: "notifications/initialized" });
  assert.equal(res, null);
  assert.equal(server.isInitialized, true);
});

test("ping responds with an empty result", async () => {
  const server = createQproofServer();
  const res = expectSuccess(await server.handle({ jsonrpc: "2.0", id: 7, method: "ping" }));
  assert.deepEqual(res.result, {});
});

test("tools/list returns every tool with a valid object inputSchema", async () => {
  const server = createQproofServer();
  const res = expectSuccess(await server.handle({ jsonrpc: "2.0", id: 2, method: "tools/list" }));

  const { tools } = res.result as {
    tools: Array<{ name: string; description: string; inputSchema: { type: string } }>;
  };
  const names = tools.map((t) => t.name).sort();
  assert.deepEqual(names, [
    "explain_finding",
    "generate_cbom",
    "inventory_crypto",
    "list_rules",
    "scan_path",
    "suggest_hybrid",
  ]);

  for (const t of tools) {
    assert.equal(typeof t.name, "string");
    assert.ok(t.description.length > 0, `${t.name} should have a description`);
    assert.equal(t.inputSchema.type, "object", `${t.name} inputSchema.type should be object`);
  }
});

test("unknown method yields JSON-RPC error -32601", async () => {
  const server = createQproofServer();
  const res = expectFailure(
    await server.handle({ jsonrpc: "2.0", id: 3, method: "does/not/exist" }),
  );
  assert.equal(res.error.code, ErrorCode.MethodNotFound);
  assert.equal(res.error.code, -32601);
  assert.match(res.error.message, /does\/not\/exist/);
});

test("malformed (non-JSON-RPC) request yields InvalidRequest", async () => {
  const server = createQproofServer();

  // Missing jsonrpc/method entirely.
  const res1 = expectFailure(await server.handle({ foo: "bar" }));
  assert.equal(res1.error.code, ErrorCode.InvalidRequest);
  assert.equal(res1.id, null);

  // Wrong jsonrpc version.
  const res2 = expectFailure(await server.handle({ jsonrpc: "1.0", id: 9, method: "ping" }));
  assert.equal(res2.error.code, ErrorCode.InvalidRequest);

  // Not even an object.
  const res3 = expectFailure(await server.handle("hello"));
  assert.equal(res3.error.code, ErrorCode.InvalidRequest);
});

test("tools/call with a bad tool name yields InvalidParams", async () => {
  const server = createQproofServer();
  const res = expectFailure(
    await server.handle({
      jsonrpc: "2.0",
      id: 4,
      method: "tools/call",
      params: { name: "no_such_tool", arguments: {} },
    }),
  );
  assert.equal(res.error.code, ErrorCode.InvalidParams);
});

test("tools/call missing name yields InvalidParams", async () => {
  const server = createQproofServer();
  const res = expectFailure(
    await server.handle({
      jsonrpc: "2.0",
      id: 5,
      method: "tools/call",
      params: { arguments: {} },
    }),
  );
  assert.equal(res.error.code, ErrorCode.InvalidParams);
});
