/**
 * Tool-level tests, driven through {@link McpServer.handle} via `tools/call`.
 *
 * `@qproof/core` is partly stubbed (scan/buildInventory/remediationFor throw
 * "not implemented"). These tests assert the MCP envelope contract and the
 * behaviour that holds regardless of core's stub state:
 *   - tool handlers never crash the server (no protocol error from a stub);
 *   - every result is a well-formed { content: [...], isError? } object;
 *   - suggest_hybrid always returns actionable text via its static fallback.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { createQproofServer } from "../src/index.js";
import type { JsonRpcSuccess } from "../src/protocol.js";

interface ToolCallResult {
  content: Array<{ type: string; text: string }>;
  isError?: boolean;
}

/** Call a tool and return its (validated) ToolResult. */
async function callTool(
  name: string,
  args: Record<string, unknown>,
): Promise<ToolCallResult> {
  const server = createQproofServer();
  const res = await server.handle({
    jsonrpc: "2.0",
    id: 1,
    method: "tools/call",
    params: { name, arguments: args },
  });

  assert.ok(res && "result" in (res as object), `tools/call ${name} should succeed at protocol level`);
  const result = (res as JsonRpcSuccess).result as ToolCallResult;

  // Envelope invariants every tool must satisfy.
  assert.ok(Array.isArray(result.content), "content must be an array");
  assert.ok(result.content.length > 0, "content must be non-empty");
  for (const c of result.content) {
    assert.equal(c.type, "text");
    assert.equal(typeof c.text, "string");
  }
  return result;
}

test("suggest_hybrid (algorithm) returns PQC guidance content", async () => {
  const result = await callTool("suggest_hybrid", { algorithm: "RSA" });
  assert.notEqual(result.isError, true);
  const text = result.content.map((c) => c.text).join("\n");
  assert.match(text, /RSA/);
  assert.match(text, /ML-KEM|ML-DSA|hybrid/i);
});

test("suggest_hybrid (context) infers a family and recommends a migration", async () => {
  const result = await callTool("suggest_hybrid", {
    context: "we use ECDH for our TLS key exchange",
  });
  assert.notEqual(result.isError, true);
  const text = result.content.map((c) => c.text).join("\n");
  assert.match(text, /ECDH/);
  assert.match(text, /X25519MLKEM768|ML-KEM|hybrid/i);
});

test("suggest_hybrid with no args returns an error result", async () => {
  const result = await callTool("suggest_hybrid", {});
  assert.equal(result.isError, true);
  assert.match(result.content[0].text, /requires/i);
});

test("explain_finding by ruleId returns a structured explanation", async () => {
  const result = await callTool("explain_finding", { ruleId: "rsa-keygen" });
  // Detector catalog may be empty in the stub; either way we get readable text,
  // and resolving only a ruleId never depends on remediationFor (no throw path).
  assert.notEqual(result.isError, true);
  const text = result.content.map((c) => c.text).join("\n");
  assert.match(text, /rsa-keygen/);
});

test("explain_finding with neither ruleId nor algorithm errors", async () => {
  const result = await callTool("explain_finding", {});
  assert.equal(result.isError, true);
  assert.match(result.content[0].text, /requires at least one/i);
});

test("explain_finding by algorithm returns remediation or a clean error", async () => {
  const result = await callTool("explain_finding", { algorithm: "ECDSA" });
  const text = result.content.map((c) => c.text).join("\n");
  // With a real core: remediation text. With the stub: a readable failure result.
  // Either way the envelope is valid and the algorithm is echoed/referenced.
  if (result.isError) {
    assert.match(text, /failed/i);
  } else {
    assert.match(text, /ECDSA/);
  }
});

test("list_rules returns a catalog (possibly empty) as valid content", async () => {
  const result = await callTool("list_rules", {});
  assert.notEqual(result.isError, true);
  const text = result.content.map((c) => c.text).join("\n");
  assert.match(text, /detector|catalog|empty/i);
});

test("scan_path requires a path argument", async () => {
  const result = await callTool("scan_path", {});
  assert.equal(result.isError, true);
  assert.match(result.content[0].text, /path/i);
});

test("scan_path on a stubbed core surfaces a clean error, not a crash", async () => {
  const result = await callTool("scan_path", { path: "." });
  // The stub throws "not implemented"; the tool maps it to an isError result.
  // When core lands, this returns a real summary instead.
  assert.ok(Array.isArray(result.content));
  if (result.isError) {
    assert.match(result.content[0].text, /scan failed/i);
  }
});

test("inventory_crypto requires a path argument", async () => {
  const result = await callTool("inventory_crypto", {});
  assert.equal(result.isError, true);
  assert.match(result.content[0].text, /path/i);
});
