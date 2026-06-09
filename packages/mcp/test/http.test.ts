/**
 * HTTP transport tests (P0-1) — safe-by-default hosting posture.
 *
 * The auth, host, tool-gating and startup decisions are pure functions, tested
 * directly. A few end-to-end tests boot the real HTTP server on an ephemeral
 * loopback port and drive it with `fetch` to confirm the policy is wired into
 * tools/list, tools/call, and the request pipeline.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";

import {
  authorizeRequest,
  resolveHttpConfig,
  startupDecision,
  gateHttpTools,
  isLoopbackHost,
  createHttpMcpServer,
  createHttpServer,
} from "../src/http.js";
import { qproofTools, FS_TOOL_NAMES } from "../src/tools.js";
import type { ToolDefinition } from "../src/protocol.js";

/* ----------------------------- pure: config ------------------------------- */

test("resolveHttpConfig defaults to a safe loopback bind with no auth", () => {
  const cfg = resolveHttpConfig({});
  assert.equal(cfg.host, "127.0.0.1");
  assert.equal(cfg.port, 3000);
  assert.equal(cfg.token, "");
  assert.equal(cfg.allowFs, false);
  assert.equal(cfg.loopback, true);
  assert.ok(cfg.timeoutMs > 0);
  assert.ok(cfg.maxResponseBytes > 0);
});

test("resolveHttpConfig reads env: host, token, allow-fs, port", () => {
  const cfg = resolveHttpConfig({
    QPROOF_MCP_HOST: "0.0.0.0",
    QPROOF_MCP_TOKEN: "  secret  ",
    QPROOF_MCP_ALLOW_FS: "1",
    PORT: "8080",
  });
  assert.equal(cfg.host, "0.0.0.0");
  assert.equal(cfg.token, "secret"); // trimmed
  assert.equal(cfg.allowFs, true);
  assert.equal(cfg.port, 8080);
  assert.equal(cfg.loopback, false);
});

test("explicit options win over env", () => {
  const cfg = resolveHttpConfig(
    { QPROOF_MCP_HOST: "0.0.0.0", QPROOF_MCP_ALLOW_FS: "1" },
    { host: "127.0.0.1", allowFs: false },
  );
  assert.equal(cfg.host, "127.0.0.1");
  assert.equal(cfg.allowFs, false);
});

/* --------------------------- pure: loopback ------------------------------- */

test("isLoopbackHost recognizes the loopback interfaces", () => {
  for (const h of ["127.0.0.1", "::1", "localhost", "LOCALHOST"]) {
    assert.equal(isLoopbackHost(h), true, h);
  }
  for (const h of ["0.0.0.0", "10.0.0.1", "example.com"]) {
    assert.equal(isLoopbackHost(h), false, h);
  }
});

/* --------------------------- pure: startup -------------------------------- */

test("startupDecision refuses a non-loopback bind without a token", () => {
  const cfg = resolveHttpConfig({ QPROOF_MCP_HOST: "0.0.0.0" });
  const decision = startupDecision(cfg);
  assert.equal(decision.ok, false);
  assert.match(decision.reason ?? "", /token|loopback/i);
});

test("startupDecision allows a non-loopback bind with a token", () => {
  const cfg = resolveHttpConfig({ QPROOF_MCP_HOST: "0.0.0.0", QPROOF_MCP_TOKEN: "t" });
  assert.equal(startupDecision(cfg).ok, true);
});

test("startupDecision allows the default loopback bind without a token", () => {
  assert.equal(startupDecision(resolveHttpConfig({})).ok, true);
});

/* ----------------------------- pure: auth --------------------------------- */

test("authorizeRequest allows all when no token is configured", () => {
  assert.equal(authorizeRequest("", undefined).authorized, true);
  assert.equal(authorizeRequest("", "Bearer whatever").authorized, true);
});

test("authorizeRequest requires a matching bearer token when one is set", () => {
  assert.equal(authorizeRequest("s3cret", "Bearer s3cret").authorized, true);
  const missing = authorizeRequest("s3cret", undefined);
  assert.equal(missing.authorized, false);
  assert.equal(missing.status, 401);
  const wrong = authorizeRequest("s3cret", "Bearer nope");
  assert.equal(wrong.authorized, false);
  assert.equal(wrong.status, 401);
  // Case-insensitive scheme, tolerant of surrounding whitespace.
  assert.equal(authorizeRequest("s3cret", "  bearer   s3cret  ").authorized, true);
});

/* --------------------------- pure: gating --------------------------------- */

test("gateHttpTools hides the FS tools by default, keeps knowledge tools", () => {
  const gated = gateHttpTools(qproofTools, false).map((t: ToolDefinition) => t.name);
  for (const fs of FS_TOOL_NAMES) {
    assert.equal(gated.includes(fs), false, `${fs} must be gated off`);
  }
  assert.ok(gated.includes("explain_finding"));
  assert.ok(gated.includes("suggest_hybrid"));
  assert.ok(gated.includes("list_rules"));
});

test("gateHttpTools exposes the FS tools when allowFs is true", () => {
  const gated = gateHttpTools(qproofTools, true).map((t: ToolDefinition) => t.name);
  for (const fs of FS_TOOL_NAMES) {
    assert.equal(gated.includes(fs), true, `${fs} must be exposed`);
  }
});

/* --------------------------- end-to-end ----------------------------------- */

/** Boot the server on an ephemeral loopback port; returns base URL + closer. */
async function boot(
  env: Record<string, string | undefined>,
): Promise<{ base: string; close: () => Promise<void> }> {
  const cfg = resolveHttpConfig({ ...env, PORT: undefined });
  const mcp = createHttpMcpServer(cfg);
  const server = createHttpServer(mcp, cfg);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return {
    base: `http://127.0.0.1:${port}`,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

async function rpc(base: string, body: unknown, headers: Record<string, string> = {}) {
  return fetch(`${base}/mcp`, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
}

test("end-to-end: FS tools off by default in tools/list and tools/call", async () => {
  const { base, close } = await boot({});
  try {
    const listRes = await rpc(base, { jsonrpc: "2.0", id: 1, method: "tools/list" });
    assert.equal(listRes.status, 200);
    const list = (await listRes.json()) as { result: { tools: Array<{ name: string }> } };
    const names = list.result.tools.map((t) => t.name);
    assert.equal(names.includes("scan_path"), false);
    assert.equal(names.includes("inventory_crypto"), false);
    assert.equal(names.includes("generate_cbom"), false);
    assert.ok(names.includes("list_rules"));

    // Calling a gated-off tool fails as an unknown tool (InvalidParams).
    const callRes = await rpc(base, {
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: { name: "scan_path", arguments: { path: "/etc" } },
    });
    const call = (await callRes.json()) as { error?: { code: number } };
    assert.ok(call.error, "scan_path must not be callable when gated off");
  } finally {
    await close();
  }
});

test("end-to-end: FS tools appear when QPROOF_MCP_ALLOW_FS=1", async () => {
  const { base, close } = await boot({ QPROOF_MCP_ALLOW_FS: "1" });
  try {
    const res = await rpc(base, { jsonrpc: "2.0", id: 1, method: "tools/list" });
    const list = (await res.json()) as { result: { tools: Array<{ name: string }> } };
    const names = list.result.tools.map((t) => t.name);
    assert.ok(names.includes("scan_path"));
    assert.ok(names.includes("inventory_crypto"));
    assert.ok(names.includes("generate_cbom"));
  } finally {
    await close();
  }
});

test("end-to-end: bearer auth is enforced when a token is set", async () => {
  const { base, close } = await boot({ QPROOF_MCP_TOKEN: "letmein" });
  try {
    const unauth = await rpc(base, { jsonrpc: "2.0", id: 1, method: "tools/list" });
    assert.equal(unauth.status, 401);
    assert.equal(unauth.headers.get("www-authenticate"), "Bearer");

    const ok = await rpc(
      base,
      { jsonrpc: "2.0", id: 2, method: "tools/list" },
      { authorization: "Bearer letmein" },
    );
    assert.equal(ok.status, 200);
  } finally {
    await close();
  }
});

test("end-to-end: /health needs no auth", async () => {
  const { base, close } = await boot({ QPROOF_MCP_TOKEN: "letmein" });
  try {
    const res = await fetch(`${base}/health`);
    assert.equal(res.status, 200);
    const body = (await res.json()) as { status: string };
    assert.equal(body.status, "ok");
  } finally {
    await close();
  }
});
