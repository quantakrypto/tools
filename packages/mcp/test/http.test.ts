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
  timingSafeEqualStr,
  originDecision,
  allowedOriginHosts,
} from "../src/http.js";
import { quantakryptoTools, FS_TOOL_NAMES } from "../src/tools.js";
import type { ToolDefinition, ToolContext } from "../src/protocol.js";
import { McpServer } from "../src/server.js";

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
    QUANTAKRYPTO_MCP_HOST: "0.0.0.0",
    QUANTAKRYPTO_MCP_TOKEN: "  secret  ",
    QUANTAKRYPTO_MCP_ALLOW_FS: "1",
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
    { QUANTAKRYPTO_MCP_HOST: "0.0.0.0", QUANTAKRYPTO_MCP_ALLOW_FS: "1" },
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
  const cfg = resolveHttpConfig({ QUANTAKRYPTO_MCP_HOST: "0.0.0.0" });
  const decision = startupDecision(cfg);
  assert.equal(decision.ok, false);
  assert.match(decision.reason ?? "", /token|loopback/i);
});

test("startupDecision allows a non-loopback bind with a token", () => {
  const cfg = resolveHttpConfig({ QUANTAKRYPTO_MCP_HOST: "0.0.0.0", QUANTAKRYPTO_MCP_TOKEN: "t" });
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

/* ------------------ pure: constant-time token compare (M2) ---------------- */

test("timingSafeEqualStr authenticates the correct token and rejects others", () => {
  assert.equal(timingSafeEqualStr("s3cret", "s3cret"), true);
  assert.equal(timingSafeEqualStr("s3cret", "s3cret-wrong"), false);
  assert.equal(timingSafeEqualStr("s3cret", "S3CRET"), false);
  // Different lengths must NOT throw (the hashing equalizes digest length) and
  // must compare unequal — the old early length-return is gone.
  assert.equal(timingSafeEqualStr("short", "a-much-longer-token"), false);
  assert.equal(timingSafeEqualStr("", ""), true);
  assert.equal(timingSafeEqualStr("", "x"), false);
});

test("authorizeRequest stays correct on top of the constant-time compare", () => {
  assert.equal(authorizeRequest("s3cret", "Bearer s3cret").authorized, true);
  // A token that is a prefix of the real one must be rejected.
  assert.equal(authorizeRequest("s3cret", "Bearer s3cre").authorized, false);
  assert.equal(authorizeRequest("s3cret", "Bearer s3cretX").authorized, false);
});

/* -------------------- pure: Origin validation (P0) ------------------------ */

test("originDecision allows requests with no Origin (non-browser clients)", () => {
  const hosts = allowedOriginHosts(resolveHttpConfig({}));
  assert.equal(originDecision(hosts, undefined).ok, true);
  assert.equal(originDecision(hosts, "").ok, true);
});

test("originDecision allows loopback Origins by default", () => {
  const hosts = allowedOriginHosts(resolveHttpConfig({}));
  assert.equal(originDecision(hosts, "http://127.0.0.1:3000").ok, true);
  assert.equal(originDecision(hosts, "http://localhost:8080").ok, true);
});

test("originDecision rejects a foreign Origin (DNS-rebinding / CSRF guard)", () => {
  const hosts = allowedOriginHosts(resolveHttpConfig({}));
  const evil = originDecision(hosts, "http://evil.example.com");
  assert.equal(evil.ok, false);
  assert.match(evil.reason ?? "", /allow-list/i);
  assert.equal(originDecision(hosts, "null").ok, false);
});

test("originDecision honours QUANTAKRYPTO_MCP_ALLOW_ORIGIN", () => {
  const hosts = allowedOriginHosts(
    resolveHttpConfig({ QUANTAKRYPTO_MCP_ALLOW_ORIGIN: "https://app.example.com" }),
  );
  assert.equal(originDecision(hosts, "https://app.example.com").ok, true);
  assert.equal(originDecision(hosts, "https://other.example.com").ok, false);
});

/* --------------------------- pure: gating --------------------------------- */

test("gateHttpTools hides the FS tools by default, keeps knowledge tools", () => {
  const gated = gateHttpTools(quantakryptoTools, false).map((t: ToolDefinition) => t.name);
  for (const fs of FS_TOOL_NAMES) {
    assert.equal(gated.includes(fs), false, `${fs} must be gated off`);
  }
  assert.ok(gated.includes("explain_finding"));
  assert.ok(gated.includes("suggest_hybrid"));
  assert.ok(gated.includes("list_rules"));
});

test("gateHttpTools exposes the FS tools when allowFs is true", () => {
  const gated = gateHttpTools(quantakryptoTools, true).map((t: ToolDefinition) => t.name);
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

test("end-to-end: FS tools appear when QUANTAKRYPTO_MCP_ALLOW_FS=1", async () => {
  const { base, close } = await boot({ QUANTAKRYPTO_MCP_ALLOW_FS: "1" });
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
  const { base, close } = await boot({ QUANTAKRYPTO_MCP_TOKEN: "letmein" });
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
  const { base, close } = await boot({ QUANTAKRYPTO_MCP_TOKEN: "letmein" });
  try {
    const res = await fetch(`${base}/health`);
    assert.equal(res.status, 200);
    const body = (await res.json()) as { status: string };
    assert.equal(body.status, "ok");
  } finally {
    await close();
  }
});

/* ---------------------- end-to-end: Origin (P0) --------------------------- */

test("end-to-end: a foreign Origin is rejected with 403", async () => {
  const { base, close } = await boot({});
  try {
    const res = await rpc(
      base,
      { jsonrpc: "2.0", id: 1, method: "tools/list" },
      { origin: "http://evil.example.com" },
    );
    assert.equal(res.status, 403);
    const body = (await res.json()) as { error?: { message: string } };
    assert.match(body.error?.message ?? "", /origin/i);
  } finally {
    await close();
  }
});

test("end-to-end: a loopback Origin is accepted", async () => {
  const { base, close } = await boot({});
  try {
    const res = await rpc(
      base,
      { jsonrpc: "2.0", id: 1, method: "tools/list" },
      { origin: "http://localhost" },
    );
    assert.equal(res.status, 200);
  } finally {
    await close();
  }
});

/* -------------------- end-to-end: body errors (M1) ------------------------ */

test("end-to-end: an oversized body is 413, a malformed body is 400", async () => {
  const { base, close } = await boot({});
  try {
    // > 1 MiB body → BodyTooLargeError → 413.
    const huge = "x".repeat(1024 * 1024 + 16);
    const tooBig = await fetch(`${base}/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: huge,
    });
    assert.equal(tooBig.status, 413);
    const bigBody = (await tooBig.json()) as { error?: { message: string } };
    assert.match(bigBody.error?.message ?? "", /too large/i);

    // Well-formed transport, invalid JSON → 400 (a parse error, not a 413).
    const bad = await fetch(`${base}/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{ not json",
    });
    assert.equal(bad.status, 400);
  } finally {
    await close();
  }
});

/* ---------- end-to-end: timeout aborts the underlying work (P0) ----------- */

/** Boot an HTTP server wrapping a custom McpServer, on an ephemeral port. */
async function bootServer(
  mcp: McpServer,
  envOverrides: Record<string, string | undefined> = {},
): Promise<{ base: string; close: () => Promise<void> }> {
  const cfg = resolveHttpConfig({ ...envOverrides, PORT: undefined });
  const server = createHttpServer(mcp, cfg);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return {
    base: `http://127.0.0.1:${port}`,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

test("end-to-end: a timed-out request returns 504 AND aborts the in-flight work", async () => {
  // A tool that hangs until its abort signal fires, recording that it was
  // aborted. This proves the timeout doesn't just 504 the client while the work
  // keeps running in the background — the signal is threaded through and fires.
  let aborted = false;
  const slowTool: ToolDefinition = {
    name: "slow",
    description: "blocks until aborted",
    inputSchema: { type: "object", additionalProperties: false },
    handler: (_args: Record<string, unknown>, context?: ToolContext) =>
      new Promise((resolve) => {
        const signal = context?.signal;
        if (!signal) {
          resolve({ content: [{ type: "text", text: "no signal" }] });
          return;
        }
        signal.addEventListener("abort", () => {
          aborted = true;
          resolve({ content: [{ type: "text", text: "aborted" }], isError: true });
        });
      }),
  };
  const mcp = new McpServer({ info: { name: "test", version: "0" } });
  mcp.registerTool(slowTool);

  const { base, close } = await bootServer(mcp, { QUANTAKRYPTO_MCP_TIMEOUT_MS: "50" });
  try {
    const res = await rpc(base, {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: "slow", arguments: {} },
    });
    assert.equal(res.status, 504);
    const body = (await res.json()) as { error?: { message: string } };
    // The message is generic — no internal detail leaked.
    assert.equal(body.error?.message, "request timed out");
    // Give the abort listener a tick to run, then confirm the work was cancelled.
    await new Promise((r) => setTimeout(r, 20));
    assert.equal(aborted, true, "the in-flight scan must be aborted, not leaked");
  } finally {
    await close();
  }
});

/* ------------- end-to-end: server errors are sanitized (P0) --------------- */

test("end-to-end: an internal tool throw is sanitized for the remote caller", async () => {
  const boomTool: ToolDefinition = {
    name: "boom",
    description: "throws with a server path in the message",
    inputSchema: { type: "object", additionalProperties: false },
    handler: () => {
      throw new Error("ENOENT: no such file or directory, open '/etc/shadow'");
    },
  };
  const mcp = new McpServer({ info: { name: "test", version: "0" } });
  mcp.registerTool(boomTool);

  const { base, close } = await bootServer(mcp);
  try {
    const res = await rpc(base, {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: "boom", arguments: {} },
    });
    const body = (await res.json()) as { error?: { message: string } };
    // The raw ENOENT/path must not reach the client; a generic message is used.
    assert.equal(body.error?.message, "internal error");
    assert.doesNotMatch(JSON.stringify(body), /\/etc\/shadow/);
  } finally {
    await close();
  }
});
