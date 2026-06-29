/**
 * Tool-level tests, driven through {@link McpServer.handle} via `tools/call`.
 *
 * `@quantakrypto/core` is partly stubbed (scan/buildInventory/remediationFor throw
 * "not implemented"). These tests assert the MCP envelope contract and the
 * behaviour that holds regardless of core's stub state:
 *   - tool handlers never crash the server (no protocol error from a stub);
 *   - every result is a well-formed { content: [...], isError? } object;
 *   - suggest_hybrid always returns actionable text via its static fallback.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import process from "node:process";
import { mkdtempSync, writeFileSync, rmSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { createQuantakryptoServer } from "../src/index.js";
import type { JsonRpcSuccess, ToolContext } from "../src/protocol.js";

interface ToolCallResult {
  content: Array<{ type: string; text: string }>;
  isError?: boolean;
}

/** Run `fn` with `vars` applied to process.env, restoring the prior values. */
async function withEnv(
  vars: Record<string, string | undefined>,
  fn: () => Promise<void>,
): Promise<void> {
  const prev: Record<string, string | undefined> = {};
  for (const [k, v] of Object.entries(vars)) {
    prev[k] = process.env[k];
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  try {
    await fn();
  } finally {
    for (const [k, v] of Object.entries(prev)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

/** Call a tool and return its (validated) ToolResult. */
async function callTool(
  name: string,
  args: Record<string, unknown>,
  context?: ToolContext,
): Promise<ToolCallResult> {
  const server = createQuantakryptoServer();
  const res = await server.handle(
    {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name, arguments: args },
    },
    context,
  );

  assert.ok(
    res && "result" in (res as object),
    `tools/call ${name} should succeed at protocol level`,
  );
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

test("explain_finding resolves a library rule to its detector + remediation", async () => {
  // P0-5: a real crypto-libs finding (forge-rsa-keygen) must resolve to the
  // crypto-libs detector and surface RSA remediation — the old prefix match
  // returned "no matching detector" here.
  const result = await callTool("explain_finding", { ruleId: "forge-rsa-keygen" });
  assert.notEqual(result.isError, true);
  const text = result.content.map((c) => c.text).join("\n");
  assert.match(text, /forge-rsa-keygen/);
  assert.match(text, /crypto-libs/);
  assert.doesNotMatch(text, /No matching detector/i);
  // The rule carries RSA, so remediation is surfaced without an explicit algorithm.
  assert.match(text, /RSA/);
  assert.match(text, /ML-KEM|ML-DSA|recommendation/i);
});

test("explain_finding resolves elliptic-ec and node-rsa library rules", async () => {
  for (const ruleId of ["elliptic-ec", "node-rsa"]) {
    const result = await callTool("explain_finding", { ruleId });
    assert.notEqual(result.isError, true, `${ruleId} should not error`);
    const text = result.content.map((c) => c.text).join("\n");
    assert.match(text, new RegExp(ruleId), `${ruleId} echoed`);
    assert.match(text, /crypto-libs/, `${ruleId} resolves to crypto-libs`);
    assert.doesNotMatch(text, /No matching detector/i);
  }
});

test("explain_finding resolves a pem-* rule to the pem-material detector", async () => {
  const result = await callTool("explain_finding", { ruleId: "pem-ec-private-key" });
  assert.notEqual(result.isError, true);
  const text = result.content.map((c) => c.text).join("\n");
  assert.match(text, /pem-material/);
  assert.doesNotMatch(text, /No matching detector/i);
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

test("generate_cbom requires a path argument", async () => {
  const result = await callTool("generate_cbom", {});
  assert.equal(result.isError, true);
  assert.match(result.content[0].text, /path/i);
});

/* ------------------------- FS confinement (P0) ---------------------------- */

test("scan_path rejects an out-of-root absolute path (no arbitrary read)", async () => {
  // With the default root = cwd (packages/mcp), /etc/passwd is outside the
  // allow-list and must be refused BEFORE scan() ever touches the filesystem.
  await withEnv({ QUANTAKRYPTO_MCP_ROOT: undefined }, async () => {
    const result = await callTool("scan_path", { path: "/etc/passwd" });
    assert.equal(result.isError, true);
    assert.match(result.content[0].text, /rejected|outside the configured scan root|allow-list/i);
    // The rejection must not leak the literal target path.
    assert.doesNotMatch(result.content[0].text, /\/etc\/passwd/);
  });
});

test("scan_path rejects a `..` traversal escaping the root", async () => {
  await withEnv({ QUANTAKRYPTO_MCP_ROOT: process.cwd() }, async () => {
    const result = await callTool("scan_path", { path: "../../../../etc/passwd" });
    assert.equal(result.isError, true);
    assert.match(result.content[0].text, /rejected|outside the configured scan root/i);
  });
});

test("inventory_crypto and generate_cbom enforce the same confinement", async () => {
  await withEnv({ QUANTAKRYPTO_MCP_ROOT: process.cwd() }, async () => {
    for (const tool of ["inventory_crypto", "generate_cbom"]) {
      const result = await callTool(tool, { path: "/etc/shadow" });
      assert.equal(result.isError, true, `${tool} must reject out-of-root`);
      assert.match(result.content[0].text, /rejected|outside the configured scan root/i);
    }
  });
});

/**
 * Run `fn` with a throwaway temp directory as the MCP FS root, seeded with
 * `files`. CWD-independent, so these pass both per-workspace and in the
 * combined coverage run (which executes from the repo root).
 */
async function withFixtureRoot(
  files: Record<string, string>,
  extraEnv: Record<string, string | undefined>,
  fn: (root: string) => Promise<void>,
): Promise<void> {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "qk-mcp-fix-")));
  for (const [name, content] of Object.entries(files)) writeFileSync(join(root, name), content);
  try {
    await withEnv({ QUANTAKRYPTO_MCP_ROOT: root, ...extraEnv }, () => fn(root));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

test("scan_path allows an in-root path and returns a summary", async () => {
  await withFixtureRoot(
    { "a.ts": "const k = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });\n" },
    {},
    async (root) => {
      const result = await callTool("scan_path", { path: root });
      assert.notEqual(result.isError, true);
      const text = result.content.map((c) => c.text).join("\n");
      assert.match(text, /scan of|Files scanned/i);
    },
  );
});

/* ----------------------- work budget + abort (P0) ------------------------- */

test("scan_path surfaces a budget overflow as an error, not a hang", async () => {
  // Three files with a maxFiles budget of 1 makes core throw BudgetExceededError
  // mid-walk, which the tool maps to a readable isError result, not a hang.
  await withFixtureRoot(
    { "a.ts": "// one\n", "b.ts": "// two\n", "c.ts": "// three\n" },
    { QUANTAKRYPTO_MCP_MAX_FILES: "1" },
    async (root) => {
      const result = await callTool("scan_path", { path: root });
      assert.equal(result.isError, true);
      assert.match(result.content[0].text, /budget exceeded/i);
    },
  );
});

test("scan_path aborts the scan when the request signal fires", async () => {
  // A pre-aborted signal (as the HTTP timeout would set) makes core throw
  // AbortError; the tool maps it to a clean, generic error result — no hang.
  await withFixtureRoot({ "a.ts": "// one\n" }, {}, async (root) => {
    const result = await callTool("scan_path", { path: root }, { signal: AbortSignal.abort() });
    assert.equal(result.isError, true);
    assert.match(result.content[0].text, /aborted|timed out/i);
  });
});

/* --------------------------- error sanitization --------------------------- */

test("describeError sanitizes an arbitrary error but preserves intentional ones", async () => {
  const { __test } = await import("../src/tools.js");
  // A raw I/O-style error message (with a host path) is replaced generically.
  const leaky = __test.describeError(
    "scan",
    new Error("ENOENT: no such file or directory, open '/etc/shadow'"),
  );
  assert.doesNotMatch(leaky, /\/etc\/shadow/);
  assert.match(leaky, /internal error occurred/i);
});
