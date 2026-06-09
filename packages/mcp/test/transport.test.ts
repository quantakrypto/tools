/**
 * Transport-helper tests.
 *
 * The stdio loop is tested by feeding it in-memory streams (no child process),
 * verifying newline-delimited JSON framing and that notifications get no reply.
 * The algorithm normalizer is unit-tested directly via the `__test` export.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { PassThrough } from "node:stream";

import { createQproofServer } from "../src/index.js";
import { runStdioServer } from "../src/stdio.js";
import { __test } from "../src/tools.js";

const { normalizeAlgorithm } = __test;

test("normalizeAlgorithm maps aliases onto canonical families", () => {
  assert.equal(normalizeAlgorithm("rsa-2048"), "RSA");
  assert.equal(normalizeAlgorithm("RSA"), "RSA");
  assert.equal(normalizeAlgorithm("ecdsa"), "ECDSA");
  assert.equal(normalizeAlgorithm("Ed25519"), "EdDSA");
  assert.equal(normalizeAlgorithm("x25519"), "X25519");
  assert.equal(normalizeAlgorithm("Diffie-Hellman"), "DH");
  assert.equal(normalizeAlgorithm("totally-made-up"), "unknown");
});

test("stdio loop frames responses as newline-delimited JSON", async () => {
  const server = createQproofServer();
  const input = new PassThrough();
  const output = new PassThrough();

  const collected: string[] = [];
  output.setEncoding("utf8");
  output.on("data", (chunk: string) => collected.push(chunk));

  runStdioServer(server, input, output);

  // Two requests on two lines, plus one notification (should yield no output).
  input.write(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }) + "\n");
  input.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");
  input.write(JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" }) + "\n");
  input.end();

  // Let the async handlers flush.
  await new Promise((resolve) => setTimeout(resolve, 50));

  const lines = collected.join("").trim().split("\n").filter(Boolean);
  assert.equal(lines.length, 2, "expected exactly two responses (notification has none)");

  const first = JSON.parse(lines[0]) as { id: number; result: unknown };
  assert.equal(first.id, 1);
  assert.deepEqual(first.result, {});

  const second = JSON.parse(lines[1]) as { id: number; result: { tools: unknown[] } };
  assert.equal(second.id, 2);
  assert.ok(Array.isArray(second.result.tools));
  assert.equal(second.result.tools.length, 6);
});

test("stdio loop replies with a parse error on malformed JSON", async () => {
  const server = createQproofServer();
  const input = new PassThrough();
  const output = new PassThrough();
  const collected: string[] = [];
  output.setEncoding("utf8");
  output.on("data", (chunk: string) => collected.push(chunk));

  runStdioServer(server, input, output);
  input.write("{ this is not json }\n");
  input.end();

  await new Promise((resolve) => setTimeout(resolve, 50));
  const line = collected.join("").trim();
  const parsed = JSON.parse(line) as { error: { code: number } };
  assert.equal(parsed.error.code, -32700);
});
