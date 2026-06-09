/**
 * P0-3: the runner must spawn the SUT with a SCRUBBED, minimal environment by
 * default — not the full parent env — so an untrusted SUT cannot read harness
 * secrets. These tests cover buildSutEnv directly (pure, no spawn) and an
 * end-to-end check that a secret in the parent env does NOT reach the SUT.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { join } from "node:path";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";

import { buildSutEnv, DEFAULT_ENV_ALLOWLIST, Runner } from "../src/runner.js";

test("buildSutEnv scrubs secrets by default, keeping only the allow-list", () => {
  const parent = {
    PATH: "/usr/bin",
    HOME: "/home/u",
    GITHUB_TOKEN: "ghp_supersecret",
    NPM_TOKEN: "npm_secret",
    AWS_SECRET_ACCESS_KEY: "aws_secret",
  } as NodeJS.ProcessEnv;

  const env = buildSutEnv({}, parent);
  assert.equal(env["PATH"], "/usr/bin");
  assert.equal(env["HOME"], "/home/u");
  assert.equal(env["GITHUB_TOKEN"], undefined, "secret must not be forwarded");
  assert.equal(env["NPM_TOKEN"], undefined);
  assert.equal(env["AWS_SECRET_ACCESS_KEY"], undefined);
  // Every key present must be in the allow-list.
  for (const k of Object.keys(env)) {
    assert.ok(DEFAULT_ENV_ALLOWLIST.includes(k), `unexpected env key leaked: ${k}`);
  }
});

test("buildSutEnv honours explicit extra env and envAllowlist, never aliases parent", () => {
  const parent = { PATH: "/bin", MY_VAR: "from-parent", SECRET: "x" } as NodeJS.ProcessEnv;
  const env = buildSutEnv({ env: { EXPLICIT: "yes" }, envAllowlist: ["MY_VAR"] }, parent);
  assert.equal(env["EXPLICIT"], "yes");
  assert.equal(env["MY_VAR"], "from-parent", "allow-listed name should be copied");
  assert.equal(env["SECRET"], undefined, "non-allow-listed secret stays out");
  // Mutating the result must not touch the parent.
  env["PATH"] = "tampered";
  assert.equal(parent["PATH"], "/bin");
});

test("buildSutEnv inheritEnv passes the full parent env (opt-in)", () => {
  const parent = { PATH: "/bin", SECRET: "leak" } as NodeJS.ProcessEnv;
  const env = buildSutEnv({ inheritEnv: true }, parent);
  assert.equal(env["SECRET"], "leak");
  assert.equal(env["PATH"], "/bin");
});

test("explicit env overrides an inherited value", () => {
  const parent = { PATH: "/bin", FOO: "parent" } as NodeJS.ProcessEnv;
  const env = buildSutEnv({ inheritEnv: true, env: { FOO: "override" } }, parent);
  assert.equal(env["FOO"], "override");
});

/**
 * End-to-end: set a fake secret in THIS process's env, spawn a tiny echo SUT
 * that reports whether it can see that secret, and assert it cannot under the
 * default scrubbed env but can under inheritEnv.
 */
test("a parent-env secret does not reach the spawned SUT by default", async () => {
  const probe = join(
    mkdtempSync(join(tmpdir(), "sieve-envprobe-")),
    "probe.mjs",
  );
  // The probe answers one request: it echoes whether SIEVE_FAKE_SECRET is set.
  writeFileSync(
    probe,
    [
      "import { createInterface } from 'node:readline';",
      "const rl = createInterface({ input: process.stdin });",
      "rl.on('line', (line) => {",
      "  if (!line.trim()) return;",
      "  const r = JSON.parse(line);",
      "  const sawSecret = process.env.SIEVE_FAKE_SECRET !== undefined;",
      "  process.stdout.write(JSON.stringify({ id: r.id, ok: true, ss: Buffer.from([sawSecret?1:0]).toString('base64') }) + '\\n');",
      "});",
    ].join("\n"),
  );

  process.env["SIEVE_FAKE_SECRET"] = "top-secret-" + Math.random();
  try {
    // Default: scrubbed env — the SUT must NOT see the secret.
    const scrubbed = new Runner({ command: [process.execPath, probe], timeoutMs: 10_000 });
    const r1 = await scrubbed.send({ family: "ml-kem", param: "ml-kem-512", op: "decaps", sk: "", ct: "" });
    await scrubbed.close();
    assert.equal(r1.ok, true);
    assert.ok("ss" in r1 && r1.ss === Buffer.from([0]).toString("base64"), "SUT saw a scrubbed env");

    // Opt-in inheritEnv: the SUT now sees it.
    const inherited = new Runner({ command: [process.execPath, probe], inheritEnv: true, timeoutMs: 10_000 });
    const r2 = await inherited.send({ family: "ml-kem", param: "ml-kem-512", op: "decaps", sk: "", ct: "" });
    await inherited.close();
    assert.ok("ss" in r2 && r2.ss === Buffer.from([1]).toString("base64"), "inheritEnv should pass the secret");
  } finally {
    delete process.env["SIEVE_FAKE_SECRET"];
  }
});
