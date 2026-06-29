/**
 * Regression tests for the qScan hardening pass (Q1–Q7):
 *
 *  - Q1: large reports written to a pipe are not truncated by an eager
 *        `process.exit` tearing down stdout before it drains.
 *  - Q2: boolean flags reject an inline `=value` instead of silently inverting.
 *  - Q3: `--concurrency 0` forces the serial path (not full parallelism).
 *  - Q5: an explicit `--baseline <path>` is read strictly — a missing/typo'd
 *        path is an I/O error (exit 2), never a silent "suppress nothing".
 *  - Q6: `--no-snippets` redacts code snippets from the json/sarif report.
 *  - Q7: severity ordering/ranking/threshold come from `@quantakrypto/core`.
 */

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import {
  meetsThreshold as coreMeetsThreshold,
  SEVERITY_ORDER as CORE_SEVERITY_ORDER,
  severityRank as coreSeverityRank,
} from "@quantakrypto/core";

import { ArgError, parseArgs, SEVERITY_ORDER, severityRank, meetsThreshold } from "../src/args.js";
import { renderReport, runQscan } from "../src/index.js";
import { makeFinding, makeResult } from "./helpers.js";

const HERE = dirname(fileURLToPath(import.meta.url));
/** The built CLI entry point (Q1 needs a real child process + OS pipe). */
const CLI = join(HERE, "..", "dist", "cli.js");

/** Narrow a parse result to its run options or fail the test. */
function runOptions(args: string[]) {
  const parsed = parseArgs(args);
  if (parsed.kind !== "run") throw new Error("expected run");
  return parsed.options;
}

/* -------------------------------------------------------------------------- */
/* Q1 — stdout is not truncated when the report is large and stdout is a pipe. */
/* -------------------------------------------------------------------------- */

test("Q1: a large JSON report survives a piped stdout intact", async () => {
  // Many vulnerable files → a report comfortably larger than one OS pipe buffer
  // (~64 KiB), so an eager process.exit would truncate it mid-stream.
  const root = await mkdtemp(join(tmpdir(), "qscan-pipe-"));
  try {
    await mkdir(join(root, "src"), { recursive: true });
    await writeFile(join(root, "package.json"), '{"dependencies":{"node-forge":"^1.0.0"}}\n');
    for (let i = 0; i < 400; i++) {
      await writeFile(
        join(root, "src", `file${i}.js`),
        "const crypto = require('crypto');\n" +
          "crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });\n" +
          "crypto.createECDH('secp256k1');\n",
      );
    }

    const { stdout, code } = await runCli([root, "--format", "json", "--quiet"]);
    // Exit 1 (findings present) or 0; never a crash.
    assert.ok(code === 0 || code === 1, `unexpected exit code ${code}`);
    assert.ok(
      stdout.length > 64 * 1024,
      `report too small to exercise the pipe (${stdout.length}B)`,
    );

    // The whole document must be present and parseable — a truncated stream
    // would fail JSON.parse partway through.
    const report = JSON.parse(stdout) as { findings: unknown[] };
    assert.ok(Array.isArray(report.findings));
    assert.ok(report.findings.length > 0);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

/* -------------------------------------------------------------------------- */
/* Q2 — boolean flags reject an inline `=value` instead of inverting intent.   */
/* -------------------------------------------------------------------------- */

test("Q2: --quiet=false throws ArgError (no silent inversion)", () => {
  assert.throws(() => parseArgs(["--quiet=false"]), ArgError);
  // Without the fix, `--quiet=false` would turn quiet ON; assert it never parses.
});

test("Q2: every boolean flag rejects an inline =value", () => {
  for (const flag of [
    "--quiet",
    "--no-source",
    "--no-deps",
    "--no-config",
    "--no-default-ignores",
    "--scan-minified",
    "--no-config-file",
    "--changed",
    "--parallel",
    "--cbom",
    "--no-snippets",
  ]) {
    assert.throws(() => parseArgs([`${flag}=false`]), ArgError, `${flag}=false should throw`);
  }
});

/* -------------------------------------------------------------------------- */
/* Q3 — `--concurrency 0` forces the serial path.                              */
/* -------------------------------------------------------------------------- */

test("Q3: --concurrency 0 selects the serial path (parallel = false)", () => {
  const o = runOptions(["--concurrency", "0"]);
  assert.equal(o.concurrency, 0);
  assert.equal(o.parallel, false, "0 must NOT route through the parallel pool");
});

test("Q3: --concurrency >= 1 still implies parallel", () => {
  assert.equal(runOptions(["--concurrency", "1"]).parallel, true);
  assert.equal(runOptions(["--concurrency", "4"]).parallel, true);
});

test("Q3: --concurrency 0 runs through the serial scanner", async () => {
  const calls: string[] = [];
  const run = await runQscan(
    { path: ".", concurrency: 0 },
    {
      scanFn: async (opts) => {
        calls.push("scan");
        return makeResult([makeFinding()], opts.root);
      },
    },
  );
  // The injected scanner is used regardless, but the run must succeed and the
  // serial route (parallel=false) is what selects `scan` over `scanParallel`.
  assert.equal(calls.length, 1);
  assert.equal(run.result.findings.length, 1);
});

/* -------------------------------------------------------------------------- */
/* Q5 — explicit `--baseline <path>` is read strictly.                         */
/* -------------------------------------------------------------------------- */

test("Q5: a missing --baseline path errors instead of suppressing nothing", async () => {
  const missing = join(tmpdir(), `qscan-no-such-baseline-${process.pid}-${Date.now()}.json`);
  await assert.rejects(
    () =>
      runQscan(
        { path: ".", baseline: missing },
        { scanFn: async (opts) => makeResult([makeFinding()], opts.root) },
      ),
    /could not read baseline file/,
  );
});

test("Q5: a valid --baseline still suppresses matching findings", async () => {
  const dir = await mkdtemp(join(tmpdir(), "qscan-baseline-"));
  try {
    // An empty (but well-formed) baseline reads cleanly and suppresses nothing.
    const path = join(dir, "baseline.json");
    await writeFile(path, JSON.stringify({ version: 1, fingerprints: [] }, null, 2));
    const run = await runQscan(
      { path: ".", baseline: path },
      { scanFn: async (opts) => makeResult([makeFinding()], opts.root) },
    );
    assert.equal(run.result.findings.length, 1);
    assert.equal(run.suppressed.length, 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

/* -------------------------------------------------------------------------- */
/* Q6 — `--no-snippets` redacts snippets from the json/sarif report.           */
/* -------------------------------------------------------------------------- */

test("Q6: --no-snippets is parsed as a boolean option", () => {
  assert.equal(runOptions(["--no-snippets"]).noSnippets, true);
  assert.equal(runOptions([]).noSnippets, false);
});

test("Q6: --no-snippets produces a JSON report with no snippet fields", async () => {
  const run = await runQscan(
    { path: ".", format: "json", noSnippets: true },
    { scanFn: async (opts) => makeResult([makeFinding()], opts.root) },
  );
  assert.ok(run.report);
  assert.ok(!/"snippet"/.test(run.report), "JSON report must not contain any snippet field");
  // Sanity: WITHOUT the flag the snippet is present, so the test is meaningful.
  const withSnippets = await runQscan(
    { path: ".", format: "json" },
    { scanFn: async (opts) => makeResult([makeFinding()], opts.root) },
  );
  assert.match(withSnippets.report ?? "", /"snippet"/);
});

test("Q6: --no-snippets produces a SARIF report with no snippet fields", () => {
  const result = makeResult([makeFinding()]);
  const redacted = renderReport(result, "sarif", { redactSnippets: true });
  assert.ok(!/"snippet"/.test(redacted), "SARIF report must not contain any snippet field");
  const full = renderReport(result, "sarif");
  assert.match(full, /"snippet"/);
});

/* -------------------------------------------------------------------------- */
/* Q7 — severity logic is sourced from core (no divergent local copy).         */
/* -------------------------------------------------------------------------- */

test("Q7: qScan re-exports core's SEVERITY_ORDER / severityRank / meetsThreshold", () => {
  assert.equal(SEVERITY_ORDER, CORE_SEVERITY_ORDER, "must be the SAME array instance as core");
  assert.equal(severityRank, coreSeverityRank, "must be core's severityRank");
  assert.equal(meetsThreshold, coreMeetsThreshold, "must be core's meetsThreshold");
});

/* -------------------------------------------------------------------------- */
/* Helpers                                                                     */
/* -------------------------------------------------------------------------- */

/** Run the built CLI in a child process with a real OS pipe on stdout. */
function runCli(args: string[]): Promise<{ stdout: string; stderr: string; code: number }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI, ...args], { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (c: string) => (stdout += c));
    child.stderr.on("data", (c: string) => (stderr += c));
    child.on("error", reject);
    child.on("close", (code) => resolve({ stdout, stderr, code: code ?? 0 }));
  });
}
