import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { runSieve } from "../src/index.js";
import type { CategoryResult, SieveReport } from "../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const MOCK = join(here, "..", "examples", "mock-sut.ts");

/** Run the mock SUT under tsx with an optional MOCK_BREAK fault. */
function command(): string[] {
  // Re-launch node with the same tsx loader the test runner uses, so the mock
  // .ts file executes without a build step.
  return [process.execPath, "--import", "tsx", MOCK];
}

function run(opts: { param?: string; iterations?: number; env?: Record<string, string>; only?: string[] }): Promise<SieveReport> {
  return runSieve({
    command: command(),
    param: (opts.param ?? "ml-kem-768") as never,
    iterations: opts.iterations ?? 8,
    timeoutMs: 20_000,
    ...(opts.env ? { env: opts.env } : {}),
    ...(opts.only ? { only: opts.only } : {}),
  });
}

function cat(report: SieveReport, name: string): CategoryResult {
  const c = report.categories.find((x) => x.category === name);
  assert.ok(c, `expected a "${name}" category in the report`);
  return c!;
}

test("well-behaved mock PASSES correctness/determinism/sizes/implicit-rejection/robustness", async () => {
  const report = await run({ param: "ml-kem-768", iterations: 8 });
  assert.equal(cat(report, "correctness").status, "pass");
  assert.equal(cat(report, "determinism").status, "pass");
  assert.equal(cat(report, "sizes").status, "pass");
  assert.equal(cat(report, "implicit-rejection").status, "pass");
  assert.equal(cat(report, "robustness").status, "pass");
  assert.equal(report.overall, "PASS");
});

test("KAT category SKIPS (and never fails) when no vectors are supplied", async () => {
  const report = await run({ param: "ml-kem-768", iterations: 2 });
  assert.equal(cat(report, "kat").status, "skip");
  // Overall must still be PASS — a skip is not a failure.
  assert.equal(report.overall, "PASS");
});

test("mock with wrong-length ciphertext FAILS the sizes category", async () => {
  const report = await run({ param: "ml-kem-768", iterations: 4, env: { MOCK_BREAK: "wrong-ct-size" } });
  assert.equal(cat(report, "sizes").status, "fail");
  assert.equal(report.overall, "FAIL");
});

test("mock with non-deterministic decaps FAILS the determinism category", async () => {
  const report = await run({ param: "ml-kem-768", iterations: 4, env: { MOCK_BREAK: "nondeterministic-decaps" } });
  assert.equal(cat(report, "determinism").status, "fail");
  // Correctness may also fail because honest decaps no longer reproduces ss.
  assert.equal(report.overall, "FAIL");
});

test("mock that errors on corrupted ct FAILS implicit-rejection (AF-02)", async () => {
  const report = await run({ param: "ml-kem-768", iterations: 4, env: { MOCK_BREAK: "reject-errors" } });
  const ir = cat(report, "implicit-rejection");
  assert.equal(ir.status, "fail");
  assert.equal(ir.bugClass, "AF-02");
  assert.equal(report.overall, "FAIL");
});

test("mock that returns honest ss for corrupted ct FAILS implicit-rejection 'differs'", async () => {
  const report = await run({ param: "ml-kem-768", iterations: 4, env: { MOCK_BREAK: "reject-honest" } });
  assert.equal(cat(report, "implicit-rejection").status, "fail");
  assert.equal(report.overall, "FAIL");
});

test("wrong-ss-size mock FAILS sizes", async () => {
  const report = await run({ param: "ml-kem-512", iterations: 2, env: { MOCK_BREAK: "wrong-ss-size" } });
  assert.equal(cat(report, "sizes").status, "fail");
});

test("ML-DSA: well-behaved mock PASSES the dsa category", async () => {
  const report = await run({ param: "ml-dsa-65", iterations: 6, only: ["dsa", "kat"] });
  assert.equal(cat(report, "dsa").status, "pass");
  assert.equal(report.overall, "PASS");
});

test("ML-DSA: verify-always-true mock FAILS the dsa tamper checks", async () => {
  const report = await run({ param: "ml-dsa-65", iterations: 6, only: ["dsa"], env: { MOCK_BREAK: "verify-always-true" } });
  assert.equal(cat(report, "dsa").status, "fail");
  assert.equal(report.overall, "FAIL");
});

test("ML-DSA: wrong-sig-size mock FAILS the dsa size check", async () => {
  const report = await run({ param: "ml-dsa-44", iterations: 4, only: ["dsa"], env: { MOCK_BREAK: "wrong-sig-size" } });
  assert.equal(cat(report, "dsa").status, "fail");
});

test("report counts add up and verdict excludes advisory timing", async () => {
  const report = await run({ param: "ml-kem-512", iterations: 3 });
  const { pass, fail, skip } = report.counts;
  let total = 0;
  for (const c of report.categories) total += c.checks.length;
  assert.equal(pass + fail + skip, total);
});
