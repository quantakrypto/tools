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

function run(opts: {
  param?: string;
  iterations?: number;
  env?: Record<string, string>;
  only?: string[];
  pipelineDepth?: number;
}): Promise<SieveReport> {
  return runSieve({
    command: command(),
    param: (opts.param ?? "ml-kem-768") as never,
    iterations: opts.iterations ?? 8,
    timeoutMs: 20_000,
    ...(opts.env ? { env: opts.env } : {}),
    ...(opts.only ? { only: opts.only } : {}),
    ...(opts.pipelineDepth !== undefined ? { pipelineDepth: opts.pipelineDepth } : {}),
  });
}

function check(c: CategoryResult, name: string) {
  const chk = c.checks.find((x) => x.name === name);
  assert.ok(chk, `expected a "${name}" check in category "${c.category}"`);
  return chk!;
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

// --- P1-7: FIPS 203 §7.2 ek modulus-range check (AF-05 deepening) ----------

test("well-behaved mock PASSES the ek modulus-range check", async () => {
  const report = await run({ param: "ml-kem-768", iterations: 4, only: ["sizes"] });
  const sizesCat = cat(report, "sizes");
  assert.equal(check(sizesCat, "encaps-ek-coeff-out-of-range").status, "pass");
  assert.equal(sizesCat.status, "pass");
});

test("mock that accepts an out-of-range ek FAILS the ek modulus-range check (AF-05)", async () => {
  const report = await run({
    param: "ml-kem-768",
    iterations: 4,
    only: ["sizes"],
    env: { MOCK_BREAK: "accept-out-of-range-ek" },
  });
  const sizesCat = cat(report, "sizes");
  const ekCheck = check(sizesCat, "encaps-ek-coeff-out-of-range");
  assert.equal(ekCheck.status, "fail");
  assert.equal(ekCheck.bugClass, "AF-05");
  assert.equal(sizesCat.status, "fail");
  assert.equal(report.overall, "FAIL");
});

// --- P1-7: deterministic-vs-hedged signing advisory ------------------------

test("ML-DSA signing-mode advisory reports HEDGED for the randomized mock (never fails)", async () => {
  const report = await run({ param: "ml-dsa-65", iterations: 4, only: ["dsa"] });
  const dsaCat = cat(report, "dsa");
  const mode = check(dsaCat, "signing-mode");
  assert.equal(mode.status, "skip", "advisory must not affect the verdict");
  assert.match(mode.detail, /HEDGED/);
  assert.equal(dsaCat.status, "pass");
});

test("ML-DSA signing-mode advisory reports DETERMINISTIC when the mock signs deterministically", async () => {
  const report = await run({
    param: "ml-dsa-65",
    iterations: 4,
    only: ["dsa"],
    env: { MOCK_BREAK: "deterministic-sign" },
  });
  const dsaCat = cat(report, "dsa");
  const mode = check(dsaCat, "signing-mode");
  assert.equal(mode.status, "skip");
  assert.match(mode.detail, /DETERMINISTIC/);
  // Both signatures still verify, so the category still passes.
  assert.equal(dsaCat.status, "pass");
});

// --- P2-8: SLH-DSA (FIPS 205) support --------------------------------------

test("SLH-DSA: well-behaved mock PASSES the slh-dsa category (sha2-128f)", async () => {
  const report = await runSieve({
    command: command(),
    param: "slh-dsa-sha2-128f",
    iterations: 4,
    timeoutMs: 30_000,
    only: ["slh-dsa", "kat"],
  });
  assert.equal(cat(report, "slh-dsa").status, "pass");
  assert.equal(report.overall, "PASS");
});

test("SLH-DSA: size conformance holds across a shake variant (shake-192s)", async () => {
  const report = await runSieve({
    command: command(),
    param: "slh-dsa-shake-192s",
    iterations: 2,
    timeoutMs: 60_000,
    only: ["slh-dsa"],
  });
  const c = cat(report, "slh-dsa");
  assert.equal(check(c, "pk-length").status, "pass");
  assert.equal(check(c, "sk-length").status, "pass");
  assert.equal(c.status, "pass");
});

test("SLH-DSA: verify-always-true mock FAILS the slh-dsa tamper checks", async () => {
  const report = await runSieve({
    command: command(),
    param: "slh-dsa-sha2-128f",
    iterations: 4,
    timeoutMs: 30_000,
    only: ["slh-dsa"],
    env: { MOCK_BREAK: "verify-always-true" },
  });
  assert.equal(cat(report, "slh-dsa").status, "fail");
  assert.equal(report.overall, "FAIL");
});

test("SLH-DSA: wrong-sig-size mock FAILS the slh-dsa size check", async () => {
  const report = await runSieve({
    command: command(),
    param: "slh-dsa-sha2-128f",
    iterations: 4,
    timeoutMs: 30_000,
    only: ["slh-dsa"],
    env: { MOCK_BREAK: "wrong-sig-size" },
  });
  assert.equal(cat(report, "slh-dsa").status, "fail");
});

// --- P2-3: bounded-concurrency pipelining ----------------------------------

test("pipelined and serial runs reach the same verdict (correctness/determinism)", async () => {
  const serial = await run({ param: "ml-kem-768", iterations: 12, pipelineDepth: 1 });
  const pipelined = await run({ param: "ml-kem-768", iterations: 12, pipelineDepth: 8 });
  assert.equal(serial.overall, "PASS");
  assert.equal(pipelined.overall, "PASS");
  assert.equal(cat(serial, "correctness").status, cat(pipelined, "correctness").status);
  assert.equal(cat(serial, "determinism").status, cat(pipelined, "determinism").status);
});

test("Runner.sendMany preserves request order and bounds concurrency", async () => {
  const { Runner } = await import("../src/index.js");
  const runner = new Runner({ command: command(), timeoutMs: 20_000 });
  try {
    // Issue many independent keygens; results must come back in request order.
    const reqs = Array.from({ length: 20 }, () => ({
      family: "ml-kem" as const,
      param: "ml-kem-512" as const,
      op: "keygen" as const,
    }));
    const responses = await runner.sendMany(reqs, 5);
    assert.equal(responses.length, 20);
    for (const r of responses) {
      assert.equal(r.ok, true);
      assert.ok("pk" in r && "sk" in r);
    }
  } finally {
    await runner.close();
  }
});
