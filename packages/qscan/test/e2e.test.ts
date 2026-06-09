/**
 * End-to-end test.
 *
 * Builds a temporary project containing samples of classical crypto (RSA key
 * generation, an ECDH usage, and a package.json depending on `node-forge`),
 * runs the full programmatic pipeline (`runQscan`), and asserts on the
 * findings, exit code, baseline behavior, and JSON round-trip.
 *
 * The scanner is injected (`fakeScan`) so the test exercises the real file
 * traversal + runQscan/baseline/report pipeline against the locked
 * `@qproof/core` contract even while core's own `scan` remains a stub.
 */

import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { EXIT, renderReport, runQscan } from "../src/index.js";
import { fakeScan } from "./helpers.js";

/** Materialize a small vulnerable project in a fresh temp dir. */
async function makeFixture(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "qscan-e2e-"));
  await mkdir(join(root, "src"), { recursive: true });

  await writeFile(
    join(root, "src", "keys.ts"),
    [
      "import { generateKeyPairSync } from 'node:crypto';",
      "",
      "export function makeKeys() {",
      "  return generateKeyPairSync('rsa', { modulusLength: 2048 });",
      "}",
      "",
    ].join("\n"),
    "utf8",
  );

  await writeFile(
    join(root, "src", "exchange.ts"),
    [
      "import { createECDH } from 'node:crypto';",
      "",
      "export function agree() {",
      "  const ecdh = createECDH('prime256v1');",
      "  return ecdh.generateKeys();",
      "}",
      "",
    ].join("\n"),
    "utf8",
  );

  await writeFile(
    join(root, "package.json"),
    JSON.stringify(
      {
        name: "vulnerable-fixture",
        version: "1.0.0",
        dependencies: { "node-forge": "^1.3.1" },
      },
      null,
      2,
    ),
    "utf8",
  );

  // A clean file with no crypto, to confirm it produces no findings.
  await writeFile(
    join(root, "src", "util.ts"),
    "export const add = (a: number, b: number) => a + b;\n",
    "utf8",
  );

  return root;
}

test("e2e: detects RSA, ECDH, and a vulnerable dependency", async () => {
  const root = await makeFixture();
  try {
    const run = await runQscan({ path: root, severityThreshold: "high" }, { scanFn: fakeScan });

    const ruleIds = run.result.findings.map((f) => f.ruleId).sort();
    assert.deepEqual(ruleIds, ["dep-vulnerable", "ecdh-usage", "rsa-keygen"]);

    // Files: keys.ts, exchange.ts, util.ts, package.json (4 read).
    assert.ok(run.result.filesScanned >= 4, `scanned ${run.result.filesScanned} files`);

    // A high-severity finding (RSA / node-forge) crosses the threshold.
    assert.equal(run.exitCode, EXIT.FINDINGS);

    // Inventory reflects the algorithms and HNDL exposure.
    assert.ok((run.result.inventory.byAlgorithm.RSA ?? 0) >= 1);
    assert.ok((run.result.inventory.byAlgorithm.ECDH ?? 0) >= 1);
    assert.ok(run.result.inventory.hndlCount >= 1);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("e2e: --ignore excludes paths from the scan", async () => {
  const root = await makeFixture();
  try {
    const run = await runQscan(
      { path: root, ignore: ["package.json"], severityThreshold: "high" },
      { scanFn: fakeScan },
    );
    const ruleIds = run.result.findings.map((f) => f.ruleId);
    assert.ok(!ruleIds.includes("dep-vulnerable"), "node-forge finding excluded");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("e2e: --no-deps skips the dependency scan", async () => {
  const root = await makeFixture();
  try {
    const run = await runQscan(
      { path: root, dependencies: false, severityThreshold: "high" },
      { scanFn: fakeScan },
    );
    assert.ok(!run.result.findings.some((f) => f.ruleId === "dep-vulnerable"));
    assert.ok(run.result.findings.some((f) => f.ruleId === "rsa-keygen"));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("e2e: --format json round-trips through parse/serialize", async () => {
  const root = await makeFixture();
  try {
    const run = await runQscan({ path: root, format: "json" }, { scanFn: fakeScan });

    // run.report is the JSON string; it must parse back to a result-shaped object.
    const parsed = JSON.parse(run.report ?? "");
    assert.ok(Array.isArray(parsed.findings), "findings is an array");
    assert.equal(parsed.findings.length, run.result.findings.length);

    // Re-render from the live result and confirm structural stability.
    const reRendered = JSON.parse(renderReport(run.result, "json"));
    assert.deepEqual(reRendered.findings.map((f: { ruleId: string }) => f.ruleId).sort(), [
      "dep-vulnerable",
      "ecdh-usage",
      "rsa-keygen",
    ]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("e2e: --format sarif emits valid SARIF 2.1.0", async () => {
  const root = await makeFixture();
  try {
    const run = await runQscan({ path: root, format: "sarif" }, { scanFn: fakeScan });
    const sarif = JSON.parse(run.report ?? "");
    assert.equal(sarif.version, "2.1.0");
    assert.ok(Array.isArray(sarif.runs) && sarif.runs.length >= 1);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("e2e: baseline written on one run suppresses everything on the next", async () => {
  const root = await makeFixture();
  try {
    const baselinePath = join(root, "qscan-baseline.json");
    const write = await runQscan({ path: root, writeBaseline: baselinePath }, { scanFn: fakeScan });
    assert.equal(write.exitCode, EXIT.OK);
    assert.ok((write.baselineWritten?.fingerprints.length ?? 0) >= 3);

    const second = await runQscan(
      {
        path: root,
        baseline: baselinePath,
        severityThreshold: "high",
        ignore: ["qscan-baseline.json"],
      },
      { scanFn: fakeScan },
    );
    assert.equal(second.result.findings.length, 0, "all findings suppressed");
    assert.equal(second.exitCode, EXIT.OK);
    assert.ok(second.suppressed.length >= 3);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
