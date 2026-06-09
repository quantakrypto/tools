/**
 * Wiring tests for the new CLI surface (P1-2 / P2-1 / P2-2 / P2-6):
 *   - new walk flags (include / max-file-size / no-default-ignores /
 *     scan-minified) reaching core's ScanOptions,
 *   - incremental `--changed` mode populating ScanOptions.files via changedFiles,
 *   - `--parallel` / `--concurrency` routing to the parallel scanner,
 *   - CBOM (`--format cbom`) output round-tripping.
 *
 * These use an injected, *recording* scanner so they assert on the exact options
 * runQscan hands to core, without depending on core's real scan implementation.
 */

import assert from "node:assert/strict";
import { test } from "node:test";

import type { ParallelScanOptions } from "@qproof/core";

import { renderReport, runQscan } from "../src/index.js";
import { makeFinding, makeResult } from "./helpers.js";

/** A scanner that records the last options it was called with. */
function recordingScanner() {
  const calls: ParallelScanOptions[] = [];
  const scanFn = async (options: ParallelScanOptions) => {
    calls.push(options);
    return makeResult([makeFinding()], options.root);
  };
  return { scanFn, calls };
}

test("walk flags are wired into ScanOptions", async () => {
  const { scanFn, calls } = recordingScanner();
  await runQscan(
    {
      path: ".",
      include: ["src", "lib"],
      ignore: ["dist"],
      maxFileSize: 4096,
      noDefaultIgnores: true,
      scanMinified: true,
    },
    { scanFn },
  );
  const opts = calls[0];
  assert.ok(opts);
  assert.deepEqual(opts.include, ["src", "lib"]);
  assert.deepEqual(opts.exclude, ["dist"]);
  assert.equal(opts.maxFileSize, 4096);
  assert.equal(opts.noDefaultIgnores, true);
  assert.equal(opts.scanMinified, true);
});

test("absent walk flags are not forced onto ScanOptions", async () => {
  const { scanFn, calls } = recordingScanner();
  await runQscan({ path: "." }, { scanFn });
  const opts = calls[0];
  assert.ok(opts);
  assert.equal(opts.include, undefined);
  assert.equal(opts.exclude, undefined);
  assert.equal(opts.maxFileSize, undefined);
  assert.equal(opts.files, undefined);
  // Toggle defaults are still passed explicitly.
  assert.equal(opts.noDefaultIgnores, false);
  assert.equal(opts.scanMinified, false);
});

test("--changed populates ScanOptions.files from changedFiles(root, since)", async () => {
  const { scanFn, calls } = recordingScanner();
  const seen: { root: string; since?: string }[] = [];
  await runQscan(
    { path: "/repo", changed: true, since: "origin/main" },
    {
      scanFn,
      changedFilesFn: async (root, since) => {
        seen.push({ root, since });
        return ["src/a.ts", "src/b.ts"];
      },
    },
  );
  assert.deepEqual(seen, [{ root: "/repo", since: "origin/main" }]);
  assert.deepEqual(calls[0]?.files, ["src/a.ts", "src/b.ts"]);
});

test("--changed with no changes scans an empty file list (not the whole tree)", async () => {
  const { scanFn, calls } = recordingScanner();
  await runQscan({ path: ".", changed: true }, { scanFn, changedFilesFn: async () => [] });
  assert.deepEqual(calls[0]?.files, []);
});

test("changedFiles is only consulted in --changed mode", async () => {
  const { scanFn } = recordingScanner();
  let called = false;
  await runQscan(
    { path: "." },
    {
      scanFn,
      changedFilesFn: async () => {
        called = true;
        return [];
      },
    },
  );
  assert.equal(called, false);
});

test("--concurrency is passed through to the parallel scanner", async () => {
  const { scanFn, calls } = recordingScanner();
  await runQscan({ path: ".", parallel: true, concurrency: 3 }, { scanFn });
  assert.equal(calls[0]?.concurrency, 3);
});

test("parallel routing falls through the injected scanner deterministically", async () => {
  // With an injected scanFn, parallel/serial both use the same fn; the run must
  // still produce a coherent result + exit code (small-input fallback is core's
  // concern and is exercised by core's own tests).
  const { scanFn } = recordingScanner();
  const run = await runQscan({ path: ".", parallel: true, severityThreshold: "high" }, { scanFn });
  assert.equal(run.result.findings.length, 1);
  assert.equal(run.exitCode, 1);
});

test("--format cbom emits a CycloneDX 1.6 CBOM that round-trips", async () => {
  const result = makeResult([
    makeFinding({ ruleId: "rsa-keygen", algorithm: "RSA", category: "kem" }),
    makeFinding({ ruleId: "ecdh-usage", algorithm: "ECDH", category: "key-exchange" }),
  ]);
  const cbom = JSON.parse(renderReport(result, "cbom"));
  assert.equal(cbom.bomFormat, "CycloneDX");
  assert.equal(cbom.specVersion, "1.6");
  assert.ok(Array.isArray(cbom.components));
  // One cryptographic-asset component per (algorithm, primitive) pair.
  assert.ok(cbom.components.length >= 2);
  for (const c of cbom.components) {
    assert.equal(c.type, "cryptographic-asset");
    assert.ok(typeof c["bom-ref"] === "string");
  }
  const algos = cbom.components.map((c: { name: string }) => c.name).join(" ");
  assert.match(algos, /RSA/);
  assert.match(algos, /ECDH/);
});

test("runQscan renders cbom output through the format pipeline", async () => {
  const { scanFn } = recordingScanner();
  const run = await runQscan({ path: ".", format: "cbom" }, { scanFn });
  const cbom = JSON.parse(run.report ?? "");
  assert.equal(cbom.bomFormat, "CycloneDX");
  assert.equal(cbom.specVersion, "1.6");
});
