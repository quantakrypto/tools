/**
 * Tests for parallel scanning. The pure merge + chunk helpers are tested
 * directly; `scanParallel` is exercised via its in-process fall-back path
 * (small file count stays serial, so no workers are spawned — see the crossover
 * guard). Worker-spawning is not exercised here because tsx-loaded worker
 * entries are environment-dependent; the worker reuses `detectFile`, which is
 * covered by the serial scan tests.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import * as path from "node:path";

import { scanParallel, mergeChunkResults, chunkByBytes, scan } from "../src/index.js";
import type { Finding } from "../src/index.js";

function finding(file: string, line: number, ruleId: string): Finding {
  return {
    ruleId,
    title: ruleId,
    category: "signature",
    severity: "high",
    confidence: "high",
    hndl: false,
    message: ruleId,
    location: { file, line, snippet: ruleId },
  };
}

test("chunkByBytes buckets by total bytes, preserving order", () => {
  const files = [
    { rel: "a", size: 3 },
    { rel: "b", size: 3 },
    { rel: "c", size: 3 },
    { rel: "d", size: 1 },
  ];
  const chunks = chunkByBytes(files, 5);
  // a (3) → b would push to 6 > 5, new chunk; b (3) + c? 6 > 5 new; ...
  assert.deepEqual(chunks.map((c) => c.files), [["a"], ["b"], ["c", "d"]]);
});

test("chunkByBytes never produces an empty chunk and handles a huge single file", () => {
  const chunks = chunkByBytes([{ rel: "big", size: 10_000 }], 10);
  assert.deepEqual(chunks, [{ files: ["big"] }]);
});

test("mergeChunkResults is deterministic regardless of chunk order", () => {
  const c1 = { findings: [finding("b.ts", 2, "r2"), finding("a.ts", 1, "r1")], filesScanned: 2 };
  const c2 = { findings: [finding("a.ts", 1, "r0")], filesScanned: 1 };
  const merged = mergeChunkResults([c1, c2]);
  const mergedReordered = mergeChunkResults([c2, c1]);
  assert.deepEqual(merged, mergedReordered);
  assert.equal(merged.filesScanned, 3);
  // Sorted by file, then line, then ruleId.
  assert.deepEqual(
    merged.findings.map((f) => `${f.location.file}:${f.location.line}:${f.ruleId}`),
    ["a.ts:1:r0", "a.ts:1:r1", "b.ts:2:r2"],
  );
});

test("scanParallel falls back to serial on a small repo and matches scan()", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "qproof-par-"));
  try {
    await mkdir(path.join(dir, "src"), { recursive: true });
    await writeFile(path.join(dir, "src", "a.ts"), "const e = crypto.createECDH('p256');\n");
    await writeFile(path.join(dir, "src", "b.ts"), "jwt.sign(p, k, { algorithm: 'RS256' });\n");

    const serial = await scan({ root: dir });
    const parallel = await scanParallel({ root: dir, concurrency: 4 });

    // Same findings (ignore timestamps which differ by run).
    assert.deepEqual(
      parallel.findings.map((f) => `${f.location.file}:${f.location.line}:${f.ruleId}`),
      serial.findings.map((f) => `${f.location.file}:${f.location.line}:${f.ruleId}`),
    );
    assert.equal(parallel.filesScanned, serial.filesScanned);
    assert.equal(parallel.inventory.readinessScore, serial.inventory.readinessScore);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("scanParallel with concurrency 1 runs in-process", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "qproof-par1-"));
  try {
    await writeFile(path.join(dir, "a.ts"), "const e = crypto.createECDH('p256');\n");
    const r = await scanParallel({ root: dir, concurrency: 1 });
    assert.ok(r.findings.some((f) => f.ruleId === "node-crypto-ecdh"));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
