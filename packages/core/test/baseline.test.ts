/**
 * Tests for the canonical baseline module: line-insensitive, snippet-stable
 * fingerprints, baseline build/apply, and load/save round-trips.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import * as path from "node:path";

import {
  fingerprintFinding,
  baselineFromFindings,
  applyBaseline,
  loadBaseline,
  saveBaseline,
  BASELINE_VERSION,
} from "../src/index.js";
import type { Finding } from "../src/index.js";

function finding(over: Partial<Finding> = {}): Finding {
  return {
    ruleId: "node-crypto-ecdh",
    title: "ECDH",
    category: "key-exchange",
    severity: "high",
    confidence: "high",
    algorithm: "ECDH",
    hndl: true,
    message: "ecdh",
    location: { file: "src/a.ts", line: 10, snippet: "const ecdh = crypto.createECDH('p256');" },
    ...over,
  };
}

test("fingerprint is line-insensitive", () => {
  const a = finding({ location: { file: "src/a.ts", line: 10, snippet: "x = createECDH()" } });
  const b = finding({ location: { file: "src/a.ts", line: 999, snippet: "x = createECDH()" } });
  assert.equal(fingerprintFinding(a), fingerprintFinding(b));
});

test("fingerprint normalizes snippet whitespace", () => {
  const a = finding({ location: { file: "src/a.ts", line: 1, snippet: "a   b\tc" } });
  const b = finding({ location: { file: "src/a.ts", line: 1, snippet: "a b c" } });
  assert.equal(fingerprintFinding(a), fingerprintFinding(b));
});

test("fingerprint differs on ruleId / file / snippet", () => {
  const base = finding();
  assert.notEqual(fingerprintFinding(base), fingerprintFinding(finding({ ruleId: "other" })));
  assert.notEqual(
    fingerprintFinding(base),
    fingerprintFinding(finding({ location: { file: "src/b.ts", line: 10, snippet: base.location.snippet } })),
  );
  assert.notEqual(
    fingerprintFinding(base),
    fingerprintFinding(finding({ location: { file: "src/a.ts", line: 10, snippet: "different" } })),
  );
});

test("fingerprint is a full sha256 hex string", () => {
  assert.match(fingerprintFinding(finding()), /^[0-9a-f]{64}$/);
});

test("baselineFromFindings dedupes and sorts", () => {
  const b = baselineFromFindings([finding(), finding(), finding({ ruleId: "x" })]);
  assert.equal(b.version, BASELINE_VERSION);
  assert.equal(b.fingerprints.length, 2);
  assert.deepEqual([...b.fingerprints].sort(), b.fingerprints);
});

test("applyBaseline splits new vs suppressed", () => {
  const known = finding();
  const fresh = finding({ ruleId: "node-crypto-dh", location: { file: "src/a.ts", line: 5, snippet: "dh" } });
  const baseline = baselineFromFindings([known]);
  const { newFindings, suppressed } = applyBaseline([known, fresh], baseline);
  assert.equal(suppressed.length, 1);
  assert.equal(suppressed[0].ruleId, "node-crypto-ecdh");
  assert.equal(newFindings.length, 1);
  assert.equal(newFindings[0].ruleId, "node-crypto-dh");
});

test("saveBaseline / loadBaseline round-trip", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "qproof-baseline-"));
  try {
    const file = path.join(dir, "baseline.json");
    const saved = await saveBaseline(file, [finding(), finding({ ruleId: "x" })]);
    const text = await readFile(file, "utf8");
    assert.ok(text.endsWith("\n"), "trailing newline written");
    const loaded = await loadBaseline(file);
    assert.deepEqual(loaded, saved);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("loadBaseline tolerates a missing / malformed file", async () => {
  const empty = await loadBaseline(path.join(tmpdir(), "does-not-exist-qproof.json"));
  assert.deepEqual(empty, { version: BASELINE_VERSION, fingerprints: [] });
});
