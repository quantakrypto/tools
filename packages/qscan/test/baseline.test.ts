/**
 * Baseline + fingerprint tests: stability, sensitivity, filtering, and round
 * trips through disk.
 */

import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  applyBaseline,
  BASELINE_VERSION,
  buildBaseline,
  fingerprint,
  readBaseline,
  writeBaseline,
} from "../src/baseline.js";
import { makeFinding } from "./helpers.js";

test("fingerprint is a stable 12-char hex string", () => {
  const f = makeFinding();
  const fp = fingerprint(f);
  assert.match(fp, /^[0-9a-f]{12}$/);
  // Stable across calls.
  assert.equal(fingerprint(makeFinding()), fp);
});

test("fingerprint ignores volatile fields but tracks identity fields", () => {
  const base = makeFinding();
  const fp = fingerprint(base);

  // Changing severity / message / remediation must NOT change the fingerprint.
  assert.equal(fingerprint(makeFinding({ severity: "low" })), fp);
  assert.equal(fingerprint(makeFinding({ message: "different" })), fp);
  assert.equal(fingerprint(makeFinding({ remediation: "do X" })), fp);

  // Changing ruleId / file / line / snippet MUST change it.
  assert.notEqual(fingerprint(makeFinding({ ruleId: "ecdh-usage" })), fp);
  assert.notEqual(
    fingerprint(makeFinding({ location: { file: "src/b.ts", line: 1, snippet: base.location.snippet } })),
    fp,
  );
  assert.notEqual(
    fingerprint(makeFinding({ location: { file: base.location.file, line: 99, snippet: base.location.snippet } })),
    fp,
  );
  assert.notEqual(
    fingerprint(makeFinding({ location: { file: base.location.file, line: 1, snippet: "other" } })),
    fp,
  );
});

test("buildBaseline dedupes and sorts fingerprints", () => {
  const a = makeFinding({ ruleId: "rsa-keygen" });
  const b = makeFinding({ ruleId: "ecdh-usage" });
  const baseline = buildBaseline([a, b, a]); // duplicate a
  assert.equal(baseline.version, BASELINE_VERSION);
  assert.equal(baseline.fingerprints.length, 2);
  assert.deepEqual(baseline.fingerprints, [...baseline.fingerprints].sort());
});

test("applyBaseline suppresses matching findings only", () => {
  const kept = makeFinding({ ruleId: "ecdh-usage", location: { file: "src/k.ts", line: 5 } });
  const suppressedFinding = makeFinding({ ruleId: "rsa-keygen", location: { file: "src/s.ts", line: 9 } });
  const set = new Set([fingerprint(suppressedFinding)]);

  const out = applyBaseline([kept, suppressedFinding], set);
  assert.deepEqual(out.kept, [kept]);
  assert.deepEqual(out.suppressed, [suppressedFinding]);
});

test("empty baseline keeps everything", () => {
  const findings = [makeFinding(), makeFinding({ ruleId: "ecdh-usage" })];
  const out = applyBaseline(findings, new Set());
  assert.equal(out.kept.length, 2);
  assert.equal(out.suppressed.length, 0);
});

test("write then read round-trips through disk", async () => {
  const dir = await mkdtemp(join(tmpdir(), "qscan-baseline-"));
  try {
    const path = join(dir, "baseline.json");
    const findings = [makeFinding(), makeFinding({ ruleId: "ecdh-usage" })];
    const built = buildBaseline(findings);

    await writeBaseline(path, built);
    const raw = await readFile(path, "utf8");
    assert.ok(raw.endsWith("\n"), "file ends with newline");
    assert.deepEqual(JSON.parse(raw), built);

    const loaded = await readBaseline(path);
    for (const f of findings) assert.ok(loaded.has(fingerprint(f)));
    assert.equal(loaded.size, 2);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("readBaseline rejects missing files and bad JSON", async () => {
  const dir = await mkdtemp(join(tmpdir(), "qscan-baseline-"));
  try {
    await assert.rejects(() => readBaseline(join(dir, "nope.json")), /could not read baseline/);

    const bad = join(dir, "bad.json");
    await writeBaseline(bad, { version: 1, fingerprints: ["abc"] });
    // Corrupt it.
    const { writeFile } = await import("node:fs/promises");
    await writeFile(bad, "{ not json", "utf8");
    await assert.rejects(() => readBaseline(bad), /not valid JSON/);

    const wrongShape = join(dir, "wrong.json");
    await writeFile(wrongShape, JSON.stringify({ version: 1 }), "utf8");
    await assert.rejects(() => readBaseline(wrongShape), /missing a string "fingerprints" array/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
