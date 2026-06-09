/**
 * Baseline + fingerprint tests.
 *
 * qScan's baseline is now a thin adapter over the canonical implementation in
 * `@qproof/core` (P1-1): a full, line-INSENSITIVE SHA-256 fingerprint and the
 * shared `{ version, fingerprints }` on-disk format. These tests assert the
 * adapter preserves qScan's historical API shape (`fingerprint`, `kept`/
 * `suppressed`, strict `readBaseline`) while delegating identity to core.
 */

import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  fingerprintFinding as coreFingerprint,
  loadBaseline as coreLoadBaseline,
  saveBaseline as coreSaveBaseline,
} from "@qproof/core";

import {
  applyBaseline,
  BASELINE_VERSION,
  buildBaseline,
  fingerprint,
  readBaseline,
  writeBaseline,
} from "../src/baseline.js";
import { makeFinding } from "./helpers.js";

test("fingerprint is a stable full sha-256 hex string from core", () => {
  const f = makeFinding();
  const fp = fingerprint(f);
  assert.match(fp, /^[0-9a-f]{64}$/);
  // Stable across calls.
  assert.equal(fingerprint(makeFinding()), fp);
  // Delegates to core's canonical fingerprint (single source of truth).
  assert.equal(fp, coreFingerprint(f));
});

test("fingerprint ignores volatile fields AND the line number (line-insensitive)", () => {
  const base = makeFinding();
  const fp = fingerprint(base);

  // Changing severity / message / remediation must NOT change the fingerprint.
  assert.equal(fingerprint(makeFinding({ severity: "low" })), fp);
  assert.equal(fingerprint(makeFinding({ message: "different" })), fp);
  assert.equal(fingerprint(makeFinding({ remediation: "do X" })), fp);

  // The line number is deliberately excluded so a baseline survives line shifts.
  assert.equal(
    fingerprint(
      makeFinding({
        location: { file: base.location.file, line: 99, snippet: base.location.snippet },
      }),
    ),
    fp,
  );

  // Changing ruleId / file / snippet MUST change it.
  assert.notEqual(fingerprint(makeFinding({ ruleId: "ecdh-usage" })), fp);
  assert.notEqual(
    fingerprint(
      makeFinding({ location: { file: "src/b.ts", line: 1, snippet: base.location.snippet } }),
    ),
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

test("applyBaseline accepts a Set and suppresses matching findings only", () => {
  const kept = makeFinding({ ruleId: "ecdh-usage", location: { file: "src/k.ts", line: 5 } });
  const suppressedFinding = makeFinding({
    ruleId: "rsa-keygen",
    location: { file: "src/s.ts", line: 9 },
  });
  const set = new Set([fingerprint(suppressedFinding)]);

  const out = applyBaseline([kept, suppressedFinding], set);
  assert.deepEqual(out.kept, [kept]);
  assert.deepEqual(out.suppressed, [suppressedFinding]);
});

test("applyBaseline accepts a core Baseline object directly", () => {
  const kept = makeFinding({ ruleId: "ecdh-usage", location: { file: "src/k.ts", line: 5 } });
  const known = makeFinding({ ruleId: "rsa-keygen", location: { file: "src/s.ts", line: 9 } });
  const baseline = buildBaseline([known]);

  const out = applyBaseline([kept, known], baseline);
  assert.deepEqual(out.kept, [kept]);
  assert.deepEqual(out.suppressed, [known]);
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

test("on-disk format is interoperable with core's save/load (P1-1)", async () => {
  const dir = await mkdtemp(join(tmpdir(), "qscan-baseline-"));
  try {
    const path = join(dir, "shared.json");
    const findings = [makeFinding(), makeFinding({ ruleId: "ecdh-usage" })];

    // Write with core, read with qScan's adapter.
    const written = await coreSaveBaseline(path, findings);
    assert.equal(written.version, BASELINE_VERSION);
    const loadedByQscan = await readBaseline(path);
    for (const f of findings) assert.ok(loadedByQscan.has(fingerprint(f)));

    // Write with qScan's adapter, read with core.
    await writeBaseline(path, buildBaseline(findings));
    const loadedByCore = await coreLoadBaseline(path);
    assert.deepEqual(loadedByCore, buildBaseline(findings));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("readBaseline rejects missing files and bad JSON (strict adapter)", async () => {
  const dir = await mkdtemp(join(tmpdir(), "qscan-baseline-"));
  try {
    await assert.rejects(() => readBaseline(join(dir, "nope.json")), /could not read baseline/);

    const bad = join(dir, "bad.json");
    await writeBaseline(bad, buildBaseline([makeFinding()]));
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
