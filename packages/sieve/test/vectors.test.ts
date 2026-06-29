import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { loadVectors } from "../src/vectors.js";

/**
 * These tests exercise the ACVP PARSER only. The hex values below are NOT real
 * cryptographic vectors — they are tiny arbitrary byte strings chosen solely to
 * verify field extraction and normalization. Sieve ships no real KAT data.
 */

function tmp(files: Record<string, unknown>): string {
  const dir = mkdtempSync(join(tmpdir(), "sieve-vec-"));
  for (const [name, doc] of Object.entries(files)) {
    writeFileSync(join(dir, name), JSON.stringify(doc));
  }
  return dir;
}

test("loadVectors throws on a missing directory", () => {
  assert.throws(() => loadVectors(join(tmpdir(), "definitely-does-not-exist-xyz")));
});

test("loadVectors throws when no .json files are present", () => {
  const dir = mkdtempSync(join(tmpdir(), "sieve-empty-"));
  try {
    assert.throws(() => loadVectors(dir), /no \.json vector files/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("parses an ML-KEM decap ACVP group (field shape only)", () => {
  const dir = tmp({
    "kem-decap.json": {
      algorithm: "ML-KEM",
      mode: "encapDecap",
      testGroups: [
        {
          parameterSet: "ML-KEM-768",
          function: "decapsulation",
          tests: [{ dk: "00112233", c: "44556677", k: "8899aabb" }],
        },
      ],
    },
  });
  try {
    const set = loadVectors(dir);
    const decaps = set.vectors.filter((v) => v.kind === "kem-decap");
    assert.equal(decaps.length, 1);
    const v = decaps[0]!;
    assert.equal(v.param, "ml-kem-768");
    assert.ok(v.kind === "kem-decap");
    assert.deepEqual([...v.sk], [0x00, 0x11, 0x22, 0x33]);
    assert.deepEqual([...v.ct], [0x44, 0x55, 0x66, 0x77]);
    assert.deepEqual([...v.ss], [0x88, 0x99, 0xaa, 0xbb]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("parses an ML-DSA sigVer ACVP group with testPassed verdict", () => {
  const dir = tmp({
    "dsa-sigver.json": {
      algorithm: "ML-DSA",
      mode: "sigVer",
      testGroups: [
        {
          parameterSet: "ML-DSA-65",
          tests: [
            { pk: "0011", message: "2233", signature: "4455", testPassed: false },
            { pk: "0011", message: "2233", signature: "6677", testPassed: true },
          ],
        },
      ],
    },
  });
  try {
    const set = loadVectors(dir);
    const vv = set.vectors.filter((v) => v.kind === "dsa-verify");
    assert.equal(vv.length, 2);
    assert.equal(vv[0]!.kind === "dsa-verify" && vv[0]!.expected, false);
    assert.equal(vv[1]!.kind === "dsa-verify" && vv[1]!.expected, true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a sigVer case with an absent testPassed verdict is skipped, not assumed valid", () => {
  // NIST ACVP sigVer files contain intentionally-invalid signatures. If the
  // expected verdict is missing we must NOT default it to `expected:true` —
  // doing so would flag a conformant SUT (which correctly returns valid:false
  // on a bad signature) as failing. The case is skipped instead.
  const dir = tmp({
    "dsa-sigver-noverdict.json": {
      algorithm: "ML-DSA",
      mode: "sigVer",
      testGroups: [
        {
          parameterSet: "ML-DSA-65",
          tests: [
            // No testPassed at all.
            { pk: "0011", message: "2233", signature: "4455" },
            // Non-boolean testPassed (e.g. a stringified verdict) is also skipped.
            { pk: "0011", message: "2233", signature: "6677", testPassed: "false" },
            // A well-formed false verdict is still parsed.
            { pk: "0011", message: "2233", signature: "8899", testPassed: false },
          ],
        },
      ],
    },
  });
  try {
    const set = loadVectors(dir);
    const vv = set.vectors.filter((v) => v.kind === "dsa-verify");
    // Only the one case with a boolean verdict survives.
    assert.equal(vv.length, 1);
    assert.equal(vv[0]!.kind === "dsa-verify" && vv[0]!.expected, false);
    // None of the surviving vectors were invented as expected:true.
    assert.ok(
      !vv.some((v) => v.kind === "dsa-verify" && v.expected === true),
      "no case may default to expected:true",
    );
    // The skipped cases are surfaced as notes, not silently dropped.
    assert.ok(set.notes.some((n) => /no boolean "testPassed"/.test(n)));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("unrecognized algorithm is noted, not invented", () => {
  const dir = tmp({ "weird.json": { algorithm: "RSA", testGroups: [] } });
  try {
    const set = loadVectors(dir);
    assert.equal(set.vectors.length, 0);
    assert.ok(set.notes.some((n) => n.includes("unrecognized algorithm")));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
