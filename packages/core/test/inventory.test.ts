/**
 * Tests for inventory aggregation and the readiness score (monotonicity +
 * clamping + diminishing returns).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { buildInventory } from "../src/index.js";
import type { Finding, Severity } from "../src/index.js";

let counter = 0;
function finding(severity: Severity, over: Partial<Finding> = {}): Finding {
  counter += 1;
  return {
    ruleId: "test-rule",
    title: "test",
    category: "signature",
    severity,
    confidence: "high",
    hndl: false,
    message: "m",
    location: { file: "a.ts", line: counter },
    ...over,
  };
}

test("empty findings → perfect score, zeroed counts", () => {
  const inv = buildInventory([]);
  assert.equal(inv.readinessScore, 100);
  assert.equal(inv.hndlCount, 0);
  for (const s of ["critical", "high", "medium", "low", "info"] as Severity[]) {
    assert.equal(inv.bySeverity[s], 0);
  }
});

test("counts by algorithm, category, severity, and HNDL", () => {
  const inv = buildInventory([
    finding("high", { algorithm: "RSA", category: "kem", hndl: true }),
    finding("high", { algorithm: "ECDH", category: "key-exchange", hndl: true }),
    finding("low", { algorithm: "RSA", category: "kem", hndl: false }),
  ]);
  assert.equal(inv.byAlgorithm.RSA, 2);
  assert.equal(inv.byAlgorithm.ECDH, 1);
  assert.equal(inv.byCategory.kem, 2);
  assert.equal(inv.byCategory["key-exchange"], 1);
  assert.equal(inv.bySeverity.high, 2);
  assert.equal(inv.bySeverity.low, 1);
  assert.equal(inv.hndlCount, 2);
});

test("score decreases (monotonic non-increasing) as findings accumulate", () => {
  const findings: Finding[] = [];
  let prev = buildInventory(findings).readinessScore;
  assert.equal(prev, 100);
  for (let i = 0; i < 10; i++) {
    findings.push(finding("high"));
    const score = buildInventory(findings).readinessScore;
    assert.ok(score <= prev, `score should not increase (step ${i}: ${score} <= ${prev})`);
    prev = score;
  }
});

test("more severe findings lower the score more than less severe ones", () => {
  const critical = buildInventory([finding("critical")]).readinessScore;
  const info = buildInventory([finding("info")]).readinessScore;
  assert.ok(critical < info, `critical (${critical}) should score lower than info (${info})`);
});

test("score is clamped to [0, 100]", () => {
  const many = Array.from({ length: 200 }, () => finding("critical"));
  const score = buildInventory(many).readinessScore;
  assert.ok(score >= 0 && score <= 100);
});
