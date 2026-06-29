/**
 * Tests for the shared severity utilities lifted into src/severity.ts. These
 * are the locked contract the qscan / mcp / action packages consume.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { SEVERITY_ORDER, severityRank, meetsThreshold, sarifLevel } from "../src/index.js";
import type { Severity } from "../src/index.js";

test("SEVERITY_ORDER is most → least severe", () => {
  assert.deepEqual([...SEVERITY_ORDER], ["critical", "high", "medium", "low", "info"]);
});

test("severityRank is the index in SEVERITY_ORDER (lower = more severe)", () => {
  assert.equal(severityRank("critical"), 0);
  assert.equal(severityRank("high"), 1);
  assert.equal(severityRank("medium"), 2);
  assert.equal(severityRank("low"), 3);
  assert.equal(severityRank("info"), 4);
  // Strictly increasing across the order.
  for (let i = 1; i < SEVERITY_ORDER.length; i++) {
    assert.ok(severityRank(SEVERITY_ORDER[i]) > severityRank(SEVERITY_ORDER[i - 1]));
  }
});

test("meetsThreshold: severity at or above threshold", () => {
  // high meets a high threshold, and meets weaker thresholds too.
  assert.ok(meetsThreshold("high", "high"));
  assert.ok(meetsThreshold("critical", "high"));
  assert.ok(meetsThreshold("high", "low"));
  // medium does NOT meet a high threshold.
  assert.ok(!meetsThreshold("medium", "high"));
  assert.ok(!meetsThreshold("info", "low"));
  // Everything meets the lowest threshold; nothing below critical meets critical.
  for (const s of SEVERITY_ORDER) assert.ok(meetsThreshold(s, "info"));
  assert.ok(meetsThreshold("critical", "critical"));
  assert.ok(!meetsThreshold("high", "critical"));
});

test("sarifLevel maps to error/warning/note", () => {
  const cases: Array<[Severity, "error" | "warning" | "note"]> = [
    ["critical", "error"],
    ["high", "error"],
    ["medium", "warning"],
    ["low", "note"],
    ["info", "note"],
  ];
  for (const [sev, level] of cases) assert.equal(sarifLevel(sev), level);
});
