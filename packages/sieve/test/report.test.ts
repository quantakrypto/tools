import { test } from "node:test";
import assert from "node:assert/strict";

import { buildReport, formatHuman, formatJson, overallVerdict } from "../src/report.js";
import type { CategoryResult } from "../src/categories/types.js";

function mk(category: string, status: "pass" | "fail" | "skip"): CategoryResult {
  return {
    category,
    status,
    checks: [{ name: "c", status, detail: "d" }],
    summary: `${category} ${status}`,
  };
}

test("overallVerdict is FAIL if any non-advisory category fails", () => {
  assert.equal(overallVerdict([mk("correctness", "pass"), mk("sizes", "fail")]), "FAIL");
  assert.equal(overallVerdict([mk("correctness", "pass"), mk("sizes", "skip")]), "PASS");
});

test("overallVerdict ignores advisory timing failures", () => {
  // timing never actually returns fail, but assert the policy regardless.
  assert.equal(overallVerdict([mk("correctness", "pass"), mk("timing", "fail")]), "PASS");
});

test("buildReport tallies check counts", () => {
  const report = buildReport({
    param: "ml-kem-768",
    impl: ["node", "impl.js"],
    iterations: 10,
    startedAt: new Date(0),
    durationMs: 123,
    categories: [mk("correctness", "pass"), mk("sizes", "fail"), mk("kat", "skip")],
  });
  assert.equal(report.counts.pass, 1);
  assert.equal(report.counts.fail, 1);
  assert.equal(report.counts.skip, 1);
  assert.equal(report.overall, "FAIL");
  assert.equal(report.tool, "sieve");
});

test("formatJson is valid JSON; formatHuman shows OVERALL", () => {
  const report = buildReport({
    param: "ml-kem-512",
    impl: ["x"],
    iterations: 1,
    startedAt: new Date(0),
    durationMs: 5,
    categories: [mk("correctness", "pass")],
  });
  const j = JSON.parse(formatJson(report));
  assert.equal(j.param, "ml-kem-512");
  const h = formatHuman(report);
  assert.match(h, /OVERALL: PASS/);
  assert.match(h, /correctness/);
});
