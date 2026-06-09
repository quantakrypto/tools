import assert from "node:assert/strict";
import { test } from "node:test";

import { applyBaseline, fingerprintFinding } from "@qproof/core";
import type { Baseline, Finding, ScanResult } from "@qproof/core";

import { buildSummary, fingerprint, meetsThreshold, readInputs, shouldFail } from "../src/main.js";

/** Build a Finding with sensible defaults for tests. */
function makeFinding(over: Partial<Finding> = {}): Finding {
  return {
    ruleId: "rsa-keygen",
    title: "RSA key generation",
    category: "signature",
    severity: "high",
    confidence: "high",
    algorithm: "RSA",
    hndl: true,
    message: "RSA-2048 key generation detected",
    location: { file: "src/crypto.ts", line: 10 },
    ...over,
  };
}

/** Build a minimal ScanResult around the given findings. */
function makeResult(findings: Finding[], readinessScore = 75): ScanResult {
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) bySeverity[f.severity]++;
  return {
    root: ".",
    findings,
    filesScanned: 1,
    inventory: {
      byAlgorithm: {},
      byCategory: {},
      bySeverity,
      hndlCount: findings.filter((f) => f.hndl).length,
      readinessScore,
    },
    startedAt: "2026-01-01T00:00:00.000Z",
    finishedAt: "2026-01-01T00:00:01.000Z",
    toolVersion: "0.1.0",
  };
}

/** Wrap a set of fingerprints in the shared core baseline shape. */
function baselineOf(...fingerprints: string[]): Baseline {
  return { version: 1, fingerprints };
}

test("readInputs applies defaults when env is empty", () => {
  const i = readInputs({});
  assert.equal(i.path, ".");
  assert.equal(i.severityThreshold, "high");
  assert.equal(i.failOnFindings, true);
  assert.equal(i.format, "sarif");
  assert.equal(i.output, "qproof.sarif.json");
  assert.equal(i.baseline, undefined);
  assert.equal(i.commentPr, false);
  assert.equal(i.githubToken, undefined);
});

test("readInputs reads provided values", () => {
  const i = readInputs({
    INPUT_PATH: "packages/app",
    INPUT_SEVERITY_THRESHOLD: "medium",
    INPUT_FAIL_ON_FINDINGS: "false",
    INPUT_FORMAT: "json",
    INPUT_OUTPUT: "report.json",
    INPUT_BASELINE: "base.sarif.json",
    INPUT_COMMENT_PR: "true",
    INPUT_GITHUB_TOKEN: "ghs_x",
  });
  assert.equal(i.path, "packages/app");
  assert.equal(i.severityThreshold, "medium");
  assert.equal(i.failOnFindings, false);
  assert.equal(i.format, "json");
  assert.equal(i.output, "report.json");
  assert.equal(i.baseline, "base.sarif.json");
  assert.equal(i.commentPr, true);
  assert.equal(i.githubToken, "ghs_x");
});

test("readInputs rejects an invalid severity-threshold", () => {
  assert.throws(() => readInputs({ INPUT_SEVERITY_THRESHOLD: "nope" }), TypeError);
});

test("readInputs rejects an invalid format", () => {
  assert.throws(() => readInputs({ INPUT_FORMAT: "xml" }), TypeError);
});

test("meetsThreshold respects severity ordering", () => {
  assert.equal(meetsThreshold("critical", "high"), true);
  assert.equal(meetsThreshold("high", "high"), true);
  assert.equal(meetsThreshold("medium", "high"), false);
  assert.equal(meetsThreshold("info", "info"), true);
  assert.equal(meetsThreshold("low", "critical"), false);
});

test("shouldFail gates on blocking count and fail-on-findings", () => {
  assert.equal(shouldFail(2, true), true);
  assert.equal(shouldFail(0, true), false);
  assert.equal(shouldFail(5, false), false);
});

test("fingerprint is the shared @qproof/core fingerprint", () => {
  // The Action re-exports core's fingerprint so it and the CLI share one
  // baseline format.
  assert.equal(fingerprint, fingerprintFinding);
});

test("applyBaseline (shared) suppresses findings present in the baseline", () => {
  const a = makeFinding({ ruleId: "rsa-keygen" });
  const b = makeFinding({
    ruleId: "ecdh-usage",
    message: "new",
    location: { file: "x.ts", line: 1 },
  });
  const baseline = baselineOf(fingerprint(a));
  const { newFindings, suppressed } = applyBaseline([a, b], baseline);
  assert.equal(newFindings.length, 1);
  assert.equal(newFindings[0]?.ruleId, "ecdh-usage");
  assert.equal(suppressed.length, 1);
  assert.equal(suppressed[0]?.ruleId, "rsa-keygen");
});

test("applyBaseline (shared) is a no-op when the baseline is empty", () => {
  const a = makeFinding();
  const { newFindings, suppressed } = applyBaseline([a], baselineOf());
  assert.deepEqual(newFindings, [a]);
  assert.equal(suppressed.length, 0);
});

test("fingerprint ignores line number so shifted findings still match", () => {
  const a = makeFinding({ location: { file: "src/crypto.ts", line: 10 } });
  const b = makeFinding({ location: { file: "src/crypto.ts", line: 42 } });
  assert.equal(fingerprint(a), fingerprint(b));
});

test("buildSummary reports a clean run when nothing blocks", () => {
  const md = buildSummary(makeResult([], 100), [], "high");
  assert.match(md, /Readiness score:\*\* 100\/100/);
  assert.match(md, /No new quantum-vulnerable cryptography/);
});

test("buildSummary tabulates blocking findings", () => {
  const f = makeFinding();
  const md = buildSummary(makeResult([f]), [f], "high");
  assert.match(md, /\| high \| `rsa-keygen` \| src\/crypto\.ts:10 \|/);
});

// ---------------------------------------------------------------------------
// P0-2: output-injection defenses in the PR-comment Markdown table.
// Finding `file`/`message`/`ruleId` are attacker-controlled in a fork PR.
// ---------------------------------------------------------------------------

test("buildSummary: a hostile filename with a pipe cannot break the table", () => {
  const f = makeFinding({
    location: { file: "evil|name.ts", line: 1 },
    message: "msg",
  });
  const md = buildSummary(makeResult([f]), [f], "high");
  const row = md.split("\n").find((l) => l.includes("evil"));
  assert.ok(row, "expected a row containing the hostile filename");
  // The cell-internal pipe is escaped, so the row still has exactly the 4
  // columns' worth of UNescaped pipes (5 delimiters for 4 cells).
  const unescapedPipes = (row.match(/(?<!\\)\|/g) ?? []).length;
  assert.equal(unescapedPipes, 5);
  assert.match(row, /evil\\\|name\.ts/);
});

test("buildSummary: backticks in finding text are escaped (no code-span breakout)", () => {
  const f = makeFinding({
    ruleId: "r`id",
    message: "see `secret` and `more`",
    location: { file: "a`b.ts", line: 2 },
  });
  const md = buildSummary(makeResult([f]), [f], "high");
  const row = md.split("\n").find((l) => l.includes("a\\`b.ts"));
  assert.ok(row, "expected the file cell with an escaped backtick");
  // No bare backticks survive except the two we add around the (escaped) ruleId.
  assert.match(row, /\\`secret\\`/);
  assert.match(row, /r\\`id/);
});

test("buildSummary: HTML in a filename is entity-encoded (no HTML injection)", () => {
  const f = makeFinding({
    location: { file: '<img src=x onerror="alert(1)">.ts', line: 3 },
    message: "<b>bold</b> & <script>evil</script>",
  });
  const md = buildSummary(makeResult([f]), [f], "high");
  assert.doesNotMatch(md, /<img/);
  assert.doesNotMatch(md, /<script>/);
  assert.doesNotMatch(md, /<b>/);
  assert.match(md, /&lt;img/);
  assert.match(md, /&lt;script&gt;/);
  assert.match(md, /&amp;/);
});

test("buildSummary: newlines and ']' in finding text cannot add rows or break out", () => {
  const f = makeFinding({
    message: "line1\nline2\r\n| injected | row |",
    location: { file: "weird]name::x.ts", line: 4 },
  });
  const md = buildSummary(makeResult([f]), [f], "high");
  // The injected "| injected | row |" must remain inside one cell: the table
  // body has exactly one data row plus the header + divider.
  const dataRows = md
    .split("\n")
    .filter((l) => l.startsWith("|") && !/^\| ---/.test(l) && !/^\| Severity/.test(l));
  assert.equal(dataRows.length, 1);
  // The newline was flattened to a space inside the single cell.
  assert.doesNotMatch(dataRows[0] ?? "", /\n/);
  assert.match(dataRows[0] ?? "", /line1 line2/);
});

test("buildSummary: a backslash before a pipe cannot un-escape the delimiter", () => {
  // Naive `replace(/\|/, "\\|")` is defeated by a trailing backslash:
  // "x\" + "|" would render as an escaped-backslash then a LIVE pipe. mdCell
  // doubles backslashes first, so the pipe stays escaped.
  const f = makeFinding({ message: "x\\| y | z", location: { file: "f.ts", line: 1 } });
  const md = buildSummary(makeResult([f]), [f], "high");
  const row = md.split("\n").find((l) => l.includes("f.ts"));
  assert.ok(row);
  const unescapedPipes = (row.match(/(?<!\\)\|/g) ?? []).length;
  assert.equal(unescapedPipes, 5);
});
