import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { applyBaseline, fingerprintFinding } from "@quantakrypto/core";
import type { Baseline, Finding, ScanResult } from "@quantakrypto/core";

import {
  annotateFindings,
  buildSummary,
  fingerprint,
  meetsThreshold,
  readInputs,
  run,
  shouldFail,
} from "../src/main.js";

/** Run `fn` with `process.stdout.write` captured; return the written text. */
function captureStdout(fn: () => void): string {
  const original = process.stdout.write.bind(process.stdout);
  let buf = "";
  process.stdout.write = ((chunk: string | Uint8Array): boolean => {
    buf += typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf8");
    return true;
  }) as typeof process.stdout.write;
  try {
    fn();
  } finally {
    process.stdout.write = original;
  }
  return buf;
}

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
  assert.equal(i.output, "quantakrypto.sarif.json");
  assert.equal(i.baseline, undefined);
  assert.equal(i.commentPr, false);
  assert.equal(i.githubToken, undefined);
});

test("readInputs reads provided values", () => {
  const i = readInputs({
    INPUT_PATH: "packages/app",
    "INPUT_SEVERITY-THRESHOLD": "medium",
    "INPUT_FAIL-ON-FINDINGS": "false",
    INPUT_FORMAT: "json",
    INPUT_OUTPUT: "report.json",
    INPUT_BASELINE: "base.sarif.json",
    "INPUT_COMMENT-PR": "true",
    "INPUT_GITHUB-TOKEN": "ghs_x",
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
  assert.throws(() => readInputs({ "INPUT_SEVERITY-THRESHOLD": "nope" }), TypeError);
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

test("fingerprint is the shared @quantakrypto/core fingerprint", () => {
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

// ---------------------------------------------------------------------------
// A2: an `info` finding (below every threshold) must annotate as a `notice`,
// not a `warning`. Previously the two-way error/warning split swallowed the
// dead `notice` branch and routed info findings to ::warning::.
// ---------------------------------------------------------------------------

test("annotateFindings routes an info finding to ::notice:: (not ::warning::)", () => {
  const f = makeFinding({
    severity: "info",
    hndl: false,
    message: "informational note",
    remediation: undefined,
    location: { file: "src/info.ts", line: 7 },
  });
  // threshold "high": the info finding is below it, so it takes the
  // annotationLevel path, which is "notice".
  const out = captureStdout(() => annotateFindings([f], "high"));
  assert.match(out, /^::notice .*::informational note$/m);
  assert.doesNotMatch(out, /::warning /);
  assert.doesNotMatch(out, /::error /);
});

test("annotateFindings still uses ::error:: for blocking and ::warning:: for medium/low", () => {
  const high = makeFinding({ severity: "high", message: "blocking", remediation: undefined });
  const low = makeFinding({
    severity: "low",
    message: "minor",
    remediation: undefined,
    location: { file: "x.ts", line: 1 },
  });
  const out = captureStdout(() => annotateFindings([high, low], "high"));
  assert.match(out, /::error .*::blocking/);
  assert.match(out, /::warning .*::minor/);
});

// ---------------------------------------------------------------------------
// A3: resolveInWorkspace (used for output/baseline) must keep paths inside the
// workspace. A "../../x" input must be rejected rather than escaping the tree.
// resolveInWorkspace is internal, so we exercise it through run()/readInputs.
// ---------------------------------------------------------------------------

test("run rejects an output path that escapes the workspace via ../", async () => {
  const ws = mkdtempSync(join(tmpdir(), "quantakrypto-ws-"));
  const env: NodeJS.ProcessEnv = {
    GITHUB_WORKSPACE: ws,
    INPUT_PATH: ".",
    INPUT_OUTPUT: "../../escape.sarif.json",
    "INPUT_FAIL-ON-FINDINGS": "false",
  };
  await assert.rejects(() => run(env), /escapes the workspace/);
});

test("run rejects a baseline path that escapes the workspace via ../", async () => {
  const ws = mkdtempSync(join(tmpdir(), "quantakrypto-ws-"));
  const env: NodeJS.ProcessEnv = {
    GITHUB_WORKSPACE: ws,
    INPUT_PATH: ".",
    INPUT_BASELINE: "../../../etc/passwd",
    "INPUT_FAIL-ON-FINDINGS": "false",
  };
  await assert.rejects(() => run(env), /escapes the workspace/);
});

// ---------------------------------------------------------------------------
// A5: the `redact-snippets` input is parsed and honored end-to-end — when set,
// the written report carries no matched source snippet.
// ---------------------------------------------------------------------------

test("readInputs parses redact-snippets (default false)", () => {
  assert.equal(readInputs({}).redactSnippets, false);
  assert.equal(readInputs({ "INPUT_REDACT-SNIPPETS": "true" }).redactSnippets, true);
  assert.equal(readInputs({ "INPUT_REDACT-SNIPPETS": "false" }).redactSnippets, false);
});

test("run honors redact-snippets: snippet text is omitted from the written report", async () => {
  const ws = mkdtempSync(join(tmpdir(), "quantakrypto-ws-"));
  // A file with detectable, quantum-vulnerable crypto whose snippet is unique.
  const marker = "generateKeyPairSync";
  writeFileSync(
    join(ws, "crypto.ts"),
    `import { ${marker} } from "node:crypto";\nconst kp = ${marker}("rsa", { modulusLength: 2048 });\n`,
  );

  // 1) Without redaction the snippet text appears in the report.
  const plainEnv: NodeJS.ProcessEnv = {
    GITHUB_WORKSPACE: ws,
    INPUT_PATH: ".",
    INPUT_FORMAT: "sarif",
    INPUT_OUTPUT: "plain.sarif.json",
    "INPUT_FAIL-ON-FINDINGS": "false",
  };
  await run(plainEnv);
  const plain = readFileSync(join(ws, "plain.sarif.json"), "utf8");
  assert.ok(plain.includes(marker), "expected the snippet text in the unredacted report");

  // 2) With redact-snippets=true the snippet text is gone.
  const redactedEnv: NodeJS.ProcessEnv = {
    ...plainEnv,
    INPUT_OUTPUT: "redacted.sarif.json",
    "INPUT_REDACT-SNIPPETS": "true",
  };
  await run(redactedEnv);
  const redacted = readFileSync(join(ws, "redacted.sarif.json"), "utf8");
  assert.ok(!redacted.includes(marker), "expected the snippet text to be redacted out");
});
