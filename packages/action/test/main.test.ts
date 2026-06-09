import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import type { Finding, ScanResult, Severity } from "@qproof/core";

import {
  applyBaseline,
  buildSummary,
  fingerprint,
  fingerprintsFromReport,
  meetsThreshold,
  readInputs,
  renderReport,
  shouldFail,
} from "../src/main.js";

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

test("applyBaseline suppresses findings present in the baseline", () => {
  const a = makeFinding({ ruleId: "rsa-keygen", message: "old" });
  const b = makeFinding({ ruleId: "ecdh-usage", message: "new", location: { file: "x.ts", line: 1 } });
  const baseline = new Set<string>([fingerprint(a)]);
  const result = applyBaseline([a, b], baseline);
  assert.equal(result.length, 1);
  assert.equal(result[0]?.ruleId, "ecdh-usage");
});

test("applyBaseline is a no-op when the baseline is empty", () => {
  const a = makeFinding();
  assert.deepEqual(applyBaseline([a], new Set()), [a]);
});

test("fingerprint ignores line number so shifted findings still match", () => {
  const a = makeFinding({ location: { file: "src/crypto.ts", line: 10 } });
  const b = makeFinding({ location: { file: "src/crypto.ts", line: 42 } });
  assert.equal(fingerprint(a), fingerprint(b));
});

test("fingerprintsFromReport reads JSON-report findings", () => {
  const a = makeFinding();
  const set = fingerprintsFromReport({ findings: [a] });
  assert.equal(set.has(fingerprint(a)), true);
});

test("fingerprintsFromReport reads SARIF results", () => {
  const sarif = {
    runs: [
      {
        results: [
          {
            ruleId: "rsa-keygen",
            message: { text: "RSA-2048 key generation detected" },
            locations: [
              { physicalLocation: { artifactLocation: { uri: "src/crypto.ts" } } },
            ],
          },
        ],
      },
    ],
  };
  const set = fingerprintsFromReport(sarif);
  assert.equal(set.has(fingerprint(makeFinding())), true);
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

test("renderReport(json) is parseable and pretty-printed", () => {
  const json = renderReport(makeResult([makeFinding()]), "json");
  const parsed = JSON.parse(json) as unknown;
  assert.equal(typeof parsed, "object");
  assert.match(json, /\n {2}/); // 2-space pretty-print
});

test("a SARIF report round-trips through fingerprintsFromReport", () => {
  // Simulate a previously-written SARIF report on disk and confirm the baseline
  // loader can read it back. (Independent of core's toSarif stub.)
  const dir = mkdtempSync(join(tmpdir(), "qproof-sarif-"));
  const file = join(dir, "qproof.sarif.json");
  const sarif = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        results: [
          {
            ruleId: "rsa-keygen",
            message: { text: "RSA-2048 key generation detected" },
            locations: [{ physicalLocation: { artifactLocation: { uri: "src/crypto.ts" } } }],
          },
        ],
      },
    ],
  };
  writeFileSync(file, JSON.stringify(sarif, null, 2), "utf8");
  const onDisk = JSON.parse(readFileSync(file, "utf8"));
  const set = fingerprintsFromReport(onDisk);
  const threshold: Severity = "high";
  assert.equal(meetsThreshold("high", threshold), true);
  assert.equal(set.has(fingerprint(makeFinding())), true);
});
