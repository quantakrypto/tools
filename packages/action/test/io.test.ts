import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  formatCommand,
  getBooleanInput,
  getInput,
  setOutput,
} from "../src/io.js";

test("getInput reads INPUT_<UPPER_WITH_UNDERSCORES> and trims", () => {
  const env = { INPUT_SEVERITY_THRESHOLD: "  high  " };
  assert.equal(getInput("severity-threshold", env), "high");
});

test("getInput returns empty string when unset", () => {
  assert.equal(getInput("missing", {}), "");
});

test("getInput maps spaces and dashes to underscores", () => {
  const env = { INPUT_FAIL_ON_FINDINGS: "true" };
  assert.equal(getInput("fail-on-findings", env), "true");
});

test("getBooleanInput parses YAML 1.2 core booleans", () => {
  assert.equal(getBooleanInput("x", false, { INPUT_X: "true" }), true);
  assert.equal(getBooleanInput("x", false, { INPUT_X: "True" }), true);
  assert.equal(getBooleanInput("x", true, { INPUT_X: "FALSE" }), false);
});

test("getBooleanInput falls back to the default when empty", () => {
  assert.equal(getBooleanInput("x", true, {}), true);
  assert.equal(getBooleanInput("x", false, {}), false);
});

test("getBooleanInput throws on non-boolean values", () => {
  assert.throws(() => getBooleanInput("x", false, { INPUT_X: "yes" }), TypeError);
});

test("formatCommand emits ::error file=...,line=...::message", () => {
  const out = formatCommand("error", "boom", { file: "src/a.ts", line: 12 });
  assert.equal(out, "::error file=src/a.ts,line=12::boom");
});

test("formatCommand emits a bare command with no properties", () => {
  assert.equal(formatCommand("warning", "hi"), "::warning::hi");
});

test("formatCommand escapes property separators and data newlines", () => {
  const out = formatCommand("error", "a\nb", { file: "a,b:c.ts", line: 1 });
  // ',' → %2C and ':' → %3A in properties; '\n' → %0A in data.
  assert.equal(out, "::error file=a%2Cb%3Ac.ts,line=1::a%0Ab");
});

test("formatCommand includes title and endLine when present", () => {
  const out = formatCommand("error", "m", { title: "T", file: "f.ts", line: 3, endLine: 5 });
  assert.equal(out, "::error title=T,file=f.ts,line=3,endLine=5::m");
});

test("setOutput appends a heredoc entry to $GITHUB_OUTPUT", () => {
  const dir = mkdtempSync(join(tmpdir(), "qproof-out-"));
  const file = join(dir, "out.txt");
  const env = { GITHUB_OUTPUT: file };
  setOutput("findings-count", "3", env);
  setOutput("readiness-score", "88", env);
  const contents = readFileSync(file, "utf8");
  assert.match(contents, /findings-count<<ghadelimiter_findings-count\n3\nghadelimiter_findings-count\n/);
  assert.match(contents, /readiness-score<<ghadelimiter_readiness-score\n88\nghadelimiter_readiness-score\n/);
});
