import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { formatCommand, getBooleanInput, getInput, setOutput } from "../src/io.js";

test("getInput reads INPUT_<UPPERCASED> and trims", () => {
  const env = { "INPUT_SEVERITY-THRESHOLD": "  high  " };
  assert.equal(getInput("severity-threshold", env), "high");
});

test("getInput returns empty string when unset", () => {
  assert.equal(getInput("missing", {}), "");
});

test("getInput preserves dashes and maps spaces to underscores (matching the runner)", () => {
  // The runner uppercases and replaces spaces with "_", but keeps hyphens.
  assert.equal(getInput("fail-on-findings", { "INPUT_FAIL-ON-FINDINGS": "true" }), "true");
  assert.equal(getInput("two words", { INPUT_TWO_WORDS: "x" }), "x");
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

// ---------------------------------------------------------------------------
// P0-2: workflow-command injection. The finding-derived `message` and `file`
// are attacker-controlled in a fork PR and must not break out of the command.
// ---------------------------------------------------------------------------

test("formatCommand: a hostile filename cannot break out of the property list", () => {
  // ',' would start a new property; ':' would close the property list; CR/LF
  // would terminate the command. All are percent-encoded in properties.
  const out = formatCommand("error", "boom", {
    file: "a,b:c\nd::e]f.ts",
    line: 1,
  });
  // The encoded file must contain no raw ',' ':' or newline that could break out.
  assert.match(out, /file=a%2Cb%3Ac%0Ad%3A%3Ae\]f\.ts,/);
  // Exactly two raw "::" — the command's own opening "::error" and the
  // properties→message separator. The injected "::" was percent-encoded, so no
  // extra delimiter could be smuggled in.
  assert.equal(out.split("::").length - 1, 2);
  assert.doesNotMatch(out, /\n/);
});

test("formatCommand: a hostile message cannot inject a new command", () => {
  // Newlines in the data section are encoded so an attacker cannot start a
  // fresh "::set-output::" / "::error::" line; '%' is encoded too.
  const message = "ok\n::set-output name=x::pwned\r100%done";
  const out = formatCommand("error", message, { file: "f.ts", line: 2 });
  assert.match(out, /::error file=f\.ts,line=2::/);
  // No raw newline / CR survived in the data section, so no second command line.
  assert.doesNotMatch(out, /\n/);
  assert.doesNotMatch(out, /\r/);
  assert.match(out, /ok%0A::set-output name=x::pwned%0D100%25done/);
  // The whole thing is still a single line (one workflow command).
  assert.equal(out.split("\n").length, 1);
});

test("formatCommand: backticks/']' in text are inert in a workflow command", () => {
  // These are not workflow-command metacharacters, so they pass through
  // verbatim — confirming we don't over-escape and corrupt the message.
  const out = formatCommand("warning", "use `RSA` here ]", { file: "x.ts", line: 1 });
  assert.equal(out, "::warning file=x.ts,line=1::use `RSA` here ]");
});

test("setOutput appends a heredoc entry to $GITHUB_OUTPUT with a random delimiter", () => {
  const dir = mkdtempSync(join(tmpdir(), "quantakrypto-out-"));
  const file = join(dir, "out.txt");
  const env = { GITHUB_OUTPUT: file };
  setOutput("findings-count", "3", env);
  setOutput("readiness-score", "88", env);
  const contents = readFileSync(file, "utf8");
  // The delimiter is a fresh ghadelimiter_<uuid> per call, not the predictable
  // name-derived form, so a value can never pre-guess and forge it.
  assert.match(
    contents,
    /findings-count<<ghadelimiter_[0-9a-f-]{36}\n3\nghadelimiter_[0-9a-f-]{36}\n/,
  );
  assert.match(
    contents,
    /readiness-score<<ghadelimiter_[0-9a-f-]{36}\n88\nghadelimiter_[0-9a-f-]{36}\n/,
  );
  // The legacy predictable delimiter must no longer appear.
  assert.doesNotMatch(contents, /ghadelimiter_findings-count/);
});

// ---------------------------------------------------------------------------
// P0: output injection via a forged heredoc delimiter. With the old predictable
// `ghadelimiter_<name>`, a value containing that exact line could close the
// heredoc early and start a second `forged<<…` block, injecting other outputs.
// The random delimiter defeats this; the explicit guards add defense in depth.
// ---------------------------------------------------------------------------

test("setOutput: a value that forges the heredoc framing is contained, not injected", () => {
  const dir = mkdtempSync(join(tmpdir(), "quantakrypto-out-"));
  const file = join(dir, "out.txt");
  const env = { GITHUB_OUTPUT: file };
  // An attacker-shaped value that tries to close the (predictable) heredoc and
  // open a fresh `is-admin<<…` output.
  const hostile = [
    "ghadelimiter_findings-count",
    "is-admin<<ghadelimiter_is-admin",
    "true",
    "ghadelimiter_is-admin",
  ].join("\n");
  setOutput("findings-count", hostile, env);
  const contents = readFileSync(file, "utf8");
  // The forged content is sandwiched between the two RANDOM delimiters, so it is
  // the literal VALUE of findings-count — it never becomes its own output entry.
  const m = contents.match(/findings-count<<(ghadelimiter_[0-9a-f-]{36})\n([\s\S]*?)\n\1\n/);
  assert.ok(m, "expected a single random-delimited heredoc entry");
  assert.equal(m![2], hostile, "the hostile lines stay inside the value, not as new outputs");
});

test("setOutput rejects an output name containing a newline", () => {
  const dir = mkdtempSync(join(tmpdir(), "quantakrypto-out-"));
  const env = { GITHUB_OUTPUT: join(dir, "out.txt") };
  assert.throws(() => setOutput("bad\nname", "v", env), /should not contain a CR or LF/);
});
