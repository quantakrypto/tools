import assert from "node:assert/strict";
import { test } from "node:test";

import { mdCell } from "../src/escape.js";

test("mdCell passes ordinary text through unchanged", () => {
  assert.equal(mdCell("src/crypto.ts:10"), "src/crypto.ts:10");
});

test("mdCell escapes pipes so a cell cannot end early", () => {
  assert.equal(mdCell("a|b|c"), "a\\|b\\|c");
});

test("mdCell escapes backticks so an inline code span cannot open", () => {
  assert.equal(mdCell("a`b`c"), "a\\`b\\`c");
});

test("mdCell entity-encodes HTML so raw tags cannot render", () => {
  assert.equal(mdCell('<img src=x onerror="y">'), '&lt;img src=x onerror="y"&gt;');
  assert.equal(mdCell("a & b"), "a &amp; b");
  assert.equal(mdCell("<script>"), "&lt;script&gt;");
});

test("mdCell flattens CR/LF runs to a single space (no new rows)", () => {
  assert.equal(mdCell("line1\nline2"), "line1 line2");
  assert.equal(mdCell("a\r\n\r\nb"), "a b");
});

test("mdCell doubles backslashes so escapes cannot be undone", () => {
  // A trailing backslash before a pipe would otherwise un-escape it.
  assert.equal(mdCell("x\\"), "x\\\\");
  assert.equal(mdCell("x\\|"), "x\\\\\\|");
});

test("mdCell handles a combined hostile payload", () => {
  const out = mdCell("] | `code` <b>\n::x");
  // No raw pipe, backtick, '<', '>' or newline survives.
  assert.doesNotMatch(out, /(?<!\\)\|/);
  assert.doesNotMatch(out, /(?<!\\)`/);
  assert.doesNotMatch(out, /[<>\r\n]/);
});

test("mdCell clips pathologically long input", () => {
  const out = mdCell("a".repeat(5000));
  assert.ok(out.length <= 513); // 512 chars + the ellipsis
  assert.ok(out.endsWith("…"));
});
