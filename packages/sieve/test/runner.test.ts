/**
 * S2: a stray, non-protocol line on the SUT's stdout (a banner, a log line,
 * progress noise) must NOT poison the runner. Previously any undecodable line
 * triggered `failAll`, rejecting every in-flight and future request; and stdout
 * had no per-line cap, so a runaway line could be buffered without bound. These
 * tests spawn tiny SUTs that exercise both behaviors.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { join } from "node:path";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";

import { Runner } from "../src/runner.js";

/** Write a probe .mjs SUT to a temp dir and return its path. */
function writeProbe(body: string): string {
  const probe = join(mkdtempSync(join(tmpdir(), "sieve-runner-")), "probe.mjs");
  writeFileSync(probe, body);
  return probe;
}

test("a banner line on stdout does not kill an otherwise-valid run", async () => {
  // The SUT prints a human banner BEFORE answering, then replies with a valid
  // protocol line. A conformant-but-chatty SUT must still be drivable.
  const probe = writeProbe(
    [
      "import { createInterface } from 'node:readline';",
      // Noise to stdout before any request arrives.
      "process.stdout.write('quantakrypto SUT v1.2.3 — starting up\\n');",
      "const rl = createInterface({ input: process.stdin });",
      "rl.on('line', (line) => {",
      "  if (!line.trim()) return;",
      "  const r = JSON.parse(line);",
      // More noise interleaved with the real answer.
      "  process.stdout.write('debug: handling request ' + r.id + '\\n');",
      "  process.stdout.write(JSON.stringify({ id: r.id, ok: true, valid: true }) + '\\n');",
      "});",
    ].join("\n"),
  );

  const notes: string[] = [];
  const runner = new Runner({
    command: [process.execPath, probe],
    timeoutMs: 10_000,
    onStderr: (l) => notes.push(l),
  });
  try {
    const resp = await runner.send({
      family: "ml-dsa",
      param: "ml-dsa-65",
      op: "verify",
      pk: "",
      msg: "",
      sig: "",
    });
    assert.equal(resp.ok, true);
    assert.ok("valid" in resp && resp.valid === true, "the real protocol response still arrived");
    // A second request must also succeed — the runner was not poisoned.
    const resp2 = await runner.send({
      family: "ml-dsa",
      param: "ml-dsa-65",
      op: "verify",
      pk: "",
      msg: "",
      sig: "",
    });
    assert.ok("valid" in resp2 && resp2.valid === true);
  } finally {
    await runner.close();
  }
  // The banner/debug lines were sidelined to the stderr sink, not made fatal.
  assert.ok(
    notes.some((n) => /ignored non-protocol stdout line/.test(n)),
    "non-protocol stdout lines should be surfaced via onStderr",
  );
});

test("an oversized stdout line is sidelined, not buffered or made fatal", async () => {
  // The SUT emits one enormous non-protocol line (no newline for a long time),
  // then a valid response. The giant line must be capped/ignored, not buffered
  // without bound nor treated as a protocol violation that aborts the run.
  const probe = writeProbe(
    [
      "import { createInterface } from 'node:readline';",
      "const rl = createInterface({ input: process.stdin });",
      "rl.on('line', (line) => {",
      "  if (!line.trim()) return;",
      "  const r = JSON.parse(line);",
      // ~512 KiB of junk on a single stdout line, then the real answer.
      "  process.stdout.write('x'.repeat(512 * 1024) + '\\n');",
      "  process.stdout.write(JSON.stringify({ id: r.id, ok: true, valid: false }) + '\\n');",
      "});",
    ].join("\n"),
  );

  const runner = new Runner({ command: [process.execPath, probe], timeoutMs: 10_000 });
  try {
    const resp = await runner.send({
      family: "ml-dsa",
      param: "ml-dsa-65",
      op: "verify",
      pk: "",
      msg: "",
      sig: "",
    });
    assert.equal(resp.ok, true);
    assert.ok("valid" in resp && resp.valid === false, "valid response survives the oversize line");
  } finally {
    await runner.close();
  }
});
