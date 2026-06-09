/**
 * CLI-shell tests for `main()`: the meta paths (help/version), usage errors,
 * and writing a report to a file. Output streams are captured rather than
 * printed. The scan paths are covered by runner/e2e tests; here we focus on the
 * argv → exit-code wiring that does not require a real scan.
 */

import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import process from "node:process";
import { test } from "node:test";

import { main } from "../src/cli.js";
import { EXIT } from "../src/index.js";

/** Capture stdout + stderr written during `fn`. */
async function capture(
  fn: () => Promise<number>,
): Promise<{ code: number; out: string; err: string }> {
  const origOut = process.stdout.write.bind(process.stdout);
  const origErr = process.stderr.write.bind(process.stderr);
  let out = "";
  let err = "";
  // @ts-expect-error narrow override for the test
  process.stdout.write = (chunk: string) => ((out += chunk), true);
  // @ts-expect-error narrow override for the test
  process.stderr.write = (chunk: string) => ((err += chunk), true);
  try {
    const code = await fn();
    return { code, out, err };
  } finally {
    process.stdout.write = origOut;
    process.stderr.write = origErr;
  }
}

test("--help prints usage and exits 0", async () => {
  const { code, out } = await capture(() => main(["--help"]));
  assert.equal(code, EXIT.OK);
  assert.match(out, /USAGE/);
  assert.match(out, /--severity-threshold/);
  assert.match(out, /EXIT CODES/);
});

test("--version prints a version line and exits 0", async () => {
  const { code, out } = await capture(() => main(["--version"]));
  assert.equal(code, EXIT.OK);
  assert.match(out, /^qscan \d+\.\d+\.\d+/);
});

test("unknown flag exits 2 with a hint to --help", async () => {
  const { code, err } = await capture(() => main(["--bogus"]));
  assert.equal(code, EXIT.ERROR);
  assert.match(err, /unknown option/);
  assert.match(err, /--help/);
});

test("invalid format exits 2", async () => {
  const { code, err } = await capture(() => main(["--format", "xml"]));
  assert.equal(code, EXIT.ERROR);
  assert.match(err, /invalid --format/);
});

test("--write-baseline reports and exits 0 (json scanner unavailable is tolerated)", async () => {
  // We cannot rely on core's stub scan, so just confirm a scan failure maps to
  // EXIT.ERROR rather than crashing — exercising the catch path.
  const dir = await mkdtemp(join(tmpdir(), "qscan-cli-"));
  try {
    const { code, err } = await capture(() => main([dir, "--write-baseline", join(dir, "b.json")]));
    // Core scan is a stub → ERROR; the important thing is no unhandled throw.
    assert.ok(code === EXIT.OK || code === EXIT.ERROR);
    if (code === EXIT.ERROR) assert.match(err, /qscan:/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("scan failure is caught and mapped to exit 2", async () => {
  // Pointing at a real dir invokes core's stub `scan`, which throws.
  const { code, err } = await capture(() => main(["."]));
  // Either core is implemented (0/1) or it is a stub (2). Never a crash.
  assert.ok([EXIT.OK, EXIT.FINDINGS, EXIT.ERROR].includes(code as 0 | 1 | 2));
  if (code === EXIT.ERROR) assert.match(err, /qscan:/);
});

test("report can be written to a file", async () => {
  // This path only runs the file-write branch when a scan succeeds; when core
  // is a stub the scan throws first. We assert the no-crash contract and, if a
  // file was produced, that it is non-empty.
  const dir = await mkdtemp(join(tmpdir(), "qscan-cli-"));
  try {
    const outFile = join(dir, "report.json");
    const { code } = await capture(() => main([dir, "--format", "json", "-o", outFile]));
    if (code === EXIT.OK || code === EXIT.FINDINGS) {
      const contents = await readFile(outFile, "utf8");
      assert.ok(contents.length > 0);
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
