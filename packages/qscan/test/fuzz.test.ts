/**
 * Deterministic fuzz target for qScan's hand-rolled argv parser (ROADMAP
 * P1-10). Contract: `parseArgs` over an arbitrary argv array must either return
 * a well-typed {@link ParsedArgs} (run/help/version) or throw a typed
 * {@link ArgError} — never an unhandled throw of another type and never a
 * crash. Seeds are fixed (_fuzz.ts) so failures reproduce.
 */
import assert from "node:assert/strict";
import { test } from "node:test";

import { ArgError, parseArgs } from "../src/args.js";
import { FUZZ_ITERATIONS, makeRng } from "./_fuzz.js";
import type { Rng } from "./_fuzz.js";

/** A pool of real flags (some value-taking) plus junk tokens to interleave. */
const FLAGS = [
  "--format",
  "--cbom",
  "-o",
  "--output",
  "--severity-threshold",
  "--no-source",
  "--no-deps",
  "--no-config",
  "--config",
  "--no-config-file",
  "--ignore",
  "--include",
  "--max-file-size",
  "--no-default-ignores",
  "--scan-minified",
  "--changed",
  "--since",
  "--parallel",
  "--concurrency",
  "--baseline",
  "--write-baseline",
  "--quiet",
  "-h",
  "--help",
  "-v",
  "--version",
];

const VALUES = [
  "json",
  "sarif",
  "human",
  "cbom",
  "xml", // invalid format
  "critical",
  "nuclear", // invalid severity
  "123",
  "-5", // invalid int
  "out.json",
  "src",
  "origin/main",
  "./qproof.config.json",
];

/** Build a random argv: a mix of real flags, `--flag=value`, junk, positionals. */
function randomArgv(rng: Rng): string[] {
  const n = rng.int(0, 10);
  const argv: string[] = [];
  for (let i = 0; i < n; i++) {
    const kind = rng.int(0, 5);
    switch (kind) {
      case 0:
        argv.push(rng.pick(FLAGS));
        break;
      case 1:
        argv.push(`${rng.pick(FLAGS)}=${rng.pick(VALUES)}`);
        break;
      case 2:
        argv.push(rng.pick(VALUES));
        break;
      case 3:
        argv.push(rng.asciiString(rng.int(0, 12))); // arbitrary junk token
        break;
      case 4:
        argv.push("--" + rng.asciiString(rng.int(0, 8))); // unknown long flag
        break;
      default:
        argv.push("-" + rng.asciiString(rng.int(0, 3))); // unknown short flag
        break;
    }
  }
  return argv;
}

test("fuzz: parseArgs returns ParsedArgs or throws ArgError (never crashes)", () => {
  const rng = makeRng(0xa19_b175);
  for (let i = 0; i < FUZZ_ITERATIONS; i++) {
    const argv = randomArgv(rng);
    try {
      const parsed = parseArgs(argv);
      assert.ok(
        parsed.kind === "run" || parsed.kind === "help" || parsed.kind === "version",
        `unexpected kind on iteration ${i}: ${JSON.stringify(parsed)}`,
      );
      if (parsed.kind === "run") {
        // The resolved options must be coherent.
        assert.equal(typeof parsed.options.path, "string");
        assert.ok(["human", "json", "sarif", "cbom"].includes(parsed.options.format));
        assert.ok(Array.isArray(parsed.options.ignore));
        assert.ok(Array.isArray(parsed.options.include));
        assert.ok(parsed.explicit instanceof Set);
      }
    } catch (err) {
      assert.ok(
        err instanceof ArgError,
        `parseArgs threw a non-ArgError on iteration ${i}: ${String(err)}\nargv: ${JSON.stringify(argv)}`,
      );
    }
  }
});
