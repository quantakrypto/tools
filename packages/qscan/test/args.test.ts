/**
 * Argument-parsing tests: defaults, every flag, value forms, and errors.
 */

import assert from "node:assert/strict";
import { test } from "node:test";

import {
  ArgError,
  asFormat,
  asSeverity,
  defaultOptions,
  meetsThreshold,
  parseArgs,
  severityRank,
} from "../src/args.js";

test("defaults are applied when no args are given", () => {
  const parsed = parseArgs([]);
  assert.equal(parsed.kind, "run");
  if (parsed.kind !== "run") return;
  const o = parsed.options;
  assert.equal(o.path, ".");
  assert.equal(o.format, "human");
  assert.equal(o.severityThreshold, "high");
  assert.equal(o.source, true);
  assert.equal(o.dependencies, true);
  assert.equal(o.config, true);
  assert.deepEqual(o.ignore, []);
  assert.equal(o.quiet, false);
  assert.equal(o.output, undefined);
  assert.equal(o.baseline, undefined);
  assert.equal(o.writeBaseline, undefined);
});

test("matches defaultOptions()", () => {
  const parsed = parseArgs([]);
  if (parsed.kind !== "run") throw new Error("expected run");
  assert.deepEqual(parsed.options, defaultOptions());
});

test("positional path is captured", () => {
  const parsed = parseArgs(["packages/core"]);
  if (parsed.kind !== "run") throw new Error("expected run");
  assert.equal(parsed.options.path, "packages/core");
});

test("-h / --help short-circuit to help", () => {
  assert.equal(parseArgs(["-h"]).kind, "help");
  assert.equal(parseArgs(["--help"]).kind, "help");
  // help wins even with other args present
  assert.equal(parseArgs(["src", "--format", "json", "--help"]).kind, "help");
});

test("-v / --version short-circuit to version", () => {
  assert.equal(parseArgs(["-v"]).kind, "version");
  assert.equal(parseArgs(["--version"]).kind, "version");
});

test("--format with space and = forms", () => {
  for (const args of [["--format", "json"], ["--format=json"]]) {
    const parsed = parseArgs(args);
    if (parsed.kind !== "run") throw new Error("expected run");
    assert.equal(parsed.options.format, "json");
  }
});

test("-o / --output set the report file", () => {
  const a = parseArgs(["-o", "out.json"]);
  const b = parseArgs(["--output=out.sarif"]);
  if (a.kind !== "run" || b.kind !== "run") throw new Error("expected run");
  assert.equal(a.options.output, "out.json");
  assert.equal(b.options.output, "out.sarif");
});

test("--severity-threshold is parsed and validated", () => {
  const parsed = parseArgs(["--severity-threshold", "critical"]);
  if (parsed.kind !== "run") throw new Error("expected run");
  assert.equal(parsed.options.severityThreshold, "critical");
});

test("--no-source / --no-deps / --no-config toggle off", () => {
  const parsed = parseArgs(["--no-source", "--no-deps", "--no-config"]);
  if (parsed.kind !== "run") throw new Error("expected run");
  assert.equal(parsed.options.source, false);
  assert.equal(parsed.options.dependencies, false);
  assert.equal(parsed.options.config, false);
});

test("--ignore is repeatable", () => {
  const parsed = parseArgs(["--ignore", "test", "--ignore", "examples"]);
  if (parsed.kind !== "run") throw new Error("expected run");
  assert.deepEqual(parsed.options.ignore, ["test", "examples"]);
});

test("--baseline and --write-baseline are captured", () => {
  const parsed = parseArgs(["--baseline", "b.json", "--write-baseline", "w.json"]);
  if (parsed.kind !== "run") throw new Error("expected run");
  assert.equal(parsed.options.baseline, "b.json");
  assert.equal(parsed.options.writeBaseline, "w.json");
});

test("--quiet sets quiet", () => {
  const parsed = parseArgs(["--quiet"]);
  if (parsed.kind !== "run") throw new Error("expected run");
  assert.equal(parsed.options.quiet, true);
});

test("mixed flags + positional in any order", () => {
  const parsed = parseArgs(["--format", "sarif", "src/lib", "--quiet"]);
  if (parsed.kind !== "run") throw new Error("expected run");
  assert.equal(parsed.options.format, "sarif");
  assert.equal(parsed.options.path, "src/lib");
  assert.equal(parsed.options.quiet, true);
});

test("unknown option throws ArgError", () => {
  assert.throws(() => parseArgs(["--nope"]), ArgError);
  assert.throws(() => parseArgs(["-x"]), ArgError);
});

test("missing value throws ArgError", () => {
  assert.throws(() => parseArgs(["--format"]), ArgError);
  assert.throws(() => parseArgs(["--output"]), ArgError);
  // a following flag is not consumed as a value
  assert.throws(() => parseArgs(["--format", "--quiet"]), ArgError);
});

test("invalid enum values throw ArgError", () => {
  assert.throws(() => parseArgs(["--format", "xml"]), ArgError);
  assert.throws(() => parseArgs(["--severity-threshold", "nuclear"]), ArgError);
});

test("two positionals throw ArgError", () => {
  assert.throws(() => parseArgs(["a", "b"]), ArgError);
});

test("asFormat / asSeverity validate", () => {
  assert.equal(asFormat("human"), "human");
  assert.equal(asSeverity("low"), "low");
  assert.throws(() => asFormat("bogus"), ArgError);
  assert.throws(() => asSeverity("bogus"), ArgError);
});

test("severityRank orders critical < info", () => {
  assert.ok(severityRank("critical") < severityRank("high"));
  assert.ok(severityRank("high") < severityRank("medium"));
  assert.ok(severityRank("medium") < severityRank("low"));
  assert.ok(severityRank("low") < severityRank("info"));
});

test("meetsThreshold is at-or-above in seriousness", () => {
  assert.equal(meetsThreshold("critical", "high"), true);
  assert.equal(meetsThreshold("high", "high"), true);
  assert.equal(meetsThreshold("medium", "high"), false);
  assert.equal(meetsThreshold("info", "info"), true);
  assert.equal(meetsThreshold("critical", "info"), true);
});
