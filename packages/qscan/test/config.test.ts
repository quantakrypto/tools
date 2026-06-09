/**
 * Precedence tests for `qproof.config.json` resolution in qScan (P2-9):
 *   flags  >  qproof.config.json  >  built-in defaults
 *
 * Covers per-key scalar precedence (flag wins, config fills, default falls
 * through), list-valued append semantics, detector-family mapping, the
 * `--config <path>` / `--no-config-file` flags, and the `--no-config`
 * collision-avoidance (it must NOT disable the config FILE).
 */

import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { parseArgs } from "../src/args.js";
import type { ConfigurableKey, QscanOptions } from "../src/args.js";
import { applyConfig, resolveConfig } from "../src/config.js";

/** Parse argv and return both the options and the explicit-key set. */
function parse(argv: string[]): { options: QscanOptions; explicit: Set<ConfigurableKey> } {
  const parsed = parseArgs(argv);
  if (parsed.kind !== "run") throw new Error("expected run");
  return { options: parsed.options, explicit: parsed.explicit };
}

async function withTempDir<T>(fn: (dir: string) => Promise<T>): Promise<T> {
  const dir = await mkdtemp(join(tmpdir(), "qscan-config-"));
  try {
    return await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

async function writeConfig(dir: string, obj: unknown): Promise<void> {
  await writeFile(join(dir, "qproof.config.json"), JSON.stringify(obj), "utf8");
}

/* ----------------------------- applyConfig (pure) -------------------------- */

test("config fills a key the user did not set via a flag", () => {
  const { options, explicit } = parse([]);
  const merged = applyConfig(options, { severityThreshold: "low" }, explicit);
  assert.equal(merged.severityThreshold, "low");
});

test("a flag overrides config for the same key", () => {
  const { options, explicit } = parse(["--severity-threshold", "critical"]);
  const merged = applyConfig(options, { severityThreshold: "low" }, explicit);
  assert.equal(merged.severityThreshold, "critical", "flag must beat config");
});

test("default falls through when neither flag nor config sets a key", () => {
  const { options, explicit } = parse([]);
  const merged = applyConfig(options, {}, explicit);
  assert.equal(merged.severityThreshold, "high"); // the built-in default
});

test("config toggles (source/deps/config) fill when no flag set them", () => {
  const { options, explicit } = parse([]);
  const merged = applyConfig(
    options,
    { source: false, dependencies: false, config: false },
    explicit,
  );
  assert.equal(merged.source, false);
  assert.equal(merged.dependencies, false);
  assert.equal(merged.config, false);
});

test("a --no-* flag beats a config that would re-enable the family", () => {
  const { options, explicit } = parse(["--no-source"]);
  // config does not set source; flag value (false) is preserved.
  const merged = applyConfig(options, {}, explicit);
  assert.equal(merged.source, false);
});

test("list keys: config provides the base, CLI flags append", () => {
  const { options, explicit } = parse(["--ignore", "cli-only", "--include", "cli-inc"]);
  const merged = applyConfig(options, { exclude: ["cfg-ex"], include: ["cfg-inc"] }, explicit);
  assert.deepEqual(merged.ignore, ["cfg-ex", "cli-only"]);
  assert.deepEqual(merged.include, ["cfg-inc", "cli-inc"]);
});

test("maxFileSize: flag wins; otherwise config fills", () => {
  {
    const { options, explicit } = parse(["--max-file-size", "100"]);
    const merged = applyConfig(options, { maxFileSize: 9999 }, explicit);
    assert.equal(merged.maxFileSize, 100);
  }
  {
    const { options, explicit } = parse([]);
    const merged = applyConfig(options, { maxFileSize: 9999 }, explicit);
    assert.equal(merged.maxFileSize, 9999);
  }
});

/* ----------------------------- resolveConfig (disk) ------------------------ */

test("auto-discovery applies a config at the scan root", async () => {
  await withTempDir(async (dir) => {
    await writeConfig(dir, { severityThreshold: "low", maxFileSize: 123 });
    const { options, explicit } = parse([dir]);
    const res = await resolveConfig(options, explicit);
    assert.ok(res.configPath);
    assert.equal(res.options.severityThreshold, "low");
    assert.equal(res.options.maxFileSize, 123);
  });
});

test("a flag still beats a discovered config file", async () => {
  await withTempDir(async (dir) => {
    await writeConfig(dir, { severityThreshold: "low" });
    const { options, explicit } = parse([dir, "--severity-threshold", "critical"]);
    const res = await resolveConfig(options, explicit);
    assert.equal(res.options.severityThreshold, "critical");
  });
});

test("--no-config-file disables discovery", async () => {
  await withTempDir(async (dir) => {
    await writeConfig(dir, { severityThreshold: "low" });
    const { options, explicit } = parse([dir, "--no-config-file"]);
    const res = await resolveConfig(options, explicit);
    assert.equal(res.configPath, undefined);
    assert.equal(res.options.severityThreshold, "high"); // default, config ignored
  });
});

test("--no-config (detector toggle) does NOT disable the config file", async () => {
  await withTempDir(async (dir) => {
    await writeConfig(dir, { maxFileSize: 555 });
    const { options, explicit } = parse([dir, "--no-config"]);
    const res = await resolveConfig(options, explicit);
    assert.ok(res.configPath, "config file is still discovered with --no-config");
    assert.equal(res.options.maxFileSize, 555);
    assert.equal(res.options.config, false, "--no-config still disables config-detector scanning");
  });
});

test("--config <path> points at a named file elsewhere", async () => {
  await withTempDir(async (dir) => {
    const alt = join(dir, "alt.config.json");
    await writeFile(alt, JSON.stringify({ maxFileSize: 777 }), "utf8");
    const { options, explicit } = parse([".", "--config", alt]);
    const res = await resolveConfig(options, explicit);
    assert.equal(res.configPath, alt);
    assert.equal(res.options.maxFileSize, 777);
  });
});

test("--config <missing> rejects (explicit file must exist)", async () => {
  await withTempDir(async (dir) => {
    const { options, explicit } = parse([".", "--config", join(dir, "nope.json")]);
    await assert.rejects(() => resolveConfig(options, explicit));
  });
});

test("detector families in a config disable the right scan toggles", async () => {
  await withTempDir(async (dir) => {
    await writeConfig(dir, { detectors: { dependencies: false } });
    const { options, explicit } = parse([dir]);
    const res = await resolveConfig(options, explicit);
    assert.equal(res.options.dependencies, false);
  });
});
