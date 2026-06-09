/**
 * Tests for the `qproof.config.json` loader (P2-9): parsing, type validation,
 * detector-family mapping, baseline path resolution, and tolerant absence.
 */
import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { loadConfig, ConfigError, CONFIG_FILENAME } from "../src/config.js";

/** Create a temp dir, run `fn`, then clean up. */
async function withTempDir<T>(fn: (dir: string) => Promise<T>): Promise<T> {
  const dir = await mkdtemp(join(tmpdir(), "qproof-config-"));
  try {
    return await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

/** Write `qproof.config.json` into `dir` with the given object. */
async function writeConfig(dir: string, obj: unknown): Promise<string> {
  const file = join(dir, CONFIG_FILENAME);
  await writeFile(file, JSON.stringify(obj), "utf8");
  return file;
}

test("absent config is tolerated (returns empty config, no path)", async () => {
  await withTempDir(async (dir) => {
    const res = await loadConfig(dir);
    assert.deepEqual(res.config, {});
    assert.equal(res.path, undefined);
    assert.deepEqual(res.warnings, []);
  });
});

test("explicit missing file is an error", async () => {
  await withTempDir(async (dir) => {
    await assert.rejects(
      () => loadConfig(join(dir, CONFIG_FILENAME), { explicit: true }),
      ConfigError,
    );
  });
});

test("valid config parses all known scalar/list keys", async () => {
  await withTempDir(async (dir) => {
    await writeConfig(dir, {
      version: 1,
      include: ["src/**"],
      exclude: ["**/vendor/**"],
      noDefaultIgnores: true,
      maxFileSize: 4096,
      scanMinified: true,
      severityThreshold: "medium",
    });
    const res = await loadConfig(dir);
    assert.equal(res.path, join(dir, CONFIG_FILENAME));
    assert.deepEqual(res.config.include, ["src/**"]);
    assert.deepEqual(res.config.exclude, ["**/vendor/**"]);
    assert.equal(res.config.noDefaultIgnores, true);
    assert.equal(res.config.maxFileSize, 4096);
    assert.equal(res.config.scanMinified, true);
    assert.equal(res.config.severityThreshold, "medium");
    assert.deepEqual(res.warnings, []);
  });
});

test("detector families map onto source/config/dependencies toggles", async () => {
  await withTempDir(async (dir) => {
    await writeConfig(dir, {
      detectors: {
        "node-crypto": false, // source-scope
        dependencies: false,
        "tls-config": false, // config-scope
        webcrypto: true, // true is a no-op
      },
    });
    const res = await loadConfig(dir);
    assert.equal(res.config.source, false);
    assert.equal(res.config.dependencies, false);
    assert.equal(res.config.config, false);
  });
});

test("baseline path is resolved relative to the config file's directory", async () => {
  await withTempDir(async (dir) => {
    await writeConfig(dir, { baseline: ".qproof/baseline.json" });
    const res = await loadConfig(dir);
    assert.equal(res.config.baseline, join(dir, ".qproof", "baseline.json"));
  });
});

test("absolute baseline path is kept verbatim", async () => {
  await withTempDir(async (dir) => {
    const abs = join(dir, "abs-baseline.json");
    await writeConfig(dir, { baseline: abs });
    const res = await loadConfig(dir);
    assert.equal(res.config.baseline, abs);
  });
});

test("unknown top-level keys warn but do not fail", async () => {
  await withTempDir(async (dir) => {
    await writeConfig(dir, { include: ["src"], somethingNew: 42 });
    const res = await loadConfig(dir);
    assert.deepEqual(res.config.include, ["src"]);
    assert.ok(res.warnings.some((w) => w.includes("somethingNew")));
  });
});

test("a future config version warns but still loads", async () => {
  await withTempDir(async (dir) => {
    await writeConfig(dir, { version: 99, maxFileSize: 1 });
    const res = await loadConfig(dir);
    assert.equal(res.config.maxFileSize, 1);
    assert.ok(res.warnings.some((w) => w.includes("99")));
  });
});

test("languages is accepted (validated) but inert (warns)", async () => {
  await withTempDir(async (dir) => {
    await writeConfig(dir, { languages: ["python", "go"] });
    const res = await loadConfig(dir);
    assert.ok(res.warnings.some((w) => w.includes("languages")));
  });
});

test("a wrong value type for a known key is a ConfigError", async () => {
  await withTempDir(async (dir) => {
    await writeConfig(dir, { maxFileSize: "huge" });
    await assert.rejects(() => loadConfig(dir), ConfigError);
  });
  await withTempDir(async (dir) => {
    await writeConfig(dir, { include: "src" }); // must be an array
    await assert.rejects(() => loadConfig(dir), ConfigError);
  });
  await withTempDir(async (dir) => {
    await writeConfig(dir, { severityThreshold: "nuclear" });
    await assert.rejects(() => loadConfig(dir), ConfigError);
  });
  await withTempDir(async (dir) => {
    await writeConfig(dir, { noDefaultIgnores: "yes" });
    await assert.rejects(() => loadConfig(dir), ConfigError);
  });
});

test("malformed JSON is a ConfigError", async () => {
  await withTempDir(async (dir) => {
    await writeFile(join(dir, CONFIG_FILENAME), "{ not json", "utf8");
    await assert.rejects(() => loadConfig(dir), ConfigError);
  });
});

test("a non-object top-level value is a ConfigError", async () => {
  await withTempDir(async (dir) => {
    await writeFile(join(dir, CONFIG_FILENAME), "[1, 2, 3]", "utf8");
    await assert.rejects(() => loadConfig(dir), ConfigError);
  });
});

test("an explicit file path (not a directory) is read directly", async () => {
  await withTempDir(async (dir) => {
    const file = await writeConfig(dir, { maxFileSize: 7 });
    const res = await loadConfig(file, { explicit: true });
    assert.equal(res.path, file);
    assert.equal(res.config.maxFileSize, 7);
  });
});
