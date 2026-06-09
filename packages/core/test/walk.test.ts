/**
 * Tests for the filesystem walker: default ignores, exclude patterns, the
 * binary-extension and size filters, and single-file mode.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import * as path from "node:path";

import { walkFiles } from "../src/index.js";

/** Collect an async iterator into a sorted array. */
async function collect(iter: AsyncIterable<string>): Promise<string[]> {
  const out: string[] = [];
  for await (const x of iter) out.push(x);
  return out.sort();
}

async function makeTree(): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), "qproof-walk-"));
  await writeFile(path.join(dir, "a.ts"), "export const a = 1;\n");
  await mkdir(path.join(dir, "src"), { recursive: true });
  await writeFile(path.join(dir, "src", "b.js"), "const b = 2;\n");
  // default-ignored dir
  await mkdir(path.join(dir, "node_modules", "pkg"), { recursive: true });
  await writeFile(path.join(dir, "node_modules", "pkg", "index.js"), "x");
  // binary extension
  await writeFile(path.join(dir, "logo.png"), "not really an image");
  // excludable dir
  await mkdir(path.join(dir, "legacy"), { recursive: true });
  await writeFile(path.join(dir, "legacy", "old.ts"), "old");
  return dir;
}

test("walkFiles skips default ignores and binaries", async () => {
  const dir = await makeTree();
  try {
    const files = await collect(walkFiles(dir));
    assert.deepEqual(files, ["a.ts", "legacy/old.ts", "src/b.js"]);
    assert.ok(!files.includes("logo.png"), "binary extension skipped");
    assert.ok(!files.some((f) => f.startsWith("node_modules/")), "node_modules ignored");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("walkFiles honours exclude patterns", async () => {
  const dir = await makeTree();
  try {
    const files = await collect(walkFiles(dir, { exclude: ["legacy"] }));
    assert.ok(!files.some((f) => f.startsWith("legacy/")), "legacy/ excluded");
    assert.ok(files.includes("a.ts"));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("walkFiles honours noDefaultIgnores", async () => {
  const dir = await makeTree();
  try {
    const files = await collect(walkFiles(dir, { noDefaultIgnores: true }));
    assert.ok(
      files.includes("node_modules/pkg/index.js"),
      "node_modules included when ignores disabled",
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("walkFiles skips files larger than maxFileSize", async () => {
  const dir = await makeTree();
  try {
    await writeFile(path.join(dir, "big.ts"), "x".repeat(5000));
    const files = await collect(walkFiles(dir, { maxFileSize: 100 }));
    assert.ok(!files.includes("big.ts"), "oversized file skipped");
    assert.ok(files.includes("a.ts"), "small files still yielded");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("walkFiles supports single-file roots", async () => {
  const dir = await makeTree();
  try {
    const file = path.join(dir, "a.ts");
    const files = await collect(walkFiles(file));
    assert.deepEqual(files, ["a.ts"]);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
