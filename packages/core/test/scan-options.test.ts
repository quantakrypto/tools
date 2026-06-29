/**
 * Tests for the repaired ScanOptions: `include` wiring, the explicit `files`
 * list (incremental scans), minified-file skipping, the `detectors` override,
 * and large-lockfile handling.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import * as path from "node:path";

import {
  scan,
  walkFiles,
  looksMinified,
  isGeneratedPath,
  AbortError,
  BudgetExceededError,
} from "../src/index.js";
import type { Detector } from "../src/index.js";

async function collect(iter: AsyncIterable<string>): Promise<string[]> {
  const out: string[] = [];
  for await (const x of iter) out.push(x);
  return out.sort();
}

async function makeTree(): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), "quantakrypto-opts-"));
  await mkdir(path.join(dir, "src"), { recursive: true });
  await mkdir(path.join(dir, "lib"), { recursive: true });
  await writeFile(path.join(dir, "src", "a.ts"), "const e = crypto.createECDH('p256');\n");
  await writeFile(path.join(dir, "lib", "b.ts"), "jwt.sign(p, k, { algorithm: 'RS256' });\n");
  return dir;
}

test("include filter restricts the walk", async () => {
  const dir = await makeTree();
  try {
    const files = await collect(walkFiles(dir, { include: ["src"] }));
    assert.deepEqual(files, ["src/a.ts"]);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("scan honours include (only src/ scanned)", async () => {
  const dir = await makeTree();
  try {
    const r = await scan({ root: dir, include: ["src"] });
    assert.ok(r.findings.some((f) => f.ruleId === "node-crypto-ecdh"));
    assert.ok(
      !r.findings.some((f) => f.ruleId === "jwt-classical-alg"),
      "lib/ excluded by include",
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("scan honours an explicit files list (incremental)", async () => {
  const dir = await makeTree();
  try {
    const r = await scan({ root: dir, files: ["lib/b.ts"] });
    assert.equal(r.filesScanned, 1);
    assert.ok(r.findings.some((f) => f.ruleId === "jwt-classical-alg"));
    assert.ok(!r.findings.some((f) => f.ruleId === "node-crypto-ecdh"), "src/a.ts not scanned");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("scan files-list ignores binaries and missing files gracefully", async () => {
  const dir = await makeTree();
  try {
    const r = await scan({ root: dir, files: ["lib/b.ts", "gone.ts", "image.png"] });
    assert.equal(r.filesScanned, 1);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("looksMinified flags long single-line content; isGeneratedPath flags bundles", () => {
  assert.ok(looksMinified("var a=1;".repeat(20_000)));
  assert.ok(!looksMinified("const a = 1;\nconst b = 2;\n"));
  assert.ok(isGeneratedPath("vendor.bundle.js"));
  assert.ok(isGeneratedPath("types.generated.ts"));
  assert.ok(!isGeneratedPath("index.ts"));
});

test("scan skips minified content by default but scans it with scanMinified", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "quantakrypto-min-"));
  try {
    // A long single-line file containing a crypto call.
    const line = "const x=1;".repeat(8000) + "crypto.createECDH('p256');";
    await writeFile(path.join(dir, "huge.ts"), line);
    const skipped = await scan({ root: dir });
    assert.equal(skipped.findings.length, 0, "minified file skipped by default");
    const scanned = await scan({ root: dir, scanMinified: true });
    assert.ok(scanned.findings.some((f) => f.ruleId === "node-crypto-ecdh"));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("scan accepts a detectors override", async () => {
  const dir = await makeTree();
  try {
    const onlyEcdh: Detector = {
      id: "only-ecdh",
      description: "test",
      scope: "source",
      language: "js",
      appliesTo: (f) => f.endsWith(".ts"),
      detect: ({ file, content }) =>
        content.includes("createECDH")
          ? [
              {
                ruleId: "only-ecdh",
                title: "x",
                category: "key-exchange",
                severity: "high",
                confidence: "high",
                hndl: true,
                message: "x",
                location: { file, line: 1 },
              },
            ]
          : [],
    };
    const r = await scan({ root: dir, detectors: [onlyEcdh] });
    const rules = new Set(r.findings.map((f) => f.ruleId));
    assert.ok(rules.has("only-ecdh"));
    assert.ok(!rules.has("node-crypto-ecdh"), "built-ins replaced by override");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

/** A tree of N tiny source files under src/, each with a crypto call. */
async function makeManyFiles(n: number): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), "quantakrypto-budget-"));
  await mkdir(path.join(dir, "src"), { recursive: true });
  for (let i = 0; i < n; i++) {
    await writeFile(
      path.join(dir, "src", `f${String(i).padStart(3, "0")}.ts`),
      "const e = crypto.createECDH('p256');\n",
    );
  }
  return dir;
}

test("scan aborts cooperatively via an AbortSignal", async () => {
  const dir = await makeManyFiles(10);
  try {
    const ctrl = new AbortController();
    let seen = 0;
    // Abort after the first file is reported; the next iteration must throw.
    await assert.rejects(
      scan({
        root: dir,
        signal: ctrl.signal,
        onFile: () => {
          seen += 1;
          if (seen === 1) ctrl.abort();
        },
      }),
      (err: unknown) => {
        assert.ok(err instanceof AbortError, "throws AbortError");
        assert.equal((err as Error).name, "AbortError");
        return true;
      },
    );
    // It stopped early rather than walking all 10 files.
    assert.ok(seen < 10, `aborted mid-walk (saw ${seen} of 10)`);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("scan throws BudgetExceededError when maxFiles is exceeded", async () => {
  const dir = await makeManyFiles(10);
  try {
    await assert.rejects(scan({ root: dir, maxFiles: 3 }), (err: unknown) => {
      assert.ok(err instanceof BudgetExceededError, "throws BudgetExceededError");
      assert.match((err as Error).message, /maxFiles/);
      return true;
    });
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("scan throws BudgetExceededError when maxBytes is exceeded", async () => {
  const dir = await makeManyFiles(10);
  try {
    // Each file is ~37 bytes; a 50-byte budget is blown after the second file.
    await assert.rejects(scan({ root: dir, maxBytes: 50 }), (err: unknown) => {
      assert.ok(err instanceof BudgetExceededError, "throws BudgetExceededError");
      assert.match((err as Error).message, /maxBytes/);
      return true;
    });
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("scan with generous budgets and no signal completes normally", async () => {
  const dir = await makeManyFiles(5);
  try {
    const r = await scan({ root: dir, maxFiles: 100, maxBytes: 1_000_000 });
    assert.equal(r.filesScanned, 5);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("large lockfiles over the size cap are still scanned for deps", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "quantakrypto-lock-"));
  try {
    // A package-lock.json larger than a small maxFileSize, containing a vuln dep.
    const lock = {
      name: "demo",
      lockfileVersion: 3,
      packages: { "": { name: "demo" }, "node_modules/elliptic": { version: "6.5.4" } },
      filler: "x".repeat(5000),
    };
    await writeFile(path.join(dir, "package-lock.json"), JSON.stringify(lock));
    const r = await scan({ root: dir, maxFileSize: 100 });
    assert.ok(
      r.findings.some((f) => f.ruleId === "dep-vulnerable"),
      "lockfile dep findings not dropped by the size cap",
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
