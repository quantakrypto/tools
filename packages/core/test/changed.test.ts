/**
 * Tests for the changed-files incremental helper. Exercises the non-git
 * tolerance path always, and the git path when git is available on PATH.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

import { changedFiles } from "../src/index.js";

const execFileAsync = promisify(execFile);

async function gitAvailable(): Promise<boolean> {
  try {
    await execFileAsync("git", ["--version"], { windowsHide: true });
    return true;
  } catch {
    return false;
  }
}

test("changedFiles returns [] outside a git repo (tolerant)", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "quantakrypto-nogit-"));
  try {
    await writeFile(path.join(dir, "a.ts"), "x");
    assert.deepEqual(await changedFiles(dir), []);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("changedFiles lists untracked + modified files in a git repo", async (t) => {
  if (!(await gitAvailable())) {
    t.skip("git not available");
    return;
  }
  const dir = await mkdtemp(path.join(tmpdir(), "quantakrypto-git-"));
  try {
    const run = (args: string[]) => execFileAsync("git", args, { cwd: dir, windowsHide: true });
    await run(["init"]);
    await run(["config", "user.email", "t@example.com"]);
    await run(["config", "user.name", "t"]);
    await mkdir(path.join(dir, "src"), { recursive: true });
    await writeFile(path.join(dir, "src", "committed.ts"), "const a = 1;\n");
    await run(["add", "."]);
    await run(["commit", "-m", "init"]);

    // Now create an untracked file and modify a tracked one.
    await writeFile(path.join(dir, "src", "new.ts"), "const b = 2;\n");
    await writeFile(path.join(dir, "src", "committed.ts"), "const a = 2;\n");

    const changed = await changedFiles(dir);
    assert.ok(changed.includes("src/new.ts"), "untracked file listed");
    assert.ok(changed.includes("src/committed.ts"), "modified file listed");
    // Sorted output.
    assert.deepEqual([...changed].sort(), changed);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("changedFiles on a subdirectory returns paths relative to that subdir", async (t) => {
  if (!(await gitAvailable())) {
    t.skip("git not available");
    return;
  }
  const dir = await mkdtemp(path.join(tmpdir(), "quantakrypto-gitsub-"));
  try {
    const run = (args: string[], cwd = dir) =>
      execFileAsync("git", args, { cwd, windowsHide: true });
    await run(["init"]);
    await run(["config", "user.email", "t@example.com"]);
    await run(["config", "user.name", "t"]);
    await mkdir(path.join(dir, "pkg", "src"), { recursive: true });
    await mkdir(path.join(dir, "other"), { recursive: true });
    await writeFile(path.join(dir, "pkg", "src", "committed.ts"), "const a = 1;\n");
    await writeFile(path.join(dir, "other", "x.ts"), "const x = 1;\n");
    await run(["add", "."]);
    await run(["commit", "-m", "init"]);

    // Change a file inside the subdir, add an untracked one there, and touch a
    // sibling-dir file that must NOT show up when scanning the subdir.
    await writeFile(path.join(dir, "pkg", "src", "committed.ts"), "const a = 2;\n");
    await writeFile(path.join(dir, "pkg", "src", "new.ts"), "const b = 2;\n");
    await writeFile(path.join(dir, "other", "x.ts"), "const x = 2;\n");

    const subRoot = path.join(dir, "pkg");
    const changed = await changedFiles(subRoot);

    // Paths are relative to the subdir root (so scan() can join them), NOT
    // repo-root-relative ("pkg/src/...") — that was the silent-empty bug.
    assert.ok(changed.includes("src/committed.ts"), "modified file relative to subdir");
    assert.ok(changed.includes("src/new.ts"), "untracked file relative to subdir");
    assert.ok(
      !changed.some((f) => f.startsWith("pkg/") || f.includes("other/")),
      "no repo-root-relative or sibling-dir paths leak in",
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
