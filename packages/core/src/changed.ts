/**
 * Incremental-scan helper: list the files that changed in a git working tree,
 * for feeding into {@link ScanOptions.files}. Tolerant of non-git directories —
 * returns an empty list rather than throwing.
 */
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

/** Run a git command in `cwd`, returning stdout or `null` on any failure. */
async function git(cwd: string, args: string[]): Promise<string | null> {
  try {
    const { stdout } = await execFileAsync("git", args, {
      cwd,
      maxBuffer: 64 * 1024 * 1024,
      windowsHide: true,
    });
    return stdout;
  } catch {
    return null;
  }
}

/** Split git output into trimmed, non-empty, POSIX-relative path lines. */
function toLines(stdout: string | null): string[] {
  if (!stdout) return [];
  return stdout
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 0);
}

/**
 * Return the list of changed files (relative POSIX paths) under `root`.
 *
 * - With `since` (a ref / range), returns `git diff --name-only --diff-filter=ACMR <since>`
 *   plus currently-modified-but-uncommitted files, deduped.
 * - Without `since`, returns uncommitted changes (`git diff` working+staged) plus
 *   untracked files (`git ls-files --others --exclude-standard`).
 * - When `root` is not a git repository (or git is unavailable), returns `[]`.
 *
 * Deleted files are excluded (ACMR filter / existence is the caller's concern).
 */
export async function changedFiles(root: string, since?: string): Promise<string[]> {
  // Confirm this is a git work tree first; bail out tolerantly if not.
  const inside = await git(root, ["rev-parse", "--is-inside-work-tree"]);
  if (inside === null || inside.trim() !== "true") return [];

  const out = new Set<string>();

  if (since) {
    for (const f of toLines(await git(root, ["diff", "--name-only", "--diff-filter=ACMR", since]))) {
      out.add(f);
    }
  }

  // Always include local uncommitted edits (staged + unstaged), filtered to ACMR.
  for (const f of toLines(await git(root, ["diff", "--name-only", "--diff-filter=ACMR"]))) {
    out.add(f);
  }
  for (const f of toLines(await git(root, ["diff", "--name-only", "--diff-filter=ACMR", "--cached"]))) {
    out.add(f);
  }

  // Untracked (but not ignored) files.
  for (const f of toLines(await git(root, ["ls-files", "--others", "--exclude-standard"]))) {
    out.add(f);
  }

  return [...out].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}
