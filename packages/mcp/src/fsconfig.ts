/**
 * Filesystem-tool safety policy for the quantakrypto MCP (P0 — FS confinement
 * and work budgets).
 *
 * The FS-backed tools (`scan_path`, `inventory_crypto`, `generate_cbom`) pass a
 * caller-supplied `path` straight into `@quantakrypto/core`'s `scan()`. With the
 * filesystem tools enabled (`QUANTAKRYPTO_MCP_ALLOW_FS=1`) that turns the server
 * into an arbitrary-file-read oracle: `path` could be `/etc/passwd` or any tree
 * on the host (SECURITY.md warns about exactly this). This module turns that
 * warning into enforced policy:
 *
 *   - **Root allow-list** (`QUANTAKRYPTO_MCP_ROOT`, `:`-separated): every scanned
 *     path must resolve inside one of the configured roots. When unset, the
 *     process CWD is the single implicit root.
 *   - **`..` traversal rejection**: a resolved path that escapes every root is
 *     refused, even if the literal string contained no `..`.
 *   - **Work budgets** (`maxFiles` / `maxBytes`): bounded by default and capped,
 *     so a single `scan_path` cannot exhaust host resources.
 *
 * Everything here is a pure function of an env snapshot + the requested path so
 * it is fully unit-testable; only {@link resolveFsConfig} reads `process.env`.
 */

import * as path from "node:path";
import process from "node:process";

/** Minimal env shape so the resolver stays pure and testable. */
export type FsEnv = Record<string, string | undefined>;

/** Default file-count budget for a single FS tool call. */
export const DEFAULT_MAX_FILES = 25_000;

/** Hard cap on the file-count budget, even when raised via env. */
export const MAX_MAX_FILES = 250_000;

/** Default cumulative-bytes budget for a single FS tool call (256 MiB). */
export const DEFAULT_MAX_BYTES = 256 * 1024 * 1024;

/** Hard cap on the cumulative-bytes budget, even when raised via env (2 GiB). */
export const MAX_MAX_BYTES = 2 * 1024 * 1024 * 1024;

/** Resolved FS-tool policy: where scans may read and how much work they may do. */
export interface FsConfig {
  /**
   * Absolute, normalized roots a scan may read inside. Always non-empty; defaults
   * to `[process.cwd()]` when `QUANTAKRYPTO_MCP_ROOT` is unset.
   */
  roots: string[];
  /** Max files a single scan may read before {@link BudgetExceededError}. */
  maxFiles: number;
  /** Max cumulative bytes a single scan may read before {@link BudgetExceededError}. */
  maxBytes: number;
}

/** Parse a positive integer from an env string, clamped to `[1, cap]`. */
function toBudget(value: string | undefined, fallback: number, cap: number): number {
  if (value === undefined) return Math.min(fallback, cap);
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0) return Math.min(fallback, cap);
  return Math.min(Math.floor(n), cap);
}

/** Split the `:`-separated root allow-list, dropping empty segments. */
function parseRoots(value: string | undefined, cwd: string): string[] {
  const raw = (value ?? "")
    .split(path.delimiter)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  const list = raw.length > 0 ? raw : [cwd];
  // Normalize to absolute, de-duplicated roots.
  const seen = new Set<string>();
  const roots: string[] = [];
  for (const r of list) {
    const abs = path.resolve(cwd, r);
    if (!seen.has(abs)) {
      seen.add(abs);
      roots.push(abs);
    }
  }
  return roots;
}

/**
 * Resolve the FS-tool policy from an env snapshot. Pure aside from the supplied
 * `cwd` default (so callers/tests can pin it).
 */
export function resolveFsConfig(env: FsEnv, cwd: string = process.cwd()): FsConfig {
  return {
    roots: parseRoots(env.QUANTAKRYPTO_MCP_ROOT, cwd),
    maxFiles: toBudget(env.QUANTAKRYPTO_MCP_MAX_FILES, DEFAULT_MAX_FILES, MAX_MAX_FILES),
    maxBytes: toBudget(env.QUANTAKRYPTO_MCP_MAX_BYTES, DEFAULT_MAX_BYTES, MAX_MAX_BYTES),
  };
}

/** Outcome of validating a requested path against the root allow-list. */
export type PathDecision = { ok: true; path: string } | { ok: false; reason: string };

/** True when `child` is `root` itself or lives beneath it (no `..` escape). */
function isInsideRoot(child: string, root: string): boolean {
  if (child === root) return true;
  const rel = path.relative(root, child);
  // `rel` starting with ".." (or being absolute) means `child` escapes `root`.
  return rel.length > 0 && !rel.startsWith("..") && !path.isAbsolute(rel);
}

/**
 * Validate and resolve a caller-supplied scan path against the allow-list.
 *
 * Relative paths are resolved against the FIRST configured root (the primary
 * scan root), not the process CWD, so a relative request can never reach outside
 * the allow-list. Absolute paths must already sit inside a configured root. Any
 * path that resolves outside every root — whether via an absolute path or a
 * `..` traversal — is rejected. Pure: does no filesystem I/O (it does not follow
 * symlinks; the allow-list is the trust boundary).
 */
export function resolveScanPath(config: FsConfig, requested: string): PathDecision {
  const trimmed = requested.trim();
  if (trimmed.length === 0) {
    return { ok: false, reason: "path must be a non-empty string" };
  }

  const primaryRoot = config.roots[0];
  const resolved = path.isAbsolute(trimmed)
    ? path.resolve(trimmed)
    : path.resolve(primaryRoot, trimmed);

  for (const root of config.roots) {
    if (isInsideRoot(resolved, root)) {
      return { ok: true, path: resolved };
    }
  }
  return {
    ok: false,
    reason:
      "path is outside the configured scan root(s). " +
      "Set QUANTAKRYPTO_MCP_ROOT to allow-list the directories the MCP may scan.",
  };
}
