/**
 * Filesystem walker. A zero-dependency recursive async generator that yields
 * scannable text files as relative POSIX paths. It honours a default ignore
 * list, user-supplied exclude patterns, a max file size, and a binary-extension
 * filter. The root may be a directory or a single file.
 */
import { readdir, stat } from "node:fs/promises";
import type { Dirent } from "node:fs";
import * as path from "node:path";

/** Directories ignored by default (can be disabled with noDefaultIgnores). */
export const DEFAULT_IGNORES: readonly string[] = [
  "node_modules",
  ".git",
  "dist",
  "build",
  ".next",
  "out",
  "coverage",
  "vendor",
  ".turbo",
  ".cache",
];

/** Default maximum file size to read: 2 MiB. */
export const DEFAULT_MAX_FILE_SIZE = 2 * 1024 * 1024;

/**
 * File extensions we treat as binary / non-text and therefore skip. Keeping this
 * as an extension allow-list-by-exclusion is cheap and avoids reading bytes.
 */
const BINARY_EXTENSIONS = new Set<string>([
  // images
  ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".tiff", ".avif",
  // fonts
  ".woff", ".woff2", ".ttf", ".otf", ".eot",
  // archives / compressed
  ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".tar",
  // media
  ".mp3", ".mp4", ".mov", ".avi", ".mkv", ".wav", ".flac", ".ogg", ".webm",
  // documents / binaries
  ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
  ".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a", ".class", ".wasm",
  // data blobs / db
  ".db", ".sqlite", ".sqlite3", ".dat", ".pack", ".idx",
  // misc
  ".lock", ".map", ".min.js", ".node",
]);

/** Options accepted by {@link walkFiles}. */
export interface WalkOptions {
  /**
   * Restrict to paths matching one of these include patterns (substring or
   * relative-path-prefix match). When omitted/empty, all files pass.
   */
  include?: string[];
  /** Extra exclude patterns (substring or relative-path-prefix match). */
  exclude?: string[];
  /** Disable the built-in directory ignore list. */
  noDefaultIgnores?: boolean;
  /** Max file size in bytes; larger files are skipped. */
  maxFileSize?: number;
}

/** Normalise a path to forward-slash POSIX separators. */
export function toPosix(p: string): string {
  return p.split(path.sep).join("/");
}

/** True if `rel` (a POSIX relative path) matches any pattern (substring/prefix). */
function matchesAny(rel: string, patterns: readonly string[]): boolean {
  for (const pattern of patterns) {
    if (!pattern) continue;
    const p = toPosix(pattern).replace(/\/+$/, "");
    // Substring match (handles "src/legacy" or "secrets")...
    if (rel.includes(p)) return true;
    // ...and explicit path-prefix match ("foo" should match "foo/bar.ts").
    if (rel === p || rel.startsWith(`${p}/`)) return true;
  }
  return false;
}

/** True if `rel` (a POSIX relative path) matches any exclude pattern. */
function isExcluded(rel: string, exclude: readonly string[]): boolean {
  return matchesAny(rel, exclude);
}

/**
 * True if `rel` passes the include filter. An empty include list means "include
 * everything"; otherwise the file must match at least one include pattern.
 */
function isIncluded(rel: string, include: readonly string[]): boolean {
  if (include.length === 0) return true;
  return matchesAny(rel, include);
}

/** True if the file's extension marks it as binary / non-text. */
export function isBinaryPath(rel: string): boolean {
  const lower = rel.toLowerCase();
  // Handle compound extensions like ".min.js" first.
  if (lower.endsWith(".min.js")) return true;
  const ext = path.posix.extname(lower);
  return BINARY_EXTENSIONS.has(ext);
}

/**
 * Compound / pattern extensions that mark generated or bundled output we skip
 * by default (beyond `.min.js` / `.map`, which {@link isBinaryPath} handles).
 */
const GENERATED_PATH_RE =
  /(?:\.min\.[mc]?js|[.-]min\.[mc]?js|\.bundle\.[mc]?js|\.chunk\.[mc]?js|\.generated\.[jt]sx?|_pb\.js|\.pb\.go)$/i;

/** True if the path looks like generated / bundled output (by name). */
export function isGeneratedPath(rel: string): boolean {
  return GENERATED_PATH_RE.test(rel.toLowerCase());
}

/**
 * Heuristic content check for machine-minified / generated files with no
 * telltale extension: a very long average line length, or any single line over
 * ~50 KB, in the first ~64 KB sampled. Used at read time, not in the walker.
 */
export function looksMinified(content: string): boolean {
  const sample = content.length > 65_536 ? content.slice(0, 65_536) : content;
  if (sample.length === 0) return false;
  let maxLine = 0;
  let cur = 0;
  let lines = 1;
  for (let i = 0; i < sample.length; i++) {
    if (sample.charCodeAt(i) === 10 /* \n */) {
      if (cur > maxLine) maxLine = cur;
      cur = 0;
      lines++;
    } else {
      cur++;
    }
  }
  if (cur > maxLine) maxLine = cur;
  if (maxLine > 50_000) return true;
  const avgLine = sample.length / lines;
  return avgLine > 1_000;
}

/**
 * Recursively yield scannable file paths (relative to `root`, POSIX) under a
 * directory. If `root` points at a single file, yields just that file's
 * basename (subject to the size / binary filters).
 */
export async function* walkFiles(
  root: string,
  options: WalkOptions = {},
): AsyncGenerator<string> {
  const include = options.include ?? [];
  const exclude = options.exclude ?? [];
  const maxFileSize = options.maxFileSize ?? DEFAULT_MAX_FILE_SIZE;
  const ignores = options.noDefaultIgnores ? [] : DEFAULT_IGNORES;

  const rootStat = await stat(root);

  // Single-file mode: yield the file itself (by basename) if it passes filters.
  if (rootStat.isFile()) {
    const name = toPosix(path.basename(root));
    if (
      !isBinaryPath(name) &&
      isIncluded(name, include) &&
      passesSizeLimit(name, rootStat.size, maxFileSize)
    ) {
      yield name;
    }
    return;
  }

  yield* walkDir(root, "", { include, exclude, maxFileSize, ignores });
}

interface WalkContext {
  include: readonly string[];
  exclude: readonly string[];
  maxFileSize: number;
  ignores: readonly string[];
}

/**
 * True if a file passes the size limit. Dependency manifests (package.json /
 * package-lock.json) are exempt from the cap so large lockfiles still get
 * scanned for vulnerable dependencies instead of being silently dropped.
 */
function passesSizeLimit(rel: string, size: number, maxFileSize: number): boolean {
  if (isManifestPath(rel)) return true;
  return size <= maxFileSize;
}

/** True if the path's basename is a dependency manifest we always read. */
function isManifestPath(rel: string): boolean {
  const base = rel.split("/").pop() ?? rel;
  return base === "package.json" || base === "package-lock.json";
}

/** Internal recursive directory walker. `relDir` is POSIX-relative to the root. */
async function* walkDir(
  absDir: string,
  relDir: string,
  ctx: WalkContext,
): AsyncGenerator<string> {
  let entries: Dirent[];
  try {
    entries = await readdir(absDir, { withFileTypes: true });
  } catch {
    // Unreadable directory (permissions, transient races) — skip silently.
    return;
  }

  // Stable, deterministic ordering for reproducible scans.
  entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));

  for (const entry of entries) {
    const rel = relDir ? `${relDir}/${entry.name}` : entry.name;
    const abs = path.join(absDir, entry.name);

    if (entry.isSymbolicLink()) {
      // Don't follow symlinks: avoids cycles and escaping the root.
      continue;
    }

    if (entry.isDirectory()) {
      if (ctx.ignores.includes(entry.name)) continue;
      if (isExcluded(rel, ctx.exclude)) continue;
      yield* walkDir(abs, rel, ctx);
      continue;
    }

    if (!entry.isFile()) continue;
    if (isExcluded(rel, ctx.exclude)) continue;
    if (!isIncluded(rel, ctx.include)) continue;
    if (isBinaryPath(rel)) continue;
    if (isGeneratedPath(rel)) continue;

    try {
      const s = await stat(abs);
      if (!passesSizeLimit(rel, s.size, ctx.maxFileSize)) continue;
    } catch {
      continue;
    }

    yield rel;
  }
}
