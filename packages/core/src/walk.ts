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

/** True if `rel` (a POSIX relative path) matches any exclude pattern. */
function isExcluded(rel: string, exclude: readonly string[]): boolean {
  for (const pattern of exclude) {
    if (!pattern) continue;
    const p = toPosix(pattern).replace(/\/+$/, "");
    // Substring match (handles "src/legacy" or "secrets")...
    if (rel.includes(p)) return true;
    // ...and explicit path-prefix match ("foo" should exclude "foo/bar.ts").
    if (rel === p || rel.startsWith(`${p}/`)) return true;
  }
  return false;
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
 * Recursively yield scannable file paths (relative to `root`, POSIX) under a
 * directory. If `root` points at a single file, yields just that file's
 * basename (subject to the size / binary filters).
 */
export async function* walkFiles(
  root: string,
  options: WalkOptions = {},
): AsyncGenerator<string> {
  const exclude = options.exclude ?? [];
  const maxFileSize = options.maxFileSize ?? DEFAULT_MAX_FILE_SIZE;
  const ignores = options.noDefaultIgnores ? [] : DEFAULT_IGNORES;

  const rootStat = await stat(root);

  // Single-file mode: yield the file itself (by basename) if it passes filters.
  if (rootStat.isFile()) {
    const name = path.basename(root);
    if (!isBinaryPath(name) && rootStat.size <= maxFileSize) {
      yield toPosix(name);
    }
    return;
  }

  yield* walkDir(root, "", { exclude, maxFileSize, ignores });
}

interface WalkContext {
  exclude: readonly string[];
  maxFileSize: number;
  ignores: readonly string[];
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
    if (isBinaryPath(rel)) continue;

    try {
      const s = await stat(abs);
      if (s.size > ctx.maxFileSize) continue;
    } catch {
      continue;
    }

    yield rel;
  }
}
