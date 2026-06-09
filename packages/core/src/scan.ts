/**
 * Scan orchestrator. Walks the target (or an explicit file list), runs the
 * applicable detectors over each file, parses dependency manifests, aggregates
 * everything into an inventory, and returns a {@link ScanResult} with timing and
 * the tool version.
 *
 * Detector scope (source vs config) is driven by each {@link Detector}'s
 * declared `scope` (defaulting to "source"), not by ruleId prefixes. The
 * detector set comes from {@link defaultRegistry} unless overridden via
 * `options.detectors`.
 */
import { readFile, stat } from "node:fs/promises";
import * as path from "node:path";

import type { Detector, Finding, ScanOptions, ScanResult } from "./types.js";
import { walkFiles, toPosix, isBinaryPath, looksMinified } from "./walk.js";
import { sourceDetectors } from "./detectors/source.js";
import { pemDetector } from "./detectors/pem.js";
import { defaultRegistry, detectorScope } from "./registry.js";
import { isManifestFile, scanManifest } from "./dependencies.js";
import { buildInventory } from "./inventory.js";
import { VERSION } from "./version.js";

/**
 * The full set of built-in detectors exposed on the public API. The PEM
 * detector applies to every text file; the source detectors apply only to
 * JS/TS. The manifest scanner is handled separately (it parses JSON rather than
 * running a Detector).
 */
export const detectors: Detector[] = [...sourceDetectors, pemDetector];

/** Stable comparator: by file, then line, then ruleId. Exported for reuse. */
export function compareFindings(a: Finding, b: Finding): number {
  if (a.location.file !== b.location.file) return a.location.file < b.location.file ? -1 : 1;
  if (a.location.line !== b.location.line) return a.location.line - b.location.line;
  return a.ruleId < b.ruleId ? -1 : a.ruleId > b.ruleId ? 1 : 0;
}

/** Resolve the active detector list for a scan (override or the default registry). */
function resolveDetectors(options: ScanOptions): Detector[] {
  return options.detectors ?? defaultRegistry.all();
}

/**
 * Run all applicable detectors + the manifest scanner over a single file's
 * contents, honouring the source / config / dependencies toggles. Pure: no I/O.
 * Exported so the parallel worker and unit tests can drive it directly.
 */
export function detectFile(
  file: string,
  content: string,
  dets: readonly Detector[],
  toggles: { source: boolean; config: boolean; deps: boolean },
): Finding[] {
  const out: Finding[] = [];

  for (const det of dets) {
    if (!det.appliesTo(file)) continue;
    const isConfig = detectorScope(det) === "config";
    if (isConfig ? !toggles.config : !toggles.source) continue;
    out.push(...det.detect({ file, content }));
  }

  if (toggles.deps && isManifestFile(file)) {
    out.push(...scanManifest(file, content));
  }

  return out;
}

/**
 * Recursively scan a directory (or single file, or explicit file list) for
 * classical asymmetric crypto. Honours the source / dependencies / config
 * toggles (all default true) and reports progress through `options.onFile`.
 */
export async function scan(options: ScanOptions): Promise<ScanResult> {
  const startedAt = new Date();

  const doSource = options.source !== false;
  const doDeps = options.dependencies !== false;
  const doConfig = options.config !== false;
  const scanMinified = options.scanMinified === true;
  const dets = resolveDetectors(options);

  // Resolve whether the root is a file so we can rebuild absolute paths to read.
  const rootStat = await stat(options.root);
  const rootIsFile = rootStat.isFile();
  const baseDir = rootIsFile ? path.dirname(options.root) : options.root;
  const singleFileName = rootIsFile ? path.basename(options.root) : null;

  const findings: Finding[] = [];
  let filesScanned = 0;

  // Source of relative paths: an explicit file list (incremental) or the walker.
  const relPaths: AsyncIterable<string> = options.files
    ? filterExplicitFiles(options.files, options)
    : walkFiles(options.root, {
        include: options.include,
        exclude: options.exclude,
        noDefaultIgnores: options.noDefaultIgnores,
        maxFileSize: options.maxFileSize,
      });

  for await (const rel of relPaths) {
    // In single-file mode, walkFiles yields the basename; map back to the file.
    const absPath = singleFileName ? options.root : path.join(baseDir, ...rel.split("/"));
    const reportedPath = singleFileName ? toPosix(rel) : rel;

    options.onFile?.(reportedPath);

    let content: string;
    try {
      content = await readFile(absPath, "utf8");
    } catch {
      continue; // unreadable / vanished file — skip.
    }

    // Skip machine-minified / generated content (unless explicitly enabled).
    // Manifests are always scanned (their findings are dependency findings).
    if (!scanMinified && !isManifestFile(reportedPath) && looksMinified(content)) {
      continue;
    }

    filesScanned += 1;
    findings.push(
      ...detectFile(reportedPath, content, dets, {
        source: doSource,
        config: doConfig,
        deps: doDeps,
      }),
    );
  }

  // Stable ordering: by file, then line, then ruleId.
  findings.sort(compareFindings);

  const inventory = buildInventory(findings);
  const finishedAt = new Date();

  return {
    root: options.root,
    findings,
    filesScanned,
    inventory,
    startedAt: startedAt.toISOString(),
    finishedAt: finishedAt.toISOString(),
    toolVersion: VERSION,
  };
}

/**
 * Filter an explicit relative file list down to the paths that pass the binary
 * filter and the include/exclude patterns, yielding them in sorted order for
 * deterministic output. Size limits are enforced later (we still read manifests
 * over the cap). Non-existent files are simply skipped at read time.
 */
async function* filterExplicitFiles(files: string[], options: ScanOptions): AsyncGenerator<string> {
  const include = options.include ?? [];
  const exclude = options.exclude ?? [];
  const seen = new Set<string>();
  const list = [...files]
    .map((f) => toPosix(f))
    .filter((f) => {
      if (seen.has(f)) return false;
      seen.add(f);
      return true;
    })
    .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));

  for (const rel of list) {
    if (isBinaryPath(rel)) continue;
    if (include.length > 0 && !matchesAny(rel, include)) continue;
    if (matchesAny(rel, exclude)) continue;
    yield rel;
  }
}

/** Local substring/prefix matcher (mirrors the walker's pattern semantics). */
function matchesAny(rel: string, patterns: readonly string[]): boolean {
  for (const pattern of patterns) {
    if (!pattern) continue;
    const p = toPosix(pattern).replace(/\/+$/, "");
    if (rel.includes(p)) return true;
    if (rel === p || rel.startsWith(`${p}/`)) return true;
  }
  return false;
}
