/**
 * Scan orchestrator. Walks the target, runs the applicable detectors over each
 * file, parses dependency manifests, aggregates everything into an inventory,
 * and returns a {@link ScanResult} with timing and the tool version.
 */
import { readFile, stat } from "node:fs/promises";
import * as path from "node:path";

import type { Detector, Finding, ScanOptions, ScanResult } from "./types.js";
import { walkFiles, toPosix } from "./walk.js";
import { sourceDetectors } from "./detectors/source.js";
import { pemDetector } from "./detectors/pem.js";
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

/** Detectors whose findings belong to the "config" scope (PEM / TLS / certs). */
const CONFIG_RULE_PREFIXES = ["pem-", "tls-"];

/** True if a finding came from a config-scope detector. */
function isConfigFinding(f: Finding): boolean {
  return CONFIG_RULE_PREFIXES.some((p) => f.ruleId.startsWith(p));
}

/**
 * Recursively scan a directory (or single file) for classical asymmetric
 * crypto. Honours the source / dependencies / config toggles (all default true)
 * and reports progress through `options.onFile`.
 */
export async function scan(options: ScanOptions): Promise<ScanResult> {
  const startedAt = new Date();

  const doSource = options.source !== false;
  const doDeps = options.dependencies !== false;
  const doConfig = options.config !== false;

  // Resolve whether the root is a file so we can rebuild absolute paths to read.
  const rootStat = await stat(options.root);
  const rootIsFile = rootStat.isFile();
  const baseDir = rootIsFile ? path.dirname(options.root) : options.root;
  const singleFileName = rootIsFile ? path.basename(options.root) : null;

  const findings: Finding[] = [];
  let filesScanned = 0;

  for await (const rel of walkFiles(options.root, {
    exclude: options.exclude,
    noDefaultIgnores: options.noDefaultIgnores,
    maxFileSize: options.maxFileSize,
  })) {
    // In single-file mode, walkFiles yields the basename; map back to the file.
    const absPath = singleFileName
      ? options.root
      : path.join(baseDir, ...rel.split("/"));
    const reportedPath = singleFileName ? toPosix(rel) : rel;

    options.onFile?.(reportedPath);

    let content: string;
    try {
      content = await readFile(absPath, "utf8");
    } catch {
      continue; // unreadable / vanished file — skip.
    }
    filesScanned += 1;

    const input = { file: reportedPath, content };

    // Source + config detectors (Detector instances).
    for (const det of detectors) {
      if (!det.appliesTo(reportedPath)) continue;
      const detFindings = det.detect(input);
      for (const f of detFindings) {
        const config = isConfigFinding(f);
        // Apply scope toggles: config findings need doConfig; the rest need doSource.
        if (config ? !doConfig : !doSource) continue;
        findings.push(f);
      }
    }

    // Dependency manifests (JSON parsing, separate from Detector instances).
    if (doDeps && isManifestFile(reportedPath)) {
      findings.push(...scanManifest(reportedPath, content));
    }
  }

  // Stable ordering: by file, then line, then ruleId.
  findings.sort((a, b) => {
    if (a.location.file !== b.location.file) return a.location.file < b.location.file ? -1 : 1;
    if (a.location.line !== b.location.line) return a.location.line - b.location.line;
    return a.ruleId < b.ruleId ? -1 : a.ruleId > b.ruleId ? 1 : 0;
  });

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
