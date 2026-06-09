/**
 * Baseline support for qScan.
 *
 * A *baseline* records the fingerprints of findings that have been triaged and
 * accepted. On subsequent scans, any finding whose fingerprint is in the
 * baseline is suppressed, so CI only fails on *new* problems.
 *
 * The fingerprint is intentionally stable across runs and machines: it is a
 * truncated SHA-256 of the rule id, file path, snippet, and line number. It
 * deliberately omits volatile fields (timestamps, scan root) so that moving the
 * repository or rescanning does not invalidate a baseline.
 */

import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import type { Finding } from "@qproof/core";

/** Current on-disk baseline schema version. */
export const BASELINE_VERSION = 1 as const;

/** Shape of a baseline file on disk. */
export interface BaselineFile {
  /** Schema version, for forward compatibility. */
  version: number;
  /** Sorted, de-duplicated finding fingerprints. */
  fingerprints: string[];
}

/**
 * Compute a stable fingerprint for a finding.
 *
 * The hash inputs are `ruleId|file|snippet|line`. The result is the first 12
 * hex characters of the SHA-256 digest — short enough to read in a diff, wide
 * enough (48 bits) to avoid collisions in realistic repositories.
 */
export function fingerprint(finding: Finding): string {
  const { ruleId, location } = finding;
  const snippet = location.snippet ?? "";
  const line = location.line;
  const input = `${ruleId}|${location.file}|${snippet}|${line}`;
  return createHash("sha256").update(input).digest("hex").slice(0, 12);
}

/**
 * Partition findings into those kept and those suppressed by the baseline.
 *
 * @param findings All findings produced by a scan.
 * @param baseline Set of accepted fingerprints (e.g. from {@link readBaseline}).
 * @returns `kept` are findings not present in the baseline; `suppressed` are
 *   the ones that were.
 */
export function applyBaseline(
  findings: Finding[],
  baseline: ReadonlySet<string>,
): { kept: Finding[]; suppressed: Finding[] } {
  const kept: Finding[] = [];
  const suppressed: Finding[] = [];
  for (const finding of findings) {
    if (baseline.has(fingerprint(finding))) {
      suppressed.push(finding);
    } else {
      kept.push(finding);
    }
  }
  return { kept, suppressed };
}

/** Build a {@link BaselineFile} from a set of findings. */
export function buildBaseline(findings: Finding[]): BaselineFile {
  const fingerprints = Array.from(new Set(findings.map(fingerprint))).sort();
  return { version: BASELINE_VERSION, fingerprints };
}

/**
 * Read and validate a baseline file from disk.
 *
 * @throws {Error} If the file cannot be read or is not a valid baseline.
 */
export async function readBaseline(path: string): Promise<Set<string>> {
  let raw: string;
  try {
    raw = await readFile(path, "utf8");
  } catch (cause) {
    throw new Error(`could not read baseline file "${path}": ${errMessage(cause)}`);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (cause) {
    throw new Error(`baseline file "${path}" is not valid JSON: ${errMessage(cause)}`);
  }

  if (!isBaselineFile(parsed)) {
    throw new Error(`baseline file "${path}" is missing a string "fingerprints" array`);
  }
  return new Set(parsed.fingerprints);
}

/** Serialize and write a baseline file to disk (pretty-printed, trailing newline). */
export async function writeBaseline(path: string, baseline: BaselineFile): Promise<void> {
  const json = `${JSON.stringify(baseline, null, 2)}\n`;
  try {
    await writeFile(path, json, "utf8");
  } catch (cause) {
    throw new Error(`could not write baseline file "${path}": ${errMessage(cause)}`);
  }
}

/** Narrowing type guard for parsed baseline JSON. */
function isBaselineFile(value: unknown): value is BaselineFile {
  if (typeof value !== "object" || value === null) return false;
  const obj = value as Record<string, unknown>;
  return (
    Array.isArray(obj.fingerprints) &&
    obj.fingerprints.every((f) => typeof f === "string")
  );
}

/** Extract a human message from an unknown thrown value. */
function errMessage(cause: unknown): string {
  return cause instanceof Error ? cause.message : String(cause);
}
