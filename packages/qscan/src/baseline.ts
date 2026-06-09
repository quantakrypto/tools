/**
 * Baseline support for qScan — a thin adapter over the **canonical** baseline
 * implementation in `@qproof/core` (P1-1).
 *
 * Historically qScan carried its own baseline scheme (12-char hash of
 * `ruleId|file|snippet|line`) that was incompatible with the GitHub Action's.
 * Both have been unified onto core's single source of truth, so this module no
 * longer defines its own format or hashing — it re-exports core's primitives
 * and adds only the small filename-resolution / API-shape conveniences the CLI
 * and `@qproof/action` rely on.
 *
 * The on-disk format is core's {@link Baseline}: `{ version, fingerprints }`,
 * where each fingerprint is a full, line-INSENSITIVE SHA-256 (so unrelated edits
 * that shift line numbers no longer invalidate a baseline).
 */

import {
  applyBaseline as coreApplyBaseline,
  baselineFromFindings,
  BASELINE_VERSION,
  fingerprintFinding,
  loadBaseline,
  saveBaseline,
} from "@qproof/core";
import type { Baseline, Finding } from "@qproof/core";

// Re-export core's canonical primitives so downstream tools (and tests) can use
// them through `@qproof/qscan` without reaching into `@qproof/core` internals.
export { baselineFromFindings, BASELINE_VERSION, fingerprintFinding, loadBaseline, saveBaseline };
export type { Baseline };

/**
 * Compute a stable fingerprint for a finding. Alias for core's
 * {@link fingerprintFinding}; kept under the historical name `fingerprint` for
 * source compatibility with existing call sites and tests.
 */
export const fingerprint = fingerprintFinding;

/**
 * Partition findings into those kept and those suppressed by a baseline.
 *
 * Wraps core's {@link coreApplyBaseline} (which takes a {@link Baseline} and
 * returns `{ newFindings, suppressed }`) but preserves qScan's historical
 * `{ kept, suppressed }` shape and its lenient `ReadonlySet<string>` overload so
 * existing callers keep working.
 *
 * @param findings All findings produced by a scan.
 * @param baseline Either a {@link Baseline} object or a set of accepted
 *   fingerprints.
 */
export function applyBaseline(
  findings: readonly Finding[],
  baseline: Baseline | ReadonlySet<string>,
): { kept: Finding[]; suppressed: Finding[] } {
  const resolved: Baseline =
    baseline instanceof Set
      ? { version: BASELINE_VERSION, fingerprints: [...baseline] }
      : (baseline as Baseline);
  const { newFindings, suppressed } = coreApplyBaseline(findings, resolved);
  return { kept: newFindings, suppressed };
}

/**
 * Build a {@link Baseline} from a set of findings (deduped + sorted). Alias for
 * core's {@link baselineFromFindings} under qScan's historical name.
 */
export function buildBaseline(findings: readonly Finding[]): Baseline {
  return baselineFromFindings(findings);
}

/**
 * Read a baseline file from disk and return its accepted fingerprints as a set.
 *
 * Unlike core's tolerant {@link loadBaseline} (which returns an empty baseline
 * for a missing/unparseable file), this preserves qScan's historical *strict*
 * contract: a missing or malformed file is an error, surfaced to the CLI as an
 * I/O failure (exit 2).
 *
 * @throws {Error} If the file cannot be read or is not valid baseline JSON.
 */
export async function readBaseline(path: string): Promise<Set<string>> {
  const { readFile } = await import("node:fs/promises");
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

/** Serialize and write a baseline to disk (pretty-printed, trailing newline). */
export async function writeBaseline(path: string, baseline: Baseline): Promise<void> {
  const { writeFile } = await import("node:fs/promises");
  const json = `${JSON.stringify(baseline, null, 2)}\n`;
  try {
    await writeFile(path, json, "utf8");
  } catch (cause) {
    throw new Error(`could not write baseline file "${path}": ${errMessage(cause)}`);
  }
}

/** Narrowing type guard for parsed baseline JSON. */
function isBaselineFile(value: unknown): value is Baseline {
  if (typeof value !== "object" || value === null) return false;
  const obj = value as Record<string, unknown>;
  return Array.isArray(obj.fingerprints) && obj.fingerprints.every((f) => typeof f === "string");
}

/** Extract a human message from an unknown thrown value. */
function errMessage(cause: unknown): string {
  return cause instanceof Error ? cause.message : String(cause);
}
