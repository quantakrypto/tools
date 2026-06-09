/**
 * Canonical baseline module — the single source of truth for suppressing known
 * findings across qScan and the GitHub Action (replacing their two divergent,
 * mutually-unintelligible schemes).
 *
 * A baseline is a versioned set of finding fingerprints. A fingerprint is
 * **line-insensitive** (so unrelated edits that shift line numbers don't
 * invalidate it) and snippet-whitespace-normalized (so reformatting doesn't
 * either). Identity = `sha256(ruleId | file | normalizedSnippet)`.
 */
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";

import type { Finding } from "./types.js";

/** Current on-disk baseline schema version. */
export const BASELINE_VERSION = 1 as const;

/** The on-disk baseline shape: a version tag and a set of fingerprints. */
export interface Baseline {
  version: number;
  fingerprints: string[];
}

/** Collapse all whitespace runs to single spaces and trim (snippet stability). */
function normalizeSnippet(snippet: string | undefined): string {
  if (!snippet) return "";
  return snippet.replace(/\s+/g, " ").trim();
}

/**
 * Stable, line-INSENSITIVE fingerprint of a finding: the hex SHA-256 of
 * `ruleId|file|normalizedSnippet`. The line number is deliberately excluded so
 * the fingerprint survives line shifts; the snippet's whitespace is normalized
 * so it survives reformatting.
 */
export function fingerprintFinding(f: Finding): string {
  const snippet = normalizeSnippet(f.location.snippet);
  const input = `${f.ruleId}|${f.location.file}|${snippet}`;
  return createHash("sha256").update(input, "utf8").digest("hex");
}

/** Build a {@link Baseline} from a set of findings (deduped, sorted). */
export function baselineFromFindings(findings: readonly Finding[]): Baseline {
  const set = new Set<string>();
  for (const f of findings) set.add(fingerprintFinding(f));
  return {
    version: BASELINE_VERSION,
    fingerprints: [...set].sort(),
  };
}

/**
 * Split findings into those NOT in the baseline (`newFindings`) and those that
 * ARE (`suppressed`). Order within each group is preserved from the input.
 */
export function applyBaseline(
  findings: readonly Finding[],
  baseline: Baseline,
): { newFindings: Finding[]; suppressed: Finding[] } {
  const accepted = new Set(baseline.fingerprints);
  const newFindings: Finding[] = [];
  const suppressed: Finding[] = [];
  for (const f of findings) {
    if (accepted.has(fingerprintFinding(f))) suppressed.push(f);
    else newFindings.push(f);
  }
  return { newFindings, suppressed };
}

/** Normalize an arbitrary parsed object into a valid {@link Baseline}. */
function coerceBaseline(value: unknown): Baseline {
  if (value === null || typeof value !== "object") {
    return { version: BASELINE_VERSION, fingerprints: [] };
  }
  const obj = value as Record<string, unknown>;
  const version = typeof obj.version === "number" ? obj.version : BASELINE_VERSION;
  const fingerprints = Array.isArray(obj.fingerprints)
    ? obj.fingerprints.filter((x): x is string => typeof x === "string")
    : [];
  return { version, fingerprints };
}

/**
 * Load a baseline from disk. Returns an empty baseline (rather than throwing)
 * when the file is missing or unparseable, so callers can treat "no baseline"
 * and "absent baseline" uniformly.
 */
export async function loadBaseline(path: string): Promise<Baseline> {
  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch {
    return { version: BASELINE_VERSION, fingerprints: [] };
  }
  try {
    return coerceBaseline(JSON.parse(text));
  } catch {
    return { version: BASELINE_VERSION, fingerprints: [] };
  }
}

/**
 * Write a baseline derived from the given findings to disk as pretty JSON
 * (trailing newline). Returns the baseline that was written.
 */
export async function saveBaseline(path: string, findings: readonly Finding[]): Promise<Baseline> {
  const baseline = baselineFromFindings(findings);
  await writeFile(path, `${JSON.stringify(baseline, null, 2)}\n`, "utf8");
  return baseline;
}
