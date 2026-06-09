/**
 * Report aggregation and formatting.
 *
 * Combines per-category results into a single {@link SieveReport} with an
 * overall PASS/FAIL verdict, then renders it as JSON or as a human-readable
 * terminal summary. Advisory categories (timing) never affect the verdict.
 */

import type { CategoryResult, Status } from "./categories/types.js";
import { PROTOCOL_VERSION } from "./protocol.js";
import type { ParamSet } from "./sizes.js";

/** Categories that are informational and must not change the overall verdict. */
const ADVISORY_CATEGORIES = new Set<string>(["timing"]);

/** Per-category counts. */
export interface CategoryCounts {
  pass: number;
  fail: number;
  skip: number;
}

/** The full report. */
export interface SieveReport {
  tool: "sieve";
  protocolVersion: number;
  param: ParamSet;
  /** Argv of the SUT that was tested. */
  impl: string[];
  iterations: number;
  vectorsDir?: string;
  startedAt: string;
  durationMs: number;
  /** Overall verdict (advisory categories excluded). */
  overall: "PASS" | "FAIL";
  categories: CategoryResult[];
  counts: CategoryCounts;
}

/** Tally check-level pass/fail/skip across all categories. */
function tally(categories: readonly CategoryResult[]): CategoryCounts {
  const counts: CategoryCounts = { pass: 0, fail: 0, skip: 0 };
  for (const c of categories) {
    for (const chk of c.checks) counts[chk.status]++;
  }
  return counts;
}

/** Compute the overall verdict: FAIL if any non-advisory category failed. */
export function overallVerdict(categories: readonly CategoryResult[]): "PASS" | "FAIL" {
  for (const c of categories) {
    if (ADVISORY_CATEGORIES.has(c.category)) continue;
    if (c.status === "fail") return "FAIL";
  }
  return "PASS";
}

/** Assemble a {@link SieveReport} from category results and run metadata. */
export function buildReport(args: {
  param: ParamSet;
  impl: string[];
  iterations: number;
  vectorsDir?: string;
  startedAt: Date;
  durationMs: number;
  categories: CategoryResult[];
}): SieveReport {
  return {
    tool: "sieve",
    protocolVersion: PROTOCOL_VERSION,
    param: args.param,
    impl: args.impl,
    iterations: args.iterations,
    ...(args.vectorsDir ? { vectorsDir: args.vectorsDir } : {}),
    startedAt: args.startedAt.toISOString(),
    durationMs: args.durationMs,
    overall: overallVerdict(args.categories),
    categories: args.categories,
    counts: tally(args.categories),
  };
}

/** Pretty JSON rendering. */
export function formatJson(report: SieveReport): string {
  return JSON.stringify(report, null, 2);
}

const SYMBOL: Record<Status, string> = { pass: "PASS", fail: "FAIL", skip: "SKIP" };

/** Human-readable terminal rendering (no color codes; CI-friendly). */
export function formatHuman(report: SieveReport): string {
  const lines: string[] = [];
  lines.push(`sieve — ML-KEM/ML-DSA conformance battery`);
  lines.push(`  param      : ${report.param}`);
  lines.push(`  impl       : ${report.impl.join(" ")}`);
  lines.push(`  iterations : ${report.iterations}`);
  if (report.vectorsDir) lines.push(`  vectors    : ${report.vectorsDir}`);
  lines.push(`  duration   : ${report.durationMs} ms`);
  lines.push("");

  for (const cat of report.categories) {
    const advisory = ADVISORY_CATEGORIES.has(cat.category) ? " (advisory)" : "";
    const bug = cat.bugClass ? ` [${cat.bugClass}]` : "";
    lines.push(`[${SYMBOL[cat.status]}] ${cat.category}${bug}${advisory} — ${cat.summary}`);
    // Show failing and skipped checks; collapse passes.
    for (const chk of cat.checks) {
      if (chk.status === "pass") continue;
      const cbug = chk.bugClass ? ` [${chk.bugClass}]` : "";
      lines.push(`      - ${SYMBOL[chk.status]} ${chk.name}${cbug}: ${chk.detail}`);
    }
  }

  lines.push("");
  lines.push(
    `checks: ${report.counts.pass} pass, ${report.counts.fail} fail, ${report.counts.skip} skip`,
  );
  lines.push(`OVERALL: ${report.overall}`);
  return lines.join("\n");
}
