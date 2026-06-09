/**
 * Shared result types for test categories.
 *
 * Every category is an async function that drives a {@link Runner} and returns
 * a {@link CategoryResult}. Categories never throw for *expected* SUT failures;
 * they record them as failing checks. They only throw for harness-level faults
 * (e.g. inability to spawn), which the report layer surfaces as an "error".
 */

import type { Runner } from "../runner.js";
import type { Sizes } from "../sizes.js";

/** Status of a single check or a whole category. */
export type Status = "pass" | "fail" | "skip";

/**
 * A bug-class tag linking a category/check to qproof's antiform taxonomy.
 *
 *   - AF-02: implicit-rejection / Fujisaki-Okamoto reject-path mistakes.
 *   - AF-05: size/format confusion (wrong-length artifacts accepted/emitted).
 */
export type BugClass = "AF-02" | "AF-05" | undefined;

/** One atomic assertion within a category. */
export interface Check {
  /** Short name, unique within its category. */
  name: string;
  status: Status;
  /** Human-readable detail (why it passed/failed/was skipped). */
  detail: string;
  /** Optional bug-class tag. */
  bugClass?: BugClass;
}

/** The aggregate outcome of running one category. */
export interface CategoryResult {
  /** Category identifier, e.g. "correctness". */
  category: string;
  /** Rolled-up status: fail if any check failed, else pass; all-skip => skip. */
  status: Status;
  /** Bug class this category primarily exercises, if any. */
  bugClass?: BugClass;
  /** Individual checks. */
  checks: Check[];
  /** Free-form summary line. */
  summary: string;
}

/** Context handed to every category. */
export interface CategoryContext {
  runner: Runner;
  sizes: Sizes;
  /** Number of randomized iterations to perform (where applicable). */
  iterations: number;
  /**
   * Max concurrent in-flight requests for categories that issue many
   * INDEPENDENT requests (via {@link Runner.sendMany}). Default 16 when unset.
   * Categories with dependent/ordered ops ignore this and use serial `send`.
   */
  pipelineDepth?: number;
  /** Optional directory of official ACVP/KAT vectors (kat category only). */
  vectorsDir?: string;
}

/** A category is a named driver producing one {@link CategoryResult}. */
export type Category = (ctx: CategoryContext) => Promise<CategoryResult>;

/** Roll a list of checks up into a category-level status. */
export function rollUp(checks: readonly Check[]): Status {
  if (checks.length === 0) return "skip";
  if (checks.some((c) => c.status === "fail")) return "fail";
  if (checks.every((c) => c.status === "skip")) return "skip";
  return "pass";
}

/** Convenience constructor for a passing check. */
export function pass(name: string, detail: string, bugClass?: BugClass): Check {
  return { name, status: "pass", detail, bugClass };
}

/** Convenience constructor for a failing check. */
export function fail(name: string, detail: string, bugClass?: BugClass): Check {
  return { name, status: "fail", detail, bugClass };
}

/** Convenience constructor for a skipped check. */
export function skip(name: string, detail: string, bugClass?: BugClass): Check {
  return { name, status: "skip", detail, bugClass };
}
