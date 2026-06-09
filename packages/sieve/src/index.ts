/**
 * @qproof/sieve — programmatic API.
 *
 * Sieve is a conformance battery for ML-KEM (FIPS 203) and ML-DSA (FIPS 204)
 * implementations. It TESTS other people's implementations; it implements no
 * cryptography of its own and ships no Known-Answer-Test vectors. See README.md
 * and PROTOCOL.md.
 *
 * Typical use:
 * ```ts
 * import { runSieve } from "@qproof/sieve";
 * const report = await runSieve({ command: ["node", "./my-impl.js"], param: "ml-kem-768" });
 * console.log(report.overall);
 * ```
 */

import { categoriesFor } from "./categories/index.js";
import type { CategoryResult } from "./categories/types.js";
import { Runner } from "./runner.js";
import { buildReport, type SieveReport } from "./report.js";
import { isParamSet, sizesFor, type ParamSet } from "./sizes.js";

export type { SieveReport, CategoryCounts } from "./report.js";
export type { CategoryResult, Check, Status, BugClass } from "./categories/types.js";
export type { ParamSet, Family, Sizes, KemSizes, DsaSizes } from "./sizes.js";
export type { Request, Response } from "./protocol.js";

export { PARAM_SETS, isParamSet, sizesFor } from "./sizes.js";
export { CATEGORIES, categoriesFor } from "./categories/index.js";
export { buildReport, formatHuman, formatJson, overallVerdict } from "./report.js";
export { encodeRequest, decodeResponse, ProtocolError, PROTOCOL_VERSION, toB64, fromB64 } from "./protocol.js";
export { Runner, TimeoutError, SutCrashError } from "./runner.js";
export { loadVectors } from "./vectors.js";
export type { Vector, VectorSet } from "./vectors.js";

/** Options for {@link runSieve}. */
export interface RunSieveOptions {
  /** Argv of the SUT, e.g. ["node", "./impl.js"]. */
  command: readonly string[];
  /** Parameter set to test, e.g. "ml-kem-768". */
  param: ParamSet;
  /** Randomized iterations for applicable categories (default 32). */
  iterations?: number;
  /** Per-request timeout in milliseconds (default 10000). */
  timeoutMs?: number;
  /** Directory of official ACVP vectors for the kat category (optional). */
  vectorsDir?: string;
  /** Include the advisory timing category (default false). */
  timing?: boolean;
  /** Working directory for the SUT. */
  cwd?: string;
  /** Extra env for the SUT. */
  env?: Record<string, string>;
  /** Restrict to these category names (default: all applicable). */
  only?: readonly string[];
}

/**
 * Spawn the SUT, run the applicable categories, and return an aggregated
 * report. The SUT process is always torn down before returning, even on error.
 */
export async function runSieve(opts: RunSieveOptions): Promise<SieveReport> {
  if (!isParamSet(opts.param)) {
    throw new RangeError(`unknown parameter set: ${opts.param}`);
  }
  const sizes = sizesFor(opts.param);
  const iterations = opts.iterations ?? 32;
  const startedAt = new Date();
  const t0 = performance.now();

  const runner = new Runner({
    command: opts.command,
    ...(opts.timeoutMs !== undefined ? { timeoutMs: opts.timeoutMs } : {}),
    ...(opts.cwd ? { cwd: opts.cwd } : {}),
    ...(opts.env ? { env: opts.env } : {}),
  });

  const results: CategoryResult[] = [];
  try {
    let cats = categoriesFor(sizes.family, opts.timing ?? false);
    if (opts.only && opts.only.length > 0) {
      const want = new Set(opts.only);
      cats = cats.filter((c) => want.has(c.name));
    }
    for (const cat of cats) {
      try {
        const res = await cat.run({
          runner,
          sizes,
          iterations,
          ...(opts.vectorsDir ? { vectorsDir: opts.vectorsDir } : {}),
        });
        results.push(res);
      } catch (err) {
        // A category that throws (rather than recording a fail) is a harness
        // fault; surface it as a failing category so the report is complete.
        results.push({
          category: cat.name,
          status: "fail",
          checks: [
            {
              name: "category-error",
              status: "fail",
              detail: `category threw: ${(err as Error).message}`,
            },
          ],
          summary: "category aborted with an error",
        });
      }
    }
  } finally {
    await runner.close();
  }

  return buildReport({
    param: opts.param,
    impl: [...opts.command],
    iterations,
    ...(opts.vectorsDir ? { vectorsDir: opts.vectorsDir } : {}),
    startedAt,
    durationMs: Math.round(performance.now() - t0),
    categories: results,
  });
}
