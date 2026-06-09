/**
 * Timing category — ADVISORY ONLY (ML-KEM).
 *
 * Coarsely compares decapsulation wall-clock time for valid vs. invalid
 * ciphertexts over many trials. A large, consistent difference can hint at a
 * non-constant-time reject path (an AF-02-adjacent timing oracle).
 *
 * THIS IS NOT A CONFORMANCE VERDICT. Cross-process timing over stdin/stdout is
 * dominated by IPC and scheduler noise, so the result is reported as ADVISORY
 * and NEVER fails the overall run. Real constant-time analysis needs in-process
 * statistical tooling (e.g. dudect), not a black-box harness. Treat any signal
 * here as "worth a closer look", not proof.
 */

import {
  type Category,
  type CategoryResult,
  type Check,
  pass,
  skip,
} from "./types.js";
import { flipBitB64, kemDecapsRaw, kemEncaps, kemKeygen, requireKem } from "./helpers.js";
import { toB64 } from "../protocol.js";

export const timing: Category = async (ctx): Promise<CategoryResult> => {
  if (ctx.sizes.family !== "ml-kem") {
    return {
      category: "timing",
      status: "skip",
      checks: [skip("applicability", "timing probe targets ML-KEM decaps")],
      summary: "skipped (not ML-KEM)",
    };
  }

  const km = requireKem(ctx.sizes);
  const param = km.id;
  const checks: Check[] = [];

  // Establish a single key + honest ct + one corrupted ct.
  let skB64: string;
  let honestCtB64: string;
  let badCtB64: string;
  try {
    const { pk, sk } = await kemKeygen(ctx.runner, param);
    skB64 = toB64(sk);
    const { ct } = await kemEncaps(ctx.runner, param, toB64(pk));
    honestCtB64 = toB64(ct);
    badCtB64 = flipBitB64(honestCtB64, 0, 0);
  } catch (err) {
    return {
      category: "timing",
      status: "skip",
      checks: [skip("setup", `could not set up timing probe: ${(err as Error).message}`)],
      summary: "skipped — setup failed",
    };
  }

  const trials = Math.max(50, Math.min(ctx.iterations * 20, 2000));

  // Warm-up to amortize JIT/spawn effects.
  for (let i = 0; i < 10; i++) {
    await kemDecapsRaw(ctx.runner, param, skB64, honestCtB64);
    await kemDecapsRaw(ctx.runner, param, skB64, badCtB64);
  }

  const validTimes = await measure(ctx, skB64, honestCtB64, trials, param);
  const invalidTimes = await measure(ctx, skB64, badCtB64, trials, param);

  const vMed = median(validTimes);
  const iMed = median(invalidTimes);
  const denom = Math.min(vMed, iMed) || 1;
  const relDiff = Math.abs(vMed - iMed) / denom;

  // Heuristic, intentionally loose threshold given cross-process noise.
  const ADVISORY_THRESHOLD = 0.25; // 25% median difference
  const signal = relDiff > ADVISORY_THRESHOLD;

  const detail =
    `valid decaps median ${vMed.toFixed(3)}ms, invalid median ${iMed.toFixed(3)}ms ` +
    `(rel. diff ${(relDiff * 100).toFixed(1)}%, ${trials} trials each). ` +
    (signal
      ? "ADVISORY: noticeable timing gap between valid/invalid decaps — investigate with " +
        "in-process constant-time tooling; cross-process timing is noisy and not conclusive."
      : "no strong cross-process timing signal (this is NOT proof of constant-time behavior).");

  // Always a pass/skip — never fails the run.
  checks.push(pass("decaps-timing", detail));

  return {
    category: "timing",
    status: "pass",
    checks,
    summary: signal
      ? `ADVISORY timing signal: ${(relDiff * 100).toFixed(1)}% median gap (not a verdict)`
      : `no strong timing signal (${(relDiff * 100).toFixed(1)}% median gap, advisory)`,
  };
};

async function measure(
  ctx: import("./types.js").CategoryContext,
  skB64: string,
  ctB64: string,
  trials: number,
  param: import("../sizes.js").ParamSet,
): Promise<number[]> {
  const out: number[] = [];
  for (let i = 0; i < trials; i++) {
    const t0 = performance.now();
    await kemDecapsRaw(ctx.runner, param, skB64, ctB64);
    out.push(performance.now() - t0);
  }
  return out;
}

function median(xs: number[]): number {
  if (xs.length === 0) return 0;
  const sorted = [...xs].sort((a, b) => a - b);
  const mid = sorted.length >> 1;
  return sorted.length % 2 === 0
    ? ((sorted[mid - 1] as number) + (sorted[mid] as number)) / 2
    : (sorted[mid] as number);
}
