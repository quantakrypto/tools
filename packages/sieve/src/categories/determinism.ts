/**
 * Determinism category (ML-KEM).
 *
 * Decapsulation is a deterministic function of (sk, ct): calling decaps twice
 * with identical inputs must return identical shared secrets. A SUT that mixes
 * fresh randomness into decaps (a real-world implementation smell) fails here.
 *
 * This is a self-consistency property; no external vectors are required.
 */

import {
  type Category,
  type CategoryResult,
  type Check,
  fail,
  pass,
  rollUp,
} from "./types.js";
import { bytesEqual, kemDecaps, kemEncaps, kemKeygen, requireKem, UnexpectedResponse } from "./helpers.js";
import { toB64 } from "../protocol.js";

const REPEATS = 3;

export const determinism: Category = async (ctx): Promise<CategoryResult> => {
  const checks: Check[] = [];

  if (ctx.sizes.family !== "ml-kem") {
    return {
      category: "determinism",
      status: "skip",
      checks: [],
      summary: "decaps-determinism is defined for ML-KEM",
    };
  }

  const param = requireKem(ctx.sizes).id;
  let nondeterministic = 0;
  let errored = 0;

  for (let i = 0; i < ctx.iterations; i++) {
    try {
      const { pk, sk } = await kemKeygen(ctx.runner, param);
      const { ct } = await kemEncaps(ctx.runner, param, toB64(pk));
      const skB64 = toB64(sk);
      const ctB64 = toB64(ct);

      const first = await kemDecaps(ctx.runner, param, skB64, ctB64);
      let stable = true;
      for (let r = 1; r < REPEATS; r++) {
        const again = await kemDecaps(ctx.runner, param, skB64, ctB64);
        if (!bytesEqual(first, again)) {
          stable = false;
          break;
        }
      }
      if (!stable) {
        nondeterministic++;
        if (nondeterministic <= 3) {
          checks.push(
            fail(
              `decaps-stable[${i}]`,
              `decaps(sk, ct) returned different shared secrets across ${REPEATS} identical calls`,
            ),
          );
        }
      }
    } catch (err) {
      errored++;
      if (errored <= 3) {
        const detail =
          err instanceof UnexpectedResponse
            ? `SUT returned an unexpected response: ${err.message}`
            : `harness error: ${(err as Error).message}`;
        checks.push(fail(`decaps-stable[${i}]`, detail));
      }
    }
  }

  if (nondeterministic === 0 && errored === 0) {
    checks.push(
      pass(
        "decaps-stable",
        `decaps was deterministic across ${REPEATS} repeats for all ${ctx.iterations} ciphertexts`,
      ),
    );
  }

  const status = rollUp(checks);
  return {
    category: "determinism",
    status,
    checks,
    summary:
      status === "pass"
        ? `decaps deterministic over ${ctx.iterations} ciphertexts`
        : `${nondeterministic} non-deterministic, ${errored} error(s)`,
  };
};
