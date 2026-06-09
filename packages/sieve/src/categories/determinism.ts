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
import { bytesEqual, kemDecaps, kemEncaps, kemKeygen, mapBounded, requireKem, UnexpectedResponse } from "./helpers.js";
import { toB64 } from "../protocol.js";

const REPEATS = 3;

/** Outcome of one determinism iteration. */
type Outcome =
  | { kind: "ok" }
  | { kind: "unstable" }
  | { kind: "error"; detail: string };

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

  // Iterations are independent → run concurrently (bounded). The REPEATS decaps
  // calls within an iteration MUST stay serial: determinism is a property of
  // repeated identical calls, so we issue them one after another on purpose.
  const outcomes = await mapBounded<Outcome>(
    ctx.iterations,
    ctx.pipelineDepth ?? 16,
    async (): Promise<Outcome> => {
      try {
        const { pk, sk } = await kemKeygen(ctx.runner, param);
        const { ct } = await kemEncaps(ctx.runner, param, toB64(pk));
        const skB64 = toB64(sk);
        const ctB64 = toB64(ct);

        const first = await kemDecaps(ctx.runner, param, skB64, ctB64);
        for (let r = 1; r < REPEATS; r++) {
          const again = await kemDecaps(ctx.runner, param, skB64, ctB64);
          if (!bytesEqual(first, again)) return { kind: "unstable" };
        }
        return { kind: "ok" };
      } catch (err) {
        const detail =
          err instanceof UnexpectedResponse
            ? `SUT returned an unexpected response: ${err.message}`
            : `harness error: ${(err as Error).message}`;
        return { kind: "error", detail };
      }
    },
  );

  for (let i = 0; i < outcomes.length; i++) {
    const o = outcomes[i] as Outcome;
    if (o.kind === "unstable") {
      nondeterministic++;
      if (nondeterministic <= 3) {
        checks.push(
          fail(
            `decaps-stable[${i}]`,
            `decaps(sk, ct) returned different shared secrets across ${REPEATS} identical calls`,
          ),
        );
      }
    } else if (o.kind === "error") {
      errored++;
      if (errored <= 3) checks.push(fail(`decaps-stable[${i}]`, o.detail));
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
