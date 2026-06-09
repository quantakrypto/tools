/**
 * Correctness category (ML-KEM).
 *
 * The fundamental KEM round-trip: for N independent key pairs,
 *   keygen -> encaps(pk) -> decaps(sk, ct)
 * must yield ss_encaps === ss_decaps. This needs no external vectors: it is a
 * self-consistency property every conforming implementation must satisfy.
 *
 * (ML-DSA correctness — sign then verify === true — lives in dsa.ts.)
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

export const correctness: Category = async (ctx): Promise<CategoryResult> => {
  const checks: Check[] = [];

  if (ctx.sizes.family !== "ml-kem") {
    return {
      category: "correctness",
      status: "skip",
      checks: [],
      summary: "correctness round-trip is defined for ML-KEM; see DSA category for ML-DSA",
    };
  }

  const km = requireKem(ctx.sizes);
  const param = km.id;
  let mismatches = 0;
  let errored = 0;

  for (let i = 0; i < ctx.iterations; i++) {
    try {
      const { pk, sk } = await kemKeygen(ctx.runner, param);
      const { ct, ss: ssEncaps } = await kemEncaps(ctx.runner, param, toB64(pk));
      const ssDecaps = await kemDecaps(ctx.runner, param, toB64(sk), toB64(ct));

      if (!bytesEqual(ssEncaps, ssDecaps)) {
        mismatches++;
        if (mismatches <= 3) {
          checks.push(
            fail(
              `roundtrip[${i}]`,
              `shared secrets differ: encaps ss != decaps ss ` +
                `(encaps=${toB64(ssEncaps).slice(0, 12)}…, decaps=${toB64(ssDecaps).slice(0, 12)}…)`,
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
        checks.push(fail(`roundtrip[${i}]`, detail));
      }
    }
  }

  if (mismatches === 0 && errored === 0) {
    checks.push(
      pass(
        "roundtrip",
        `${ctx.iterations}/${ctx.iterations} keygen→encaps→decaps round-trips produced matching shared secrets`,
      ),
    );
  }

  const status = rollUp(checks);
  return {
    category: "correctness",
    status,
    checks,
    summary:
      status === "pass"
        ? `${ctx.iterations} round-trips OK`
        : `${mismatches} mismatch(es), ${errored} error(s) over ${ctx.iterations} iterations`,
  };
};
