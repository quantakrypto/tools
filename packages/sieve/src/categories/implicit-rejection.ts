/**
 * Implicit-rejection category — AF-02 family (ML-KEM).
 *
 * ML-KEM uses the Fujisaki-Okamoto transform with *implicit rejection*: when
 * decapsulation receives a ciphertext that does not re-encrypt to itself, it
 * MUST NOT signal an error. Instead it derives a pseudo-random shared secret
 * from the secret key and the (rejected) ciphertext — a deterministic value
 * that an attacker cannot distinguish from a real one without the key.
 *
 * Concretely, for a corrupted ciphertext ct', a conforming SUT must:
 *   1. NOT return an error or crash (it returns ok with an `ss`);
 *   2. return a shared secret of the correct length;
 *   3. be deterministic: decaps(sk, ct') is stable across repeated calls;
 *   4. return a value that differs from the honest decaps(sk, ct).
 *
 * We make NO exact-value assertions — the implicit-rejection secret is
 * implementation-internal and we never fabricate it. We only assert the
 * observable structural properties above.
 *
 * Common AF-02 bugs this catches:
 *   - returning an error/throwing on bad ct (leaks validity — Kyber's whole
 *     point is to avoid this),
 *   - returning a zero/constant ss (the "reject" secret isn't keyed),
 *   - returning the honest ss anyway (no integrity check),
 *   - non-deterministic reject secret.
 */

import {
  type Category,
  type CategoryResult,
  type Check,
  fail,
  pass,
  rollUp,
  skip,
} from "./types.js";
import {
  bytesEqual,
  flipBitB64,
  kemDecaps,
  kemDecapsRaw,
  kemEncaps,
  kemKeygen,
  requireKem,
  UnexpectedResponse,
} from "./helpers.js";
import { fromB64, toB64 } from "../protocol.js";

const BUG = "AF-02" as const;
const REPEATS = 3;

export const implicitRejection: Category = async (ctx): Promise<CategoryResult> => {
  const checks: Check[] = [];

  if (ctx.sizes.family !== "ml-kem") {
    return {
      category: "implicit-rejection",
      status: "skip",
      bugClass: BUG,
      checks: [skip("applicability", "implicit rejection is an ML-KEM property", BUG)],
      summary: "skipped (not ML-KEM)",
    };
  }

  const km = requireKem(ctx.sizes);
  const param = km.id;
  const ssLen = km.sharedSecret;

  // Iterate over several fresh keys, corrupting one bit of each honest ct.
  const trials = Math.max(1, Math.min(ctx.iterations, 16));
  let noError = 0;
  let goodLen = 0;
  let deterministic = 0;
  let differs = 0;
  let attempted = 0;

  for (let i = 0; i < trials; i++) {
    try {
      const { pk, sk } = await kemKeygen(ctx.runner, param);
      const skB64 = toB64(sk);
      const { ct } = await kemEncaps(ctx.runner, param, toB64(pk));
      const honestCtB64 = toB64(ct);
      const honestSs = await kemDecaps(ctx.runner, param, skB64, honestCtB64);

      // Corrupt a different byte/bit each iteration so we exercise variety.
      const badCtB64 = flipBitB64(honestCtB64, i % ct.length, i % 8);
      attempted++;

      // (1) must NOT error and must NOT crash.
      const resp = await kemDecapsRaw(ctx.runner, param, skB64, badCtB64);
      if (resp.ok !== true || !("ss" in resp)) {
        checks.push(
          fail(
            `no-error[${i}]`,
            `decaps of a corrupted ciphertext returned an error/non-ss response ` +
              `(${resp.ok === false ? `${resp.code}: ${resp.message}` : "no ss field"}); ` +
              `ML-KEM must implicitly reject, not signal failure`,
            BUG,
          ),
        );
        continue;
      }
      noError++;
      const rejectSs = fromB64(resp.ss);

      // (2) correct length.
      if (rejectSs.length === ssLen) {
        goodLen++;
      } else {
        checks.push(
          fail(
            `length[${i}]`,
            `implicit-rejection shared secret was ${rejectSs.length} bytes, expected ${ssLen}`,
            BUG,
          ),
        );
      }

      // (3) deterministic for the same corrupted ct.
      let stable = true;
      for (let r = 1; r < REPEATS; r++) {
        const again = await kemDecaps(ctx.runner, param, skB64, badCtB64);
        if (!bytesEqual(rejectSs, again)) {
          stable = false;
          break;
        }
      }
      if (stable) {
        deterministic++;
      } else {
        checks.push(
          fail(
            `deterministic[${i}]`,
            `implicit-rejection secret was not stable across ${REPEATS} identical corrupted decaps`,
            BUG,
          ),
        );
      }

      // (4) differs from the honest shared secret.
      if (!bytesEqual(rejectSs, honestSs)) {
        differs++;
      } else {
        checks.push(
          fail(
            `differs-from-honest[${i}]`,
            `implicit-rejection secret equals the honest shared secret — ` +
              `corruption was not detected`,
            BUG,
          ),
        );
      }
    } catch (err) {
      const detail =
        err instanceof UnexpectedResponse
          ? `SUT returned an unexpected response: ${err.message}`
          : `harness error (possible crash on bad ct): ${(err as Error).message}`;
      checks.push(fail(`trial[${i}]`, detail, BUG));
    }
  }

  if (attempted > 0 && checks.length === 0) {
    checks.push(
      pass(
        "implicit-rejection",
        `${noError}/${attempted} corrupted ciphertexts implicitly rejected: ` +
          `no error, correct length, deterministic, distinct from honest ss`,
        BUG,
      ),
    );
  }

  const status = rollUp(checks);
  return {
    category: "implicit-rejection",
    status,
    bugClass: BUG,
    checks,
    summary:
      status === "pass"
        ? `${attempted} corrupted ciphertexts handled by implicit rejection`
        : `implicit-rejection violations detected (no-error:${noError} len:${goodLen} det:${deterministic} differs:${differs} of ${attempted})`,
  };
};
