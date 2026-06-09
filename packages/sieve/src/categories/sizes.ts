/**
 * Sizes/format category — AF-05 family (ML-KEM).
 *
 * Two complementary checks:
 *
 *   A. Positive — emitted artifacts have the standardized byte lengths.
 *      keygen pk/sk, encaps ct/ss, decaps ss must match the parameter set's
 *      sizes from the public size table (the only constants we trust).
 *
 *   B. Negative — the SUT rejects wrong-length inputs with a *defined error*,
 *      not a crash and not a silent success. We feed:
 *        - a too-short and too-long public key to encaps,
 *        - a too-short and too-long ciphertext to decaps,
 *        - a too-short secret key to decaps.
 *      Each must yield a protocol `error` response (ok:false) OR be otherwise
 *      cleanly handled; accepting it and returning a normal result is a fail.
 *
 * AF-05 is size/format confusion: an implementation that doesn't length-check
 * its inputs can read out of bounds or accept malformed material.
 */

import {
  type Category,
  type CategoryResult,
  type Check,
  fail,
  pass,
  rollUp,
} from "./types.js";
import {
  kemDecapsRaw,
  kemEncapsRaw,
  kemKeygen,
  requireKem,
  UnexpectedResponse,
  zerosB64,
} from "./helpers.js";
import { toB64 } from "../protocol.js";

const BUG = "AF-05" as const;

export const sizes: Category = async (ctx): Promise<CategoryResult> => {
  const checks: Check[] = [];

  if (ctx.sizes.family !== "ml-kem") {
    return {
      category: "sizes",
      status: "skip",
      bugClass: BUG,
      checks: [],
      summary: "size checks for ML-DSA live in the dsa category",
    };
  }

  const km = requireKem(ctx.sizes);
  const param = km.id;

  // --- A. Positive: emitted lengths -----------------------------------------
  let pkB64: string;
  try {
    const { pk, sk } = await kemKeygen(ctx.runner, param);
    pkB64 = toB64(pk);

    checks.push(
      pk.length === km.publicKey
        ? pass("pk-length", `public key is ${pk.length} bytes (expected ${km.publicKey})`, BUG)
        : fail("pk-length", `public key is ${pk.length} bytes, expected ${km.publicKey}`, BUG),
    );
    checks.push(
      sk.length === km.secretKey
        ? pass("sk-length", `secret key is ${sk.length} bytes (expected ${km.secretKey})`, BUG)
        : fail("sk-length", `secret key is ${sk.length} bytes, expected ${km.secretKey}`, BUG),
    );

    // encaps ct/ss lengths
    const enc = await ctx.runner.send({ family: "ml-kem", param, op: "encaps", pk: pkB64 });
    if (enc.ok === true && "ct" in enc && "ss" in enc) {
      const ct = Buffer.from(enc.ct, "base64");
      const ss = Buffer.from(enc.ss, "base64");
      checks.push(
        ct.length === km.ciphertext
          ? pass("ct-length", `ciphertext is ${ct.length} bytes (expected ${km.ciphertext})`, BUG)
          : fail("ct-length", `ciphertext is ${ct.length} bytes, expected ${km.ciphertext}`, BUG),
      );
      checks.push(
        ss.length === km.sharedSecret
          ? pass("ss-length", `shared secret is ${ss.length} bytes (expected ${km.sharedSecret})`, BUG)
          : fail("ss-length", `shared secret is ${ss.length} bytes, expected ${km.sharedSecret}`, BUG),
      );
    } else {
      checks.push(fail("encaps-shape", "encaps did not return ct/ss for a valid public key", BUG));
    }
  } catch (err) {
    const detail =
      err instanceof UnexpectedResponse
        ? `SUT returned an unexpected response: ${err.message}`
        : `harness error: ${(err as Error).message}`;
    checks.push(fail("positive-sizes", detail, BUG));
    pkB64 = "";
  }

  // --- B. Negative: wrong-length inputs must be rejected cleanly -------------
  // Wrong-length public key to encaps.
  await expectReject(
    checks,
    "encaps-pk-too-short",
    () => kemEncapsRaw(ctx.runner, param, zerosB64(km.publicKey - 1)),
  );
  await expectReject(
    checks,
    "encaps-pk-too-long",
    () => kemEncapsRaw(ctx.runner, param, zerosB64(km.publicKey + 1)),
  );

  // Wrong-length ciphertext to decaps (use a valid-length sk of zeros).
  const skZeros = zerosB64(km.secretKey);
  await expectReject(
    checks,
    "decaps-ct-too-short",
    () => kemDecapsRaw(ctx.runner, param, skZeros, zerosB64(km.ciphertext - 1)),
  );
  await expectReject(
    checks,
    "decaps-ct-too-long",
    () => kemDecapsRaw(ctx.runner, param, skZeros, zerosB64(km.ciphertext + 1)),
  );

  // Wrong-length secret key to decaps (use a valid-length ct of zeros).
  await expectReject(
    checks,
    "decaps-sk-too-short",
    () => kemDecapsRaw(ctx.runner, param, zerosB64(km.secretKey - 1), zerosB64(km.ciphertext)),
  );

  // --- C. FIPS 203 §7.2 encapsulation-key modulus-range check ---------------
  // A correctly-SIZED ek whose t̂ coefficients are NOT reduced mod q (< 3329)
  // must be rejected: §7.2 requires encaps to perform the "modulus check"
  // (ek must round-trip through ByteEncode₁₂/ByteDecode₁₂). The length checks
  // above do NOT catch this — an ek with an out-of-range coefficient still has
  // the right byte length. We take a VALID ek from keygen and force its first
  // 12-bit coefficient to 0xFFF (4095 ≥ 3329) while preserving the length, then
  // require encaps to reject it with a defined error. We assert NO crypto bytes.
  if (pkB64.length > 0) {
    await expectReject(
      checks,
      "encaps-ek-coeff-out-of-range",
      () => kemEncapsRaw(ctx.runner, param, outOfRangeEk(pkB64)),
    );
  } else {
    checks.push(
      fail(
        "encaps-ek-coeff-out-of-range",
        "could not obtain a valid ek from keygen to build the modulus-range probe",
        BUG,
      ),
    );
  }

  const status = rollUp(checks);
  return {
    category: "sizes",
    status,
    bugClass: BUG,
    checks,
    summary:
      status === "pass"
        ? "all artifact lengths correct; wrong-length inputs rejected"
        : `${checks.filter((c) => c.status === "fail").length} size/format issue(s)`,
  };
};

/**
 * Build a same-length-but-out-of-range encapsulation key from a valid one.
 *
 * FIPS 203 packs t̂ with ByteEncode₁₂: each consecutive 3 bytes [b0,b1,b2] hold
 * two 12-bit little-endian coefficients
 *   d0 = b0 | ((b1 & 0x0F) << 8)
 *   d1 = (b1 >> 4) | (b2 << 4)
 * We set the FIRST coefficient d0 to 0xFFF (4095), which is ≥ q (3329) and thus
 * NOT a valid reduced coefficient — this is the classic "ek not reduced mod q"
 * malleability. The byte length is unchanged, so only a real §7.2 modulus check
 * (not a length check) catches it. We touch only b0/b1, leaving everything else
 * (including ρ) intact, so the ek stays structurally well-formed apart from the
 * single out-of-range coefficient. No cryptographic values are fabricated.
 */
function outOfRangeEk(ekB64: string): string {
  const buf = Buffer.from(ekB64, "base64");
  if (buf.length >= 2) {
    buf[0] = 0xff; // low 8 bits of d0
    buf[1] = (buf[1] as number) | 0x0f; // high 4 bits of d0 -> d0 = 0xFFF = 4095
  }
  return buf.toString("base64");
}

/**
 * Run an operation that SHOULD be rejected. A clean protocol `error` (ok:false)
 * passes. A normal success (the SUT accepted a wrong-length input) fails. A
 * harness error such as a crash or timeout also fails — a conforming SUT must
 * reject gracefully, not die.
 */
async function expectReject(
  checks: Check[],
  name: string,
  op: () => Promise<import("../protocol.js").Response>,
): Promise<void> {
  try {
    const resp = await op();
    if (resp.ok === false) {
      checks.push(pass(name, `rejected with defined error: ${resp.code} (${resp.message})`, BUG));
    } else {
      checks.push(
        fail(name, "SUT accepted a wrong-length input and returned a success result", BUG),
      );
    }
  } catch (err) {
    checks.push(
      fail(
        name,
        `SUT crashed/hung on a wrong-length input instead of returning a defined error: ` +
          `${(err as Error).message}`,
        BUG,
      ),
    );
  }
}
