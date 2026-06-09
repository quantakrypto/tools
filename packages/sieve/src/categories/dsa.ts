/**
 * ML-DSA self-consistency category (FIPS 204).
 *
 * Signing is randomized (hedged) by default, so we cannot assert exact
 * signature bytes without official vectors. But several properties hold for any
 * conforming implementation and need no external data:
 *
 *   - sign-then-verify: verify(pk, msg, sign(sk, msg)) === true, over N msgs.
 *   - tamper-message:   verify(pk, msg', sig) === false when msg' != msg.
 *   - tamper-signature: verify(pk, msg, flip-a-bit(sig)) === false.
 *   - sizes:            pk/sk lengths match the parameter set; signature length
 *                       matches the fixed ML-DSA encoding.
 *   - wrong-length verify input is rejected with a defined error (AF-05).
 *
 * Exact-value KAT (sigVer vectors) is handled separately by the kat category.
 */

import {
  type Category,
  type CategoryResult,
  type Check,
  fail,
  pass,
  rollUp,
} from "./types.js";
import { flipBitB64, zerosB64 } from "./helpers.js";
import { fromB64, toB64, type Response } from "../protocol.js";
import { asDsaSizes } from "../sizes.js";

const BUG_SIZE = "AF-05" as const;

export const dsa: Category = async (ctx): Promise<CategoryResult> => {
  const d = asDsaSizes(ctx.sizes);
  if (!d) {
    return {
      category: "dsa",
      status: "skip",
      checks: [],
      summary: "ML-DSA category applies only to ML-DSA parameter sets",
    };
  }

  const param = d.id;
  const checks: Check[] = [];
  const msgs = makeMessages(ctx.iterations);

  // Keygen once; reuse the key pair across messages.
  let pkB64: string;
  let skB64: string;
  try {
    const kg = await ctx.runner.send({ family: "ml-dsa", param, op: "keygen" });
    if (kg.ok !== true || !("pk" in kg) || !("sk" in kg)) {
      return wrap(checks, [fail("keygen", "ML-DSA keygen did not return pk/sk")]);
    }
    pkB64 = kg.pk;
    skB64 = kg.sk;
    const pk = fromB64(pkB64);
    const sk = fromB64(skB64);
    checks.push(
      pk.length === d.publicKey
        ? pass("pk-length", `verification key ${pk.length} bytes (expected ${d.publicKey})`, BUG_SIZE)
        : fail("pk-length", `verification key ${pk.length} bytes, expected ${d.publicKey}`, BUG_SIZE),
    );
    checks.push(
      sk.length === d.secretKey
        ? pass("sk-length", `signing key ${sk.length} bytes (expected ${d.secretKey})`, BUG_SIZE)
        : fail("sk-length", `signing key ${sk.length} bytes, expected ${d.secretKey}`, BUG_SIZE),
    );
  } catch (err) {
    return wrap(checks, [fail("keygen", `harness error: ${(err as Error).message}`)]);
  }

  let goodVerify = 0;
  let tamperMsgCaught = 0;
  let tamperSigCaught = 0;
  let sigLenOk = 0;
  let attempts = 0;

  for (let i = 0; i < msgs.length; i++) {
    const msgB64 = msgs[i] as string;
    attempts++;
    try {
      const signed = await ctx.runner.send({ family: "ml-dsa", param, op: "sign", sk: skB64, msg: msgB64 });
      if (signed.ok !== true || !("sig" in signed)) {
        checks.push(fail(`sign[${i}]`, "sign did not return a signature"));
        continue;
      }
      const sigB64 = signed.sig;
      const sig = fromB64(sigB64);
      if (sig.length === d.signature) {
        sigLenOk++;
      } else if (i < 3) {
        checks.push(
          fail(`sig-length[${i}]`, `signature ${sig.length} bytes, expected ${d.signature}`, BUG_SIZE),
        );
      }

      // sign-then-verify must succeed.
      if (await verifyVerdict(ctx, param, pkB64, msgB64, sigB64)) {
        goodVerify++;
      } else if (i < 3) {
        checks.push(fail(`verify[${i}]`, "a freshly produced signature failed to verify"));
      }

      // tamper the message -> must fail.
      const tamperedMsg = flipBitB64(msgB64.length > 0 ? msgB64 : toB64(new Uint8Array([0])), 0, 1);
      if (!(await verifyVerdict(ctx, param, pkB64, tamperedMsg, sigB64))) {
        tamperMsgCaught++;
      } else if (i < 3) {
        checks.push(fail(`tamper-msg[${i}]`, "signature verified against a different message"));
      }

      // tamper the signature -> must fail.
      const tamperedSig = flipBitB64(sigB64, sig.length >> 1, 3);
      if (!(await verifyVerdict(ctx, param, pkB64, msgB64, tamperedSig))) {
        tamperSigCaught++;
      } else if (i < 3) {
        checks.push(fail(`tamper-sig[${i}]`, "a bit-flipped signature still verified"));
      }
    } catch (err) {
      checks.push(fail(`sign-verify[${i}]`, `harness error: ${(err as Error).message}`));
    }
  }

  if (attempts > 0) {
    if (goodVerify === attempts) {
      checks.push(pass("sign-verify", `${goodVerify}/${attempts} signatures verified`));
    }
    if (tamperMsgCaught === attempts) {
      checks.push(pass("tamper-msg", `${tamperMsgCaught}/${attempts} altered-message forgeries rejected`));
    }
    if (tamperSigCaught === attempts) {
      checks.push(pass("tamper-sig", `${tamperSigCaught}/${attempts} altered-signature forgeries rejected`));
    }
    if (sigLenOk === attempts) {
      checks.push(pass("sig-length", `all ${sigLenOk} signatures had the expected ${d.signature} bytes`, BUG_SIZE));
    }
  }

  // Negative: wrong-length verify inputs must be rejected with a defined error.
  await expectVerifyReject(checks, "verify-pk-too-short", () =>
    ctx.runner.send({
      family: "ml-dsa",
      param,
      op: "verify",
      pk: zerosB64(d.publicKey - 1),
      msg: toB64(new Uint8Array([1, 2, 3])),
      sig: zerosB64(d.signature),
    }),
  );
  await expectVerifyReject(checks, "verify-sig-too-long", () =>
    ctx.runner.send({
      family: "ml-dsa",
      param,
      op: "verify",
      pk: pkB64,
      msg: toB64(new Uint8Array([1, 2, 3])),
      sig: zerosB64(d.signature + 1),
    }),
  );

  return wrap(checks, []);
};

function wrap(checks: Check[], extra: Check[]): CategoryResult {
  const all = [...checks, ...extra];
  const status = rollUp(all);
  return {
    category: "dsa",
    status,
    checks: all,
    summary:
      status === "pass"
        ? "ML-DSA sign/verify self-consistency holds"
        : `${all.filter((c) => c.status === "fail").length} ML-DSA issue(s)`,
  };
}

async function verifyVerdict(
  ctx: import("./types.js").CategoryContext,
  param: import("../sizes.js").ParamSet,
  pkB64: string,
  msgB64: string,
  sigB64: string,
): Promise<boolean> {
  const resp = await ctx.runner.send({ family: "ml-dsa", param, op: "verify", pk: pkB64, msg: msgB64, sig: sigB64 });
  if (resp.ok !== true || !("valid" in resp)) {
    throw new Error("verify did not return a 'valid' verdict");
  }
  return resp.valid;
}

async function expectVerifyReject(
  checks: Check[],
  name: string,
  op: () => Promise<Response>,
): Promise<void> {
  try {
    const resp = await op();
    if (resp.ok === false) {
      checks.push(pass(name, `rejected with defined error: ${resp.code}`, BUG_SIZE));
    } else if ("valid" in resp && resp.valid === false) {
      // Returning a false verdict for malformed input is also acceptable.
      checks.push(pass(name, "wrong-length input verified as false (acceptable)", BUG_SIZE));
    } else {
      checks.push(fail(name, "SUT accepted a wrong-length verify input and verified true", BUG_SIZE));
    }
  } catch (err) {
    checks.push(fail(name, `SUT crashed/hung on wrong-length verify input: ${(err as Error).message}`, BUG_SIZE));
  }
}

/** Deterministic, varied messages of assorted lengths (incl. empty). */
function makeMessages(n: number): string[] {
  const out: string[] = [];
  const count = Math.max(1, Math.min(n, 16));
  for (let i = 0; i < count; i++) {
    const len = (i * 7) % 33; // 0..32 varying lengths
    const bytes = new Uint8Array(len);
    for (let j = 0; j < len; j++) bytes[j] = (i * 31 + j * 17) & 0xff;
    out.push(toB64(bytes));
  }
  return out;
}
