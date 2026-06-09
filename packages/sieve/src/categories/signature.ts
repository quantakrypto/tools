/**
 * Generic signature self-consistency category (FIPS 204 ML-DSA, FIPS 205
 * SLH-DSA).
 *
 * Both schemes expose the same black-box surface — keygen, sign, verify — so a
 * single driver covers them. Signing is randomized (hedged) by default, so we
 * cannot assert exact signature bytes without official vectors; but several
 * properties hold for any conforming implementation and need no external data:
 *
 *   - sizes:            pk/sk lengths match the parameter set; signature length
 *                       matches the fixed encoding.
 *   - sign-then-verify: verify(pk, msg, sign(sk, msg)) === true, over N msgs.
 *   - tamper-message:   verify(pk, msg', sig) === false when msg' != msg.
 *   - tamper-signature: verify(pk, msg, flip-a-bit(sig)) === false.
 *   - wrong-length verify input is rejected with a defined error (AF-05).
 *   - signing-mode (advisory): detect whether sign(sk, msg) is deterministic or
 *     hedged by signing one fixed message twice and comparing. BOTH are valid;
 *     this never fails — it only surfaces the observed behavior.
 *
 * Exact-value KAT (sigVer vectors) is handled separately by the kat category.
 */

import {
  type Category,
  type CategoryContext,
  type CategoryResult,
  type Check,
  fail,
  pass,
  rollUp,
  skip,
} from "./types.js";
import { flipBitB64, zerosB64 } from "./helpers.js";
import { fromB64, toB64, type Response, type SignatureFamily } from "../protocol.js";
import { asSignatureSizes, type ParamSet, type SignatureSizes } from "../sizes.js";

const BUG_SIZE = "AF-05" as const;

/**
 * Build a signature category bound to a family. The same logic drives ML-DSA
 * and SLH-DSA; only the family tag on the wire requests differs.
 */
export function makeSignatureCategory(name: string, family: SignatureFamily): Category {
  return async (ctx): Promise<CategoryResult> => {
    const d = asSignatureSizes(ctx.sizes);
    if (!d || d.family !== family) {
      return {
        category: name,
        status: "skip",
        checks: [],
        summary: `${name} category applies only to ${family} parameter sets`,
      };
    }
    return runSignature(name, family, d, ctx);
  };
}

async function runSignature(
  name: string,
  family: SignatureFamily,
  d: SignatureSizes,
  ctx: CategoryContext,
): Promise<CategoryResult> {
  const param = d.id;
  const checks: Check[] = [];
  const msgs = makeMessages(ctx.iterations);

  // Keygen once; reuse the key pair across messages.
  let pkB64: string;
  let skB64: string;
  try {
    const kg = await ctx.runner.send({ family, param, op: "keygen" });
    if (kg.ok !== true || !("pk" in kg) || !("sk" in kg)) {
      return wrap(name, checks, [fail("keygen", `${family} keygen did not return pk/sk`)]);
    }
    pkB64 = kg.pk;
    skB64 = kg.sk;
    const pk = fromB64(pkB64);
    const sk = fromB64(skB64);
    checks.push(
      pk.length === d.publicKey
        ? pass(
            "pk-length",
            `verification key ${pk.length} bytes (expected ${d.publicKey})`,
            BUG_SIZE,
          )
        : fail(
            "pk-length",
            `verification key ${pk.length} bytes, expected ${d.publicKey}`,
            BUG_SIZE,
          ),
    );
    checks.push(
      sk.length === d.secretKey
        ? pass("sk-length", `signing key ${sk.length} bytes (expected ${d.secretKey})`, BUG_SIZE)
        : fail("sk-length", `signing key ${sk.length} bytes, expected ${d.secretKey}`, BUG_SIZE),
    );
  } catch (err) {
    return wrap(name, checks, [fail("keygen", `harness error: ${(err as Error).message}`)]);
  }

  // --- Round-trips. Each message's sign is independent, so we PIPELINE the
  // sign requests (bounded concurrency), then process verdicts. Verify probes
  // for a given message are independent across messages too. ----------------
  let signed: Response[];
  try {
    signed = await ctx.runner.sendMany(
      msgs.map((msg) => ({ family, param, op: "sign" as const, sk: skB64, msg })),
      ctx.pipelineDepth ?? 16,
    );
  } catch (err) {
    return wrap(name, checks, [fail("sign", `harness error: ${(err as Error).message}`)]);
  }

  let goodVerify = 0;
  let tamperMsgCaught = 0;
  let tamperSigCaught = 0;
  let sigLenOk = 0;
  let attempts = 0;

  for (let i = 0; i < msgs.length; i++) {
    const msgB64 = msgs[i] as string;
    const s = signed[i] as Response;
    attempts++;
    if (s.ok !== true || !("sig" in s)) {
      checks.push(fail(`sign[${i}]`, "sign did not return a signature"));
      continue;
    }
    const sigB64 = s.sig;
    const sig = fromB64(sigB64);
    if (sig.length === d.signature) {
      sigLenOk++;
    } else if (i < 3) {
      checks.push(
        fail(
          `sig-length[${i}]`,
          `signature ${sig.length} bytes, expected ${d.signature}`,
          BUG_SIZE,
        ),
      );
    }

    try {
      // The three verify probes for this message are independent → pipeline them.
      const tamperedMsg = flipBitB64(msgB64.length > 0 ? msgB64 : toB64(new Uint8Array([0])), 0, 1);
      const tamperedSig = flipBitB64(sigB64, sig.length >> 1, 3);
      const [good, badMsg, badSig] = await ctx.runner.sendMany(
        [
          { family, param, op: "verify" as const, pk: pkB64, msg: msgB64, sig: sigB64 },
          { family, param, op: "verify" as const, pk: pkB64, msg: tamperedMsg, sig: sigB64 },
          { family, param, op: "verify" as const, pk: pkB64, msg: msgB64, sig: tamperedSig },
        ],
        ctx.pipelineDepth ?? 16,
      );

      if (verdict(good as Response)) {
        goodVerify++;
      } else if (i < 3) {
        checks.push(fail(`verify[${i}]`, "a freshly produced signature failed to verify"));
      }
      if (!verdict(badMsg as Response)) {
        tamperMsgCaught++;
      } else if (i < 3) {
        checks.push(fail(`tamper-msg[${i}]`, "signature verified against a different message"));
      }
      if (!verdict(badSig as Response)) {
        tamperSigCaught++;
      } else if (i < 3) {
        checks.push(fail(`tamper-sig[${i}]`, "a bit-flipped signature still verified"));
      }
    } catch (err) {
      checks.push(fail(`verify[${i}]`, `harness error: ${(err as Error).message}`));
    }
  }

  if (attempts > 0) {
    if (goodVerify === attempts) {
      checks.push(pass("sign-verify", `${goodVerify}/${attempts} signatures verified`));
    }
    if (tamperMsgCaught === attempts) {
      checks.push(
        pass("tamper-msg", `${tamperMsgCaught}/${attempts} altered-message forgeries rejected`),
      );
    }
    if (tamperSigCaught === attempts) {
      checks.push(
        pass("tamper-sig", `${tamperSigCaught}/${attempts} altered-signature forgeries rejected`),
      );
    }
    if (sigLenOk === attempts) {
      checks.push(
        pass(
          "sig-length",
          `all ${sigLenOk} signatures had the expected ${d.signature} bytes`,
          BUG_SIZE,
        ),
      );
    }
  }

  // --- Advisory: deterministic vs hedged signing ---------------------------
  await probeSigningMode(checks, ctx, family, param, skB64, pkB64);

  // --- Negative: wrong-length verify inputs must be rejected cleanly -------
  await expectVerifyReject(checks, "verify-pk-too-short", () =>
    ctx.runner.send({
      family,
      param,
      op: "verify",
      pk: zerosB64(d.publicKey - 1),
      msg: toB64(new Uint8Array([1, 2, 3])),
      sig: zerosB64(d.signature),
    }),
  );
  await expectVerifyReject(checks, "verify-sig-too-long", () =>
    ctx.runner.send({
      family,
      param,
      op: "verify",
      pk: pkB64,
      msg: toB64(new Uint8Array([1, 2, 3])),
      sig: zerosB64(d.signature + 1),
    }),
  );

  return wrap(name, checks, []);
}

function verdict(resp: Response): boolean {
  if (resp.ok !== true || !("valid" in resp)) {
    throw new Error("verify did not return a 'valid' verdict");
  }
  return resp.valid;
}

/**
 * Advisory probe: sign one fixed message twice and report whether the SUT is
 * deterministic (identical signatures) or hedged (differing signatures). BOTH
 * are FIPS-conforming, so this NEVER fails — it records a `skip`-status note (so
 * it cannot affect the verdict) describing the observed behavior. We also
 * confirm both signatures verify, which IS asserted.
 */
async function probeSigningMode(
  checks: Check[],
  ctx: CategoryContext,
  family: SignatureFamily,
  param: ParamSet,
  skB64: string,
  pkB64: string,
): Promise<void> {
  const msgB64 = toB64(new Uint8Array([0x73, 0x69, 0x67, 0x6d, 0x6f, 0x64, 0x65])); // "sigmode"
  try {
    const [a, b] = await ctx.runner.sendMany(
      [
        { family, param, op: "sign" as const, sk: skB64, msg: msgB64 },
        { family, param, op: "sign" as const, sk: skB64, msg: msgB64 },
      ],
      // Keep these two strictly ordered/serial-equivalent is unnecessary; they
      // are independent. A depth of 2 is fine.
      2,
    );
    if (a.ok !== true || !("sig" in a) || b.ok !== true || !("sig" in b)) {
      checks.push(skip("signing-mode", "could not obtain two signatures to compare (advisory)"));
      return;
    }
    const deterministic = a.sig === b.sig;
    checks.push(
      skip(
        "signing-mode",
        deterministic
          ? "advisory: sign(sk, msg) is DETERMINISTIC (identical signatures for a repeated message)"
          : "advisory: sign(sk, msg) is HEDGED/randomized (signatures differ across calls)",
      ),
    );
    // Both must still verify — this part IS asserted.
    const [va, vb] = await ctx.runner.sendMany(
      [
        { family, param, op: "verify" as const, pk: pkB64, msg: msgB64, sig: a.sig },
        { family, param, op: "verify" as const, pk: pkB64, msg: msgB64, sig: b.sig },
      ],
      2,
    );
    if (verdict(va as Response) && verdict(vb as Response)) {
      checks.push(pass("signing-mode-verify", "both repeated-message signatures verify"));
    } else {
      checks.push(fail("signing-mode-verify", "a repeated-message signature failed to verify"));
    }
  } catch (err) {
    checks.push(skip("signing-mode", `advisory probe could not run: ${(err as Error).message}`));
  }
}

function wrap(name: string, checks: Check[], extra: Check[]): CategoryResult {
  const all = [...checks, ...extra];
  const status = rollUp(all);
  return {
    category: name,
    status,
    checks: all,
    summary:
      status === "pass"
        ? `${name} sign/verify self-consistency holds`
        : `${all.filter((c) => c.status === "fail").length} ${name} issue(s)`,
  };
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
      checks.push(
        fail(name, "SUT accepted a wrong-length verify input and verified true", BUG_SIZE),
      );
    }
  } catch (err) {
    checks.push(
      fail(
        name,
        `SUT crashed/hung on wrong-length verify input: ${(err as Error).message}`,
        BUG_SIZE,
      ),
    );
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
