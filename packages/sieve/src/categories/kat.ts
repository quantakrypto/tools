/**
 * KAT category — Known-Answer Tests against OFFICIAL NIST ACVP vectors.
 *
 * This category is SKIPPED unless the user supplies `--vectors <dir>` with real
 * ACVP files. Sieve never fabricates expected values; if no vectors are
 * present, every check is a `skip` with a clear message pointing at
 * vectors/README.md.
 *
 * What we check when vectors ARE present:
 *   - kem-keygen: if a seed is given, deterministic keygen must reproduce the
 *     expected pk/sk exactly. (Skipped if the SUT can't do seeded keygen.)
 *   - kem-encap: if coins are given, deterministic encaps must reproduce ct/ss.
 *   - kem-decap: decaps(sk, ct) must equal the expected ss exactly.
 *   - dsa-verify: verify(pk, msg, sig) must equal the expected verdict.
 *
 * These ARE exact-value assertions — but the expected bytes come from the
 * user's NIST files, not from Sieve.
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
import { bytesEqual } from "./helpers.js";
import { fromB64, toB64 } from "../protocol.js";
import { loadVectors, type Vector } from "../vectors.js";

export const kat: Category = async (ctx): Promise<CategoryResult> => {
  if (!ctx.vectorsDir) {
    return {
      category: "kat",
      status: "skip",
      checks: [
        skip(
          "vectors",
          "no --vectors <dir> supplied; Sieve ships no test vectors and will not " +
            "fabricate them. See vectors/README.md to obtain official NIST ACVP files.",
        ),
      ],
      summary: "skipped — no official vectors provided",
    };
  }

  const checks: Check[] = [];
  let loaded: ReturnType<typeof loadVectors>;
  try {
    loaded = loadVectors(ctx.vectorsDir);
  } catch (err) {
    return {
      category: "kat",
      status: "fail",
      checks: [fail("load", `could not load vectors from ${ctx.vectorsDir}: ${(err as Error).message}`)],
      summary: "vector load failed",
    };
  }

  for (const note of loaded.notes.slice(0, 10)) {
    checks.push(skip("note", note));
  }

  // Only run vectors matching the parameter set under test.
  const param = ctx.sizes.id;
  const relevant = loaded.vectors.filter((v) => v.param === param);
  if (relevant.length === 0) {
    checks.push(
      skip(
        "applicable",
        `loaded ${loaded.vectors.length} vector(s) from ${loaded.files.length} file(s), ` +
          `but none for ${param}`,
      ),
    );
    const status = rollUp(checks);
    return { category: "kat", status, checks, summary: `no ${param} vectors among supplied files` };
  }

  let okCount = 0;
  let idx = 0;
  for (const v of relevant) {
    idx++;
    try {
      const result = await checkVector(ctx, v);
      if (result.ok) {
        okCount++;
        // Keep the report compact: don't push a pass per vector.
      } else {
        checks.push(fail(`${v.kind}[${idx}]`, result.detail, undefined));
      }
    } catch (err) {
      checks.push(fail(`${v.kind}[${idx}]`, `harness error: ${(err as Error).message}`));
    }
  }

  if (okCount > 0) {
    checks.push(pass("kat", `${okCount}/${relevant.length} ${param} vectors matched expected values`));
  }

  const status = rollUp(checks);
  return {
    category: "kat",
    status,
    checks,
    summary:
      status === "pass"
        ? `${okCount} ${param} KAT vectors passed`
        : `${checks.filter((c) => c.status === "fail").length} KAT mismatch(es)`,
  };
};

interface VectorResult {
  ok: boolean;
  detail: string;
}

async function checkVector(
  ctx: import("./types.js").CategoryContext,
  v: Vector,
): Promise<VectorResult> {
  const { runner } = ctx;
  const param = v.param;

  switch (v.kind) {
    case "kem-keygen": {
      if (!v.seed) return { ok: true, detail: "no seed; skipped" };
      const resp = await runner.send({
        family: "ml-kem",
        param,
        op: "keygen",
        seed: toB64(v.seed),
      });
      if (resp.ok !== true || !("pk" in resp) || !("sk" in resp)) {
        return { ok: false, detail: "seeded keygen did not return pk/sk (SUT may not support seeds)" };
      }
      const pkOk = bytesEqual(fromB64(resp.pk), v.pk);
      const skOk = bytesEqual(fromB64(resp.sk), v.sk);
      return pkOk && skOk
        ? { ok: true, detail: "pk/sk match" }
        : { ok: false, detail: `seeded keygen mismatch (pkOk=${pkOk}, skOk=${skOk})` };
    }
    case "kem-encap": {
      if (!v.coins) return { ok: true, detail: "no coins; skipped" };
      const resp = await runner.send({
        family: "ml-kem",
        param,
        op: "encaps",
        pk: toB64(v.pk),
        coins: toB64(v.coins),
      });
      if (resp.ok !== true || !("ct" in resp) || !("ss" in resp)) {
        return { ok: false, detail: "deterministic encaps did not return ct/ss (SUT may not support coins)" };
      }
      const ctOk = bytesEqual(fromB64(resp.ct), v.ct);
      const ssOk = bytesEqual(fromB64(resp.ss), v.ss);
      return ctOk && ssOk
        ? { ok: true, detail: "ct/ss match" }
        : { ok: false, detail: `encaps mismatch (ctOk=${ctOk}, ssOk=${ssOk})` };
    }
    case "kem-decap": {
      const resp = await runner.send({
        family: "ml-kem",
        param,
        op: "decaps",
        sk: toB64(v.sk),
        ct: toB64(v.ct),
      });
      if (resp.ok !== true || !("ss" in resp)) {
        return { ok: false, detail: "decaps did not return ss" };
      }
      return bytesEqual(fromB64(resp.ss), v.ss)
        ? { ok: true, detail: "ss matches" }
        : { ok: false, detail: "decaps shared secret does not match expected" };
    }
    case "dsa-verify": {
      const resp = await runner.send({
        family: "ml-dsa",
        param,
        op: "verify",
        pk: toB64(v.pk),
        msg: toB64(v.msg),
        sig: toB64(v.sig),
      });
      if (resp.ok !== true || !("valid" in resp)) {
        return { ok: false, detail: "verify did not return a 'valid' verdict" };
      }
      return resp.valid === v.expected
        ? { ok: true, detail: `verdict ${resp.valid} matches expected` }
        : { ok: false, detail: `verify returned ${resp.valid}, expected ${v.expected}` };
    }
  }
}
