#!/usr/bin/env node
/**
 * ============================================================================
 *  MOCK SUT — **NOT REAL CRYPTOGRAPHY**. FOR TESTING THE SIEVE HARNESS ONLY.
 * ============================================================================
 *
 * This program implements the Sieve stdin/stdout protocol with DETERMINISTIC,
 * SELF-CONSISTENT FAKE BYTES of the correct sizes. It does NOT provide any
 * security: keys, ciphertexts, shared secrets and signatures are derived with
 * plain SHA-256-based pseudorandom expansion, not ML-KEM / ML-DSA. Never use it
 * for anything but exercising Sieve's correctness/determinism/size/robustness
 * logic.
 *
 * Why it exists: Sieve must be tested without depending on a real PQC library.
 * A well-behaved mock lets us assert that the harness PASSES good behavior; the
 * `MOCK_BREAK` env var injects faults so we can assert the harness FAILS bad
 * behavior.
 *
 * Self-consistency model (so the harness's round-trip logic is meaningful):
 *   - keygen: sk = H("sk"|seed||rand); pk = H("pk"|sk), expanded to size.
 *   - encaps: derive (ct, ss) deterministically from pk and coins.
 *             A *valid* ct embeds a tag bound to pk so decaps can recover ss.
 *   - decaps: if ct's embedded pk-tag matches the sk's pk, return the same ss
 *             (honest path); otherwise return an implicit-rejection secret
 *             H("reject"|sk||ct) — deterministic, keyed, distinct. This mimics
 *             the *observable* shape of ML-KEM implicit rejection (NOT its math).
 *   - sign/verify: sig = H("sig"|sk||msg) padded to size; verify recomputes the
 *             expected tag from pk's link to sk. Tamper => mismatch => false.
 *
 * Uses only node:crypto, node:readline, node:process.
 */

import { createHash } from "node:crypto";
import { createInterface } from "node:readline";

type Sizes = { pk: number; sk: number; ct: number; ss: number; sig: number };

// Public, standardized parameter sizes (FIPS 203 / 204 / 205). The mock needs
// them to emit correctly-shaped blobs. (sig=0 for KEM sets, ss=0/ct=0 for
// signature sets.)
const SIZES: Record<string, Sizes> = {
  "ml-kem-512": { pk: 800, sk: 1632, ct: 768, ss: 32, sig: 0 },
  "ml-kem-768": { pk: 1184, sk: 2400, ct: 1088, ss: 32, sig: 0 },
  "ml-kem-1024": { pk: 1568, sk: 3168, ct: 1568, ss: 32, sig: 0 },
  "ml-dsa-44": { pk: 1312, sk: 2560, ct: 0, ss: 0, sig: 2420 },
  "ml-dsa-65": { pk: 1952, sk: 4032, ct: 0, ss: 0, sig: 3309 },
  "ml-dsa-87": { pk: 2592, sk: 4896, ct: 0, ss: 0, sig: 4627 },
  // SLH-DSA (FIPS 205, Table 2). pk=2n, sk=4n; sig per set.
  "slh-dsa-sha2-128s": { pk: 32, sk: 64, ct: 0, ss: 0, sig: 7856 },
  "slh-dsa-shake-128s": { pk: 32, sk: 64, ct: 0, ss: 0, sig: 7856 },
  "slh-dsa-sha2-128f": { pk: 32, sk: 64, ct: 0, ss: 0, sig: 17088 },
  "slh-dsa-shake-128f": { pk: 32, sk: 64, ct: 0, ss: 0, sig: 17088 },
  "slh-dsa-sha2-192s": { pk: 48, sk: 96, ct: 0, ss: 0, sig: 16224 },
  "slh-dsa-shake-192s": { pk: 48, sk: 96, ct: 0, ss: 0, sig: 16224 },
  "slh-dsa-sha2-192f": { pk: 48, sk: 96, ct: 0, ss: 0, sig: 35664 },
  "slh-dsa-shake-192f": { pk: 48, sk: 96, ct: 0, ss: 0, sig: 35664 },
  "slh-dsa-sha2-256s": { pk: 64, sk: 128, ct: 0, ss: 0, sig: 29792 },
  "slh-dsa-shake-256s": { pk: 64, sk: 128, ct: 0, ss: 0, sig: 29792 },
  "slh-dsa-sha2-256f": { pk: 64, sk: 128, ct: 0, ss: 0, sig: 49856 },
  "slh-dsa-shake-256f": { pk: 64, sk: 128, ct: 0, ss: 0, sig: 49856 },
};

/** Fault injection: set MOCK_BREAK to make the mock misbehave on purpose. */
const BREAK = process.env["MOCK_BREAK"] ?? "";

const TAG_LEN = 16; // bytes of pk-binding tag embedded near the front of ct

function h(...parts: (string | Buffer)[]): Buffer {
  const hash = createHash("sha256");
  for (const p of parts) hash.update(typeof p === "string" ? Buffer.from(p, "utf8") : p);
  return hash.digest();
}

/** Deterministic byte expansion to exactly `n` bytes from a seed buffer. */
function expand(seed: Buffer, n: number): Buffer {
  const out = Buffer.alloc(n);
  let off = 0;
  let counter = 0;
  while (off < n) {
    const block = h(seed, Buffer.from([counter & 0xff, (counter >> 8) & 0xff]));
    block.copy(out, off);
    off += block.length;
    counter++;
  }
  return out;
}

function b64(buf: Buffer): string {
  return buf.toString("base64");
}
function unb64(s: string): Buffer {
  return Buffer.from(s, "base64");
}

// --- FIPS 203 §7.2 encapsulation-key modulus-range modelling ---------------
// A real ML-KEM ek is ByteEncode₁₂(t̂) || ρ: the first (pk-32) bytes pack 12-bit
// little-endian coefficients that MUST be < q. The mock's fake pk bytes don't
// naturally satisfy this, so we (a) REDUCE the t̂ region at keygen so the
// well-behaved mock emits a valid ek, and (b) RANGE-CHECK at encaps so an
// out-of-range ek is rejected — exactly the §7.2 input validation Sieve probes.
const KEM_Q = 3329;

/** Iterate the 12-bit coefficients packed in the t̂ region; call cb per coeff. */
function eachCoeff12(that: Buffer, cb: (coeff: number, i: number) => void): void {
  const pairs = Math.floor(that.length / 3);
  for (let p = 0; p < pairs; p++) {
    const b0 = that[p * 3] as number;
    const b1 = that[p * 3 + 1] as number;
    const b2 = that[p * 3 + 2] as number;
    cb(b0 | ((b1 & 0x0f) << 8), p * 2);
    cb((b1 >> 4) | (b2 << 4), p * 2 + 1);
  }
}

/** Pack a list of 12-bit coefficients back into the t̂ byte region (in place). */
function packCoeff12(that: Buffer, coeffs: number[]): void {
  const pairs = Math.floor(that.length / 3);
  for (let p = 0; p < pairs; p++) {
    const d0 = coeffs[p * 2] as number;
    const d1 = coeffs[p * 2 + 1] as number;
    that[p * 3] = d0 & 0xff;
    that[p * 3 + 1] = ((d0 >> 8) & 0x0f) | ((d1 & 0x0f) << 4);
    that[p * 3 + 2] = (d1 >> 4) & 0xff;
  }
}

/** Reduce a fresh pk's t̂ region so every packed 12-bit coefficient is < q. */
function reduceEkCoeffs(pk: Buffer): void {
  const that = pk.subarray(0, pk.length - 32); // last 32 bytes are ρ
  const coeffs: number[] = [];
  eachCoeff12(that, (c) => coeffs.push(c % KEM_Q));
  packCoeff12(that, coeffs);
}

/** True iff any packed 12-bit coefficient in the t̂ region is ≥ q. */
function ekHasOutOfRangeCoeff(ek: Buffer): boolean {
  const that = ek.subarray(0, ek.length - 32);
  let bad = false;
  eachCoeff12(that, (c) => {
    if (c >= KEM_Q) bad = true;
  });
  return bad;
}

let reqCounter = 0;

function keygen(param: string, seedB64?: string): { pk: string; sk: string } {
  const sizes = SIZES[param] as Sizes;
  // Deterministic if a seed is given; otherwise per-call counter randomness.
  const entropy = seedB64 ? unb64(seedB64) : Buffer.from(`rand-${reqCounter++}-${Math.random()}`);
  const sk = expand(h("sk", entropy), sizes.sk);
  // pk is derived from the sk TAIL (bytes after TAG_LEN). We then overwrite the
  // sk HEAD with a pk-tag so decaps can recover it from sk alone — deriving pk
  // from the tail keeps pk stable under that overwrite (see pkFromSk).
  const pk = expand(h("pk", sk.subarray(TAG_LEN)), sizes.pk);
  // For ML-KEM, reduce the t̂ region so the emitted ek satisfies the FIPS 203
  // §7.2 modulus range (all packed 12-bit coefficients < q). Done BEFORE the
  // pk-tag is computed so the tag binds the final pk.
  if (param.startsWith("ml-kem") && pk.length > 32) reduceEkCoeffs(pk);
  const pkTag = h("pktag", pk).subarray(0, TAG_LEN);
  pkTag.copy(sk, 0);
  return { pk: b64(pk), sk: b64(sk) };
}

function encaps(param: string, pkB64: string, coinsB64?: string): { ct: string; ss: string } {
  const sizes = SIZES[param] as Sizes;
  const pk = unb64(pkB64);
  if (pk.length !== sizes.pk) throw { code: "invalid-length", message: `pk must be ${sizes.pk} bytes` };
  // FIPS 203 §7.2: reject a correctly-sized ek whose t̂ coefficients are not
  // reduced mod q. The well-behaved mock enforces this; MOCK_BREAK can disable
  // it to model an implementation that skips the modulus check.
  if (BREAK !== "accept-out-of-range-ek" && ekHasOutOfRangeCoeff(pk)) {
    throw { code: "invalid-ek", message: "encapsulation key has an out-of-range coefficient (≥ q)" };
  }
  const coins = coinsB64 ? unb64(coinsB64) : Buffer.from(`coins-${reqCounter++}-${Math.random()}`);
  // ct layout: [ pkTag(16) | body... ]. pkTag binds the ct to this pk so decaps
  // can detect corruption; body carries enough entropy to derive ss.
  const pkTag = h("pktag", pk).subarray(0, TAG_LEN);
  let ct = Buffer.concat([pkTag, expand(h("ctbody", pk, coins), sizes.ct - TAG_LEN)]).subarray(0, sizes.ct);
  // ss is a PURE FUNCTION OF THE CT BODY so decaps (which sees ct, not coins)
  // can reproduce the identical value on the honest path. See reconcileSs.
  const ss = reconcileSs(param, ct);

  if (BREAK === "wrong-ct-size") ct = ct.subarray(0, sizes.ct - 1);
  if (BREAK === "wrong-ss-size") return { ct: b64(ct), ss: b64(ss.subarray(0, sizes.ss - 1)) };

  return { ct: b64(ct), ss: b64(Buffer.from(ss)) };
}

function decaps(param: string, skB64: string, ctB64: string): { ss: string } {
  const sizes = SIZES[param] as Sizes;
  const sk = unb64(skB64);
  const ct = unb64(ctB64);
  if (sk.length !== sizes.sk) throw { code: "invalid-length", message: `sk must be ${sizes.sk} bytes` };
  if (ct.length !== sizes.ct) throw { code: "invalid-length", message: `ct must be ${sizes.ct} bytes` };

  const skPkTag = sk.subarray(0, TAG_LEN); // pk-tag stored at keygen
  const ctPkTag = ct.subarray(0, TAG_LEN); // pk-tag embedded by encaps

  if (BREAK === "nondeterministic-decaps") {
    // Mix fresh randomness — should FAIL the determinism category.
    return { ss: b64(expand(h("ss-rand", Buffer.from(`${Math.random()}`)), sizes.ss)) };
  }

  if (skPkTag.equals(ctPkTag)) {
    // Honest path: reproduce encaps' ss from the (matching) ct body.
    return { ss: b64(reconcileSs(param, ct)) };
  }

  // Corrupted / mismatched ct: implicit-rejection territory.
  if (BREAK === "reject-errors") {
    // BAD: signal an error on corrupted ct (leaks validity) — fails AF-02.
    throw { code: "decap-failed", message: "ciphertext rejected" };
  }
  if (BREAK === "reject-honest") {
    // BAD: return the honest ss anyway (no integrity check) — fails AF-02 "differs".
    return { ss: b64(reconcileSs(param, ct)) };
  }

  // Correct implicit-rejection: deterministic, keyed, distinct from honest.
  const rej = h("reject", sk, ct).subarray(0, sizes.ss);
  return { ss: b64(Buffer.from(rej)) };
}

/**
 * Canonical honest shared-secret derivation, a pure function of the ct body.
 * BOTH encaps and the honest decaps path call this, so the round-trip agrees.
 */
function reconcileSs(param: string, ct: Buffer): Buffer {
  const sizes = SIZES[param] as Sizes;
  const body = ct.subarray(TAG_LEN);
  return Buffer.from(h("ssfinal", body).subarray(0, sizes.ss));
}

/** Recompute the public verification key from the signing key (mock binding). */
function pkFromSk(param: string, sk: Buffer): Buffer {
  const sizes = SIZES[param] as Sizes;
  // Must match keygen: pk derives from the sk tail (head holds the pk-tag).
  return expand(h("pk", sk.subarray(TAG_LEN)), sizes.pk);
}

function sign(param: string, skB64: string, msgB64: string): { sig: string } {
  const sizes = SIZES[param] as Sizes;
  const sk = unb64(skB64);
  if (sk.length !== sizes.sk) throw { code: "invalid-length", message: `sk must be ${sizes.sk} bytes` };
  const msg = unb64(msgB64);
  // sig layout: [ salt(16) | mac... ] where the whole `mac` region is a keyed
  // expansion of (pk, msg, salt). The random salt makes signing non-
  // deterministic — matching ML-DSA's hedged mode — so we never assert exact
  // sig bytes. verify() recomputes the mac and checks EVERY mac byte, so a flip
  // anywhere in the body (or a changed msg/pk) breaks verification.
  const pk = pkFromSk(param, sk); // pk = expand(H("pk"|sk)) from keygen
  // Hedged by default (random salt). MOCK_BREAK=deterministic-sign forces a
  // deterministic salt so the signing-mode advisory probe reports DETERMINISTIC.
  const saltEntropy = BREAK === "deterministic-sign" ? Buffer.alloc(0) : Buffer.from(`${Math.random()}`);
  const salt = h("sigsalt", sk, msg, saltEntropy).subarray(0, TAG_LEN);
  const mac = expand(h("vmac", pk, msg, salt), sizes.sig - TAG_LEN);
  let sig = Buffer.concat([salt, mac]).subarray(0, sizes.sig);
  if (BREAK === "wrong-sig-size") sig = sig.subarray(0, sizes.sig - 1);
  return { sig: b64(sig) };
}

function verify(param: string, pkB64: string, msgB64: string, sigB64: string): { valid: boolean } {
  const sizes = SIZES[param] as Sizes;
  const pk = unb64(pkB64);
  const sig = unb64(sigB64);
  if (pk.length !== sizes.pk) throw { code: "invalid-length", message: `pk must be ${sizes.pk} bytes` };
  if (sig.length !== sizes.sig) throw { code: "invalid-length", message: `sig must be ${sizes.sig} bytes` };
  const msg = unb64(msgB64);
  if (BREAK === "verify-always-true") return { valid: true };
  const salt = sig.subarray(0, TAG_LEN);
  const expectMac = expand(h("vmac", pk, msg, salt), sizes.sig - TAG_LEN);
  const actualMac = sig.subarray(TAG_LEN);
  return { valid: expectMac.equals(actualMac) };
}

// ---------------------------------------------------------------------------
// Request loop
// ---------------------------------------------------------------------------

interface Req {
  id: number;
  family: string;
  param: string;
  op: string;
  seed?: string;
  pk?: string;
  sk?: string;
  ct?: string;
  coins?: string;
  msg?: string;
  sig?: string;
}

function handle(req: Req): object {
  const sizes = SIZES[req.param];
  if (!sizes) return { id: req.id, ok: false, code: "unsupported", message: `unknown param ${req.param}` };

  try {
    switch (req.op) {
      case "keygen": {
        const { pk, sk } = keygen(req.param, req.seed);
        return { id: req.id, ok: true, pk, sk };
      }
      case "encaps": {
        if (req.pk === undefined) throw { code: "bad-request", message: "encaps needs pk" };
        const r = encaps(req.param, req.pk, req.coins);
        return { id: req.id, ok: true, ct: r.ct, ss: r.ss };
      }
      case "decaps": {
        if (req.sk === undefined || req.ct === undefined) throw { code: "bad-request", message: "decaps needs sk, ct" };
        const r = decaps(req.param, req.sk, req.ct);
        return { id: req.id, ok: true, ss: r.ss };
      }
      case "sign": {
        if (req.sk === undefined || req.msg === undefined) throw { code: "bad-request", message: "sign needs sk, msg" };
        const r = sign(req.param, req.sk, req.msg);
        return { id: req.id, ok: true, sig: r.sig };
      }
      case "verify": {
        if (req.pk === undefined || req.msg === undefined || req.sig === undefined) {
          throw { code: "bad-request", message: "verify needs pk, msg, sig" };
        }
        const r = verify(req.param, req.pk, req.msg, req.sig);
        return { id: req.id, ok: true, valid: r.valid };
      }
      default:
        return { id: req.id, ok: false, code: "unsupported", message: `unknown op ${req.op}` };
    }
  } catch (e) {
    const err = e as { code?: string; message?: string };
    return {
      id: req.id,
      ok: false,
      code: err.code ?? "error",
      message: err.message ?? "mock error",
    };
  }
}

function main(): void {
  const rl = createInterface({ input: process.stdin });
  rl.on("line", (line) => {
    const trimmed = line.trim();
    if (trimmed.length === 0) return;
    let req: Req;
    try {
      req = JSON.parse(trimmed) as Req;
    } catch {
      process.stdout.write(JSON.stringify({ id: 0, ok: false, code: "bad-json", message: "unparseable request" }) + "\n");
      return;
    }
    if (BREAK === "crash-on-decaps" && req.op === "decaps") {
      // Simulate a hard crash on a particular op.
      process.exit(7);
    }
    process.stdout.write(JSON.stringify(handle(req)) + "\n");
  });
}

main();
