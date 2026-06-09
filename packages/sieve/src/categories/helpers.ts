/**
 * Helpers shared by the test categories: typed request wrappers that drive a
 * Runner, plus small byte utilities. No cryptography — these just move bytes.
 */

import { fromB64, type Response } from "../protocol.js";
import type { Runner } from "../runner.js";
import type { KemSizes, ParamSet } from "../sizes.js";

/** A response we expected to succeed but did not. */
export class UnexpectedResponse extends Error {
  constructor(message: string, public readonly response: Response) {
    super(message);
    this.name = "UnexpectedResponse";
  }
}

/** ML-KEM keygen, returning decoded pk/sk bytes. Throws on error/wrong shape. */
export async function kemKeygen(
  runner: Runner,
  param: ParamSet,
  seed?: string,
): Promise<{ pk: Uint8Array; sk: Uint8Array }> {
  const resp = await runner.send({ family: "ml-kem", param, op: "keygen", ...(seed ? { seed } : {}) });
  if (resp.ok !== true || !("pk" in resp) || !("sk" in resp)) {
    throw new UnexpectedResponse("expected keygen pk/sk result", resp);
  }
  return { pk: fromB64(resp.pk), sk: fromB64(resp.sk) };
}

/** ML-KEM encapsulate, returning decoded ct/ss. Throws on error/wrong shape. */
export async function kemEncaps(
  runner: Runner,
  param: ParamSet,
  pkB64: string,
  coins?: string,
): Promise<{ ct: Uint8Array; ss: Uint8Array }> {
  const resp = await runner.send({
    family: "ml-kem",
    param,
    op: "encaps",
    pk: pkB64,
    ...(coins ? { coins } : {}),
  });
  if (resp.ok !== true || !("ct" in resp) || !("ss" in resp)) {
    throw new UnexpectedResponse("expected encaps ct/ss result", resp);
  }
  return { ct: fromB64(resp.ct), ss: fromB64(resp.ss) };
}

/** ML-KEM decapsulate, returning decoded ss. Throws on error/wrong shape. */
export async function kemDecaps(
  runner: Runner,
  param: ParamSet,
  skB64: string,
  ctB64: string,
): Promise<Uint8Array> {
  const resp = await runner.send({ family: "ml-kem", param, op: "decaps", sk: skB64, ct: ctB64 });
  if (resp.ok !== true || !("ss" in resp)) {
    throw new UnexpectedResponse("expected decaps ss result", resp);
  }
  return fromB64(resp.ss);
}

/** Raw decaps that returns the full response (used by categories that expect errors). */
export function kemDecapsRaw(
  runner: Runner,
  param: ParamSet,
  skB64: string,
  ctB64: string,
): Promise<Response> {
  return runner.send({ family: "ml-kem", param, op: "decaps", sk: skB64, ct: ctB64 });
}

/** Raw encaps returning the full response (for error-path tests). */
export function kemEncapsRaw(
  runner: Runner,
  param: ParamSet,
  pkB64: string,
): Promise<Response> {
  return runner.send({ family: "ml-kem", param, op: "encaps", pk: pkB64 });
}

/** Constant-ish byte equality (length then content). Not security-critical. */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/** Base64 of `n` bytes, all zero — a deterministic wrong-but-valid blob. */
export function zerosB64(n: number): string {
  return Buffer.alloc(n).toString("base64");
}

/** Flip one bit in a base64 blob, returning new base64. Used to corrupt ct. */
export function flipBitB64(b64: string, byteIndex = 0, bit = 0): string {
  const buf = Buffer.from(b64, "base64");
  if (buf.length === 0) return b64;
  const idx = byteIndex % buf.length;
  buf[idx] = (buf[idx] as number) ^ (1 << (bit & 7));
  return buf.toString("base64");
}

/** Assert a value is a KEM size record (narrowing). */
export function requireKem(s: { family: string }): KemSizes {
  if (s.family !== "ml-kem") {
    throw new Error(`expected an ML-KEM parameter set, got ${s.family}`);
  }
  return s as KemSizes;
}

/**
 * Run `task(i)` for i in [0, count) with at most `limit` running concurrently,
 * returning results in index order. Used by categories whose ITERATIONS are
 * mutually independent (each builds its own keypair), so several iteration
 * chains can be in flight against the id-correlated SUT at once. Dependent
 * steps WITHIN a single iteration remain serial inside `task`.
 *
 * `limit <= 1` degrades to strictly serial execution. See
 * docs/audits/performance.md §7.1.
 */
export async function mapBounded<T>(
  count: number,
  limit: number,
  task: (i: number) => Promise<T>,
): Promise<T[]> {
  const n = Math.max(0, count);
  const cap = Math.max(1, Math.floor(limit));
  const out: T[] = new Array(n);
  let next = 0;
  let firstError: Error | undefined;

  const worker = async (): Promise<void> => {
    while (firstError === undefined) {
      const i = next++;
      if (i >= n) return;
      try {
        out[i] = await task(i);
      } catch (err) {
        if (firstError === undefined) firstError = err as Error;
        return;
      }
    }
  };

  const workers: Promise<void>[] = [];
  for (let w = 0; w < Math.min(cap, n); w++) workers.push(worker());
  await Promise.all(workers);
  if (firstError !== undefined) throw firstError;
  return out;
}
