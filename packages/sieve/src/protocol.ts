/**
 * The Sieve <-> SUT wire protocol.
 *
 * Sieve drives a system-under-test (SUT) — any ML-KEM / ML-DSA implementation
 * the user provides — by spawning it as a child process and exchanging
 * newline-delimited JSON (NDJSON) over stdin/stdout. One request per line, one
 * response per line. All byte fields are base64-encoded strings.
 *
 * This module defines the request/response TypeScript types and the
 * (de)serialization + validation logic. It performs NO cryptography. See
 * PROTOCOL.md for the human-readable specification.
 */

import type { Family, ParamSet } from "./sizes.js";

/** Protocol version. Bumped on any breaking wire change. */
export const PROTOCOL_VERSION = 1 as const;

// ---------------------------------------------------------------------------
// Request types
// ---------------------------------------------------------------------------

/** Operation names, shared across families where the semantics overlap. */
export type Op =
  | "keygen"
  | "encaps"
  | "decaps"
  | "sign"
  | "verify";

/** Fields common to every request. */
interface RequestBase {
  /** Correlation id; the SUT MUST echo it back on the matching response. */
  id: number;
  /** Algorithm family this request targets. */
  family: Family;
  /** Parameter-set identifier, e.g. "ml-kem-768". */
  param: ParamSet;
  /** Operation to perform. */
  op: Op;
}

/** ML-KEM / ML-DSA key generation. `seed` (base64) makes it deterministic. */
export interface KeygenRequest extends RequestBase {
  op: "keygen";
  /** Optional base64 seed for deterministic keygen (impl-defined length). */
  seed?: string;
}

/** ML-KEM encapsulation against a public key. */
export interface EncapsRequest extends RequestBase {
  family: "ml-kem";
  op: "encaps";
  /** Base64 public (encapsulation) key. */
  pk: string;
  /** Optional base64 coins/randomness for deterministic encapsulation. */
  coins?: string;
}

/** ML-KEM decapsulation of a ciphertext with a secret key. */
export interface DecapsRequest extends RequestBase {
  family: "ml-kem";
  op: "decaps";
  /** Base64 secret (decapsulation) key. */
  sk: string;
  /** Base64 ciphertext. */
  ct: string;
}

/** ML-DSA signature generation. */
export interface SignRequest extends RequestBase {
  family: "ml-dsa";
  op: "sign";
  /** Base64 secret (signing) key. */
  sk: string;
  /** Base64 message to sign. */
  msg: string;
}

/** ML-DSA signature verification. */
export interface VerifyRequest extends RequestBase {
  family: "ml-dsa";
  op: "verify";
  /** Base64 public (verification) key. */
  pk: string;
  /** Base64 message. */
  msg: string;
  /** Base64 signature. */
  sig: string;
}

/** Any request Sieve may send. */
export type Request =
  | KeygenRequest
  | EncapsRequest
  | DecapsRequest
  | SignRequest
  | VerifyRequest;

/**
 * Omit that distributes over a union, so each variant keeps its own fields
 * (plain `Omit<Request, "id">` would collapse to only the common keys).
 */
type DistributiveOmit<T, K extends keyof T> = T extends unknown ? Omit<T, K> : never;

/** A request as handed to the runner — the `id` is assigned by the runner. */
export type RequestInput = DistributiveOmit<Request, "id"> & { id?: number };

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

/** Successful keygen result. */
export interface KeygenResult {
  id: number;
  ok: true;
  /** Base64 public key. */
  pk: string;
  /** Base64 secret key. */
  sk: string;
}

/** Successful encapsulation result. */
export interface EncapsResult {
  id: number;
  ok: true;
  /** Base64 ciphertext. */
  ct: string;
  /** Base64 shared secret. */
  ss: string;
}

/** Successful decapsulation result. */
export interface DecapsResult {
  id: number;
  ok: true;
  /** Base64 shared secret. */
  ss: string;
}

/** Successful signing result. */
export interface SignResult {
  id: number;
  ok: true;
  /** Base64 signature. */
  sig: string;
}

/** Successful verification result. `valid` is the verification verdict. */
export interface VerifyResult {
  id: number;
  ok: true;
  /** Whether the signature verified against (pk, msg). */
  valid: boolean;
}

/**
 * A defined, well-formed error. The SUT MUST return this (not crash, not hang,
 * not silently produce garbage) when it cannot or will not honor a request —
 * for example when given a wrong-length key. Sieve treats a clean `error`
 * response as a *correct* rejection in the size/robustness categories.
 */
export interface ErrorResult {
  id: number;
  ok: false;
  /** Short machine-readable code, e.g. "invalid-length", "unsupported". */
  code: string;
  /** Human-readable detail. */
  message: string;
}

/** Any response the SUT may emit. */
export type Response =
  | KeygenResult
  | EncapsResult
  | DecapsResult
  | SignResult
  | VerifyResult
  | ErrorResult;

/** A successful (non-error) response. */
export type SuccessResponse = Exclude<Response, ErrorResult>;

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

/** Serialize a request to a single NDJSON line (including the trailing "\n"). */
export function encodeRequest(req: Request): string {
  return JSON.stringify(req) + "\n";
}

/** Raised when a line from the SUT cannot be parsed into a valid Response. */
export class ProtocolError extends Error {
  /** The offending raw line, truncated for safety. */
  readonly raw: string;
  constructor(message: string, raw: string) {
    super(message);
    this.name = "ProtocolError";
    this.raw = raw.length > 512 ? raw.slice(0, 512) + "…" : raw;
  }
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function isStr(v: unknown): v is string {
  return typeof v === "string";
}

/**
 * Parse one NDJSON line from the SUT into a validated {@link Response}.
 *
 * Validates structural shape only (presence and types of fields); it does NOT
 * validate cryptographic content or byte lengths — that is the categories'
 * job. Throws {@link ProtocolError} on malformed input.
 */
export function decodeResponse(line: string): Response {
  const trimmed = line.trim();
  if (trimmed.length === 0) {
    throw new ProtocolError("empty line", line);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch (err) {
    throw new ProtocolError(
      `not valid JSON: ${(err as Error).message}`,
      line,
    );
  }

  if (!isObject(parsed)) {
    throw new ProtocolError("response is not a JSON object", line);
  }

  const id = parsed["id"];
  if (typeof id !== "number" || !Number.isInteger(id)) {
    throw new ProtocolError("missing/invalid integer 'id'", line);
  }

  const ok = parsed["ok"];
  if (typeof ok !== "boolean") {
    throw new ProtocolError("missing/invalid boolean 'ok'", line);
  }

  if (ok === false) {
    const code = parsed["code"];
    const message = parsed["message"];
    if (!isStr(code) || !isStr(message)) {
      throw new ProtocolError(
        "error response must have string 'code' and 'message'",
        line,
      );
    }
    return { id, ok: false, code, message };
  }

  // ok === true: discriminate by which payload fields are present.
  if (isStr(parsed["pk"]) && isStr(parsed["sk"])) {
    return { id, ok: true, pk: parsed["pk"], sk: parsed["sk"] };
  }
  if (isStr(parsed["ct"]) && isStr(parsed["ss"])) {
    return { id, ok: true, ct: parsed["ct"], ss: parsed["ss"] };
  }
  if (isStr(parsed["ss"])) {
    return { id, ok: true, ss: parsed["ss"] };
  }
  if (isStr(parsed["sig"])) {
    return { id, ok: true, sig: parsed["sig"] };
  }
  if (typeof parsed["valid"] === "boolean") {
    return { id, ok: true, valid: parsed["valid"] };
  }

  throw new ProtocolError(
    "ok response has no recognizable payload " +
      "(expected pk+sk, ct+ss, ss, sig, or valid)",
    line,
  );
}

// ---------------------------------------------------------------------------
// Base64 helpers (Node built-in Buffer — no external dependency)
// ---------------------------------------------------------------------------

/** Encode raw bytes to a base64 string. */
export function toB64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

/**
 * Decode a base64 string to bytes.
 *
 * @throws {ProtocolError} if the input is not valid base64 (i.e. re-encoding
 *   the decoded bytes does not reproduce the canonical form).
 */
export function fromB64(b64: string): Uint8Array {
  const buf = Buffer.from(b64, "base64");
  // Buffer.from is lenient; sanity-check by re-encoding the canonical form.
  if (buf.toString("base64").replace(/=+$/, "") !==
      b64.replace(/\s/g, "").replace(/=+$/, "")) {
    throw new ProtocolError("invalid base64", b64);
  }
  return new Uint8Array(buf);
}
