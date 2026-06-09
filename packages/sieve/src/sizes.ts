/**
 * Public parameter-size tables for ML-KEM (FIPS 203), ML-DSA (FIPS 204), and
 * SLH-DSA (FIPS 205).
 *
 * These are the ONLY hard-coded cryptographic constants in Sieve. They are
 * public, standardized byte lengths — not secret Known-Answer-Test values.
 * Sieve uses them purely to check that a system-under-test (SUT) emits
 * artifacts of the correct shape; it never derives or fabricates the bytes
 * themselves.
 *
 * Sources:
 *   - ML-KEM:   NIST FIPS 203, Table 3 (sizes of key/ciphertext byte strings).
 *   - ML-DSA:   NIST FIPS 204, Table 2 (sizes of key/signature byte strings).
 *   - SLH-DSA:  NIST FIPS 205, Table 2 (parameter sets) — pk = 2n, sk = 4n,
 *               signature lengths per set. The 12 standardized sets pair each of
 *               six (security level × s/f) combinations with a SHA2 or SHAKE
 *               hash; the public sizes depend only on the level×s/f, so the
 *               SHA2 and SHAKE variants share sizes.
 */

/** Algorithm families Sieve knows how to drive. */
export type Family = "ml-kem" | "ml-dsa" | "slh-dsa";

/** Canonical parameter-set identifiers accepted on the CLI / API. */
export type ParamSet =
  | "ml-kem-512"
  | "ml-kem-768"
  | "ml-kem-1024"
  | "ml-dsa-44"
  | "ml-dsa-65"
  | "ml-dsa-87"
  | "slh-dsa-sha2-128s"
  | "slh-dsa-shake-128s"
  | "slh-dsa-sha2-128f"
  | "slh-dsa-shake-128f"
  | "slh-dsa-sha2-192s"
  | "slh-dsa-shake-192s"
  | "slh-dsa-sha2-192f"
  | "slh-dsa-shake-192f"
  | "slh-dsa-sha2-256s"
  | "slh-dsa-shake-256s"
  | "slh-dsa-sha2-256f"
  | "slh-dsa-shake-256f";

/** Byte sizes for an ML-KEM parameter set (FIPS 203, Table 3). */
export interface KemSizes {
  readonly family: "ml-kem";
  readonly id: ParamSet;
  /** Encapsulation (public) key length in bytes. */
  readonly publicKey: number;
  /** Decapsulation (secret) key length in bytes. */
  readonly secretKey: number;
  /** Ciphertext length in bytes. */
  readonly ciphertext: number;
  /** Shared secret length in bytes (32 for every ML-KEM set). */
  readonly sharedSecret: number;
}

/** Byte sizes for an ML-DSA parameter set (FIPS 204, Table 2). */
export interface DsaSizes {
  readonly family: "ml-dsa";
  readonly id: ParamSet;
  /** Verification (public) key length in bytes. */
  readonly publicKey: number;
  /** Signing (secret) key length in bytes. */
  readonly secretKey: number;
  /** Signature length in bytes (fixed-length encoding). */
  readonly signature: number;
}

/** Byte sizes for an SLH-DSA parameter set (FIPS 205, Table 2). */
export interface SlhDsaSizes {
  readonly family: "slh-dsa";
  readonly id: ParamSet;
  /** Verification (public) key length in bytes (= 2·n). */
  readonly publicKey: number;
  /** Signing (secret) key length in bytes (= 4·n). */
  readonly secretKey: number;
  /** Signature length in bytes. */
  readonly signature: number;
}

/** Union of the size shapes. */
export type Sizes = KemSizes | DsaSizes | SlhDsaSizes;

/** A signature-family size record (ML-DSA or SLH-DSA). */
export type SignatureSizes = DsaSizes | SlhDsaSizes;

/**
 * The size table. Values are public, standardized constants.
 *
 * ML-KEM (FIPS 203, Table 3):
 *   set        pk     sk     ct     ss
 *   512        800    1632   768    32
 *   768        1184   2400   1088   32
 *   1024       1568   3168   1568   32
 *
 * ML-DSA (FIPS 204, Table 2):
 *   set        pk     sk     sig
 *   44         1312   2560   2420
 *   65         1952   4032   3309
 *   87         2592   4896   4627
 *
 * SLH-DSA (FIPS 205, Table 2): pk = 2n, sk = 4n; signature length per set.
 *   level/var  n    pk    sk     sig
 *   128s       16   32    64     7856
 *   128f       16   32    64     17088
 *   192s       24   48    96     16224
 *   192f       24   48    96     35664
 *   256s       32   64    128    29792
 *   256f       32   64    128    49856
 * (SHA2 and SHAKE variants of a given level/var share these public sizes.)
 */
const TABLE: Readonly<Record<ParamSet, Sizes>> = {
  "ml-kem-512": {
    family: "ml-kem",
    id: "ml-kem-512",
    publicKey: 800,
    secretKey: 1632,
    ciphertext: 768,
    sharedSecret: 32,
  },
  "ml-kem-768": {
    family: "ml-kem",
    id: "ml-kem-768",
    publicKey: 1184,
    secretKey: 2400,
    ciphertext: 1088,
    sharedSecret: 32,
  },
  "ml-kem-1024": {
    family: "ml-kem",
    id: "ml-kem-1024",
    publicKey: 1568,
    secretKey: 3168,
    ciphertext: 1568,
    sharedSecret: 32,
  },
  "ml-dsa-44": {
    family: "ml-dsa",
    id: "ml-dsa-44",
    publicKey: 1312,
    secretKey: 2560,
    signature: 2420,
  },
  "ml-dsa-65": {
    family: "ml-dsa",
    id: "ml-dsa-65",
    publicKey: 1952,
    secretKey: 4032,
    signature: 3309,
  },
  "ml-dsa-87": {
    family: "ml-dsa",
    id: "ml-dsa-87",
    publicKey: 2592,
    secretKey: 4896,
    signature: 4627,
  },

  // SLH-DSA (FIPS 205, Table 2). SHA2 and SHAKE share sizes per level/variant.
  "slh-dsa-sha2-128s": { family: "slh-dsa", id: "slh-dsa-sha2-128s", publicKey: 32, secretKey: 64, signature: 7856 },
  "slh-dsa-shake-128s": { family: "slh-dsa", id: "slh-dsa-shake-128s", publicKey: 32, secretKey: 64, signature: 7856 },
  "slh-dsa-sha2-128f": { family: "slh-dsa", id: "slh-dsa-sha2-128f", publicKey: 32, secretKey: 64, signature: 17088 },
  "slh-dsa-shake-128f": { family: "slh-dsa", id: "slh-dsa-shake-128f", publicKey: 32, secretKey: 64, signature: 17088 },
  "slh-dsa-sha2-192s": { family: "slh-dsa", id: "slh-dsa-sha2-192s", publicKey: 48, secretKey: 96, signature: 16224 },
  "slh-dsa-shake-192s": { family: "slh-dsa", id: "slh-dsa-shake-192s", publicKey: 48, secretKey: 96, signature: 16224 },
  "slh-dsa-sha2-192f": { family: "slh-dsa", id: "slh-dsa-sha2-192f", publicKey: 48, secretKey: 96, signature: 35664 },
  "slh-dsa-shake-192f": { family: "slh-dsa", id: "slh-dsa-shake-192f", publicKey: 48, secretKey: 96, signature: 35664 },
  "slh-dsa-sha2-256s": { family: "slh-dsa", id: "slh-dsa-sha2-256s", publicKey: 64, secretKey: 128, signature: 29792 },
  "slh-dsa-shake-256s": { family: "slh-dsa", id: "slh-dsa-shake-256s", publicKey: 64, secretKey: 128, signature: 29792 },
  "slh-dsa-sha2-256f": { family: "slh-dsa", id: "slh-dsa-sha2-256f", publicKey: 64, secretKey: 128, signature: 49856 },
  "slh-dsa-shake-256f": { family: "slh-dsa", id: "slh-dsa-shake-256f", publicKey: 64, secretKey: 128, signature: 49856 },
};

/** All known parameter-set identifiers, in canonical order. */
export const PARAM_SETS: readonly ParamSet[] = Object.keys(TABLE) as ParamSet[];

/** Type guard: is `s` a recognized parameter-set identifier? */
export function isParamSet(s: string): s is ParamSet {
  return Object.prototype.hasOwnProperty.call(TABLE, s);
}

/**
 * Look up the size record for a parameter set.
 *
 * @throws {RangeError} if `id` is not a recognized parameter set.
 */
export function sizesFor(id: ParamSet): Sizes {
  const entry = TABLE[id];
  if (entry === undefined) {
    throw new RangeError(`unknown parameter set: ${id}`);
  }
  return entry;
}

/** Narrowing helper: KEM size record or `undefined`. */
export function asKemSizes(s: Sizes): KemSizes | undefined {
  return s.family === "ml-kem" ? s : undefined;
}

/** Narrowing helper: DSA size record or `undefined`. */
export function asDsaSizes(s: Sizes): DsaSizes | undefined {
  return s.family === "ml-dsa" ? s : undefined;
}

/** Narrowing helper: SLH-DSA size record or `undefined`. */
export function asSlhDsaSizes(s: Sizes): SlhDsaSizes | undefined {
  return s.family === "slh-dsa" ? s : undefined;
}

/**
 * Narrowing helper: any signature-family size record (ML-DSA or SLH-DSA) or
 * `undefined`. Both expose `publicKey`, `secretKey`, and `signature`.
 */
export function asSignatureSizes(s: Sizes): SignatureSizes | undefined {
  return s.family === "ml-dsa" || s.family === "slh-dsa" ? s : undefined;
}
