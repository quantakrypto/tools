/**
 * Post-quantum remediation guidance for each classical asymmetric algorithm
 * family. The recommendations follow NIST's standardized PQC algorithms
 * (ML-KEM / FIPS 203, ML-DSA / FIPS 204, SLH-DSA / FIPS 205) and the IETF
 * hybrid key-exchange drafts (X25519MLKEM768).
 */
import type { AlgorithmFamily, Remediation } from "./types.js";

/** Canonical remediation table, keyed by algorithm family. */
const REMEDIATIONS: Record<AlgorithmFamily, Remediation> = {
  RSA: {
    algorithm: "RSA",
    recommendation: "ML-KEM-768 for encryption/KEM; ML-DSA-65 for signatures",
    detail:
      "RSA is broken by Shor's algorithm. For key transport / encryption move to " +
      "ML-KEM-768 (FIPS 203), ideally as the hybrid X25519MLKEM768. For digital " +
      "signatures move to ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205).",
  },
  ECDH: {
    algorithm: "ECDH",
    recommendation: "hybrid X25519MLKEM768 (ML-KEM-768)",
    detail:
      "Elliptic-curve Diffie-Hellman is broken by Shor's algorithm and is exposed " +
      "to harvest-now-decrypt-later. Adopt the hybrid X25519MLKEM768 key exchange so " +
      "confidentiality survives even if one component is broken.",
  },
  ECDSA: {
    algorithm: "ECDSA",
    recommendation: "ML-DSA-65 (FIPS 204)",
    detail:
      "ECDSA signatures can be forged by a quantum attacker via Shor's algorithm. " +
      "Migrate to ML-DSA (Dilithium, FIPS 204) or SLH-DSA (SPHINCS+, FIPS 205) for " +
      "long-lived signatures.",
  },
  EdDSA: {
    algorithm: "EdDSA",
    recommendation: "ML-DSA-65 (FIPS 204)",
    detail:
      "Ed25519 / Ed448 (EdDSA) are classical signatures broken by Shor's algorithm. " +
      "Replace with ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205) for forgery resistance.",
  },
  DH: {
    algorithm: "DH",
    recommendation: "hybrid X25519MLKEM768 (ML-KEM-768)",
    detail:
      "Finite-field Diffie-Hellman is broken by Shor's algorithm and exposed to " +
      "harvest-now-decrypt-later. Move to a hybrid PQC KEM such as X25519MLKEM768.",
  },
  DSA: {
    algorithm: "DSA",
    recommendation: "ML-DSA-65 (FIPS 204)",
    detail:
      "DSA is a classical, quantum-broken signature scheme (and already deprecated). " +
      "Replace with ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205).",
  },
  X25519: {
    algorithm: "X25519",
    recommendation: "hybrid X25519MLKEM768 (ML-KEM-768)",
    detail:
      "X25519 is a modern, well-built classical key-agreement primitive but is still " +
      "broken by Shor's algorithm. Wrap it in the hybrid X25519MLKEM768 construction " +
      "so it stays useful during the PQC transition.",
  },
  X448: {
    algorithm: "X448",
    recommendation: "hybrid X25519MLKEM768 (ML-KEM-768)",
    detail:
      "X448 (Goldilocks curve) is a modern classical key-agreement primitive at a " +
      "higher classical security level, but it is still broken by Shor's algorithm. " +
      "Adopt a hybrid PQC KEM (X25519MLKEM768 / ML-KEM-768) during the transition.",
  },
  ECIES: {
    algorithm: "ECIES",
    recommendation: "ML-KEM-768 hybrid encryption",
    detail:
      "ECIES relies on classical ECDH for its key encapsulation and is exposed to " +
      "harvest-now-decrypt-later. Replace the KEM step with ML-KEM-768 (FIPS 203), " +
      "preferably in a hybrid construction.",
  },
  unknown: {
    algorithm: "unknown",
    recommendation: "review for post-quantum migration",
    detail:
      "This usage involves classical public-key cryptography. Audit it and plan a " +
      "migration to NIST PQC standards (ML-KEM / FIPS 203, ML-DSA / FIPS 204).",
  },
};

/** Look up the recommended post-quantum remediation for a classical algorithm. */
export function remediationFor(algorithm: AlgorithmFamily): Remediation | undefined {
  return REMEDIATIONS[algorithm];
}

/** Convenience: just the short recommendation string for a family (always defined). */
export function remediationText(algorithm: AlgorithmFamily): string {
  return REMEDIATIONS[algorithm].recommendation;
}

/* -------------------------------------------------------------------------- */
/* Security-tier guidance (CNSA 2.0 Category 5) + stateful HBS (SP 800-208)     */
/* -------------------------------------------------------------------------- */

/**
 * Security tier for remediation guidance.
 *  - `"category-3"` (default): commercial use — ML-KEM-768 / ML-DSA-65.
 *  - `"category-5"`: CNSA 2.0 national-security-systems / long-lived secrets —
 *    ML-KEM-1024 / ML-DSA-87.
 */
export type SecurityTier = "category-3" | "category-5";

/** Per-tier KEM / signature parameter sets. */
export const TIER_PARAMS: Record<SecurityTier, { kem: string; signature: string; note: string }> = {
  "category-3": {
    kem: "ML-KEM-768 (FIPS 203)",
    signature: "ML-DSA-65 (FIPS 204)",
    note: "NIST Category 3 — default for general commercial use.",
  },
  "category-5": {
    kem: "ML-KEM-1024 (FIPS 203)",
    signature: "ML-DSA-87 (FIPS 204)",
    note: "NIST Category 5 — CNSA 2.0 for national-security systems and long-lived secrets (2030/2033 milestones).",
  },
};

/**
 * Tier-aware remediation. Returns the base family remediation plus the
 * parameter sets for the requested CNSA tier. Category 5 surfaces the
 * ML-KEM-1024 / ML-DSA-87 sets mandated by CNSA 2.0; category 3 is the
 * commercial default.
 */
export function remediationForTier(
  algorithm: AlgorithmFamily,
  tier: SecurityTier = "category-3",
): Remediation {
  const base = REMEDIATIONS[algorithm];
  const params = TIER_PARAMS[tier];
  // Confidentiality families lean on the KEM; signature families on the signer.
  const isConfidentiality =
    algorithm === "RSA" ||
    algorithm === "ECDH" ||
    algorithm === "DH" ||
    algorithm === "X25519" ||
    algorithm === "X448" ||
    algorithm === "ECIES";
  const primary = isConfidentiality ? params.kem : params.signature;
  return {
    algorithm,
    recommendation: `${base.recommendation} — ${tier}: ${primary}`,
    detail: `${base.detail} ${params.note} For this tier use ${params.kem} (KEM) and ${params.signature} (signatures).`,
  };
}

/**
 * Guidance for stateful hash-based signatures (SP 800-208: LMS / XMSS / HSS).
 * These are NIST-approved for firmware / boot signing but are STATEFUL — each
 * private key may sign a bounded number of messages and the state MUST be
 * managed to avoid catastrophic key reuse. Surfaced where a long-lived,
 * low-volume signing root is appropriate.
 */
export const STATEFUL_HBS_NOTE =
  "For firmware / secure-boot signing, the stateful hash-based signatures " +
  "LMS, XMSS and HSS (NIST SP 800-208) are approved alternatives to ML-DSA, " +
  "but they are STATEFUL: the signer must never reuse a one-time key index. " +
  "Use only with rigorous state management; otherwise prefer stateless ML-DSA " +
  "(FIPS 204) or SLH-DSA (FIPS 205).";

/** True when stateful HBS (SP 800-208) is a reasonable alternative for a family. */
export function statefulHbsApplies(algorithm: AlgorithmFamily): boolean {
  // Signature families only — LMS/XMSS are signatures, not KEMs.
  return (
    algorithm === "RSA" ||
    algorithm === "ECDSA" ||
    algorithm === "EdDSA" ||
    algorithm === "DSA"
  );
}
