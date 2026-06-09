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
