/**
 * CWE (Common Weakness Enumeration) identifiers used to tag findings. These
 * feed SARIF rule taxa / properties and the CBOM export, and let downstream
 * compliance tooling map qProof findings to a standard weakness taxonomy.
 */

/** CWE-327: Use of a Broken or Risky Cryptographic Algorithm. */
export const CWE_BROKEN_CRYPTO = "CWE-327";

/** CWE-326: Inadequate Encryption Strength. */
export const CWE_WEAK_STRENGTH = "CWE-326";

/** CWE-295: Improper Certificate Validation. */
export const CWE_CERT_VALIDATION = "CWE-295";

/** CWE-798: Use of Hard-coded Credentials (embedded private keys). */
export const CWE_HARDCODED_KEY = "CWE-798";

/** CWE-1240: Use of a Cryptographic Primitive with a Risky Implementation. */
export const CWE_RISKY_PRIMITIVE = "CWE-1240";
