/**
 * SLH-DSA self-consistency category (FIPS 205).
 *
 * SLH-DSA (the standardized SPHINCS+) presents the same black-box surface as
 * ML-DSA — keygen / sign / verify — so it reuses the shared signature driver
 * in signature.ts with the family fixed to "slh-dsa". It covers, for each of
 * the 12 standardized parameter sets:
 *   - pk/sk/sig size conformance (FIPS 205 Table 2),
 *   - sign→verify correctness round-trips,
 *   - verify rejects a tampered signature and a wrong message,
 *   - a deterministic-vs-hedged signing advisory probe (SLH-DSA supports both),
 *   - wrong-length verify inputs rejected with a defined error (AF-05).
 *
 * No external vectors are needed for self-consistency; exact-value KAT would
 * come from official ACVP files via the kat category. We assert NO crypto bytes.
 *
 * Out of scope: SP 800-208 stateful hash signatures (LMS / XMSS / HSS). Those
 * require state-management guarantees a stateless request/response harness
 * cannot model; see README.md.
 */

import type { Category } from "./types.js";
import { makeSignatureCategory } from "./signature.js";

export const slhDsa: Category = makeSignatureCategory("slh-dsa", "slh-dsa");
