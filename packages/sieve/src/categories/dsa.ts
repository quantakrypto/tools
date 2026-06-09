/**
 * ML-DSA self-consistency category (FIPS 204).
 *
 * Thin binding over the shared signature driver in signature.ts. ML-DSA and
 * SLH-DSA present the same black-box surface (keygen / sign / verify), so the
 * driver is shared; this category fixes the family to "ml-dsa". It covers:
 *   - pk/sk/sig size conformance for ml-dsa-44/65/87,
 *   - sign→verify correctness round-trips,
 *   - verify rejects a tampered signature and a wrong message,
 *   - a deterministic-vs-hedged signing advisory probe,
 *   - wrong-length verify inputs rejected with a defined error (AF-05).
 *
 * Exact-value KAT (sigVer vectors) is handled separately by the kat category.
 */

import type { Category } from "./types.js";
import { makeSignatureCategory } from "./signature.js";

export const dsa: Category = makeSignatureCategory("dsa", "ml-dsa");
