/**
 * Rule resolution for {@link explain_finding}.
 *
 * Core's detectors are coarse-grained: a single {@link Detector} (e.g. the
 * `crypto-libs` detector) emits many distinct `ruleId`s (`forge-rsa-keygen`,
 * `elliptic-ec`, `node-rsa`, …) that do NOT share the detector's `id` as a
 * prefix. The old MCP `explain_finding` matched `ruleId` against `detector.id`
 * by prefix and therefore returned "no matching detector" for every real
 * library finding (P0-5).
 *
 * This module resolves a finding's `ruleId` against core's *actual* detector
 * set: a curated index maps each canonical core ruleId to the detector that
 * emits it plus the classical algorithm family it concerns, and the detector's
 * human description is looked up live from {@link defaultRegistry}/{@link
 * detectors}. Unknown rules fall back to a prefix match against the detector id
 * space, and finally to the algorithm remediation. Pure and synchronous — no
 * I/O — so it is directly unit-testable.
 */

import { defaultRegistry, detectors } from "@qproof/core";
import type { AlgorithmFamily, Detector } from "@qproof/core";

/** A resolved rule: the detector it belongs to (if any) and its algorithm. */
export interface ResolvedRule {
  /** The rule id that was looked up (echoed for convenience). */
  ruleId: string;
  /** The detector that emits this rule, when one could be resolved. */
  detector?: { id: string; description: string };
  /** The classical algorithm family the rule concerns, when known. */
  algorithm?: AlgorithmFamily;
  /** How the match was made — useful for tests and diagnostics. */
  via: "index" | "detector-id" | "prefix" | "unresolved";
}

/**
 * Canonical core ruleId → { detector id, algorithm } index.
 *
 * Mirrors the `ruleId`s emitted by the built-in detectors in
 * `@qproof/core` (see `packages/core/src/detectors/*` and `dependencies.ts`).
 * The `detectorId` values reference real detector ids in {@link
 * defaultRegistry}; the descriptions are not duplicated here — they are read
 * live from the registry so they never drift. Algorithms that a single rule
 * can span (e.g. `jsrsasign-*` covers RSA *and* EC) are recorded as
 * `"unknown"`, matching core's own classification.
 */
const RULE_INDEX: Record<string, { detectorId: string; algorithm: AlgorithmFamily }> = {
  // node-crypto detector
  "node-crypto-keygen": { detectorId: "node-crypto", algorithm: "unknown" },
  "node-crypto-sign": { detectorId: "node-crypto", algorithm: "unknown" },
  "node-crypto-sign-oneshot": { detectorId: "node-crypto", algorithm: "unknown" },
  "node-crypto-dh": { detectorId: "node-crypto", algorithm: "DH" },
  "node-crypto-dh-modp": { detectorId: "node-crypto", algorithm: "DH" },
  "node-crypto-ecdh": { detectorId: "node-crypto", algorithm: "ECDH" },
  "node-crypto-rsa-encrypt": { detectorId: "node-crypto", algorithm: "RSA" },
  "node-crypto-dh-keyobject": { detectorId: "node-crypto", algorithm: "DH" },

  // webcrypto detector
  "webcrypto-classical": { detectorId: "webcrypto", algorithm: "unknown" },

  // crypto-libs detector (the library findings P0-5 was about)
  "forge-rsa-keygen": { detectorId: "crypto-libs", algorithm: "RSA" },
  "forge-ed25519": { detectorId: "crypto-libs", algorithm: "EdDSA" },
  "elliptic-ec": { detectorId: "crypto-libs", algorithm: "ECDSA" },
  "secp256k1-usage": { detectorId: "crypto-libs", algorithm: "ECDSA" },
  "jsrsasign-keygen": { detectorId: "crypto-libs", algorithm: "unknown" },
  "jsrsasign-sign": { detectorId: "crypto-libs", algorithm: "unknown" },
  "node-rsa": { detectorId: "crypto-libs", algorithm: "RSA" },

  // jwt-jose detector
  "jwt-classical-alg": { detectorId: "jwt-jose", algorithm: "unknown" },
  "jose-ecdh-es": { detectorId: "jwt-jose", algorithm: "ECDH" },

  // tls-config detector
  "tls-legacy-version": { detectorId: "tls-config", algorithm: "unknown" },
  "tls-reject-unauthorized": { detectorId: "tls-config", algorithm: "unknown" },
  "tls-weak-cipher": { detectorId: "tls-config", algorithm: "unknown" },

  // ssh-cert detector
  "ssh-public-key": { detectorId: "ssh-cert", algorithm: "unknown" },
  "cert-signature-algorithm": { detectorId: "ssh-cert", algorithm: "unknown" },

  // pem-material detector
  "pem-rsa-private-key": { detectorId: "pem-material", algorithm: "RSA" },
  "pem-ec-private-key": { detectorId: "pem-material", algorithm: "ECDSA" },
  "pem-dsa-private-key": { detectorId: "pem-material", algorithm: "DSA" },
  "pem-openssh-private-key": { detectorId: "pem-material", algorithm: "unknown" },
  "pem-pgp-private-key": { detectorId: "pem-material", algorithm: "unknown" },
  "pem-pgp-message": { detectorId: "pem-material", algorithm: "unknown" },
  "pem-pkcs8-private-key": { detectorId: "pem-material", algorithm: "unknown" },
  "pem-certificate": { detectorId: "pem-material", algorithm: "unknown" },

  // dependency scanner (not a Detector, handled by scan()); no registry entry.
  "dep-vulnerable": { detectorId: "dep-vulnerable", algorithm: "unknown" },
};

/** Build a fast id → Detector lookup over the active detector set. */
function detectorMap(): Map<string, Detector> {
  const map = new Map<string, Detector>();
  // Prefer the registry; fall back to the exported `detectors` array.
  const all = (() => {
    try {
      return defaultRegistry.all();
    } catch {
      return detectors;
    }
  })();
  for (const d of all) map.set(d.id, d);
  return map;
}

/**
 * Resolve a finding's `ruleId` to its detector and algorithm.
 *
 * Resolution order:
 *   1. Curated {@link RULE_INDEX} — the canonical mapping for every core rule.
 *   2. Exact detector id (a rule that IS a detector id, e.g. a future 1:1 rule).
 *   3. Prefix against the detector id space (`node-crypto-*`, `pem-*`, …).
 *   4. Unresolved — caller falls back to the algorithm remediation.
 *
 * Pure: depends only on its argument and the static core detector set.
 */
export function resolveRule(ruleId: string): ResolvedRule {
  const id = ruleId.trim();
  const detectorsById = detectorMap();

  // 1. Curated index — the authoritative path for known core rules.
  const indexed = RULE_INDEX[id];
  if (indexed) {
    const det = detectorsById.get(indexed.detectorId);
    return {
      ruleId: id,
      detector: det ? { id: det.id, description: det.description } : undefined,
      algorithm: indexed.algorithm,
      via: "index",
    };
  }

  // 2. Exact detector id.
  const exact = detectorsById.get(id);
  if (exact) {
    return {
      ruleId: id,
      detector: { id: exact.id, description: exact.description },
      via: "detector-id",
    };
  }

  // 3. Longest-prefix detector id (e.g. `node-crypto-foo` → `node-crypto`).
  let best: Detector | undefined;
  for (const det of detectorsById.values()) {
    if (id === det.id || id.startsWith(`${det.id}-`)) {
      if (!best || det.id.length > best.id.length) best = det;
    }
  }
  if (best) {
    return {
      ruleId: id,
      detector: { id: best.id, description: best.description },
      via: "prefix",
    };
  }

  // 4. Unresolved.
  return { ruleId: id, via: "unresolved" };
}

/** Exposed for tests: the set of canonical rule ids the index knows. */
export const KNOWN_RULE_IDS: readonly string[] = Object.keys(RULE_INDEX);
