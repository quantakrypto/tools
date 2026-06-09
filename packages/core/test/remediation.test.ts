/**
 * Tests for remediation guidance: family lookup, the CNSA 2.0 Category-5 tier
 * (ML-KEM-1024 / ML-DSA-87), and SP 800-208 stateful HBS guidance.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  remediationFor,
  remediationForTier,
  TIER_PARAMS,
  STATEFUL_HBS_NOTE,
  statefulHbsApplies,
} from "../src/index.js";

test("remediationFor covers every family including X448", () => {
  for (const a of [
    "RSA",
    "ECDH",
    "ECDSA",
    "EdDSA",
    "DH",
    "DSA",
    "X25519",
    "X448",
    "ECIES",
    "unknown",
  ] as const) {
    const r = remediationFor(a);
    assert.ok(r, `remediation for ${a}`);
    assert.equal(r.algorithm, a);
  }
});

test("category-3 is the default tier (ML-KEM-768 / ML-DSA-65)", () => {
  const kem = remediationForTier("RSA");
  assert.match(kem.recommendation, /category-3/);
  assert.match(kem.recommendation, /ML-KEM-768/);
  const sig = remediationForTier("ECDSA");
  assert.match(sig.recommendation, /ML-DSA-65/);
});

test("category-5 surfaces the CNSA 2.0 ML-KEM-1024 / ML-DSA-87 tier", () => {
  assert.equal(TIER_PARAMS["category-5"].kem, "ML-KEM-1024 (FIPS 203)");
  assert.equal(TIER_PARAMS["category-5"].signature, "ML-DSA-87 (FIPS 204)");

  const kem = remediationForTier("ECDH", "category-5");
  assert.match(kem.recommendation, /ML-KEM-1024/);
  assert.match(kem.detail, /CNSA 2\.0/);

  const sig = remediationForTier("RSA", "category-5");
  // RSA is confidentiality-leaning → headline is the KEM, but the detail names both.
  assert.match(sig.detail, /ML-DSA-87/);
  assert.match(sig.detail, /ML-KEM-1024/);
});

test("SP 800-208 stateful HBS guidance applies to signature families only", () => {
  assert.ok(statefulHbsApplies("ECDSA"));
  assert.ok(statefulHbsApplies("RSA"));
  assert.ok(!statefulHbsApplies("ECDH"));
  assert.ok(!statefulHbsApplies("X25519"));
  assert.match(STATEFUL_HBS_NOTE, /SP 800-208/);
  assert.match(STATEFUL_HBS_NOTE, /LMS/);
  assert.match(STATEFUL_HBS_NOTE, /stateful/i);
});
