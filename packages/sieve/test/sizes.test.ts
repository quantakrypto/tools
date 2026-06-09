import { test } from "node:test";
import assert from "node:assert/strict";

import {
  isParamSet,
  PARAM_SETS,
  sizesFor,
  asKemSizes,
  asDsaSizes,
  asSlhDsaSizes,
} from "../src/sizes.js";

test("PARAM_SETS lists the ML-KEM, ML-DSA, and SLH-DSA standardized sets", () => {
  assert.deepEqual([...PARAM_SETS].sort(), [
    "ml-dsa-44",
    "ml-dsa-65",
    "ml-dsa-87",
    "ml-kem-1024",
    "ml-kem-512",
    "ml-kem-768",
    "slh-dsa-sha2-128f",
    "slh-dsa-sha2-128s",
    "slh-dsa-sha2-192f",
    "slh-dsa-sha2-192s",
    "slh-dsa-sha2-256f",
    "slh-dsa-sha2-256s",
    "slh-dsa-shake-128f",
    "slh-dsa-shake-128s",
    "slh-dsa-shake-192f",
    "slh-dsa-shake-192s",
    "slh-dsa-shake-256f",
    "slh-dsa-shake-256s",
  ]);
});

test("isParamSet narrows known/unknown ids", () => {
  assert.equal(isParamSet("ml-kem-768"), true);
  assert.equal(isParamSet("ml-kem-999"), false);
  assert.equal(isParamSet("rsa-2048"), false);
});

test("ML-KEM sizes match FIPS 203 Table 3", () => {
  const k512 = asKemSizes(sizesFor("ml-kem-512"));
  const k768 = asKemSizes(sizesFor("ml-kem-768"));
  const k1024 = asKemSizes(sizesFor("ml-kem-1024"));
  assert.ok(k512 && k768 && k1024);
  assert.deepEqual(
    { pk: k512!.publicKey, sk: k512!.secretKey, ct: k512!.ciphertext, ss: k512!.sharedSecret },
    { pk: 800, sk: 1632, ct: 768, ss: 32 },
  );
  assert.deepEqual(
    { pk: k768!.publicKey, sk: k768!.secretKey, ct: k768!.ciphertext, ss: k768!.sharedSecret },
    { pk: 1184, sk: 2400, ct: 1088, ss: 32 },
  );
  assert.deepEqual(
    { pk: k1024!.publicKey, sk: k1024!.secretKey, ct: k1024!.ciphertext, ss: k1024!.sharedSecret },
    { pk: 1568, sk: 3168, ct: 1568, ss: 32 },
  );
});

test("ML-DSA sizes match FIPS 204 Table 2", () => {
  const d44 = asDsaSizes(sizesFor("ml-dsa-44"));
  const d65 = asDsaSizes(sizesFor("ml-dsa-65"));
  const d87 = asDsaSizes(sizesFor("ml-dsa-87"));
  assert.ok(d44 && d65 && d87);
  assert.deepEqual(
    { pk: d44!.publicKey, sk: d44!.secretKey, sig: d44!.signature },
    { pk: 1312, sk: 2560, sig: 2420 },
  );
  assert.deepEqual(
    { pk: d65!.publicKey, sk: d65!.secretKey, sig: d65!.signature },
    { pk: 1952, sk: 4032, sig: 3309 },
  );
  assert.deepEqual(
    { pk: d87!.publicKey, sk: d87!.secretKey, sig: d87!.signature },
    { pk: 2592, sk: 4896, sig: 4627 },
  );
});

test("SLH-DSA sizes match FIPS 205 Table 2 (pk=2n, sk=4n, sig per set)", () => {
  // Public, standardized sizes; SHA2 and SHAKE variants of a level/var match.
  const expect: Record<string, { pk: number; sk: number; sig: number }> = {
    "slh-dsa-sha2-128s": { pk: 32, sk: 64, sig: 7856 },
    "slh-dsa-shake-128s": { pk: 32, sk: 64, sig: 7856 },
    "slh-dsa-sha2-128f": { pk: 32, sk: 64, sig: 17088 },
    "slh-dsa-shake-128f": { pk: 32, sk: 64, sig: 17088 },
    "slh-dsa-sha2-192s": { pk: 48, sk: 96, sig: 16224 },
    "slh-dsa-shake-192s": { pk: 48, sk: 96, sig: 16224 },
    "slh-dsa-sha2-192f": { pk: 48, sk: 96, sig: 35664 },
    "slh-dsa-shake-192f": { pk: 48, sk: 96, sig: 35664 },
    "slh-dsa-sha2-256s": { pk: 64, sk: 128, sig: 29792 },
    "slh-dsa-shake-256s": { pk: 64, sk: 128, sig: 29792 },
    "slh-dsa-sha2-256f": { pk: 64, sk: 128, sig: 49856 },
    "slh-dsa-shake-256f": { pk: 64, sk: 128, sig: 49856 },
  };
  for (const [id, exp] of Object.entries(expect)) {
    const s = asSlhDsaSizes(sizesFor(id as never));
    assert.ok(s, `expected an SLH-DSA size record for ${id}`);
    assert.deepEqual({ pk: s!.publicKey, sk: s!.secretKey, sig: s!.signature }, exp, id);
    // Structural invariants: pk = 2n, sk = 4n.
    assert.equal(s!.secretKey, s!.publicKey * 2, `${id}: sk should be 2*pk (=4n)`);
  }
});

test("asKemSizes / asDsaSizes / asSlhDsaSizes discriminate families", () => {
  assert.equal(asDsaSizes(sizesFor("ml-kem-768")), undefined);
  assert.equal(asKemSizes(sizesFor("ml-dsa-65")), undefined);
  assert.equal(asSlhDsaSizes(sizesFor("ml-dsa-65")), undefined);
  assert.equal(asDsaSizes(sizesFor("slh-dsa-sha2-128f")), undefined);
  assert.ok(asSlhDsaSizes(sizesFor("slh-dsa-sha2-128f")));
});

test("sizesFor throws on unknown set", () => {
  assert.throws(() => sizesFor("nope" as never), RangeError);
});
