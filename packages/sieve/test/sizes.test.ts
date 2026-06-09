import { test } from "node:test";
import assert from "node:assert/strict";

import { isParamSet, PARAM_SETS, sizesFor, asKemSizes, asDsaSizes } from "../src/sizes.js";

test("PARAM_SETS lists all six standardized sets", () => {
  assert.deepEqual(
    [...PARAM_SETS].sort(),
    ["ml-dsa-44", "ml-dsa-65", "ml-dsa-87", "ml-kem-1024", "ml-kem-512", "ml-kem-768"],
  );
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
  assert.deepEqual({ pk: d44!.publicKey, sk: d44!.secretKey, sig: d44!.signature }, { pk: 1312, sk: 2560, sig: 2420 });
  assert.deepEqual({ pk: d65!.publicKey, sk: d65!.secretKey, sig: d65!.signature }, { pk: 1952, sk: 4032, sig: 3309 });
  assert.deepEqual({ pk: d87!.publicKey, sk: d87!.secretKey, sig: d87!.signature }, { pk: 2592, sk: 4896, sig: 4627 });
});

test("asKemSizes / asDsaSizes discriminate families", () => {
  assert.equal(asDsaSizes(sizesFor("ml-kem-768")), undefined);
  assert.equal(asKemSizes(sizesFor("ml-dsa-65")), undefined);
});

test("sizesFor throws on unknown set", () => {
  assert.throws(() => sizesFor("nope" as never), RangeError);
});
