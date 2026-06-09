/**
 * Unit tests for the rule resolver (P0-5).
 *
 * `resolveRule` is pure — it maps a finding's `ruleId` to the core detector
 * that emits it plus the classical algorithm family. These tests pin the
 * behaviour for library rules (the regression) and the prefix / unresolved
 * fallbacks, without spawning a server.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { resolveRule, KNOWN_RULE_IDS } from "../src/rules.js";

test("library rules resolve to the crypto-libs detector with an algorithm", () => {
  const forge = resolveRule("forge-rsa-keygen");
  assert.equal(forge.via, "index");
  assert.equal(forge.detector?.id, "crypto-libs");
  assert.ok((forge.detector?.description.length ?? 0) > 0);
  assert.equal(forge.algorithm, "RSA");

  const elliptic = resolveRule("elliptic-ec");
  assert.equal(elliptic.detector?.id, "crypto-libs");
  assert.equal(elliptic.algorithm, "ECDSA");

  const nodeRsa = resolveRule("node-rsa");
  assert.equal(nodeRsa.detector?.id, "crypto-libs");
  assert.equal(nodeRsa.algorithm, "RSA");
});

test("pem and node-crypto rules resolve to their detectors", () => {
  assert.equal(resolveRule("pem-ec-private-key").detector?.id, "pem-material");
  assert.equal(resolveRule("pem-ec-private-key").algorithm, "ECDSA");
  assert.equal(resolveRule("node-crypto-ecdh").detector?.id, "node-crypto");
  assert.equal(resolveRule("node-crypto-ecdh").algorithm, "ECDH");
});

test("an unknown rule that shares a detector id prefix resolves via prefix", () => {
  // Not in the curated index, but `node-crypto-<x>` shares the detector id.
  const r = resolveRule("node-crypto-future-thing");
  assert.equal(r.via, "prefix");
  assert.equal(r.detector?.id, "node-crypto");
});

test("a wholly unknown rule is unresolved (no detector)", () => {
  const r = resolveRule("totally-made-up-rule");
  assert.equal(r.via, "unresolved");
  assert.equal(r.detector, undefined);
  assert.equal(r.algorithm, undefined);
});

test("input is trimmed and the ruleId is echoed", () => {
  const r = resolveRule("  forge-rsa-keygen  ");
  assert.equal(r.ruleId, "forge-rsa-keygen");
});

test("every curated rule id resolves and is whitespace-free", () => {
  assert.ok(KNOWN_RULE_IDS.length >= 15);
  for (const id of KNOWN_RULE_IDS) {
    assert.equal(id, id.trim());
    const r = resolveRule(id);
    assert.equal(r.via, "index");
  }
});
