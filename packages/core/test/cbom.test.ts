/**
 * Tests for the CycloneDX 1.6 CBOM export.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { toCbom, buildInventory } from "../src/index.js";
import type { Finding, ScanResult } from "../src/index.js";

function result(findings: Finding[]): ScanResult {
  return {
    root: "/repo",
    findings,
    filesScanned: 1,
    inventory: buildInventory(findings),
    startedAt: "2026-01-01T00:00:00.000Z",
    finishedAt: "2026-01-01T00:00:01.000Z",
    toolVersion: "0.1.0",
  };
}

function f(over: Partial<Finding>): Finding {
  return {
    ruleId: "node-crypto-ecdh",
    title: "ECDH",
    category: "key-exchange",
    severity: "high",
    confidence: "high",
    algorithm: "ECDH",
    hndl: true,
    message: "ecdh",
    cwe: "CWE-327",
    location: { file: "src/a.ts", line: 10, snippet: "createECDH()" },
    ...over,
  };
}

test("toCbom emits a CycloneDX 1.6 cryptographic BOM", () => {
  const bom = toCbom(result([f({})]));
  assert.equal(bom.bomFormat, "CycloneDX");
  assert.equal(bom.specVersion, "1.6");
  assert.match(bom.serialNumber, /^urn:uuid:[0-9a-f-]+$/);
  assert.equal(bom.components.length, 1);
  const comp = bom.components[0];
  assert.equal(comp.type, "cryptographic-asset");
  assert.equal((comp.cryptoProperties as { quantumVulnerable: boolean }).quantumVulnerable, true);
  assert.equal((comp.cryptoProperties as { harvestNowDecryptLater: boolean }).harvestNowDecryptLater, true);
});

test("toCbom groups by algorithm + primitive and records occurrences", () => {
  const bom = toCbom(
    result([
      f({ location: { file: "src/a.ts", line: 1, snippet: "x" } }),
      f({ location: { file: "src/b.ts", line: 2, snippet: "y" } }),
      f({ ruleId: "jwt-classical-alg", category: "signature", algorithm: "RSA", hndl: false }),
    ]),
  );
  // ECDH/key-agree is one component; RSA/signature is another.
  assert.equal(bom.components.length, 2);
  const ecdh = bom.components.find((c) => c.name.startsWith("ECDH"))!;
  const occ = (ecdh.evidence as { occurrences: Array<{ location: string }> }).occurrences;
  assert.deepEqual(occ.map((o) => o.location), ["src/a.ts:1", "src/b.ts:2"]);
});

test("toCbom is deterministic for the same result", () => {
  const r = result([f({}), f({ ruleId: "x", category: "signature", algorithm: "ECDSA", hndl: false })]);
  assert.deepEqual(toCbom(r), toCbom(r));
});
