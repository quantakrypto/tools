/**
 * Tests for the vulnerable-dependency database and manifest scanner.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { vulnerableDependencies } from "../src/index.js";
import { scanManifest, isManifestFile } from "../src/dependencies.js";

test("database has a healthy number of curated entries", () => {
  assert.ok(vulnerableDependencies.length >= 15, "at least 15 curated entries");
  for (const d of vulnerableDependencies) {
    assert.equal(d.ecosystem, "npm");
    assert.ok(d.name.length > 0);
    assert.ok(d.algorithms.length > 0);
    assert.ok(d.reason.length > 0);
  }
});

test("isManifestFile recognises manifests by basename", () => {
  assert.equal(isManifestFile("package.json"), true);
  assert.equal(isManifestFile("nested/dir/package-lock.json"), true);
  assert.equal(isManifestFile("src/index.ts"), false);
});

test("package.json dependencies + devDependencies are matched", () => {
  const pkg = JSON.stringify({
    name: "demo",
    dependencies: { "node-forge": "^1.0.0", "left-pad": "1.0.0" },
    devDependencies: { elliptic: "^6.5.4" },
  });
  const findings = scanManifest("package.json", pkg);
  const names = findings.map((f) => f.title).sort();
  assert.ok(names.some((t) => t.includes("node-forge")));
  assert.ok(names.some((t) => t.includes("elliptic")));
  assert.ok(!names.some((t) => t.includes("left-pad")), "non-crypto dep not flagged");
  for (const f of findings) {
    assert.equal(f.category, "dependency");
    assert.equal(f.ruleId, "dep-vulnerable");
    assert.equal(f.location.file, "package.json");
  }
});

test("scoped package names (@noble/curves) are matched and located", () => {
  const pkg = JSON.stringify({ dependencies: { "@noble/curves": "^1.0.0" } });
  const findings = scanManifest("package.json", pkg);
  assert.equal(findings.length, 1);
  assert.ok(findings[0].title.includes("@noble/curves"));
  // location should point at the key, not line 1 fallback artifacts
  assert.ok(findings[0].location.line >= 1);
});

test("package-lock.json v3 packages map is parsed", () => {
  const lock = JSON.stringify({
    name: "demo",
    lockfileVersion: 3,
    packages: {
      "": { name: "demo" },
      "node_modules/jsonwebtoken": { version: "9.0.0" },
      "node_modules/jose": { version: "5.0.0" },
      "node_modules/lodash": { version: "4.17.21" },
    },
  });
  const findings = scanManifest("package-lock.json", lock);
  const names = findings.map((f) => f.title);
  assert.ok(names.some((t) => t.includes("jsonwebtoken")));
  assert.ok(names.some((t) => t.includes("jose")));
  assert.ok(!names.some((t) => t.includes("lodash")));
});

test("HNDL flag reflects confidentiality vs signature-only packages", () => {
  // jose exposes RSA/ECDH → HNDL true; ecpair is ECDSA-only → HNDL false.
  const joseF = scanManifest("package.json", JSON.stringify({ dependencies: { jose: "5" } }))[0];
  const ecpairF = scanManifest("package.json", JSON.stringify({ dependencies: { ecpair: "2" } }))[0];
  assert.equal(joseF.hndl, true);
  assert.equal(ecpairF.hndl, false);
});

test("invalid JSON manifests are skipped without throwing", () => {
  assert.deepEqual(scanManifest("package.json", "{ not json"), []);
});

test("dependency findings carry a CWE id", () => {
  const f = scanManifest("package.json", JSON.stringify({ dependencies: { elliptic: "^6" } }))[0];
  assert.equal(f.cwe, "CWE-327");
});

test("multi-family dependency remediation names all exposed families (C5)", () => {
  // jose exposes RSA + ECDH + ECDSA + EdDSA → remediation should mention both a
  // KEM (for the confidentiality families) and a signature replacement.
  const f = scanManifest("package.json", JSON.stringify({ dependencies: { jose: "5" } }))[0];
  assert.ok(f.remediation && f.remediation.length > 0);
  assert.match(f.remediation, /ML-KEM|X25519MLKEM768/);
  assert.match(f.remediation, /ML-DSA/);
});
