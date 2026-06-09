/**
 * Tests for the source detectors. Each detector is exercised against a small
 * inline fixture string, asserting the ruleId, algorithm family, and line
 * number of the resulting finding.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { detectors } from "../src/index.js";
import type { Finding } from "../src/index.js";

/** Run every applicable detector over a fixture and flatten the findings. */
function run(file: string, content: string): Finding[] {
  const out: Finding[] = [];
  for (const det of detectors) {
    if (det.appliesTo(file)) out.push(...det.detect({ file, content }));
  }
  return out;
}

/** Find the first finding with a given ruleId. */
function byRule(findings: Finding[], ruleId: string): Finding | undefined {
  return findings.find((f) => f.ruleId === ruleId);
}

test("Node crypto RSA key generation", () => {
  const src = [
    "import { generateKeyPairSync } from 'node:crypto';",
    "const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });",
  ].join("\n");
  const findings = run("a.ts", src);
  const f = byRule(findings, "node-crypto-keygen");
  assert.ok(f, "rsa keygen detected");
  assert.equal(f.algorithm, "RSA");
  assert.equal(f.category, "kem");
  assert.equal(f.hndl, true);
  assert.equal(f.location.line, 2);
});

test("Node crypto ECDH key exchange is HNDL-exposed", () => {
  const findings = run("a.js", "const ecdh = crypto.createECDH('secp256k1');");
  const f = byRule(findings, "node-crypto-ecdh");
  assert.ok(f);
  assert.equal(f.algorithm, "ECDH");
  assert.equal(f.category, "key-exchange");
  assert.equal(f.hndl, true);
});

test("Node crypto Diffie-Hellman", () => {
  const f = byRule(run("a.js", "const dh = crypto.createDiffieHellman(2048);"), "node-crypto-dh");
  assert.ok(f);
  assert.equal(f.algorithm, "DH");
  assert.equal(f.hndl, true);
});

test("Node crypto RSA publicEncrypt", () => {
  const f = byRule(
    run("a.js", "const enc = crypto.publicEncrypt(key, buf);"),
    "node-crypto-rsa-encrypt",
  );
  assert.ok(f);
  assert.equal(f.algorithm, "RSA");
  assert.equal(f.category, "kem");
  assert.equal(f.hndl, true);
});

test("Node crypto createSign signatures are high but not HNDL", () => {
  const f = byRule(run("a.js", "const s = crypto.createSign('SHA256');"), "node-crypto-sign");
  assert.ok(f);
  assert.equal(f.category, "signature");
  assert.equal(f.severity, "high");
  assert.equal(f.hndl, false);
});

test("Node crypto x25519/ed25519 are flagged low", () => {
  const x = byRule(run("a.js", "generateKeyPairSync('x25519');"), "node-crypto-keygen");
  assert.ok(x);
  assert.equal(x.algorithm, "X25519");
  assert.equal(x.severity, "low");

  const ed = byRule(run("a.js", "generateKeyPairSync('ed25519');"), "node-crypto-keygen");
  assert.ok(ed);
  assert.equal(ed.algorithm, "EdDSA");
  assert.equal(ed.severity, "low");
  assert.equal(ed.hndl, false);
});

test("WebCrypto RSA-OAEP is KEM + HNDL", () => {
  const src = "await crypto.subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 2048 }, true, ['encrypt']);";
  const f = byRule(run("a.ts", src), "webcrypto-classical");
  assert.ok(f);
  assert.equal(f.algorithm, "RSA");
  assert.equal(f.category, "kem");
  assert.equal(f.hndl, true);
});

test("WebCrypto ECDH is key-exchange + HNDL", () => {
  const src = "await crypto.subtle.deriveBits({ name: 'ECDH', public: peer }, key, 256);";
  const f = byRule(run("a.ts", src), "webcrypto-classical");
  assert.ok(f);
  assert.equal(f.algorithm, "ECDH");
  assert.equal(f.hndl, true);
});

test("WebCrypto ECDSA is signature, not HNDL", () => {
  const src = "await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, data);";
  const f = byRule(run("a.ts", src), "webcrypto-classical");
  assert.ok(f);
  assert.equal(f.algorithm, "ECDSA");
  assert.equal(f.category, "signature");
  assert.equal(f.hndl, false);
});

test("WebCrypto algorithm string far from a subtle call is ignored", () => {
  const src = "const label = 'RSA-OAEP';\n".concat("// no subtle call here\n");
  const findings = run("a.ts", src).filter((f) => f.ruleId === "webcrypto-classical");
  assert.equal(findings.length, 0);
});

test("node-forge RSA key generation", () => {
  const f = byRule(run("a.js", "forge.pki.rsa.generateKeyPair({ bits: 2048 });"), "forge-rsa-keygen");
  assert.ok(f);
  assert.equal(f.algorithm, "RSA");
});

test("elliptic instantiation", () => {
  const f = byRule(run("a.js", "const ec = new EC('secp256k1');"), "elliptic-ec");
  assert.ok(f);
  assert.equal(f.algorithm, "ECDSA");
});

test("node-rsa instantiation", () => {
  const f = byRule(run("a.js", "const key = new NodeRSA({ b: 2048 });"), "node-rsa");
  assert.ok(f);
  assert.equal(f.algorithm, "RSA");
  assert.equal(f.hndl, true);
});

test("jsrsasign key generation", () => {
  const f = byRule(run("a.js", "KEYUTIL.generateKeypair('RSA', 2048);"), "jsrsasign-keygen");
  assert.ok(f);
});

test("JWT RS256 algorithm string", () => {
  const f = byRule(run("a.ts", "jwt.sign(payload, key, { algorithm: 'RS256' });"), "jwt-classical-alg");
  assert.ok(f);
  assert.equal(f.algorithm, "RSA");
  assert.equal(f.category, "signature");
});

test("JWT ES256 → ECDSA, EdDSA → EdDSA", () => {
  const es = byRule(run("a.ts", "verify(token, key, { algorithms: ['ES256'] });"), "jwt-classical-alg");
  assert.ok(es);
  assert.equal(es.algorithm, "ECDSA");

  const ed = byRule(run("a.ts", "const alg = 'EdDSA';"), "jwt-classical-alg");
  assert.ok(ed);
  assert.equal(ed.algorithm, "EdDSA");
});

test("TLS legacy version and rejectUnauthorized:false", () => {
  const src = [
    "const opts = {",
    "  minVersion: 'TLSv1',",
    "  rejectUnauthorized: false,",
    "};",
  ].join("\n");
  const findings = run("a.ts", src);
  const v = byRule(findings, "tls-legacy-version");
  const r = byRule(findings, "tls-reject-unauthorized");
  assert.ok(v, "legacy version detected");
  assert.equal(v.location.line, 2);
  assert.ok(r, "rejectUnauthorized:false detected");
  assert.equal(r.severity, "high");
});

test("TLS weak cipher", () => {
  const f = byRule(run("a.ts", "const o = { ciphers: 'RC4-MD5:HIGH' };"), "tls-weak-cipher");
  assert.ok(f);
  assert.equal(f.category, "tls");
});

test("detectors only apply to JS/TS for source rules", () => {
  // A .txt file should not trip the JS/TS source detectors.
  const findings = run("notes.txt", "crypto.createECDH('p256');");
  assert.equal(findings.filter((f) => f.ruleId === "node-crypto-ecdh").length, 0);
});

test("every source finding carries a remediation string", () => {
  const src = "crypto.createECDH('p256'); jwt.sign(p, k, { algorithm: 'RS256' });";
  for (const f of run("a.ts", src)) {
    assert.ok(f.remediation && f.remediation.length > 0, `${f.ruleId} has remediation`);
  }
});
