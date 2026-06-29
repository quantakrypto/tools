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

test("Node crypto EC keygen is key-exchange-capable and HNDL-exposed (P0-4)", () => {
  const f = byRule(
    run("a.ts", "const kp = generateKeyPairSync('ec', { namedCurve: 'P-256' });"),
    "node-crypto-keygen",
  );
  assert.ok(f, "ec keygen detected");
  // EC keys feed BOTH ECDSA (sign) and ECDH (key agreement); the ECDH path is
  // HNDL-exposed, so the finding must NOT be signature-only / hndl:false.
  assert.equal(f.algorithm, "ECDH");
  assert.equal(f.category, "key-exchange");
  assert.equal(f.hndl, true);
  assert.match(f.message, /ECDSA/);
  assert.match(f.message, /ECDH/);
  assert.ok(f.cwe, "carries a CWE id");
});

test("Node crypto one-shot sign/verify is flagged", () => {
  const f = byRule(
    run("a.ts", "crypto.sign('sha256', data, privateKey);"),
    "node-crypto-sign-oneshot",
  );
  assert.ok(f, "one-shot crypto.sign detected");
  assert.equal(f.category, "signature");
  assert.equal(f.hndl, false);
});

test("Node crypto EdDSA one-shot sign/verify with null algorithm is flagged", () => {
  // Node's Ed25519/Ed448 one-shot form passes `null` as the first argument:
  // crypto.sign(null, data, edKey). It must still be detected.
  const sign = byRule(run("a.ts", "crypto.sign(null, msg, key);"), "node-crypto-sign-oneshot");
  assert.ok(sign, "one-shot crypto.sign(null, …) detected");
  assert.equal(sign.category, "signature");

  const verify = byRule(
    run("a.ts", "crypto.verify(null, msg, key, sig);"),
    "node-crypto-sign-oneshot",
  );
  assert.ok(verify, "one-shot crypto.verify(null, …) detected");
});

test("Node crypto getDiffieHellman MODP group is HNDL", () => {
  const f = byRule(
    run("a.ts", "const dh = crypto.getDiffieHellman('modp14');"),
    "node-crypto-dh-modp",
  );
  assert.ok(f, "modp group detected");
  assert.equal(f.algorithm, "DH");
  assert.equal(f.hndl, true);
});

test("JOSE ECDH-ES key agreement is key-exchange + HNDL", () => {
  const f = byRule(run("a.ts", "const enc = { alg: 'ECDH-ES+A256KW' };"), "jose-ecdh-es");
  assert.ok(f, "ECDH-ES detected");
  assert.equal(f.category, "key-exchange");
  assert.equal(f.algorithm, "ECDH");
  assert.equal(f.hndl, true);
});

test("secp256k1 direct usage is flagged", () => {
  const f = byRule(run("a.ts", "const sig = secp256k1.sign(msgHash, privKey);"), "secp256k1-usage");
  assert.ok(f, "secp256k1 usage detected");
  assert.equal(f.algorithm, "ECDSA");
});

test("SSH public key and cert signature algorithm are config-scope findings", () => {
  const ssh = byRule(run("authorized_keys", "ssh-ed25519 AAAAC3Nz... user@host"), "ssh-public-key");
  assert.ok(ssh, "ssh-ed25519 public key detected");
  assert.equal(ssh.algorithm, "EdDSA");

  const cert = byRule(
    run("cert.cnf", "signatureAlgorithm: sha256WithRSAEncryption"),
    "cert-signature-algorithm",
  );
  assert.ok(cert, "cert signature algorithm detected");
  assert.equal(cert.algorithm, "RSA");
});

test("DSA and PGP PEM blocks are detected (C7)", () => {
  const dsa = byRule(
    run("k.pem", "-----BEGIN DSA PRIVATE KEY-----\nx\n-----END DSA PRIVATE KEY-----"),
    "pem-dsa-private-key",
  );
  assert.ok(dsa, "DSA PEM key detected");
  assert.equal(dsa.algorithm, "DSA");

  const pgp = byRule(
    run(
      "secret.asc",
      "-----BEGIN PGP PRIVATE KEY BLOCK-----\nx\n-----END PGP PRIVATE KEY BLOCK-----",
    ),
    "pem-pgp-private-key",
  );
  assert.ok(pgp, "PGP private key block detected");
  assert.equal(pgp.severity, "critical");
});

test("every source finding carries a CWE id (P2-6)", () => {
  const src = "crypto.createECDH('p256'); jwt.sign(p, k, { algorithm: 'RS256' });";
  for (const f of run("a.ts", src)) {
    assert.ok(f.cwe && /^CWE-\d+$/.test(f.cwe), `${f.ruleId} has a CWE id`);
  }
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
  const src =
    "await crypto.subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 2048 }, true, ['encrypt']);";
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
  const f = byRule(
    run("a.js", "forge.pki.rsa.generateKeyPair({ bits: 2048 });"),
    "forge-rsa-keygen",
  );
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
  const f = byRule(
    run("a.ts", "jwt.sign(payload, key, { algorithm: 'RS256' });"),
    "jwt-classical-alg",
  );
  assert.ok(f);
  assert.equal(f.algorithm, "RSA");
  assert.equal(f.category, "signature");
});

test("JWT ES256 → ECDSA, EdDSA → EdDSA", () => {
  const es = byRule(
    run("a.ts", "verify(token, key, { algorithms: ['ES256'] });"),
    "jwt-classical-alg",
  );
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

test("TLS weak-cipher regex is bounded (no catastrophic backtracking)", () => {
  // Pathological input: `ciphers:'` then a long non-quote run with no close
  // quote. The hardened {0,256} bounds keep this linear; assert it completes
  // quickly (a super-linear regex would blow well past this on 200k chars).
  const evil = "const o = { ciphers: '" + "A".repeat(200_000);
  const start = Date.now();
  const findings = run("a.ts", evil);
  const elapsed = Date.now() - start;
  assert.equal(findings.filter((f) => f.ruleId === "tls-weak-cipher").length, 0);
  assert.ok(elapsed < 1000, `cipher regex stayed bounded (${elapsed}ms)`);
});

test("WebCrypto nearCall scales on many calls/tokens (binary search)", () => {
  // Build a file with many subtle calls, then a >400-char gap, then many algo
  // tokens. A quadratic nearCall would be slow here; assert it completes fast.
  const calls = Array.from({ length: 2000 }, () => "subtle.sign(x);").join("\n");
  const gap = "/* " + "z".repeat(2000) + " */\n";
  const tokens = Array.from({ length: 2000 }, () => "'ECDSA';").join("\n");
  const start = Date.now();
  const findings = run("a.ts", calls + "\n" + gap + tokens);
  const elapsed = Date.now() - start;
  // Tokens are >400 chars past the last call, so none should be flagged.
  assert.equal(findings.filter((f) => f.ruleId === "webcrypto-classical").length, 0);
  assert.ok(elapsed < 1500, `nearCall stayed sub-quadratic (${elapsed}ms)`);
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
