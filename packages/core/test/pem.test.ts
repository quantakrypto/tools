/**
 * Tests for PEM / certificate detection across arbitrary files.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { detectors } from "../src/index.js";
import type { Finding } from "../src/index.js";

function run(file: string, content: string): Finding[] {
  const out: Finding[] = [];
  for (const det of detectors) {
    if (det.appliesTo(file)) out.push(...det.detect({ file, content }));
  }
  return out;
}

test("RSA private key PEM is critical + HNDL", () => {
  const content = [
    "-----BEGIN RSA PRIVATE KEY-----",
    "MIIEpAIBAAKCAQEA...",
    "-----END RSA PRIVATE KEY-----",
  ].join("\n");
  const f = run("secrets.pem", content).find((x) => x.ruleId === "pem-rsa-private-key");
  assert.ok(f);
  assert.equal(f.severity, "critical");
  assert.equal(f.algorithm, "RSA");
  assert.equal(f.hndl, true);
  assert.equal(f.location.line, 1);
});

test("EC private key PEM", () => {
  const content = "-----BEGIN EC PRIVATE KEY-----\nabc\n-----END EC PRIVATE KEY-----\n";
  const f = run("k.pem", content).find((x) => x.ruleId === "pem-ec-private-key");
  assert.ok(f);
  assert.equal(f.algorithm, "ECDSA");
});

test("OPENSSH private key", () => {
  const content = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n";
  const f = run("id_ed25519", content).find((x) => x.ruleId === "pem-openssh-private-key");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

test("X.509 certificate is low severity, not HNDL", () => {
  const content = "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n";
  const f = run("cert.crt", content).find((x) => x.ruleId === "pem-certificate");
  assert.ok(f);
  assert.equal(f.severity, "low");
  assert.equal(f.hndl, false);
});

test("DSA private key PEM is detected (C7)", () => {
  const content = "-----BEGIN DSA PRIVATE KEY-----\nabc\n-----END DSA PRIVATE KEY-----\n";
  const f = run("dsa.pem", content).find((x) => x.ruleId === "pem-dsa-private-key");
  assert.ok(f);
  assert.equal(f.algorithm, "DSA");
  assert.equal(f.severity, "critical");
});

test("PGP private key block and message are detected (C7)", () => {
  const priv = run(
    "secret.asc",
    "-----BEGIN PGP PRIVATE KEY BLOCK-----\nx\n-----END PGP PRIVATE KEY BLOCK-----\n",
  ).find((x) => x.ruleId === "pem-pgp-private-key");
  assert.ok(priv);
  assert.equal(priv.severity, "critical");
  assert.equal(priv.hndl, true);

  const msg = run("m.asc", "-----BEGIN PGP MESSAGE-----\nx\n-----END PGP MESSAGE-----\n").find(
    (x) => x.ruleId === "pem-pgp-message",
  );
  assert.ok(msg);
  assert.equal(msg.hndl, true);
});

test("every PEM finding carries a CWE id", () => {
  const content = "-----BEGIN RSA PRIVATE KEY-----\nx\n-----END RSA PRIVATE KEY-----\n";
  for (const f of run("k.pem", content)) {
    if (f.ruleId.startsWith("pem-")) assert.ok(f.cwe, `${f.ruleId} has a CWE`);
  }
});

test("non-PEM files produce no PEM findings", () => {
  const findings = run("readme.md", "Just some text, no keys here.");
  assert.equal(findings.filter((f) => f.ruleId.startsWith("pem-")).length, 0);
});
