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

test("non-PEM files produce no PEM findings", () => {
  const findings = run("readme.md", "Just some text, no keys here.");
  assert.equal(findings.filter((f) => f.category === "certificate").length, 0);
});
