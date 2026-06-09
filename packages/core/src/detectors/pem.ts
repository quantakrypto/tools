/**
 * Config / certificate detector: finds PEM-encoded cryptographic material in
 * any text file (source, config, .pem, .key, .crt, .env, …). This catches
 * embedded private keys and X.509 certificates regardless of language.
 */
import type { Detector, Finding } from "../types.js";
import { eachMatch, makeFinding } from "../detect-utils.js";

interface PemRule {
  /** Regex matching the PEM begin marker. */
  re: RegExp;
  ruleId: string;
  title: string;
  category: Finding["category"];
  severity: Finding["severity"];
  algorithm?: Finding["algorithm"];
  message: string;
  remediation: string;
  hndl: boolean;
}

const PEM_RULES: PemRule[] = [
  {
    re: /-----BEGIN RSA PRIVATE KEY-----/g,
    ruleId: "pem-rsa-private-key",
    title: "RSA private key (PEM)",
    category: "certificate",
    severity: "critical",
    algorithm: "RSA",
    hndl: true,
    message: "Embedded RSA private key (PKCS#1 PEM); classical and not quantum-safe.",
    remediation: "Migrate to ML-DSA / ML-KEM keys and remove embedded private keys from source.",
  },
  {
    re: /-----BEGIN EC PRIVATE KEY-----/g,
    ruleId: "pem-ec-private-key",
    title: "EC private key (PEM)",
    category: "certificate",
    severity: "critical",
    algorithm: "ECDSA",
    hndl: true,
    message: "Embedded EC private key (SEC1 PEM); classical ECDSA/ECDH key, not quantum-safe.",
    remediation: "Migrate to ML-DSA (FIPS 204) keys and remove embedded private keys from source.",
  },
  {
    re: /-----BEGIN OPENSSH PRIVATE KEY-----/g,
    ruleId: "pem-openssh-private-key",
    title: "OpenSSH private key",
    category: "certificate",
    severity: "critical",
    algorithm: "unknown",
    hndl: true,
    message: "Embedded OpenSSH private key (RSA/ECDSA/Ed25519); classical and not quantum-safe.",
    remediation: "Rotate the key; plan migration to PQC-capable SSH (e.g. sntrup761x25519).",
  },
  {
    re: /-----BEGIN (?:ENCRYPTED )?PRIVATE KEY-----/g,
    ruleId: "pem-pkcs8-private-key",
    title: "Private key (PKCS#8 PEM)",
    category: "certificate",
    severity: "critical",
    algorithm: "unknown",
    hndl: true,
    message: "Embedded PKCS#8 private key; likely classical RSA/EC, not quantum-safe.",
    remediation: "Migrate to PQC keys and remove embedded private keys from source.",
  },
  {
    re: /-----BEGIN CERTIFICATE-----/g,
    ruleId: "pem-certificate",
    title: "X.509 certificate (PEM)",
    category: "certificate",
    severity: "low",
    algorithm: "unknown",
    hndl: false,
    message: "Embedded X.509 certificate; almost certainly signed with classical RSA/ECDSA.",
    remediation: "Plan re-issuance with PQC-capable CAs as ML-DSA certificate profiles mature.",
  },
];

/** Detects PEM key/certificate material in arbitrary files. */
export const pemDetector: Detector = {
  id: "pem-material",
  description: "PEM-encoded private keys and X.509 certificates in any file",
  // Applies to every text file; the walker already filters out binaries.
  appliesTo: () => true,
  detect({ file, content }): Finding[] {
    // Fast reject: only proceed if a PEM header is present at all.
    if (!content.includes("-----BEGIN ")) return [];

    const findings: Finding[] = [];
    for (const rule of PEM_RULES) {
      eachMatch(rule.re, content, (m) => {
        findings.push(
          makeFinding({
            ruleId: rule.ruleId,
            title: rule.title,
            category: rule.category,
            severity: rule.severity,
            confidence: "high",
            algorithm: rule.algorithm,
            hndl: rule.hndl,
            message: rule.message,
            remediation: rule.remediation,
            file,
            content,
            index: m.index,
            matchLength: m[0].length,
          }),
        );
      });
    }
    return findings;
  },
};
