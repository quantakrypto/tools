// Sample quantum-vulnerable cryptography. Do NOT use any of this in production.
import { generateKeyPairSync, createECDH, sign } from "node:crypto";

// RSA key generation — broken by Shor's algorithm (KEM / signatures).
export function makeRsaKeypair() {
  return generateKeyPairSync("rsa", { modulusLength: 2048 });
}

// Elliptic-curve Diffie–Hellman key exchange — also quantum-vulnerable, and
// exposed to "harvest now, decrypt later".
export function deriveSharedSecret() {
  const ecdh = createECDH("prime256v1");
  ecdh.generateKeys();
  return ecdh;
}

// ECDSA signing over the P-256 curve.
export function signMessage(privateKey, message) {
  return sign("sha256", Buffer.from(message), privateKey);
}
