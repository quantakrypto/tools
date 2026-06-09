/**
 * Curated database of npm packages that primarily expose classical asymmetric
 * cryptography (and are therefore quantum-vulnerable), plus a manifest scanner
 * that flags any of them found in package.json / package-lock.json.
 *
 * The list is intentionally focused on libraries whose *purpose* is classical
 * public-key crypto. General-purpose packages that merely call out to Node's
 * crypto are out of scope here (those are caught by the source detectors).
 */
import type { Finding, VulnerableDependency } from "./types.js";
import { makeFinding } from "./detect-utils.js";

/** Known quantum-vulnerable npm dependencies. */
export const vulnerableDependencies: VulnerableDependency[] = [
  {
    name: "node-forge",
    ecosystem: "npm",
    reason: "Pure-JS implementation of RSA, RSA-OAEP, and X.509 PKI.",
    algorithms: ["RSA"],
    severity: "high",
  },
  {
    name: "elliptic",
    ecosystem: "npm",
    reason: "Elliptic-curve ECDSA/ECDH (secp256k1, p256, ed25519).",
    algorithms: ["ECDSA", "ECDH", "EdDSA"],
    severity: "high",
  },
  {
    name: "jsrsasign",
    ecosystem: "npm",
    reason: "RSA/ECDSA/DSA signing, JWT, and X.509 in pure JS.",
    algorithms: ["RSA", "ECDSA", "DSA"],
    severity: "high",
  },
  {
    name: "node-rsa",
    ecosystem: "npm",
    reason: "Classical RSA encryption and signing.",
    algorithms: ["RSA"],
    severity: "high",
  },
  {
    name: "ursa",
    ecosystem: "npm",
    reason: "OpenSSL-backed RSA encryption and signing bindings.",
    algorithms: ["RSA"],
    severity: "high",
  },
  {
    name: "sshpk",
    ecosystem: "npm",
    reason: "Parses/handles SSH and PEM keys (RSA, ECDSA, Ed25519, DSA).",
    algorithms: ["RSA", "ECDSA", "EdDSA", "DSA"],
    severity: "medium",
  },
  {
    name: "jsonwebtoken",
    ecosystem: "npm",
    reason: "JWTs commonly signed with RS256/ES256 (classical RSA/ECDSA).",
    algorithms: ["RSA", "ECDSA"],
    severity: "high",
  },
  {
    name: "jose",
    ecosystem: "npm",
    reason: "JWS/JWE with classical RSA-OAEP, RSA-PSS, ECDH-ES and ECDSA.",
    algorithms: ["RSA", "ECDH", "ECDSA", "EdDSA"],
    severity: "high",
  },
  {
    name: "jws",
    ecosystem: "npm",
    reason: "JSON Web Signatures using classical RS/ES algorithms.",
    algorithms: ["RSA", "ECDSA"],
    severity: "high",
  },
  {
    name: "eccrypto",
    ecosystem: "npm",
    reason: "ECIES (ECDH-based) encryption and ECDSA signatures.",
    algorithms: ["ECIES", "ECDH", "ECDSA"],
    severity: "high",
  },
  {
    name: "secp256k1",
    ecosystem: "npm",
    reason: "secp256k1 ECDSA/ECDH bindings (blockchain keys).",
    algorithms: ["ECDSA", "ECDH"],
    severity: "high",
  },
  {
    name: "tweetnacl",
    ecosystem: "npm",
    reason: "X25519 key exchange and Ed25519 signatures (modern but classical).",
    algorithms: ["X25519", "EdDSA"],
    severity: "low",
  },
  {
    name: "ed25519",
    ecosystem: "npm",
    reason: "Ed25519 signatures (classical).",
    algorithms: ["EdDSA"],
    severity: "low",
  },
  {
    name: "@noble/curves",
    ecosystem: "npm",
    reason: "Audited classical curves: ECDSA, ECDH, Ed25519, X25519, secp256k1.",
    algorithms: ["ECDSA", "ECDH", "EdDSA", "X25519"],
    severity: "medium",
  },
  {
    name: "@noble/secp256k1",
    ecosystem: "npm",
    reason: "secp256k1 ECDSA/ECDH (classical).",
    algorithms: ["ECDSA", "ECDH"],
    severity: "medium",
  },
  {
    name: "@noble/ed25519",
    ecosystem: "npm",
    reason: "Ed25519 signatures and X25519 key exchange (classical).",
    algorithms: ["EdDSA", "X25519"],
    severity: "low",
  },
  {
    name: "paseto",
    ecosystem: "npm",
    reason: "PASETO public tokens signed with classical Ed25519 (v2/v4) or RSA.",
    algorithms: ["EdDSA", "RSA"],
    severity: "medium",
  },
  {
    name: "bcrypto",
    ecosystem: "npm",
    reason: "Broad classical crypto suite: RSA, ECDSA, ECDH, Ed25519, DSA.",
    algorithms: ["RSA", "ECDSA", "ECDH", "EdDSA", "DSA"],
    severity: "high",
  },
  {
    name: "ecpair",
    ecosystem: "npm",
    reason: "secp256k1 ECDSA key pairs for Bitcoin.",
    algorithms: ["ECDSA"],
    severity: "medium",
  },
  {
    name: "keypair",
    ecosystem: "npm",
    reason: "Pure-JS RSA key pair generation.",
    algorithms: ["RSA"],
    severity: "high",
  },
];

/** Fast lookup map by package name. */
const BY_NAME = new Map<string, VulnerableDependency>(
  vulnerableDependencies.map((d) => [d.name, d]),
);

/** True if a file path looks like a manifest we can parse for dependencies. */
export function isManifestFile(file: string): boolean {
  const base = file.split("/").pop() ?? file;
  return base === "package.json" || base === "package-lock.json";
}

/**
 * Build a finding for a vulnerable dependency located in a manifest. The
 * location points at the line where the package name appears in the file (best
 * effort), falling back to line 1.
 */
function dependencyFinding(
  dep: VulnerableDependency,
  file: string,
  content: string,
  index: number,
): Finding {
  // Use the first listed algorithm to derive a default remediation/algorithm.
  const algorithm = dep.algorithms[0] ?? "unknown";
  return makeFinding({
    ruleId: "dep-vulnerable",
    title: `Quantum-vulnerable dependency: ${dep.name}`,
    category: "dependency",
    severity: dep.severity,
    confidence: "high",
    algorithm,
    // Confidentiality libs are HNDL-exposed; signature-only ones are not.
    hndl: dep.algorithms.some((a) => a === "RSA" || a === "ECDH" || a === "DH" || a === "ECIES" || a === "X25519"),
    message: `${dep.name} — ${dep.reason}`,
    file,
    content,
    index,
  });
}

/** Locate the offset of a JSON key `"name"` in the manifest text (or 0). */
function offsetOfKey(content: string, name: string): number {
  // Escape regex-special characters in the package name (e.g. @noble/curves).
  const escaped = name.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");
  const re = new RegExp(`"${escaped}"\\s*:`, "g");
  const m = re.exec(content);
  return m ? m.index : 0;
}

/**
 * Scan a single manifest file's contents for vulnerable dependencies.
 *
 * - `package.json`: dependencies / devDependencies / peerDependencies / optionalDependencies.
 * - `package-lock.json` (v2/v3): the `packages` map keys (node_modules/<name>),
 *   plus legacy `dependencies` map for v1.
 *
 * Returns one finding per distinct vulnerable package name found in the file.
 */
export function scanManifest(file: string, content: string): Finding[] {
  let json: unknown;
  try {
    json = JSON.parse(content);
  } catch {
    return []; // not valid JSON — skip quietly.
  }
  if (json === null || typeof json !== "object") return [];

  const found = new Set<string>();
  const obj = json as Record<string, unknown>;

  const collectFromRecord = (rec: unknown): void => {
    if (rec === null || typeof rec !== "object") return;
    for (const key of Object.keys(rec as Record<string, unknown>)) {
      if (BY_NAME.has(key)) found.add(key);
    }
  };

  // package.json dependency sections.
  collectFromRecord(obj.dependencies);
  collectFromRecord(obj.devDependencies);
  collectFromRecord(obj.peerDependencies);
  collectFromRecord(obj.optionalDependencies);

  // package-lock.json v2/v3 "packages" map: keys are "node_modules/<name>".
  const packages = obj.packages;
  if (packages !== null && typeof packages === "object") {
    for (const key of Object.keys(packages as Record<string, unknown>)) {
      if (!key) continue; // root package entry
      const marker = "node_modules/";
      const idx = key.lastIndexOf(marker);
      const name = idx >= 0 ? key.slice(idx + marker.length) : key;
      if (BY_NAME.has(name)) found.add(name);
    }
  }

  const findings: Finding[] = [];
  for (const name of found) {
    const dep = BY_NAME.get(name);
    if (!dep) continue;
    findings.push(dependencyFinding(dep, file, content, offsetOfKey(content, name)));
  }
  // Deterministic ordering by package name.
  findings.sort((a, b) => (a.title < b.title ? -1 : a.title > b.title ? 1 : 0));
  return findings;
}
