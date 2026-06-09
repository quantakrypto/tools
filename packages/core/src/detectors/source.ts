/**
 * Source-code detectors for classical, non-quantum-safe asymmetric cryptography
 * in JavaScript / TypeScript. Each detector is pure and stateless: it declares
 * which files it applies to and returns zero or more Findings for a file's
 * contents.
 *
 * The detection strategy is deliberately lexical (regex over source text). This
 * is robust to bundling and partial files and keeps the package dependency-free.
 * Confidence is set per-pattern to reflect how specific the match is.
 *
 * HNDL (harvest-now-decrypt-later) policy:
 *   - confidentiality primitives (key exchange / KEM: ECDH, DH, RSA-OAEP) → hndl:true
 *   - signatures (RSA-PSS, ECDSA, EdDSA, DSA, JWT alg) → hndl:false, but still high
 *     severity because a quantum attacker can forge them.
 */
import type { Detector, Finding } from "../types.js";
import {
  JS_TS_EXTENSIONS,
  eachMatch,
  hasExtension,
  makeFinding,
} from "../detect-utils.js";

/* -------------------------------------------------------------------------- */
/* Node.js `crypto` module                                                    */
/* -------------------------------------------------------------------------- */

/** Detects classical asymmetric usage from Node's built-in `crypto` module. */
const nodeCryptoDetector: Detector = {
  id: "node-crypto",
  description: "Classical asymmetric crypto via the Node.js `crypto` module",
  appliesTo: (f) => hasExtension(f, JS_TS_EXTENSIONS),
  detect({ file, content }): Finding[] {
    const findings: Finding[] = [];
    const push = (
      spec: Omit<Parameters<typeof makeFinding>[0], "file" | "content" | "index" | "matchLength">,
      m: RegExpExecArray,
    ) =>
      findings.push(
        makeFinding({ ...spec, file, content, index: m.index, matchLength: m[0].length }),
      );

    // generateKeyPair(Sync)('rsa' | 'ec' | 'dsa' | 'dh' | 'x25519' | 'ed25519', ...)
    eachMatch(
      /generateKeyPair(?:Sync)?\s*\(\s*['"`](rsa|ec|dsa|dh|x25519|x448|ed25519|ed448)['"`]/g,
      content,
      (m) => {
        const type = m[1].toLowerCase();
        const map: Record<
          string,
          { algo: Finding["algorithm"]; cat: Finding["category"]; sev: Finding["severity"]; hndl: boolean; label: string }
        > = {
          rsa: { algo: "RSA", cat: "kem", sev: "high", hndl: true, label: "RSA" },
          ec: { algo: "ECDSA", cat: "signature", sev: "high", hndl: false, label: "EC (ECDSA/ECDH)" },
          dsa: { algo: "DSA", cat: "signature", sev: "high", hndl: false, label: "DSA" },
          dh: { algo: "DH", cat: "key-exchange", sev: "high", hndl: true, label: "Diffie-Hellman" },
          x25519: { algo: "X25519", cat: "key-exchange", sev: "low", hndl: true, label: "X25519" },
          x448: { algo: "X25519", cat: "key-exchange", sev: "low", hndl: true, label: "X448" },
          ed25519: { algo: "EdDSA", cat: "signature", sev: "low", hndl: false, label: "Ed25519" },
          ed448: { algo: "EdDSA", cat: "signature", sev: "low", hndl: false, label: "Ed448" },
        };
        const info = map[type];
        push(
          {
            ruleId: "node-crypto-keygen",
            title: `${info.label} key generation`,
            category: info.cat,
            severity: info.sev,
            confidence: "high",
            algorithm: info.algo,
            hndl: info.hndl,
            message: `Generates a classical ${info.label} key pair, which is not quantum-safe.`,
          },
          m,
        );
      },
    );

    // createSign / createVerify — RSA / ECDSA / DSA signatures.
    eachMatch(/create(?:Sign|Verify)\s*\(/g, content, (m) => {
      push(
        {
          ruleId: "node-crypto-sign",
          title: "Classical signature (createSign/createVerify)",
          category: "signature",
          severity: "high",
          confidence: "medium",
          algorithm: "unknown",
          hndl: false,
          message:
            "Uses createSign/createVerify, typically RSA, ECDSA or DSA — all forgeable by a quantum attacker.",
          remediation: "ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205)",
        },
        m,
      );
    });

    // createDiffieHellman / createDiffieHellmanGroup — finite-field DH key exchange.
    eachMatch(/createDiffieHellman(?:Group)?\s*\(/g, content, (m) => {
      push(
        {
          ruleId: "node-crypto-dh",
          title: "Diffie-Hellman key exchange",
          category: "key-exchange",
          severity: "high",
          confidence: "high",
          algorithm: "DH",
          hndl: true,
          message: "Finite-field Diffie-Hellman is broken by Shor's algorithm (harvest-now-decrypt-later).",
        },
        m,
      );
    });

    // createECDH — elliptic-curve Diffie-Hellman key exchange.
    eachMatch(/createECDH\s*\(/g, content, (m) => {
      push(
        {
          ruleId: "node-crypto-ecdh",
          title: "ECDH key exchange",
          category: "key-exchange",
          severity: "high",
          confidence: "high",
          algorithm: "ECDH",
          hndl: true,
          message: "Elliptic-curve Diffie-Hellman is broken by Shor's algorithm (harvest-now-decrypt-later).",
        },
        m,
      );
    });

    // publicEncrypt / privateDecrypt — RSA encryption (KEM-like confidentiality).
    eachMatch(/(?:crypto\.)?(?:publicEncrypt|privateDecrypt)\s*\(/g, content, (m) => {
      push(
        {
          ruleId: "node-crypto-rsa-encrypt",
          title: "RSA public-key encryption",
          category: "kem",
          severity: "high",
          confidence: "high",
          algorithm: "RSA",
          hndl: true,
          message:
            "RSA public-key encryption is broken by Shor's algorithm and exposed to harvest-now-decrypt-later.",
        },
        m,
      );
    });

    // diffieHellman({ privateKey, publicKey }) — KeyObject-based DH/ECDH.
    eachMatch(/(?:crypto\.)?diffieHellman\s*\(\s*\{/g, content, (m) => {
      push(
        {
          ruleId: "node-crypto-dh-keyobject",
          title: "Diffie-Hellman (KeyObject) key exchange",
          category: "key-exchange",
          severity: "high",
          confidence: "high",
          algorithm: "ECDH",
          hndl: true,
          message: "crypto.diffieHellman() performs a classical (EC)DH agreement (harvest-now-decrypt-later).",
        },
        m,
      );
    });

    return findings;
  },
};

/* -------------------------------------------------------------------------- */
/* WebCrypto (SubtleCrypto)                                                    */
/* -------------------------------------------------------------------------- */

/**
 * Detects classical algorithms passed to WebCrypto's SubtleCrypto methods. The
 * algorithm name can appear as a bare string ("RSA-OAEP") or as
 * `{ name: "ECDH" }`; we scan both forms within a window after a subtle call.
 */
const webCryptoDetector: Detector = {
  id: "webcrypto",
  description: "Classical asymmetric algorithms via WebCrypto SubtleCrypto",
  appliesTo: (f) => hasExtension(f, JS_TS_EXTENSIONS),
  detect({ file, content }): Finding[] {
    const findings: Finding[] = [];
    const ALGO_RE =
      /\b(RSA-OAEP|RSA-PSS|RSASSA-PKCS1-v1_5|ECDH|ECDSA)\b/gi;

    // Only consider names that appear near a subtle.* call to reduce noise.
    const callRe =
      /subtle\s*\.\s*(generateKey|importKey|exportKey|deriveKey|deriveBits|sign|verify|encrypt|decrypt|wrapKey|unwrapKey)\s*\(/g;
    const callIndexes: number[] = [];
    eachMatch(callRe, content, (m) => callIndexes.push(m.index));
    if (callIndexes.length === 0) return findings;

    const nearCall = (idx: number): boolean =>
      callIndexes.some((c) => idx >= c && idx - c < 400);

    eachMatch(ALGO_RE, content, (m) => {
      if (!nearCall(m.index)) return;
      const name = m[1].toUpperCase();
      const isKem = name === "RSA-OAEP";
      const isEcdh = name === "ECDH";
      const algorithm: Finding["algorithm"] =
        name.startsWith("RSA") ? "RSA" : isEcdh ? "ECDH" : "ECDSA";
      const category: Finding["category"] = isEcdh
        ? "key-exchange"
        : isKem
          ? "kem"
          : "signature";
      const hndl = isKem || isEcdh;
      findings.push(
        makeFinding({
          ruleId: "webcrypto-classical",
          title: `WebCrypto ${m[1]}`,
          category,
          severity: "high",
          confidence: "high",
          algorithm,
          hndl,
          message: `WebCrypto algorithm "${m[1]}" is classical asymmetric crypto and not quantum-safe.`,
          file,
          content,
          index: m.index,
          matchLength: m[0].length,
        }),
      );
    });

    return findings;
  },
};

/* -------------------------------------------------------------------------- */
/* Popular crypto libraries                                                    */
/* -------------------------------------------------------------------------- */

/** Detects classical crypto from popular npm libraries used in source. */
const libraryDetector: Detector = {
  id: "crypto-libs",
  description: "Classical asymmetric crypto via node-forge, elliptic, jsrsasign, node-rsa",
  appliesTo: (f) => hasExtension(f, JS_TS_EXTENSIONS),
  detect({ file, content }): Finding[] {
    const findings: Finding[] = [];
    const add = (
      re: RegExp,
      spec: Omit<Parameters<typeof makeFinding>[0], "file" | "content" | "index" | "matchLength">,
    ) =>
      eachMatch(re, content, (m) =>
        findings.push(
          makeFinding({ ...spec, file, content, index: m.index, matchLength: m[0].length }),
        ),
      );

    // node-forge: pki.rsa.generateKeyPair(...)
    add(/pki\.rsa\.generateKeyPair\s*\(/g, {
      ruleId: "forge-rsa-keygen",
      title: "node-forge RSA key generation",
      category: "kem",
      severity: "high",
      confidence: "high",
      algorithm: "RSA",
      hndl: true,
      message: "node-forge generates a classical RSA key pair, which is not quantum-safe.",
    });

    // node-forge: forge.ed25519.* (classical EdDSA)
    add(/forge\.ed25519\b/g, {
      ruleId: "forge-ed25519",
      title: "node-forge Ed25519 usage",
      category: "signature",
      severity: "low",
      confidence: "high",
      algorithm: "EdDSA",
      hndl: false,
      message: "node-forge Ed25519 is a modern but still classical signature scheme.",
    });

    // elliptic: new EC('secp256k1') / new ec(...)
    add(/new\s+(?:elliptic\.)?ec\s*\(/gi, {
      ruleId: "elliptic-ec",
      title: "elliptic curve instantiation",
      category: "signature",
      severity: "high",
      confidence: "high",
      algorithm: "ECDSA",
      hndl: false,
      message:
        "The `elliptic` library implements classical ECDSA/ECDH, both broken by Shor's algorithm.",
    });

    // jsrsasign: KEYUTIL.generateKeypair('RSA'|'EC', ...) or KJUR.crypto.*
    add(/KEYUTIL\.generateKeypair\s*\(/g, {
      ruleId: "jsrsasign-keygen",
      title: "jsrsasign key generation",
      category: "signature",
      severity: "high",
      confidence: "high",
      algorithm: "unknown",
      hndl: false,
      message: "jsrsasign generates classical RSA/EC key pairs, which are not quantum-safe.",
      remediation: "ML-KEM-768 (FIPS 203) / ML-DSA-65 (FIPS 204)",
    });
    add(/KJUR\.crypto\.(?:Signature|ECDSA)\b/g, {
      ruleId: "jsrsasign-sign",
      title: "jsrsasign signature",
      category: "signature",
      severity: "high",
      confidence: "high",
      algorithm: "unknown",
      hndl: false,
      message: "jsrsasign signing uses classical RSA/ECDSA signatures, forgeable by a quantum attacker.",
      remediation: "ML-DSA-65 (FIPS 204)",
    });

    // node-rsa: new NodeRSA(...)
    add(/new\s+NodeRSA\s*\(/g, {
      ruleId: "node-rsa",
      title: "node-rsa key/usage",
      category: "kem",
      severity: "high",
      confidence: "high",
      algorithm: "RSA",
      hndl: true,
      message: "node-rsa wraps classical RSA encryption/signing, which is not quantum-safe.",
    });

    return findings;
  },
};

/* -------------------------------------------------------------------------- */
/* JWT / JOSE algorithm strings                                                */
/* -------------------------------------------------------------------------- */

/**
 * Detects classical signature algorithm identifiers used by JWT/JOSE. These
 * appear as string literals: `alg: "RS256"`, `algorithms: ["ES256"]`, etc.
 */
const jwtDetector: Detector = {
  id: "jwt-jose",
  description: "Classical JWT/JOSE signature algorithms (RS/PS/ES/EdDSA)",
  appliesTo: (f) => hasExtension(f, JS_TS_EXTENSIONS),
  detect({ file, content }): Finding[] {
    const findings: Finding[] = [];
    // Match a quoted classical JWS alg token. Anchored to quotes to avoid words.
    const re = /['"`](RS(?:256|384|512)|PS(?:256|384|512)|ES(?:256|384|512|256K)|EdDSA)['"`]/g;
    eachMatch(re, content, (m) => {
      const alg = m[1];
      let algorithm: Finding["algorithm"];
      if (alg.startsWith("RS") || alg.startsWith("PS")) algorithm = "RSA";
      else if (alg === "EdDSA") algorithm = "EdDSA";
      else algorithm = "ECDSA"; // ES*
      findings.push(
        makeFinding({
          ruleId: "jwt-classical-alg",
          title: `JWT/JOSE algorithm ${alg}`,
          category: "signature",
          severity: "high",
          confidence: "medium",
          algorithm,
          hndl: false,
          message: `JWT/JOSE algorithm "${alg}" is a classical signature, forgeable by a quantum attacker.`,
          remediation: "ML-DSA-65 (FIPS 204); track IETF PQC JOSE/COSE algorithms",
          file,
          content,
          index: m.index,
          matchLength: m[0].length,
        }),
      );
    });
    return findings;
  },
};

/* -------------------------------------------------------------------------- */
/* TLS legacy configuration                                                    */
/* -------------------------------------------------------------------------- */

/**
 * Detects legacy / insecure TLS configuration expressed as JS object literals:
 * forced TLS 1.0/1.1, disabled certificate verification, and weak ciphers.
 * These aren't quantum-specific but materially weaken transport security and
 * are squarely in qScan's "config" scope.
 */
const tlsDetector: Detector = {
  id: "tls-config",
  description: "Legacy / insecure TLS configuration in JS objects",
  appliesTo: (f) => hasExtension(f, JS_TS_EXTENSIONS),
  detect({ file, content }): Finding[] {
    const findings: Finding[] = [];

    // minVersion / maxVersion / secureProtocol pinned to TLS 1.0 or 1.1.
    eachMatch(
      /(?:minVersion|maxVersion)\s*:\s*['"`]TLSv1(?:\.1)?['"`]|secureProtocol\s*:\s*['"`]TLSv1(?:_1)?_method['"`]/g,
      content,
      (m) => {
        findings.push(
          makeFinding({
            ruleId: "tls-legacy-version",
            title: "Legacy TLS version pinned",
            category: "tls",
            severity: "medium",
            confidence: "high",
            hndl: false,
            message: "TLS 1.0/1.1 are deprecated and insecure; require TLS 1.3.",
            remediation: "Set minVersion: 'TLSv1.3' and prefer PQC-hybrid key exchange.",
            file,
            content,
            index: m.index,
            matchLength: m[0].length,
          }),
        );
      },
    );

    // rejectUnauthorized: false — disables certificate verification.
    eachMatch(/rejectUnauthorized\s*:\s*false/g, content, (m) => {
      findings.push(
        makeFinding({
          ruleId: "tls-reject-unauthorized",
          title: "TLS certificate verification disabled",
          category: "tls",
          severity: "high",
          confidence: "high",
          hndl: false,
          message: "rejectUnauthorized:false disables TLS certificate verification (MITM risk).",
          remediation: "Remove rejectUnauthorized:false; verify certificates properly.",
          file,
          content,
          index: m.index,
          matchLength: m[0].length,
        }),
      );
    });

    // Weak / export ciphers referenced in a ciphers string.
    eachMatch(
      /ciphers\s*:\s*['"`][^'"`]*\b(RC4|DES|3DES|MD5|NULL|EXPORT|aNULL|eNULL)\b[^'"`]*['"`]/gi,
      content,
      (m) => {
        findings.push(
          makeFinding({
            ruleId: "tls-weak-cipher",
            title: "Weak TLS cipher configured",
            category: "tls",
            severity: "medium",
            confidence: "medium",
            hndl: false,
            message: `Weak cipher (${m[1]}) configured in the TLS ciphers list.`,
            remediation: "Use a modern AEAD cipher suite (TLS 1.3 defaults).",
            file,
            content,
            index: m.index,
            matchLength: m[0].length,
          }),
        );
      },
    );

    return findings;
  },
};

/** All built-in source/config detectors, in run order. */
export const sourceDetectors: Detector[] = [
  nodeCryptoDetector,
  webCryptoDetector,
  libraryDetector,
  jwtDetector,
  tlsDetector,
];
