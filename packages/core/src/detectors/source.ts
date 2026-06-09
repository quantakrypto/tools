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
 * All per-file regexes are precompiled at module scope (not re-created per
 * file) — `eachMatch` clones a fresh stateful copy only when a regex lacks the
 * global flag, and these are all global, so they are reused safely.
 *
 * HNDL (harvest-now-decrypt-later) policy:
 *   - confidentiality primitives (key exchange / KEM: ECDH, DH, RSA-OAEP) → hndl:true
 *   - signatures (RSA-PSS, ECDSA, EdDSA, DSA, JWT alg) → hndl:false, but still high
 *     severity because a quantum attacker can forge them.
 *   - EC keygen is ambiguous (an 'ec' key feeds BOTH ECDSA and ECDH); it is
 *     classified conservatively as key-exchange-capable (hndl:true).
 */
import type { Detector, Finding } from "../types.js";
import {
  JS_TS_EXTENSIONS,
  eachMatch,
  hasExtension,
  makeFinding,
  nearSortedCall,
} from "../detect-utils.js";
import {
  CWE_BROKEN_CRYPTO,
  CWE_CERT_VALIDATION,
  CWE_WEAK_STRENGTH,
} from "../cwe.js";

/* -------------------------------------------------------------------------- */
/* Precompiled regexes (module scope — never recreated per file)              */
/* -------------------------------------------------------------------------- */

const RE_GENERATE_KEYPAIR =
  /generateKeyPair(?:Sync)?\s*\(\s*['"`](rsa|ec|dsa|dh|x25519|x448|ed25519|ed448)['"`]/g;
const RE_CREATE_SIGN_VERIFY = /create(?:Sign|Verify)\s*\(/g;
// One-shot crypto.sign/verify(algorithm, data, key). Anchored so it doesn't
// fire inside identifiers like `assign(` or `createSign(` (which the dedicated
// createSign/createVerify rule handles).
const RE_ONESHOT_SIGN_VERIFY = /(?:^|[^.\w])(?:crypto\.)?(sign|verify)\s*\(\s*['"`][\w.-]+['"`]\s*,/g;
const RE_CREATE_DH = /createDiffieHellman(?:Group)?\s*\(/g;
const RE_GET_DH = /getDiffieHellman\s*\(\s*['"`](modp\d+)['"`]\s*\)/g;
const RE_CREATE_ECDH = /createECDH\s*\(/g;
const RE_RSA_ENCRYPT = /(?:crypto\.)?(?:publicEncrypt|privateDecrypt)\s*\(/g;
const RE_DH_KEYOBJECT = /(?:crypto\.)?diffieHellman\s*\(\s*\{/g;

// WebCrypto.
const RE_WEBCRYPTO_ALGO = /\b(RSA-OAEP|RSA-PSS|RSASSA-PKCS1-v1_5|ECDH|ECDSA)\b/gi;
const RE_SUBTLE_CALL =
  /subtle\s*\.\s*(generateKey|importKey|exportKey|deriveKey|deriveBits|sign|verify|encrypt|decrypt|wrapKey|unwrapKey)\s*\(/g;

// Libraries.
const RE_FORGE_RSA = /pki\.rsa\.generateKeyPair\s*\(/g;
const RE_FORGE_ED25519 = /forge\.ed25519\b/g;
const RE_ELLIPTIC_EC = /new\s+(?:elliptic\.)?ec\s*\(/gi;
const RE_JSRSASIGN_KEYGEN = /KEYUTIL\.generateKeypair\s*\(/g;
const RE_JSRSASIGN_SIGN = /KJUR\.crypto\.(?:Signature|ECDSA)\b/g;
const RE_NODE_RSA = /new\s+NodeRSA\s*\(/g;
// secp256k1 — direct @noble/secp256k1 / secp256k1-style API usage in source.
const RE_SECP256K1 =
  /\b(?:secp(?:256k1)?|secp)\s*\.\s*(?:sign|verify|getPublicKey|getSharedSecret|ecdh|recoverPublicKey)\s*\(/g;

// JWT/JOSE.
const RE_JWT_ALG =
  /['"`](RS(?:256|384|512)|PS(?:256|384|512)|ES(?:256|384|512|256K)|EdDSA)['"`]/g;
// JOSE ECDH-ES key agreement (HNDL) and COSE algorithm identifiers.
const RE_JOSE_ECDH = /['"`](ECDH-ES(?:\+A(?:128|192|256)KW)?)['"`]/g;

// TLS config.
const RE_TLS_LEGACY_VERSION =
  /(?:minVersion|maxVersion)\s*:\s*['"`]TLSv1(?:\.1)?['"`]|secureProtocol\s*:\s*['"`]TLSv1(?:_1)?_method['"`]/g;
const RE_TLS_REJECT = /rejectUnauthorized\s*:\s*false/g;
// Hardened cipher regex: bounded spans (no unbounded `[^'"`]*` straddling the
// alternation), single-quote-style anchoring removed in favour of {0,256} bounds
// so worst-case backtracking is linear in the bound, not the file (P0-6).
const RE_TLS_WEAK_CIPHER =
  /ciphers\s*:\s*['"`][^'"`\n]{0,256}?\b(RC4|DES|3DES|MD5|NULL|EXPORT|aNULL|eNULL)\b[^'"`\n]{0,256}?['"`]/gi;

/* -------------------------------------------------------------------------- */
/* Node.js `crypto` module                                                    */
/* -------------------------------------------------------------------------- */

/** Detects classical asymmetric usage from Node's built-in `crypto` module. */
const nodeCryptoDetector: Detector = {
  id: "node-crypto",
  description: "Classical asymmetric crypto via the Node.js `crypto` module",
  scope: "source",
  language: "js",
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
    eachMatch(RE_GENERATE_KEYPAIR, content, (m) => {
      const type = m[1].toLowerCase();
      const map: Record<
        string,
        {
          algo: Finding["algorithm"];
          cat: Finding["category"];
          sev: Finding["severity"];
          hndl: boolean;
          label: string;
          message?: string;
          remediation?: string;
        }
      > = {
        rsa: { algo: "RSA", cat: "kem", sev: "high", hndl: true, label: "RSA" },
        // EC keys feed BOTH ECDSA (sign) and ECDH (key agreement). ECDH is
        // HNDL-exposed, so classify conservatively as key-exchange-capable and
        // surface both concerns rather than asserting signature-only (P0-4).
        ec: {
          algo: "ECDH",
          cat: "key-exchange",
          sev: "high",
          hndl: true,
          label: "EC (ECDSA/ECDH)",
          message:
            "Generates a classical EC key pair. EC keys feed BOTH ECDSA signatures " +
            "and ECDH key agreement; the ECDH path is harvest-now-decrypt-later exposed.",
          remediation:
            "For key agreement: hybrid X25519MLKEM768 (ML-KEM-768). For signatures: ML-DSA-65 (FIPS 204).",
        },
        dsa: { algo: "DSA", cat: "signature", sev: "high", hndl: false, label: "DSA" },
        dh: { algo: "DH", cat: "key-exchange", sev: "high", hndl: true, label: "Diffie-Hellman" },
        x25519: { algo: "X25519", cat: "key-exchange", sev: "low", hndl: true, label: "X25519" },
        x448: { algo: "X448", cat: "key-exchange", sev: "low", hndl: true, label: "X448" },
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
          cwe: CWE_BROKEN_CRYPTO,
          message:
            info.message ?? `Generates a classical ${info.label} key pair, which is not quantum-safe.`,
          ...(info.remediation ? { remediation: info.remediation } : {}),
        },
        m,
      );
    });

    // createSign / createVerify — RSA / ECDSA / DSA signatures.
    eachMatch(RE_CREATE_SIGN_VERIFY, content, (m) => {
      push(
        {
          ruleId: "node-crypto-sign",
          title: "Classical signature (createSign/createVerify)",
          category: "signature",
          severity: "high",
          confidence: "medium",
          algorithm: "unknown",
          hndl: false,
          cwe: CWE_BROKEN_CRYPTO,
          message:
            "Uses createSign/createVerify, typically RSA, ECDSA or DSA — all forgeable by a quantum attacker.",
          remediation: "ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205)",
        },
        m,
      );
    });

    // One-shot crypto.sign(algorithm, data, key) / crypto.verify(...) (Node ≥ 12).
    eachMatch(RE_ONESHOT_SIGN_VERIFY, content, (m) => {
      push(
        {
          ruleId: "node-crypto-sign-oneshot",
          title: "Classical one-shot signature (crypto.sign/verify)",
          category: "signature",
          severity: "high",
          confidence: "medium",
          algorithm: "unknown",
          hndl: false,
          cwe: CWE_BROKEN_CRYPTO,
          message:
            "Uses the one-shot crypto.sign/crypto.verify API, typically RSA/ECDSA/EdDSA — forgeable by a quantum attacker.",
          remediation: "ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205)",
        },
        m,
      );
    });

    // createDiffieHellman / createDiffieHellmanGroup — finite-field DH key exchange.
    eachMatch(RE_CREATE_DH, content, (m) => {
      push(
        {
          ruleId: "node-crypto-dh",
          title: "Diffie-Hellman key exchange",
          category: "key-exchange",
          severity: "high",
          confidence: "high",
          algorithm: "DH",
          hndl: true,
          cwe: CWE_BROKEN_CRYPTO,
          message: "Finite-field Diffie-Hellman is broken by Shor's algorithm (harvest-now-decrypt-later).",
        },
        m,
      );
    });

    // getDiffieHellman('modpN') — named built-in finite-field MODP groups.
    eachMatch(RE_GET_DH, content, (m) => {
      push(
        {
          ruleId: "node-crypto-dh-modp",
          title: `Diffie-Hellman MODP group (${m[1]})`,
          category: "key-exchange",
          severity: "high",
          confidence: "high",
          algorithm: "DH",
          hndl: true,
          cwe: CWE_BROKEN_CRYPTO,
          message: `Named finite-field DH MODP group "${m[1]}" is broken by Shor's algorithm (harvest-now-decrypt-later).`,
        },
        m,
      );
    });

    // createECDH — elliptic-curve Diffie-Hellman key exchange.
    eachMatch(RE_CREATE_ECDH, content, (m) => {
      push(
        {
          ruleId: "node-crypto-ecdh",
          title: "ECDH key exchange",
          category: "key-exchange",
          severity: "high",
          confidence: "high",
          algorithm: "ECDH",
          hndl: true,
          cwe: CWE_BROKEN_CRYPTO,
          message: "Elliptic-curve Diffie-Hellman is broken by Shor's algorithm (harvest-now-decrypt-later).",
        },
        m,
      );
    });

    // publicEncrypt / privateDecrypt — RSA encryption (KEM-like confidentiality).
    eachMatch(RE_RSA_ENCRYPT, content, (m) => {
      push(
        {
          ruleId: "node-crypto-rsa-encrypt",
          title: "RSA public-key encryption",
          category: "kem",
          severity: "high",
          confidence: "high",
          algorithm: "RSA",
          hndl: true,
          cwe: CWE_BROKEN_CRYPTO,
          message:
            "RSA public-key encryption is broken by Shor's algorithm and exposed to harvest-now-decrypt-later.",
        },
        m,
      );
    });

    // diffieHellman({ privateKey, publicKey }) — KeyObject-based DH/ECDH.
    eachMatch(RE_DH_KEYOBJECT, content, (m) => {
      push(
        {
          ruleId: "node-crypto-dh-keyobject",
          title: "Diffie-Hellman (KeyObject) key exchange",
          category: "key-exchange",
          severity: "high",
          confidence: "high",
          algorithm: "ECDH",
          hndl: true,
          cwe: CWE_BROKEN_CRYPTO,
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
  scope: "source",
  language: "js",
  appliesTo: (f) => hasExtension(f, JS_TS_EXTENSIONS),
  detect({ file, content }): Finding[] {
    const findings: Finding[] = [];

    // Only consider names that appear near a subtle.* call to reduce noise.
    // callIndexes is collected in ascending order (regex scans left→right), so
    // proximity is resolved with a binary search instead of an O(M·C) scan.
    const callIndexes: number[] = [];
    eachMatch(RE_SUBTLE_CALL, content, (m) => callIndexes.push(m.index));
    if (callIndexes.length === 0) return findings;

    eachMatch(RE_WEBCRYPTO_ALGO, content, (m) => {
      if (!nearSortedCall(callIndexes, m.index, 400)) return;
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
          cwe: CWE_BROKEN_CRYPTO,
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
  scope: "source",
  language: "js",
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
    add(RE_FORGE_RSA, {
      ruleId: "forge-rsa-keygen",
      title: "node-forge RSA key generation",
      category: "kem",
      severity: "high",
      confidence: "high",
      algorithm: "RSA",
      hndl: true,
      cwe: CWE_BROKEN_CRYPTO,
      message: "node-forge generates a classical RSA key pair, which is not quantum-safe.",
    });

    // node-forge: forge.ed25519.* (classical EdDSA)
    add(RE_FORGE_ED25519, {
      ruleId: "forge-ed25519",
      title: "node-forge Ed25519 usage",
      category: "signature",
      severity: "low",
      confidence: "high",
      algorithm: "EdDSA",
      hndl: false,
      cwe: CWE_BROKEN_CRYPTO,
      message: "node-forge Ed25519 is a modern but still classical signature scheme.",
    });

    // elliptic: new EC('secp256k1') / new ec(...)
    add(RE_ELLIPTIC_EC, {
      ruleId: "elliptic-ec",
      title: "elliptic curve instantiation",
      category: "signature",
      severity: "high",
      confidence: "high",
      algorithm: "ECDSA",
      hndl: false,
      cwe: CWE_BROKEN_CRYPTO,
      message:
        "The `elliptic` library implements classical ECDSA/ECDH, both broken by Shor's algorithm.",
    });

    // Direct secp256k1 API usage: secp.sign / getPublicKey / getSharedSecret.
    add(RE_SECP256K1, {
      ruleId: "secp256k1-usage",
      title: "secp256k1 ECDSA/ECDH usage",
      category: "signature",
      severity: "high",
      confidence: "medium",
      algorithm: "ECDSA",
      hndl: false,
      cwe: CWE_BROKEN_CRYPTO,
      message:
        "Direct secp256k1 usage (ECDSA signatures / ECDH agreement) is classical and broken by Shor's algorithm.",
      remediation: "ML-DSA-65 (FIPS 204) for signatures; hybrid X25519MLKEM768 for key agreement.",
    });

    // jsrsasign: KEYUTIL.generateKeypair('RSA'|'EC', ...) or KJUR.crypto.*
    add(RE_JSRSASIGN_KEYGEN, {
      ruleId: "jsrsasign-keygen",
      title: "jsrsasign key generation",
      category: "signature",
      severity: "high",
      confidence: "high",
      algorithm: "unknown",
      hndl: false,
      cwe: CWE_BROKEN_CRYPTO,
      message: "jsrsasign generates classical RSA/EC key pairs, which are not quantum-safe.",
      remediation: "ML-KEM-768 (FIPS 203) / ML-DSA-65 (FIPS 204)",
    });
    add(RE_JSRSASIGN_SIGN, {
      ruleId: "jsrsasign-sign",
      title: "jsrsasign signature",
      category: "signature",
      severity: "high",
      confidence: "high",
      algorithm: "unknown",
      hndl: false,
      cwe: CWE_BROKEN_CRYPTO,
      message: "jsrsasign signing uses classical RSA/ECDSA signatures, forgeable by a quantum attacker.",
      remediation: "ML-DSA-65 (FIPS 204)",
    });

    // node-rsa: new NodeRSA(...)
    add(RE_NODE_RSA, {
      ruleId: "node-rsa",
      title: "node-rsa key/usage",
      category: "kem",
      severity: "high",
      confidence: "high",
      algorithm: "RSA",
      hndl: true,
      cwe: CWE_BROKEN_CRYPTO,
      message: "node-rsa wraps classical RSA encryption/signing, which is not quantum-safe.",
    });

    return findings;
  },
};

/* -------------------------------------------------------------------------- */
/* JWT / JOSE / COSE algorithm strings                                         */
/* -------------------------------------------------------------------------- */

/**
 * Detects classical signature algorithm identifiers used by JWT/JOSE, plus
 * ECDH-ES key-agreement identifiers (HNDL-exposed). These appear as string
 * literals: `alg: "RS256"`, `algorithms: ["ES256"]`, `enc: "ECDH-ES+A256KW"`.
 */
const jwtDetector: Detector = {
  id: "jwt-jose",
  description: "Classical JWT/JOSE algorithms (RS/PS/ES/EdDSA) and ECDH-ES key agreement",
  scope: "source",
  language: "js",
  appliesTo: (f) => hasExtension(f, JS_TS_EXTENSIONS),
  detect({ file, content }): Finding[] {
    const findings: Finding[] = [];

    // Classical JWS signature alg tokens. Anchored to quotes to avoid words.
    eachMatch(RE_JWT_ALG, content, (m) => {
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
          cwe: CWE_BROKEN_CRYPTO,
          message: `JWT/JOSE algorithm "${alg}" is a classical signature, forgeable by a quantum attacker.`,
          remediation: "ML-DSA-65 (FIPS 204); track IETF PQC JOSE/COSE algorithms",
          file,
          content,
          index: m.index,
          matchLength: m[0].length,
        }),
      );
    });

    // JOSE ECDH-ES key agreement (and ECDH-ES+A*KW) — confidentiality, HNDL.
    eachMatch(RE_JOSE_ECDH, content, (m) => {
      findings.push(
        makeFinding({
          ruleId: "jose-ecdh-es",
          title: `JOSE key agreement ${m[1]}`,
          category: "key-exchange",
          severity: "high",
          confidence: "medium",
          algorithm: "ECDH",
          hndl: true,
          cwe: CWE_BROKEN_CRYPTO,
          message: `JOSE "${m[1]}" performs classical ECDH key agreement — harvest-now-decrypt-later exposed.`,
          remediation: "Track IETF PQC JOSE/COSE; adopt hybrid X25519MLKEM768 KEM-based encryption.",
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
  scope: "config",
  language: "js",
  appliesTo: (f) => hasExtension(f, JS_TS_EXTENSIONS),
  detect({ file, content }): Finding[] {
    const findings: Finding[] = [];

    // minVersion / maxVersion / secureProtocol pinned to TLS 1.0 or 1.1.
    eachMatch(RE_TLS_LEGACY_VERSION, content, (m) => {
      findings.push(
        makeFinding({
          ruleId: "tls-legacy-version",
          title: "Legacy TLS version pinned",
          category: "tls",
          severity: "medium",
          confidence: "high",
          hndl: false,
          cwe: CWE_WEAK_STRENGTH,
          message: "TLS 1.0/1.1 are deprecated and insecure; require TLS 1.3.",
          remediation: "Set minVersion: 'TLSv1.3' and prefer PQC-hybrid key exchange.",
          file,
          content,
          index: m.index,
          matchLength: m[0].length,
        }),
      );
    });

    // rejectUnauthorized: false — disables certificate verification.
    eachMatch(RE_TLS_REJECT, content, (m) => {
      findings.push(
        makeFinding({
          ruleId: "tls-reject-unauthorized",
          title: "TLS certificate verification disabled",
          category: "tls",
          severity: "high",
          confidence: "high",
          hndl: false,
          cwe: CWE_CERT_VALIDATION,
          message: "rejectUnauthorized:false disables TLS certificate verification (MITM risk).",
          remediation: "Remove rejectUnauthorized:false; verify certificates properly.",
          file,
          content,
          index: m.index,
          matchLength: m[0].length,
        }),
      );
    });

    // Weak / export ciphers referenced in a ciphers string (bounded regex).
    eachMatch(RE_TLS_WEAK_CIPHER, content, (m) => {
      findings.push(
        makeFinding({
          ruleId: "tls-weak-cipher",
          title: "Weak TLS cipher configured",
          category: "tls",
          severity: "medium",
          confidence: "medium",
          hndl: false,
          cwe: CWE_WEAK_STRENGTH,
          message: `Weak cipher (${m[1]}) configured in the TLS ciphers list.`,
          remediation: "Use a modern AEAD cipher suite (TLS 1.3 defaults).",
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
/* SSH public keys + TLS certificate signature algorithms (config scope)       */
/* -------------------------------------------------------------------------- */

const RE_SSH_PUBKEY =
  /\b(ssh-rsa|ssh-ed25519|ssh-dss|ecdsa-sha2-nistp(?:256|384|521))\b/g;
const RE_CERT_SIG_ALG =
  /\b(sha(?:1|256|384|512)WithRSAEncryption|ecdsa-with-SHA(?:1|256|384|512)|rsassaPss|dsaWithSHA(?:1|256))\b/g;

/**
 * Detects classical SSH public keys (`authorized_keys` / `known_hosts` lines)
 * and X.509 certificate signature-algorithm identifiers in any text file. These
 * are language-agnostic config surfaces — the SSH-key forgery surface and the
 * PKI signature surface that lexical PEM detection misses.
 */
const sshCertDetector: Detector = {
  id: "ssh-cert",
  description: "SSH public keys and TLS/X.509 certificate signature algorithms in config",
  scope: "config",
  language: "any",
  appliesTo: () => true,
  detect({ file, content }): Finding[] {
    const findings: Finding[] = [];

    // SSH public keys: ssh-rsa AAAA…, ecdsa-sha2-nistp256 …, ssh-ed25519 …
    eachMatch(RE_SSH_PUBKEY, content, (m) => {
      const tok = m[1];
      const algorithm: Finding["algorithm"] = tok.startsWith("ssh-rsa")
        ? "RSA"
        : tok === "ssh-ed25519"
          ? "EdDSA"
          : tok === "ssh-dss"
            ? "DSA"
            : "ECDSA";
      findings.push(
        makeFinding({
          ruleId: "ssh-public-key",
          title: `Classical SSH public key (${tok})`,
          category: "certificate",
          severity: "low",
          confidence: "medium",
          algorithm,
          hndl: false,
          cwe: CWE_BROKEN_CRYPTO,
          message: `SSH public key type "${tok}" is a classical key forgeable by a quantum attacker.`,
          remediation: "Plan migration to PQC-capable SSH (e.g. sntrup761x25519 KEX, PQC host keys).",
          file,
          content,
          index: m.index,
          matchLength: m[0].length,
        }),
      );
    });

    // X.509 / TLS certificate signature algorithm identifiers (forgery surface).
    eachMatch(RE_CERT_SIG_ALG, content, (m) => {
      const tok = m[1];
      const algorithm: Finding["algorithm"] = /RSA|rsassa/i.test(tok)
        ? "RSA"
        : tok.startsWith("ecdsa")
          ? "ECDSA"
          : "DSA";
      findings.push(
        makeFinding({
          ruleId: "cert-signature-algorithm",
          title: `Classical certificate signature algorithm (${tok})`,
          category: "certificate",
          severity: "low",
          confidence: "medium",
          algorithm,
          hndl: false,
          cwe: CWE_BROKEN_CRYPTO,
          message: `Certificate signature algorithm "${tok}" is classical (RSA/ECDSA/DSA) — a quantum forgery surface.`,
          remediation: "Plan re-issuance with PQC-capable CAs as ML-DSA certificate profiles mature.",
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

/** All built-in source/config detectors, in run order. */
export const sourceDetectors: Detector[] = [
  nodeCryptoDetector,
  webCryptoDetector,
  libraryDetector,
  jwtDetector,
  tlsDetector,
  sshCertDetector,
];
