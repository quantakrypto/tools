import { createRequire as __cr } from 'module'; const require = __cr(import.meta.url);

// src/main.ts
import { mkdir, readFile as readFile3, writeFile as writeFile2 } from "node:fs/promises";
import { dirname as dirname3, isAbsolute, join as join4, resolve } from "node:path";
import { pathToFileURL } from "node:url";

// ../core/dist/version.js
var VERSION = "0.1.0";

// ../core/dist/scan.js
import { readFile, stat as stat2 } from "node:fs/promises";
import * as path2 from "node:path";

// ../core/dist/walk.js
import { readdir, stat } from "node:fs/promises";
import * as path from "node:path";
var DEFAULT_IGNORES = [
  "node_modules",
  ".git",
  "dist",
  "build",
  ".next",
  "out",
  "coverage",
  "vendor",
  ".turbo",
  ".cache"
];
var DEFAULT_MAX_FILE_SIZE = 2 * 1024 * 1024;
var BINARY_EXTENSIONS = /* @__PURE__ */ new Set([
  // images
  ".png",
  ".jpg",
  ".jpeg",
  ".gif",
  ".webp",
  ".bmp",
  ".ico",
  ".tiff",
  ".avif",
  // fonts
  ".woff",
  ".woff2",
  ".ttf",
  ".otf",
  ".eot",
  // archives / compressed
  ".zip",
  ".gz",
  ".tgz",
  ".bz2",
  ".xz",
  ".7z",
  ".rar",
  ".tar",
  // media
  ".mp3",
  ".mp4",
  ".mov",
  ".avi",
  ".mkv",
  ".wav",
  ".flac",
  ".ogg",
  ".webm",
  // documents / binaries
  ".pdf",
  ".doc",
  ".docx",
  ".xls",
  ".xlsx",
  ".ppt",
  ".pptx",
  ".exe",
  ".dll",
  ".so",
  ".dylib",
  ".bin",
  ".o",
  ".a",
  ".class",
  ".wasm",
  // data blobs / db
  ".db",
  ".sqlite",
  ".sqlite3",
  ".dat",
  ".pack",
  ".idx",
  // misc
  ".lock",
  ".map",
  ".min.js",
  ".node"
]);
function toPosix(p) {
  return p.split(path.sep).join("/");
}
function matchesAny(rel, patterns) {
  for (const pattern of patterns) {
    if (!pattern)
      continue;
    const p = toPosix(pattern).replace(/\/+$/, "");
    if (rel.includes(p))
      return true;
    if (rel === p || rel.startsWith(`${p}/`))
      return true;
  }
  return false;
}
function isExcluded(rel, exclude) {
  return matchesAny(rel, exclude);
}
function isIncluded(rel, include) {
  if (include.length === 0)
    return true;
  return matchesAny(rel, include);
}
function isBinaryPath(rel) {
  const lower = rel.toLowerCase();
  if (lower.endsWith(".min.js"))
    return true;
  const ext = path.posix.extname(lower);
  return BINARY_EXTENSIONS.has(ext);
}
var GENERATED_PATH_RE = /(?:\.min\.[mc]?js|[.-]min\.[mc]?js|\.bundle\.[mc]?js|\.chunk\.[mc]?js|\.generated\.[jt]sx?|_pb\.js|\.pb\.go)$/i;
function isGeneratedPath(rel) {
  return GENERATED_PATH_RE.test(rel.toLowerCase());
}
function looksMinified(content) {
  const sample = content.length > 65536 ? content.slice(0, 65536) : content;
  if (sample.length === 0)
    return false;
  let maxLine = 0;
  let cur = 0;
  let lines = 1;
  for (let i = 0; i < sample.length; i++) {
    if (sample.charCodeAt(i) === 10) {
      if (cur > maxLine)
        maxLine = cur;
      cur = 0;
      lines++;
    } else {
      cur++;
    }
  }
  if (cur > maxLine)
    maxLine = cur;
  if (maxLine > 5e4)
    return true;
  const avgLine = sample.length / lines;
  return avgLine > 1e3;
}
async function* walkFiles(root, options = {}) {
  const include = options.include ?? [];
  const exclude = options.exclude ?? [];
  const maxFileSize = options.maxFileSize ?? DEFAULT_MAX_FILE_SIZE;
  const ignores = options.noDefaultIgnores ? [] : DEFAULT_IGNORES;
  const rootStat = await stat(root);
  if (rootStat.isFile()) {
    const name = toPosix(path.basename(root));
    if (!isBinaryPath(name) && isIncluded(name, include) && passesSizeLimit(name, rootStat.size, maxFileSize)) {
      yield name;
    }
    return;
  }
  yield* walkDir(root, "", { include, exclude, maxFileSize, ignores });
}
function passesSizeLimit(rel, size, maxFileSize) {
  if (isManifestPath(rel))
    return true;
  return size <= maxFileSize;
}
function isManifestPath(rel) {
  const base = rel.split("/").pop() ?? rel;
  return base === "package.json" || base === "package-lock.json";
}
async function* walkDir(absDir, relDir, ctx) {
  let entries;
  try {
    entries = await readdir(absDir, { withFileTypes: true });
  } catch {
    return;
  }
  entries.sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
  for (const entry of entries) {
    const rel = relDir ? `${relDir}/${entry.name}` : entry.name;
    const abs = path.join(absDir, entry.name);
    if (entry.isSymbolicLink()) {
      continue;
    }
    if (entry.isDirectory()) {
      if (ctx.ignores.includes(entry.name))
        continue;
      if (isExcluded(rel, ctx.exclude))
        continue;
      yield* walkDir(abs, rel, ctx);
      continue;
    }
    if (!entry.isFile())
      continue;
    if (isExcluded(rel, ctx.exclude))
      continue;
    if (!isIncluded(rel, ctx.include))
      continue;
    if (isBinaryPath(rel))
      continue;
    if (isGeneratedPath(rel))
      continue;
    try {
      const s = await stat(abs);
      if (!passesSizeLimit(rel, s.size, ctx.maxFileSize))
        continue;
    } catch {
      continue;
    }
    yield rel;
  }
}

// ../core/dist/remediation.js
var REMEDIATIONS = {
  RSA: {
    algorithm: "RSA",
    recommendation: "ML-KEM-768 for encryption/KEM; ML-DSA-65 for signatures",
    detail: "RSA is broken by Shor's algorithm. For key transport / encryption move to ML-KEM-768 (FIPS 203), ideally as the hybrid X25519MLKEM768. For digital signatures move to ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205)."
  },
  ECDH: {
    algorithm: "ECDH",
    recommendation: "hybrid X25519MLKEM768 (ML-KEM-768)",
    detail: "Elliptic-curve Diffie-Hellman is broken by Shor's algorithm and is exposed to harvest-now-decrypt-later. Adopt the hybrid X25519MLKEM768 key exchange so confidentiality survives even if one component is broken."
  },
  ECDSA: {
    algorithm: "ECDSA",
    recommendation: "ML-DSA-65 (FIPS 204)",
    detail: "ECDSA signatures can be forged by a quantum attacker via Shor's algorithm. Migrate to ML-DSA (Dilithium, FIPS 204) or SLH-DSA (SPHINCS+, FIPS 205) for long-lived signatures."
  },
  EdDSA: {
    algorithm: "EdDSA",
    recommendation: "ML-DSA-65 (FIPS 204)",
    detail: "Ed25519 / Ed448 (EdDSA) are classical signatures broken by Shor's algorithm. Replace with ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205) for forgery resistance."
  },
  DH: {
    algorithm: "DH",
    recommendation: "hybrid X25519MLKEM768 (ML-KEM-768)",
    detail: "Finite-field Diffie-Hellman is broken by Shor's algorithm and exposed to harvest-now-decrypt-later. Move to a hybrid PQC KEM such as X25519MLKEM768."
  },
  DSA: {
    algorithm: "DSA",
    recommendation: "ML-DSA-65 (FIPS 204)",
    detail: "DSA is a classical, quantum-broken signature scheme (and already deprecated). Replace with ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205)."
  },
  X25519: {
    algorithm: "X25519",
    recommendation: "hybrid X25519MLKEM768 (ML-KEM-768)",
    detail: "X25519 is a modern, well-built classical key-agreement primitive but is still broken by Shor's algorithm. Wrap it in the hybrid X25519MLKEM768 construction so it stays useful during the PQC transition."
  },
  X448: {
    algorithm: "X448",
    recommendation: "hybrid X25519MLKEM768 (ML-KEM-768)",
    detail: "X448 (Goldilocks curve) is a modern classical key-agreement primitive at a higher classical security level, but it is still broken by Shor's algorithm. Adopt a hybrid PQC KEM (X25519MLKEM768 / ML-KEM-768) during the transition."
  },
  ECIES: {
    algorithm: "ECIES",
    recommendation: "ML-KEM-768 hybrid encryption",
    detail: "ECIES relies on classical ECDH for its key encapsulation and is exposed to harvest-now-decrypt-later. Replace the KEM step with ML-KEM-768 (FIPS 203), preferably in a hybrid construction."
  },
  unknown: {
    algorithm: "unknown",
    recommendation: "review for post-quantum migration",
    detail: "This usage involves classical public-key cryptography. Audit it and plan a migration to NIST PQC standards (ML-KEM / FIPS 203, ML-DSA / FIPS 204)."
  }
};
function remediationText(algorithm) {
  return REMEDIATIONS[algorithm].recommendation;
}

// ../core/dist/detect-utils.js
function offsetToLineCol(content, offset) {
  let line = 1;
  let lastNewline = -1;
  for (let i = 0; i < offset && i < content.length; i++) {
    if (content.charCodeAt(i) === 10) {
      line++;
      lastNewline = i;
    }
  }
  return { line, column: offset - lastNewline };
}
function lineAt(content, offset) {
  let start = offset;
  while (start > 0 && content.charCodeAt(start - 1) !== 10)
    start--;
  let end = offset;
  while (end < content.length && content.charCodeAt(end) !== 10)
    end++;
  return content.slice(start, end).replace(/\r$/, "").trim();
}
function makeFinding(spec) {
  const { line, column } = offsetToLineCol(spec.content, spec.index);
  const snippet = lineAt(spec.content, spec.index);
  const remediation = spec.remediation ?? (spec.algorithm ? remediationText(spec.algorithm) : void 0);
  const location = {
    file: spec.file,
    line,
    column,
    snippet: snippet.length > 200 ? `${snippet.slice(0, 197)}...` : snippet
  };
  if (spec.matchLength && spec.matchLength > 0) {
    const matched = spec.content.slice(spec.index, spec.index + spec.matchLength);
    const extraLines = (matched.match(/\n/g) ?? []).length;
    if (extraLines > 0)
      location.endLine = line + extraLines;
  }
  const finding = {
    ruleId: spec.ruleId,
    title: spec.title,
    category: spec.category,
    severity: spec.severity,
    confidence: spec.confidence,
    hndl: spec.hndl,
    message: spec.message,
    location
  };
  if (spec.algorithm)
    finding.algorithm = spec.algorithm;
  if (remediation)
    finding.remediation = remediation;
  if (spec.cwe)
    finding.cwe = spec.cwe;
  return finding;
}
function hasExtension(filePath, exts) {
  const lower = filePath.toLowerCase();
  return exts.some((e) => lower.endsWith(e));
}
var JS_TS_EXTENSIONS = [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"];
function nearSortedCall(sortedCalls, idx, window) {
  let lo = 0;
  let hi = sortedCalls.length - 1;
  let best = -1;
  while (lo <= hi) {
    const mid = lo + hi >>> 1;
    if (sortedCalls[mid] <= idx) {
      best = mid;
      lo = mid + 1;
    } else {
      hi = mid - 1;
    }
  }
  if (best < 0)
    return false;
  return idx - sortedCalls[best] < window;
}
function eachMatch(re, content, onMatch) {
  const g = re.global ? re : new RegExp(re.source, `${re.flags}g`);
  g.lastIndex = 0;
  let m;
  while ((m = g.exec(content)) !== null) {
    onMatch(m);
    if (m.index === g.lastIndex)
      g.lastIndex++;
  }
}

// ../core/dist/cwe.js
var CWE_BROKEN_CRYPTO = "CWE-327";
var CWE_WEAK_STRENGTH = "CWE-326";
var CWE_CERT_VALIDATION = "CWE-295";
var CWE_HARDCODED_KEY = "CWE-798";

// ../core/dist/detectors/source.js
var RE_GENERATE_KEYPAIR = /generateKeyPair(?:Sync)?\s*\(\s*['"`](rsa|ec|dsa|dh|x25519|x448|ed25519|ed448)['"`]/g;
var RE_CREATE_SIGN_VERIFY = /create(?:Sign|Verify)\s*\(/g;
var RE_ONESHOT_SIGN_VERIFY = /(?:^|[^.\w])(?:crypto\.)?(sign|verify)\s*\(\s*['"`][\w.-]+['"`]\s*,/g;
var RE_CREATE_DH = /createDiffieHellman(?:Group)?\s*\(/g;
var RE_GET_DH = /getDiffieHellman\s*\(\s*['"`](modp\d+)['"`]\s*\)/g;
var RE_CREATE_ECDH = /createECDH\s*\(/g;
var RE_RSA_ENCRYPT = /(?:crypto\.)?(?:publicEncrypt|privateDecrypt)\s*\(/g;
var RE_DH_KEYOBJECT = /(?:crypto\.)?diffieHellman\s*\(\s*\{/g;
var RE_WEBCRYPTO_ALGO = /\b(RSA-OAEP|RSA-PSS|RSASSA-PKCS1-v1_5|ECDH|ECDSA)\b/gi;
var RE_SUBTLE_CALL = /subtle\s*\.\s*(generateKey|importKey|exportKey|deriveKey|deriveBits|sign|verify|encrypt|decrypt|wrapKey|unwrapKey)\s*\(/g;
var RE_FORGE_RSA = /pki\.rsa\.generateKeyPair\s*\(/g;
var RE_FORGE_ED25519 = /forge\.ed25519\b/g;
var RE_ELLIPTIC_EC = /new\s+(?:elliptic\.)?ec\s*\(/gi;
var RE_JSRSASIGN_KEYGEN = /KEYUTIL\.generateKeypair\s*\(/g;
var RE_JSRSASIGN_SIGN = /KJUR\.crypto\.(?:Signature|ECDSA)\b/g;
var RE_NODE_RSA = /new\s+NodeRSA\s*\(/g;
var RE_SECP256K1 = /\b(?:secp(?:256k1)?|secp)\s*\.\s*(?:sign|verify|getPublicKey|getSharedSecret|ecdh|recoverPublicKey)\s*\(/g;
var RE_JWT_ALG = /['"`](RS(?:256|384|512)|PS(?:256|384|512)|ES(?:256|384|512|256K)|EdDSA)['"`]/g;
var RE_JOSE_ECDH = /['"`](ECDH-ES(?:\+A(?:128|192|256)KW)?)['"`]/g;
var RE_TLS_LEGACY_VERSION = /(?:minVersion|maxVersion)\s*:\s*['"`]TLSv1(?:\.1)?['"`]|secureProtocol\s*:\s*['"`]TLSv1(?:_1)?_method['"`]/g;
var RE_TLS_REJECT = /rejectUnauthorized\s*:\s*false/g;
var RE_TLS_WEAK_CIPHER = /ciphers\s*:\s*['"`][^'"`\n]{0,256}?\b(RC4|DES|3DES|MD5|NULL|EXPORT|aNULL|eNULL)\b[^'"`\n]{0,256}?['"`]/gi;
var nodeCryptoDetector = {
  id: "node-crypto",
  description: "Classical asymmetric crypto via the Node.js `crypto` module",
  scope: "source",
  language: "js",
  appliesTo: (f) => hasExtension(f, JS_TS_EXTENSIONS),
  detect({ file, content }) {
    const findings = [];
    const push = (spec, m) => findings.push(makeFinding({ ...spec, file, content, index: m.index, matchLength: m[0].length }));
    eachMatch(RE_GENERATE_KEYPAIR, content, (m) => {
      const type = m[1].toLowerCase();
      const map = {
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
          message: "Generates a classical EC key pair. EC keys feed BOTH ECDSA signatures and ECDH key agreement; the ECDH path is harvest-now-decrypt-later exposed.",
          remediation: "For key agreement: hybrid X25519MLKEM768 (ML-KEM-768). For signatures: ML-DSA-65 (FIPS 204)."
        },
        dsa: { algo: "DSA", cat: "signature", sev: "high", hndl: false, label: "DSA" },
        dh: { algo: "DH", cat: "key-exchange", sev: "high", hndl: true, label: "Diffie-Hellman" },
        x25519: { algo: "X25519", cat: "key-exchange", sev: "low", hndl: true, label: "X25519" },
        x448: { algo: "X448", cat: "key-exchange", sev: "low", hndl: true, label: "X448" },
        ed25519: { algo: "EdDSA", cat: "signature", sev: "low", hndl: false, label: "Ed25519" },
        ed448: { algo: "EdDSA", cat: "signature", sev: "low", hndl: false, label: "Ed448" }
      };
      const info2 = map[type];
      push({
        ruleId: "node-crypto-keygen",
        title: `${info2.label} key generation`,
        category: info2.cat,
        severity: info2.sev,
        confidence: "high",
        algorithm: info2.algo,
        hndl: info2.hndl,
        cwe: CWE_BROKEN_CRYPTO,
        message: info2.message ?? `Generates a classical ${info2.label} key pair, which is not quantum-safe.`,
        ...info2.remediation ? { remediation: info2.remediation } : {}
      }, m);
    });
    eachMatch(RE_CREATE_SIGN_VERIFY, content, (m) => {
      push({
        ruleId: "node-crypto-sign",
        title: "Classical signature (createSign/createVerify)",
        category: "signature",
        severity: "high",
        confidence: "medium",
        algorithm: "unknown",
        hndl: false,
        cwe: CWE_BROKEN_CRYPTO,
        message: "Uses createSign/createVerify, typically RSA, ECDSA or DSA \u2014 all forgeable by a quantum attacker.",
        remediation: "ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205)"
      }, m);
    });
    eachMatch(RE_ONESHOT_SIGN_VERIFY, content, (m) => {
      push({
        ruleId: "node-crypto-sign-oneshot",
        title: "Classical one-shot signature (crypto.sign/verify)",
        category: "signature",
        severity: "high",
        confidence: "medium",
        algorithm: "unknown",
        hndl: false,
        cwe: CWE_BROKEN_CRYPTO,
        message: "Uses the one-shot crypto.sign/crypto.verify API, typically RSA/ECDSA/EdDSA \u2014 forgeable by a quantum attacker.",
        remediation: "ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205)"
      }, m);
    });
    eachMatch(RE_CREATE_DH, content, (m) => {
      push({
        ruleId: "node-crypto-dh",
        title: "Diffie-Hellman key exchange",
        category: "key-exchange",
        severity: "high",
        confidence: "high",
        algorithm: "DH",
        hndl: true,
        cwe: CWE_BROKEN_CRYPTO,
        message: "Finite-field Diffie-Hellman is broken by Shor's algorithm (harvest-now-decrypt-later)."
      }, m);
    });
    eachMatch(RE_GET_DH, content, (m) => {
      push({
        ruleId: "node-crypto-dh-modp",
        title: `Diffie-Hellman MODP group (${m[1]})`,
        category: "key-exchange",
        severity: "high",
        confidence: "high",
        algorithm: "DH",
        hndl: true,
        cwe: CWE_BROKEN_CRYPTO,
        message: `Named finite-field DH MODP group "${m[1]}" is broken by Shor's algorithm (harvest-now-decrypt-later).`
      }, m);
    });
    eachMatch(RE_CREATE_ECDH, content, (m) => {
      push({
        ruleId: "node-crypto-ecdh",
        title: "ECDH key exchange",
        category: "key-exchange",
        severity: "high",
        confidence: "high",
        algorithm: "ECDH",
        hndl: true,
        cwe: CWE_BROKEN_CRYPTO,
        message: "Elliptic-curve Diffie-Hellman is broken by Shor's algorithm (harvest-now-decrypt-later)."
      }, m);
    });
    eachMatch(RE_RSA_ENCRYPT, content, (m) => {
      push({
        ruleId: "node-crypto-rsa-encrypt",
        title: "RSA public-key encryption",
        category: "kem",
        severity: "high",
        confidence: "high",
        algorithm: "RSA",
        hndl: true,
        cwe: CWE_BROKEN_CRYPTO,
        message: "RSA public-key encryption is broken by Shor's algorithm and exposed to harvest-now-decrypt-later."
      }, m);
    });
    eachMatch(RE_DH_KEYOBJECT, content, (m) => {
      push({
        ruleId: "node-crypto-dh-keyobject",
        title: "Diffie-Hellman (KeyObject) key exchange",
        category: "key-exchange",
        severity: "high",
        confidence: "high",
        algorithm: "ECDH",
        hndl: true,
        cwe: CWE_BROKEN_CRYPTO,
        message: "crypto.diffieHellman() performs a classical (EC)DH agreement (harvest-now-decrypt-later)."
      }, m);
    });
    return findings;
  }
};
var webCryptoDetector = {
  id: "webcrypto",
  description: "Classical asymmetric algorithms via WebCrypto SubtleCrypto",
  scope: "source",
  language: "js",
  appliesTo: (f) => hasExtension(f, JS_TS_EXTENSIONS),
  detect({ file, content }) {
    const findings = [];
    const callIndexes = [];
    eachMatch(RE_SUBTLE_CALL, content, (m) => callIndexes.push(m.index));
    if (callIndexes.length === 0)
      return findings;
    eachMatch(RE_WEBCRYPTO_ALGO, content, (m) => {
      if (!nearSortedCall(callIndexes, m.index, 400))
        return;
      const name = m[1].toUpperCase();
      const isKem = name === "RSA-OAEP";
      const isEcdh = name === "ECDH";
      const algorithm = name.startsWith("RSA") ? "RSA" : isEcdh ? "ECDH" : "ECDSA";
      const category = isEcdh ? "key-exchange" : isKem ? "kem" : "signature";
      const hndl = isKem || isEcdh;
      findings.push(makeFinding({
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
        matchLength: m[0].length
      }));
    });
    return findings;
  }
};
var libraryDetector = {
  id: "crypto-libs",
  description: "Classical asymmetric crypto via node-forge, elliptic, jsrsasign, node-rsa",
  scope: "source",
  language: "js",
  appliesTo: (f) => hasExtension(f, JS_TS_EXTENSIONS),
  detect({ file, content }) {
    const findings = [];
    const add = (re, spec) => eachMatch(re, content, (m) => findings.push(makeFinding({ ...spec, file, content, index: m.index, matchLength: m[0].length })));
    add(RE_FORGE_RSA, {
      ruleId: "forge-rsa-keygen",
      title: "node-forge RSA key generation",
      category: "kem",
      severity: "high",
      confidence: "high",
      algorithm: "RSA",
      hndl: true,
      cwe: CWE_BROKEN_CRYPTO,
      message: "node-forge generates a classical RSA key pair, which is not quantum-safe."
    });
    add(RE_FORGE_ED25519, {
      ruleId: "forge-ed25519",
      title: "node-forge Ed25519 usage",
      category: "signature",
      severity: "low",
      confidence: "high",
      algorithm: "EdDSA",
      hndl: false,
      cwe: CWE_BROKEN_CRYPTO,
      message: "node-forge Ed25519 is a modern but still classical signature scheme."
    });
    add(RE_ELLIPTIC_EC, {
      ruleId: "elliptic-ec",
      title: "elliptic curve instantiation",
      category: "signature",
      severity: "high",
      confidence: "high",
      algorithm: "ECDSA",
      hndl: false,
      cwe: CWE_BROKEN_CRYPTO,
      message: "The `elliptic` library implements classical ECDSA/ECDH, both broken by Shor's algorithm."
    });
    add(RE_SECP256K1, {
      ruleId: "secp256k1-usage",
      title: "secp256k1 ECDSA/ECDH usage",
      category: "signature",
      severity: "high",
      confidence: "medium",
      algorithm: "ECDSA",
      hndl: false,
      cwe: CWE_BROKEN_CRYPTO,
      message: "Direct secp256k1 usage (ECDSA signatures / ECDH agreement) is classical and broken by Shor's algorithm.",
      remediation: "ML-DSA-65 (FIPS 204) for signatures; hybrid X25519MLKEM768 for key agreement."
    });
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
      remediation: "ML-KEM-768 (FIPS 203) / ML-DSA-65 (FIPS 204)"
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
      remediation: "ML-DSA-65 (FIPS 204)"
    });
    add(RE_NODE_RSA, {
      ruleId: "node-rsa",
      title: "node-rsa key/usage",
      category: "kem",
      severity: "high",
      confidence: "high",
      algorithm: "RSA",
      hndl: true,
      cwe: CWE_BROKEN_CRYPTO,
      message: "node-rsa wraps classical RSA encryption/signing, which is not quantum-safe."
    });
    return findings;
  }
};
var jwtDetector = {
  id: "jwt-jose",
  description: "Classical JWT/JOSE algorithms (RS/PS/ES/EdDSA) and ECDH-ES key agreement",
  scope: "source",
  language: "js",
  appliesTo: (f) => hasExtension(f, JS_TS_EXTENSIONS),
  detect({ file, content }) {
    const findings = [];
    eachMatch(RE_JWT_ALG, content, (m) => {
      const alg = m[1];
      let algorithm;
      if (alg.startsWith("RS") || alg.startsWith("PS"))
        algorithm = "RSA";
      else if (alg === "EdDSA")
        algorithm = "EdDSA";
      else
        algorithm = "ECDSA";
      findings.push(makeFinding({
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
        matchLength: m[0].length
      }));
    });
    eachMatch(RE_JOSE_ECDH, content, (m) => {
      findings.push(makeFinding({
        ruleId: "jose-ecdh-es",
        title: `JOSE key agreement ${m[1]}`,
        category: "key-exchange",
        severity: "high",
        confidence: "medium",
        algorithm: "ECDH",
        hndl: true,
        cwe: CWE_BROKEN_CRYPTO,
        message: `JOSE "${m[1]}" performs classical ECDH key agreement \u2014 harvest-now-decrypt-later exposed.`,
        remediation: "Track IETF PQC JOSE/COSE; adopt hybrid X25519MLKEM768 KEM-based encryption.",
        file,
        content,
        index: m.index,
        matchLength: m[0].length
      }));
    });
    return findings;
  }
};
var tlsDetector = {
  id: "tls-config",
  description: "Legacy / insecure TLS configuration in JS objects",
  scope: "config",
  language: "js",
  appliesTo: (f) => hasExtension(f, JS_TS_EXTENSIONS),
  detect({ file, content }) {
    const findings = [];
    eachMatch(RE_TLS_LEGACY_VERSION, content, (m) => {
      findings.push(makeFinding({
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
        matchLength: m[0].length
      }));
    });
    eachMatch(RE_TLS_REJECT, content, (m) => {
      findings.push(makeFinding({
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
        matchLength: m[0].length
      }));
    });
    eachMatch(RE_TLS_WEAK_CIPHER, content, (m) => {
      findings.push(makeFinding({
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
        matchLength: m[0].length
      }));
    });
    return findings;
  }
};
var RE_SSH_PUBKEY = /\b(ssh-rsa|ssh-ed25519|ssh-dss|ecdsa-sha2-nistp(?:256|384|521))\b/g;
var RE_CERT_SIG_ALG = /\b(sha(?:1|256|384|512)WithRSAEncryption|ecdsa-with-SHA(?:1|256|384|512)|rsassaPss|dsaWithSHA(?:1|256))\b/g;
var sshCertDetector = {
  id: "ssh-cert",
  description: "SSH public keys and TLS/X.509 certificate signature algorithms in config",
  scope: "config",
  language: "any",
  appliesTo: () => true,
  detect({ file, content }) {
    const findings = [];
    eachMatch(RE_SSH_PUBKEY, content, (m) => {
      const tok = m[1];
      const algorithm = tok.startsWith("ssh-rsa") ? "RSA" : tok === "ssh-ed25519" ? "EdDSA" : tok === "ssh-dss" ? "DSA" : "ECDSA";
      findings.push(makeFinding({
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
        matchLength: m[0].length
      }));
    });
    eachMatch(RE_CERT_SIG_ALG, content, (m) => {
      const tok = m[1];
      const algorithm = /RSA|rsassa/i.test(tok) ? "RSA" : tok.startsWith("ecdsa") ? "ECDSA" : "DSA";
      findings.push(makeFinding({
        ruleId: "cert-signature-algorithm",
        title: `Classical certificate signature algorithm (${tok})`,
        category: "certificate",
        severity: "low",
        confidence: "medium",
        algorithm,
        hndl: false,
        cwe: CWE_BROKEN_CRYPTO,
        message: `Certificate signature algorithm "${tok}" is classical (RSA/ECDSA/DSA) \u2014 a quantum forgery surface.`,
        remediation: "Plan re-issuance with PQC-capable CAs as ML-DSA certificate profiles mature.",
        file,
        content,
        index: m.index,
        matchLength: m[0].length
      }));
    });
    return findings;
  }
};
var sourceDetectors = [
  nodeCryptoDetector,
  webCryptoDetector,
  libraryDetector,
  jwtDetector,
  tlsDetector,
  sshCertDetector
];

// ../core/dist/detectors/pem.js
var PEM_RULES = [
  {
    re: /-----BEGIN RSA PRIVATE KEY-----/g,
    ruleId: "pem-rsa-private-key",
    title: "RSA private key (PEM)",
    category: "certificate",
    severity: "critical",
    algorithm: "RSA",
    hndl: true,
    cwe: CWE_HARDCODED_KEY,
    message: "Embedded RSA private key (PKCS#1 PEM); classical and not quantum-safe.",
    remediation: "Migrate to ML-DSA / ML-KEM keys and remove embedded private keys from source."
  },
  {
    re: /-----BEGIN EC PRIVATE KEY-----/g,
    ruleId: "pem-ec-private-key",
    title: "EC private key (PEM)",
    category: "certificate",
    severity: "critical",
    algorithm: "ECDSA",
    hndl: true,
    cwe: CWE_HARDCODED_KEY,
    message: "Embedded EC private key (SEC1 PEM); classical ECDSA/ECDH key, not quantum-safe.",
    remediation: "Migrate to ML-DSA (FIPS 204) keys and remove embedded private keys from source."
  },
  {
    re: /-----BEGIN DSA PRIVATE KEY-----/g,
    ruleId: "pem-dsa-private-key",
    title: "DSA private key (PEM)",
    category: "certificate",
    severity: "critical",
    algorithm: "DSA",
    hndl: false,
    cwe: CWE_HARDCODED_KEY,
    message: "Embedded DSA private key (PEM); classical, already deprecated, and not quantum-safe.",
    remediation: "Rotate immediately (DSA is deprecated) and migrate to ML-DSA-65 (FIPS 204)."
  },
  {
    re: /-----BEGIN OPENSSH PRIVATE KEY-----/g,
    ruleId: "pem-openssh-private-key",
    title: "OpenSSH private key",
    category: "certificate",
    severity: "critical",
    algorithm: "unknown",
    hndl: true,
    cwe: CWE_HARDCODED_KEY,
    message: "Embedded OpenSSH private key (RSA/ECDSA/Ed25519); classical and not quantum-safe.",
    remediation: "Rotate the key; plan migration to PQC-capable SSH (e.g. sntrup761x25519)."
  },
  {
    re: /-----BEGIN PGP PRIVATE KEY BLOCK-----/g,
    ruleId: "pem-pgp-private-key",
    title: "PGP/GPG private key block",
    category: "certificate",
    severity: "critical",
    algorithm: "unknown",
    hndl: true,
    cwe: CWE_HARDCODED_KEY,
    message: "Embedded PGP/GPG private key block (RSA/ECDSA/EdDSA/ElGamal); classical and not quantum-safe.",
    remediation: "Rotate the key; track OpenPGP PQC drafts for migration."
  },
  {
    re: /-----BEGIN PGP MESSAGE-----/g,
    ruleId: "pem-pgp-message",
    title: "PGP/GPG encrypted message",
    category: "certificate",
    severity: "low",
    algorithm: "unknown",
    hndl: true,
    cwe: CWE_BROKEN_CRYPTO,
    message: "Embedded PGP/GPG message; likely encrypted with classical RSA/ElGamal (harvest-now-decrypt-later).",
    remediation: "Re-encrypt with PQC-capable tooling as OpenPGP PQC profiles mature."
  },
  {
    re: /-----BEGIN (?:ENCRYPTED )?PRIVATE KEY-----/g,
    ruleId: "pem-pkcs8-private-key",
    title: "Private key (PKCS#8 PEM)",
    category: "certificate",
    severity: "critical",
    algorithm: "unknown",
    hndl: true,
    cwe: CWE_HARDCODED_KEY,
    message: "Embedded PKCS#8 private key; likely classical RSA/EC, not quantum-safe.",
    remediation: "Migrate to PQC keys and remove embedded private keys from source."
  },
  {
    re: /-----BEGIN CERTIFICATE-----/g,
    ruleId: "pem-certificate",
    title: "X.509 certificate (PEM)",
    category: "certificate",
    severity: "low",
    algorithm: "unknown",
    hndl: false,
    cwe: CWE_BROKEN_CRYPTO,
    message: "Embedded X.509 certificate; almost certainly signed with classical RSA/ECDSA.",
    remediation: "Plan re-issuance with PQC-capable CAs as ML-DSA certificate profiles mature."
  }
];
var pemDetector = {
  id: "pem-material",
  description: "PEM-encoded private keys and X.509 certificates in any file",
  scope: "config",
  language: "any",
  // Applies to every text file; the walker already filters out binaries.
  appliesTo: () => true,
  detect({ file, content }) {
    if (!content.includes("-----BEGIN "))
      return [];
    const findings = [];
    for (const rule of PEM_RULES) {
      eachMatch(rule.re, content, (m) => {
        findings.push(makeFinding({
          ruleId: rule.ruleId,
          title: rule.title,
          category: rule.category,
          severity: rule.severity,
          confidence: "high",
          algorithm: rule.algorithm,
          hndl: rule.hndl,
          cwe: rule.cwe,
          message: rule.message,
          remediation: rule.remediation,
          file,
          content,
          index: m.index,
          matchLength: m[0].length
        }));
      });
    }
    return findings;
  }
};

// ../core/dist/registry.js
function detectorScope(d) {
  return d.scope ?? "source";
}
var DetectorRegistry = class _DetectorRegistry {
  byId = /* @__PURE__ */ new Map();
  order = [];
  /** Construct a registry, optionally seeded with an initial detector set. */
  constructor(initial = []) {
    for (const d of initial)
      this.register(d);
  }
  /** Register a detector. Throws on a duplicate id. Returns `this` for chaining. */
  register(d) {
    if (this.byId.has(d.id)) {
      throw new Error(`duplicate detector id: ${d.id}`);
    }
    this.byId.set(d.id, d);
    this.order.push(d.id);
    return this;
  }
  /** Look up a detector by its id (exact, not prefix). */
  get(id) {
    return this.byId.get(id);
  }
  /** True if a detector with this id is registered. */
  has(id) {
    return this.byId.has(id);
  }
  /** All registered detectors, in registration order. */
  all() {
    return this.order.map((id) => this.byId.get(id));
  }
  /** A shallow copy of this registry (useful to extend the defaults). */
  clone() {
    return new _DetectorRegistry(this.all());
  }
};
var defaultRegistry = new DetectorRegistry([...sourceDetectors, pemDetector]);

// ../core/dist/dependencies.js
var vulnerableDependencies = [
  {
    name: "node-forge",
    ecosystem: "npm",
    reason: "Pure-JS implementation of RSA, RSA-OAEP, and X.509 PKI.",
    algorithms: ["RSA"],
    severity: "high"
  },
  {
    name: "elliptic",
    ecosystem: "npm",
    reason: "Elliptic-curve ECDSA/ECDH (secp256k1, p256, ed25519).",
    algorithms: ["ECDSA", "ECDH", "EdDSA"],
    severity: "high"
  },
  {
    name: "jsrsasign",
    ecosystem: "npm",
    reason: "RSA/ECDSA/DSA signing, JWT, and X.509 in pure JS.",
    algorithms: ["RSA", "ECDSA", "DSA"],
    severity: "high"
  },
  {
    name: "node-rsa",
    ecosystem: "npm",
    reason: "Classical RSA encryption and signing.",
    algorithms: ["RSA"],
    severity: "high"
  },
  {
    name: "ursa",
    ecosystem: "npm",
    reason: "OpenSSL-backed RSA encryption and signing bindings.",
    algorithms: ["RSA"],
    severity: "high"
  },
  {
    name: "sshpk",
    ecosystem: "npm",
    reason: "Parses/handles SSH and PEM keys (RSA, ECDSA, Ed25519, DSA).",
    algorithms: ["RSA", "ECDSA", "EdDSA", "DSA"],
    severity: "medium"
  },
  {
    name: "jsonwebtoken",
    ecosystem: "npm",
    reason: "JWTs commonly signed with RS256/ES256 (classical RSA/ECDSA).",
    algorithms: ["RSA", "ECDSA"],
    severity: "high"
  },
  {
    name: "jose",
    ecosystem: "npm",
    reason: "JWS/JWE with classical RSA-OAEP, RSA-PSS, ECDH-ES and ECDSA.",
    algorithms: ["RSA", "ECDH", "ECDSA", "EdDSA"],
    severity: "high"
  },
  {
    name: "jws",
    ecosystem: "npm",
    reason: "JSON Web Signatures using classical RS/ES algorithms.",
    algorithms: ["RSA", "ECDSA"],
    severity: "high"
  },
  {
    name: "eccrypto",
    ecosystem: "npm",
    reason: "ECIES (ECDH-based) encryption and ECDSA signatures.",
    algorithms: ["ECIES", "ECDH", "ECDSA"],
    severity: "high"
  },
  {
    name: "secp256k1",
    ecosystem: "npm",
    reason: "secp256k1 ECDSA/ECDH bindings (blockchain keys).",
    algorithms: ["ECDSA", "ECDH"],
    severity: "high"
  },
  {
    name: "tweetnacl",
    ecosystem: "npm",
    reason: "X25519 key exchange and Ed25519 signatures (modern but classical).",
    algorithms: ["X25519", "EdDSA"],
    severity: "low"
  },
  {
    name: "ed25519",
    ecosystem: "npm",
    reason: "Ed25519 signatures (classical).",
    algorithms: ["EdDSA"],
    severity: "low"
  },
  {
    name: "@noble/curves",
    ecosystem: "npm",
    reason: "Audited classical curves: ECDSA, ECDH, Ed25519, X25519, secp256k1.",
    algorithms: ["ECDSA", "ECDH", "EdDSA", "X25519"],
    severity: "medium"
  },
  {
    name: "@noble/secp256k1",
    ecosystem: "npm",
    reason: "secp256k1 ECDSA/ECDH (classical).",
    algorithms: ["ECDSA", "ECDH"],
    severity: "medium"
  },
  {
    name: "@noble/ed25519",
    ecosystem: "npm",
    reason: "Ed25519 signatures and X25519 key exchange (classical).",
    algorithms: ["EdDSA", "X25519"],
    severity: "low"
  },
  {
    name: "paseto",
    ecosystem: "npm",
    reason: "PASETO public tokens signed with classical Ed25519 (v2/v4) or RSA.",
    algorithms: ["EdDSA", "RSA"],
    severity: "medium"
  },
  {
    name: "bcrypto",
    ecosystem: "npm",
    reason: "Broad classical crypto suite: RSA, ECDSA, ECDH, Ed25519, DSA.",
    algorithms: ["RSA", "ECDSA", "ECDH", "EdDSA", "DSA"],
    severity: "high"
  },
  {
    name: "ecpair",
    ecosystem: "npm",
    reason: "secp256k1 ECDSA key pairs for Bitcoin.",
    algorithms: ["ECDSA"],
    severity: "medium"
  },
  {
    name: "keypair",
    ecosystem: "npm",
    reason: "Pure-JS RSA key pair generation.",
    algorithms: ["RSA"],
    severity: "high"
  }
];
var BY_NAME = new Map(vulnerableDependencies.map((d) => [d.name, d]));
var KEY_REGEX_BY_NAME = new Map(vulnerableDependencies.map((d) => {
  const escaped = d.name.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");
  return [d.name, new RegExp(`"${escaped}"\\s*:`)];
}));
var CONFIDENTIALITY_FAMILIES = /* @__PURE__ */ new Set([
  "RSA",
  "ECDH",
  "DH",
  "ECIES",
  "X25519",
  "X448"
]);
function multiFamilyRemediation(algorithms) {
  const parts = /* @__PURE__ */ new Set();
  for (const a of algorithms)
    parts.add(remediationText(a));
  return [...parts].join("; ");
}
function isManifestFile(file) {
  const base = file.split("/").pop() ?? file;
  return base === "package.json" || base === "package-lock.json";
}
function dependencyFinding(dep, file, content, index) {
  const algorithm = dep.algorithms[0] ?? "unknown";
  return makeFinding({
    ruleId: "dep-vulnerable",
    title: `Quantum-vulnerable dependency: ${dep.name}`,
    category: "dependency",
    severity: dep.severity,
    confidence: "high",
    algorithm,
    // Confidentiality libs are HNDL-exposed; signature-only ones are not.
    hndl: dep.algorithms.some((a) => CONFIDENTIALITY_FAMILIES.has(a)),
    cwe: CWE_BROKEN_CRYPTO,
    message: `${dep.name} \u2014 ${dep.reason}`,
    remediation: multiFamilyRemediation(dep.algorithms),
    file,
    content,
    index
  });
}
function offsetOfKey(content, name) {
  const re = KEY_REGEX_BY_NAME.get(name);
  if (!re)
    return 0;
  const m = re.exec(content);
  return m ? m.index : 0;
}
function scanManifest(file, content) {
  let json;
  try {
    json = JSON.parse(content);
  } catch {
    return [];
  }
  if (json === null || typeof json !== "object")
    return [];
  const found = /* @__PURE__ */ new Set();
  const obj = json;
  const collectFromRecord = (rec) => {
    if (rec === null || typeof rec !== "object")
      return;
    for (const key of Object.keys(rec)) {
      if (BY_NAME.has(key))
        found.add(key);
    }
  };
  collectFromRecord(obj.dependencies);
  collectFromRecord(obj.devDependencies);
  collectFromRecord(obj.peerDependencies);
  collectFromRecord(obj.optionalDependencies);
  const packages = obj.packages;
  if (packages !== null && typeof packages === "object") {
    for (const key of Object.keys(packages)) {
      if (!key)
        continue;
      const marker = "node_modules/";
      const idx = key.lastIndexOf(marker);
      const name = idx >= 0 ? key.slice(idx + marker.length) : key;
      if (BY_NAME.has(name))
        found.add(name);
    }
  }
  const findings = [];
  for (const name of found) {
    const dep = BY_NAME.get(name);
    if (!dep)
      continue;
    findings.push(dependencyFinding(dep, file, content, offsetOfKey(content, name)));
  }
  findings.sort((a, b) => a.title < b.title ? -1 : a.title > b.title ? 1 : 0);
  return findings;
}

// ../core/dist/inventory.js
var SEVERITIES = ["critical", "high", "medium", "low", "info"];
var SEVERITY_WEIGHT = {
  critical: 30,
  high: 18,
  medium: 8,
  low: 3,
  info: 1
};
function penaltyFor(weight, occurrence) {
  return weight / Math.sqrt(occurrence);
}
function readinessScore(findings) {
  if (findings.length === 0)
    return 100;
  const seen = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0
  };
  let score = 100;
  for (const f of findings) {
    seen[f.severity] += 1;
    score -= penaltyFor(SEVERITY_WEIGHT[f.severity], seen[f.severity]);
  }
  return Math.max(0, Math.min(100, Math.round(score)));
}
function buildInventory(findings) {
  const byAlgorithm = {};
  const byCategory = {};
  const bySeverity = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0
  };
  let hndlCount = 0;
  for (const f of findings) {
    if (f.algorithm) {
      byAlgorithm[f.algorithm] = (byAlgorithm[f.algorithm] ?? 0) + 1;
    }
    byCategory[f.category] = (byCategory[f.category] ?? 0) + 1;
    bySeverity[f.severity] += 1;
    if (f.hndl)
      hndlCount += 1;
  }
  void SEVERITIES;
  return {
    byAlgorithm,
    byCategory,
    bySeverity,
    hndlCount,
    readinessScore: readinessScore(findings)
  };
}

// ../core/dist/scan.js
var detectors = [...sourceDetectors, pemDetector];
function compareFindings(a, b) {
  if (a.location.file !== b.location.file)
    return a.location.file < b.location.file ? -1 : 1;
  if (a.location.line !== b.location.line)
    return a.location.line - b.location.line;
  return a.ruleId < b.ruleId ? -1 : a.ruleId > b.ruleId ? 1 : 0;
}
function resolveDetectors(options) {
  return options.detectors ?? defaultRegistry.all();
}
function detectFile(file, content, dets, toggles) {
  const out = [];
  for (const det of dets) {
    if (!det.appliesTo(file))
      continue;
    const isConfig = detectorScope(det) === "config";
    if (isConfig ? !toggles.config : !toggles.source)
      continue;
    out.push(...det.detect({ file, content }));
  }
  if (toggles.deps && isManifestFile(file)) {
    out.push(...scanManifest(file, content));
  }
  return out;
}
async function scan(options) {
  const startedAt = /* @__PURE__ */ new Date();
  const doSource = options.source !== false;
  const doDeps = options.dependencies !== false;
  const doConfig = options.config !== false;
  const scanMinified = options.scanMinified === true;
  const dets = resolveDetectors(options);
  const rootStat = await stat2(options.root);
  const rootIsFile = rootStat.isFile();
  const baseDir = rootIsFile ? path2.dirname(options.root) : options.root;
  const singleFileName = rootIsFile ? path2.basename(options.root) : null;
  const findings = [];
  let filesScanned = 0;
  const relPaths = options.files ? filterExplicitFiles(options.files, options) : walkFiles(options.root, {
    include: options.include,
    exclude: options.exclude,
    noDefaultIgnores: options.noDefaultIgnores,
    maxFileSize: options.maxFileSize
  });
  for await (const rel of relPaths) {
    const absPath = singleFileName ? options.root : path2.join(baseDir, ...rel.split("/"));
    const reportedPath = singleFileName ? toPosix(rel) : rel;
    options.onFile?.(reportedPath);
    let content;
    try {
      content = await readFile(absPath, "utf8");
    } catch {
      continue;
    }
    if (!scanMinified && !isManifestFile(reportedPath) && looksMinified(content)) {
      continue;
    }
    filesScanned += 1;
    findings.push(...detectFile(reportedPath, content, dets, {
      source: doSource,
      config: doConfig,
      deps: doDeps
    }));
  }
  findings.sort(compareFindings);
  const inventory = buildInventory(findings);
  const finishedAt = /* @__PURE__ */ new Date();
  return {
    root: options.root,
    findings,
    filesScanned,
    inventory,
    startedAt: startedAt.toISOString(),
    finishedAt: finishedAt.toISOString(),
    toolVersion: VERSION
  };
}
async function* filterExplicitFiles(files, options) {
  const include = options.include ?? [];
  const exclude = options.exclude ?? [];
  const seen = /* @__PURE__ */ new Set();
  const list = [...files].map((f) => toPosix(f)).filter((f) => {
    if (seen.has(f))
      return false;
    seen.add(f);
    return true;
  }).sort((a, b) => a < b ? -1 : a > b ? 1 : 0);
  for (const rel of list) {
    if (isBinaryPath(rel))
      continue;
    if (include.length > 0 && !matchesAny2(rel, include))
      continue;
    if (matchesAny2(rel, exclude))
      continue;
    yield rel;
  }
}
function matchesAny2(rel, patterns) {
  for (const pattern of patterns) {
    if (!pattern)
      continue;
    const p = toPosix(pattern).replace(/\/+$/, "");
    if (rel.includes(p))
      return true;
    if (rel === p || rel.startsWith(`${p}/`))
      return true;
  }
  return false;
}

// ../core/dist/parallel.js
import { stat as stat3 } from "node:fs/promises";
import * as os from "node:os";
import * as path3 from "node:path";
import { fileURLToPath } from "node:url";
var DEFAULT_PARALLEL_THRESHOLD_BYTES = 2 * 1024 * 1024;
var DEFAULT_PARALLEL_FILE_THRESHOLD = 200;
var DEFAULT_CHUNK_BYTES = 4 * 1024 * 1024;
function chunkByBytes(files, chunkBytes) {
  const limit = Math.max(1, chunkBytes);
  const chunks = [];
  let current = [];
  let currentBytes = 0;
  for (const f of files) {
    if (current.length > 0 && currentBytes + f.size > limit) {
      chunks.push({ files: current });
      current = [];
      currentBytes = 0;
    }
    current.push(f.rel);
    currentBytes += f.size;
  }
  if (current.length > 0)
    chunks.push({ files: current });
  return chunks;
}
function mergeChunkResults(results) {
  const findings = [];
  let filesScanned = 0;
  for (const r of results) {
    for (const f of r.findings)
      findings.push(f);
    filesScanned += r.filesScanned;
  }
  findings.sort(compareFindings);
  return { findings, filesScanned };
}
function resolveConcurrency(options) {
  const raw = options.concurrency;
  if (typeof raw === "number" && raw >= 1)
    return Math.floor(raw);
  const avail = typeof os.availableParallelism === "function" ? os.availableParallelism() : os.cpus().length;
  return Math.max(1, avail);
}
function shouldParallelize(options, files) {
  const totalBytes = files.reduce((acc, f) => acc + f.size, 0);
  const byteFloor = options.parallelThresholdBytes ?? DEFAULT_PARALLEL_THRESHOLD_BYTES;
  const fileFloor = options.parallelFileThreshold ?? DEFAULT_PARALLEL_FILE_THRESHOLD;
  if (resolveConcurrency(options) <= 1)
    return false;
  return totalBytes >= byteFloor && files.length >= fileFloor;
}
async function enumerateFiles(options, baseDir) {
  const rels = [];
  if (options.files) {
    for (const f of options.files)
      rels.push(toPosix(f));
  } else {
    for await (const rel of walkFiles(options.root, {
      include: options.include,
      exclude: options.exclude,
      noDefaultIgnores: options.noDefaultIgnores,
      maxFileSize: options.maxFileSize
    })) {
      rels.push(rel);
    }
  }
  const sized = [];
  for (const rel of rels) {
    let size = 0;
    try {
      size = (await stat3(path3.join(baseDir, ...rel.split("/")))).size;
    } catch {
    }
    sized.push({ rel, size });
  }
  return sized;
}
function workerEntryPath() {
  const here = fileURLToPath(import.meta.url);
  return path3.join(path3.dirname(here), "scan-worker.js");
}
async function scanParallel(options) {
  const startedAt = /* @__PURE__ */ new Date();
  const rootStat = await stat3(options.root);
  const baseDir = rootStat.isFile() ? path3.dirname(options.root) : options.root;
  if (rootStat.isFile() || options.detectors) {
    return scan(options);
  }
  const files = await enumerateFiles(options, baseDir);
  if (!shouldParallelize(options, files)) {
    return scan({ ...options, files: files.map((f) => f.rel) });
  }
  let WorkerCtor;
  try {
    ({ Worker: WorkerCtor } = await import("node:worker_threads"));
  } catch {
    return scan({ ...options, files: files.map((f) => f.rel) });
  }
  const chunks = chunkByBytes(files, options.chunkBytes ?? DEFAULT_CHUNK_BYTES);
  const concurrency = Math.min(resolveConcurrency(options), chunks.length);
  const entry = workerEntryPath();
  const toggles = {
    source: options.source !== false,
    config: options.config !== false,
    deps: options.dependencies !== false,
    scanMinified: options.scanMinified === true
  };
  let results;
  try {
    results = await runPool(WorkerCtor, entry, baseDir, toggles, chunks, concurrency, options.onFile);
  } catch {
    return scan({ ...options, files: files.map((f) => f.rel) });
  }
  const merged = mergeChunkResults(results);
  const inventory = buildInventory(merged.findings);
  const finishedAt = /* @__PURE__ */ new Date();
  return {
    root: options.root,
    findings: merged.findings,
    filesScanned: merged.filesScanned,
    inventory,
    startedAt: startedAt.toISOString(),
    finishedAt: finishedAt.toISOString(),
    toolVersion: VERSION
  };
}
function runPool(WorkerCtor, entry, baseDir, toggles, chunks, concurrency, onFile) {
  return new Promise((resolve2, reject) => {
    const results = new Array(chunks.length);
    let next = 0;
    let done = 0;
    let failed = false;
    const workers = [];
    const cleanup = () => {
      for (const w of workers)
        void w.terminate();
    };
    const dispatch = (w) => {
      if (failed)
        return;
      if (next >= chunks.length) {
        void w.terminate();
        return;
      }
      const idx = next++;
      w.postMessage({ index: idx, files: chunks[idx].files });
    };
    const spawn = () => {
      const w = new WorkerCtor(entry, { workerData: { baseDir, toggles } });
      w.on("message", (msg) => {
        if (msg.error) {
          if (!failed) {
            failed = true;
            cleanup();
            reject(new Error(msg.error));
          }
          return;
        }
        if (msg.files && onFile)
          for (const f of msg.files)
            onFile(f);
        if (msg.result) {
          results[msg.index] = msg.result;
          done++;
          if (done === chunks.length) {
            cleanup();
            resolve2(results);
            return;
          }
          dispatch(w);
        }
      });
      w.on("error", (err) => {
        if (!failed) {
          failed = true;
          cleanup();
          reject(err);
        }
      });
      return w;
    };
    const n = Math.max(1, Math.min(concurrency, chunks.length));
    for (let i = 0; i < n; i++) {
      const w = spawn();
      workers.push(w);
      dispatch(w);
    }
  });
}

// ../core/dist/baseline.js
import { createHash } from "node:crypto";
import { readFile as readFile2, writeFile } from "node:fs/promises";
var BASELINE_VERSION = 1;
function normalizeSnippet(snippet) {
  if (!snippet)
    return "";
  return snippet.replace(/\s+/g, " ").trim();
}
function fingerprintFinding(f) {
  const snippet = normalizeSnippet(f.location.snippet);
  const input = `${f.ruleId}|${f.location.file}|${snippet}`;
  return createHash("sha256").update(input, "utf8").digest("hex");
}
function baselineFromFindings(findings) {
  const set = /* @__PURE__ */ new Set();
  for (const f of findings)
    set.add(fingerprintFinding(f));
  return {
    version: BASELINE_VERSION,
    fingerprints: [...set].sort()
  };
}
function applyBaseline(findings, baseline) {
  const accepted = new Set(baseline.fingerprints);
  const newFindings = [];
  const suppressed = [];
  for (const f of findings) {
    if (accepted.has(fingerprintFinding(f)))
      suppressed.push(f);
    else
      newFindings.push(f);
  }
  return { newFindings, suppressed };
}
function coerceBaseline(value) {
  if (value === null || typeof value !== "object") {
    return { version: BASELINE_VERSION, fingerprints: [] };
  }
  const obj = value;
  const version = typeof obj.version === "number" ? obj.version : BASELINE_VERSION;
  const fingerprints = Array.isArray(obj.fingerprints) ? obj.fingerprints.filter((x) => typeof x === "string") : [];
  return { version, fingerprints };
}
async function loadBaseline(path4) {
  let text;
  try {
    text = await readFile2(path4, "utf8");
  } catch {
    return { version: BASELINE_VERSION, fingerprints: [] };
  }
  try {
    return coerceBaseline(JSON.parse(text));
  } catch {
    return { version: BASELINE_VERSION, fingerprints: [] };
  }
}
async function saveBaseline(path4, findings) {
  const baseline = baselineFromFindings(findings);
  await writeFile(path4, `${JSON.stringify(baseline, null, 2)}
`, "utf8");
  return baseline;
}

// ../core/dist/changed.js
import { execFile } from "node:child_process";
import { promisify } from "node:util";
var execFileAsync = promisify(execFile);
async function git(cwd, args) {
  try {
    const { stdout } = await execFileAsync("git", args, {
      cwd,
      maxBuffer: 64 * 1024 * 1024,
      windowsHide: true
    });
    return stdout;
  } catch {
    return null;
  }
}
function toLines(stdout) {
  if (!stdout)
    return [];
  return stdout.split("\n").map((l) => l.trim()).filter((l) => l.length > 0);
}
async function changedFiles(root, since) {
  const inside = await git(root, ["rev-parse", "--is-inside-work-tree"]);
  if (inside === null || inside.trim() !== "true")
    return [];
  const out = /* @__PURE__ */ new Set();
  if (since) {
    for (const f of toLines(await git(root, ["diff", "--name-only", "--diff-filter=ACMR", since]))) {
      out.add(f);
    }
  }
  for (const f of toLines(await git(root, ["diff", "--name-only", "--diff-filter=ACMR"]))) {
    out.add(f);
  }
  for (const f of toLines(await git(root, ["diff", "--name-only", "--diff-filter=ACMR", "--cached"]))) {
    out.add(f);
  }
  for (const f of toLines(await git(root, ["ls-files", "--others", "--exclude-standard"]))) {
    out.add(f);
  }
  return [...out].sort((a, b) => a < b ? -1 : a > b ? 1 : 0);
}

// ../core/dist/report.js
var SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";
var INFORMATION_URI = "https://github.com/quantakrypto/tools";
function sarifLevel(severity) {
  switch (severity) {
    case "critical":
    case "high":
      return "error";
    case "medium":
      return "warning";
    default:
      return "note";
  }
}
function sarifRank(severity) {
  switch (severity) {
    case "critical":
      return 100;
    case "high":
      return 80;
    case "medium":
      return 50;
    case "low":
      return 20;
    default:
      return 5;
  }
}
function toSarif(result) {
  const ruleIndex = /* @__PURE__ */ new Map();
  const rules = [];
  const cweTaxa = /* @__PURE__ */ new Set();
  for (const f of result.findings) {
    if (f.cwe)
      cweTaxa.add(f.cwe);
    if (ruleIndex.has(f.ruleId))
      continue;
    ruleIndex.set(f.ruleId, rules.length);
    rules.push({
      id: f.ruleId,
      name: f.ruleId,
      shortDescription: { text: f.title },
      fullDescription: { text: f.message },
      defaultConfiguration: { level: sarifLevel(f.severity), rank: sarifRank(f.severity) },
      ...f.remediation ? { help: { text: `Remediation: ${f.remediation}` } } : {},
      properties: {
        category: f.category,
        ...f.algorithm ? { algorithm: f.algorithm } : {},
        hndl: f.hndl,
        ...f.cwe ? { cwe: f.cwe, "security-severity": securitySeverity(f.severity) } : {},
        ...f.cwe ? { tags: ["security", f.cwe] } : {}
      },
      ...f.cwe ? {
        relationships: [
          { target: { id: f.cwe, toolComponent: { name: "CWE" } }, kinds: ["relevant"] }
        ]
      } : {}
    });
  }
  const results = result.findings.map((f) => {
    const region = { startLine: f.location.line };
    if (typeof f.location.column === "number")
      region.startColumn = f.location.column;
    if (typeof f.location.endLine === "number")
      region.endLine = f.location.endLine;
    return {
      ruleId: f.ruleId,
      ruleIndex: ruleIndex.get(f.ruleId),
      level: sarifLevel(f.severity),
      message: { text: f.message },
      properties: {
        category: f.category,
        severity: f.severity,
        confidence: f.confidence,
        hndl: f.hndl,
        ...f.algorithm ? { algorithm: f.algorithm } : {},
        ...f.remediation ? { remediation: f.remediation } : {},
        ...f.cwe ? { cwe: f.cwe } : {}
      },
      ...f.cwe ? {
        taxa: [
          {
            target: { id: f.cwe, toolComponent: { name: "CWE" } }
          }
        ]
      } : {},
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: f.location.file },
            region: {
              ...region,
              ...f.location.snippet ? { snippet: { text: f.location.snippet } } : {}
            }
          }
        }
      ]
    };
  });
  const taxonomies = cweTaxa.size > 0 ? [
    {
      name: "CWE",
      informationUri: "https://cwe.mitre.org/",
      organization: "MITRE",
      shortDescription: { text: "The MITRE Common Weakness Enumeration" },
      taxa: [...cweTaxa].sort().map((id) => ({
        id,
        helpUri: `https://cwe.mitre.org/data/definitions/${id.replace(/^CWE-/, "")}.html`
      }))
    }
  ] : [];
  return {
    $schema: SARIF_SCHEMA,
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "qScan",
            informationUri: INFORMATION_URI,
            version: result.toolVersion || VERSION,
            rules
          }
        },
        ...taxonomies.length > 0 ? { taxonomies } : {},
        results
      }
    ]
  };
}
function securitySeverity(severity) {
  switch (severity) {
    case "critical":
      return "9.5";
    case "high":
      return "8.0";
    case "medium":
      return "5.0";
    case "low":
      return "3.0";
    default:
      return "1.0";
  }
}
function toJson(result) {
  return {
    toolVersion: result.toolVersion,
    root: result.root,
    startedAt: result.startedAt,
    finishedAt: result.finishedAt,
    filesScanned: result.filesScanned,
    inventory: {
      readinessScore: result.inventory.readinessScore,
      hndlCount: result.inventory.hndlCount,
      bySeverity: result.inventory.bySeverity,
      byCategory: result.inventory.byCategory,
      byAlgorithm: result.inventory.byAlgorithm
    },
    findings: result.findings.map((f) => ({
      ruleId: f.ruleId,
      title: f.title,
      category: f.category,
      severity: f.severity,
      confidence: f.confidence,
      algorithm: f.algorithm,
      hndl: f.hndl,
      message: f.message,
      remediation: f.remediation,
      cwe: f.cwe,
      location: {
        file: f.location.file,
        line: f.location.line,
        column: f.location.column,
        endLine: f.location.endLine,
        snippet: f.location.snippet
      }
    }))
  };
}

// ../core/dist/cbom.js
import { createHash as createHash2 } from "node:crypto";
function primitiveFor(category) {
  switch (category) {
    case "kem":
      return "kem";
    case "key-exchange":
      return "key-agree";
    case "signature":
      return "signature";
    case "certificate":
      return "pki";
    case "tls":
      return "other";
    default:
      return "other";
  }
}
function isQuantumVulnerable(algorithm) {
  return algorithm !== "unknown";
}
function bomRef(key) {
  return `crypto:${createHash2("sha256").update(key, "utf8").digest("hex").slice(0, 16)}`;
}
function toCbom(result) {
  const groups = /* @__PURE__ */ new Map();
  for (const f of result.findings) {
    const algorithm = f.algorithm ?? "unknown";
    const primitive = primitiveFor(f.category);
    const key = `${algorithm}|${primitive}`;
    let g = groups.get(key);
    if (!g) {
      g = { algorithm, primitive, findings: [] };
      groups.set(key, g);
    }
    g.findings.push(f);
  }
  const components = [...groups.entries()].sort((a, b) => a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0).map(([key, g]) => {
    const occurrences = g.findings.map((f) => ({
      location: `${f.location.file}:${f.location.line}`,
      ...f.cwe ? { additionalContext: f.cwe } : {}
    })).sort((a, b) => a.location < b.location ? -1 : a.location > b.location ? 1 : 0);
    const anyHndl = g.findings.some((f) => f.hndl);
    return {
      type: "cryptographic-asset",
      "bom-ref": bomRef(key),
      name: `${g.algorithm} (${g.primitive})`,
      cryptoProperties: {
        assetType: "algorithm",
        algorithmProperties: {
          primitive: g.primitive,
          parameterSetIdentifier: g.algorithm,
          executionEnvironment: "software-plain-ram",
          classicalSecurityLevel: 0,
          nistQuantumSecurityLevel: 0,
          cryptoFunctions: g.primitive === "signature" ? ["sign", "verify"] : g.primitive === "kem" ? ["encapsulate", "decapsulate"] : g.primitive === "key-agree" ? ["keygen"] : ["other"]
        },
        quantumVulnerable: isQuantumVulnerable(g.algorithm),
        harvestNowDecryptLater: anyHndl
      },
      evidence: { occurrences }
    };
  });
  const serial = `urn:uuid:${stableUuid(result)}`;
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    serialNumber: serial,
    version: 1,
    metadata: {
      timestamp: result.finishedAt,
      tools: {
        components: [
          {
            type: "application",
            name: "qScan",
            version: result.toolVersion || VERSION
          }
        ]
      },
      component: {
        type: "application",
        "bom-ref": "root",
        name: result.root
      }
    },
    components
  };
}
function stableUuid(result) {
  const h = createHash2("sha256").update(`${result.root}|${result.toolVersion}|${result.findings.length}`, "utf8").digest("hex");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-8${h.slice(17, 20)}-${h.slice(20, 32)}`;
}

// ../qscan/dist/baseline.js
function applyBaseline2(findings, baseline) {
  const resolved = baseline instanceof Set ? { version: BASELINE_VERSION, fingerprints: [...baseline] } : baseline;
  const { newFindings, suppressed } = applyBaseline(findings, resolved);
  return { kept: newFindings, suppressed };
}

// ../qscan/dist/args.js
var SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];
function defaultOptions() {
  return {
    path: ".",
    format: "human",
    severityThreshold: "high",
    source: true,
    dependencies: true,
    config: true,
    ignore: [],
    include: [],
    noDefaultIgnores: false,
    scanMinified: false,
    changed: false,
    parallel: false,
    quiet: false,
    noConfigFile: false
  };
}
function severityRank(severity) {
  return SEVERITY_ORDER.indexOf(severity);
}
function meetsThreshold(severity, threshold) {
  return severityRank(severity) <= severityRank(threshold);
}

// ../qscan/dist/report.js
var PLAIN = { reset: "", bold: "", dim: "", red: "", yellow: "", green: "", cyan: "" };
var COLOR = {
  reset: "\x1B[0m",
  bold: "\x1B[1m",
  dim: "\x1B[2m",
  red: "\x1B[31m",
  yellow: "\x1B[33m",
  green: "\x1B[32m",
  cyan: "\x1B[36m"
};
function renderJson(result) {
  return JSON.stringify(serialize(() => toJson(result), result), null, 2);
}
function renderSarif(result) {
  return JSON.stringify(serialize(() => toSarif(result), fallbackSarif(result)), null, 2);
}
function renderCbom(result) {
  return JSON.stringify(toCbom(result), null, 2);
}
function serialize(fn, fallback) {
  try {
    return fn();
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (message.includes("not implemented"))
      return fallback;
    throw err;
  }
}
function fallbackSarif(result) {
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "qscan",
            informationUri: "https://github.com/quantakrypto/tools",
            version: result.toolVersion,
            rules: []
          }
        },
        results: result.findings.map((f) => ({
          ruleId: f.ruleId,
          level: sarifLevel2(f.severity),
          message: { text: f.message },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: f.location.file },
                region: {
                  startLine: f.location.line,
                  ...f.location.column ? { startColumn: f.location.column } : {}
                }
              }
            }
          ]
        }))
      }
    ]
  };
}
function sarifLevel2(severity) {
  switch (severity) {
    case "critical":
    case "high":
      return "error";
    case "medium":
      return "warning";
    default:
      return "note";
  }
}
function renderHuman(result, opts = {}) {
  const c = opts.color ? COLOR : PLAIN;
  const topN = opts.topN ?? 5;
  const { findings, inventory, filesScanned } = result;
  const lines = [];
  lines.push(`${c.bold}qScan \u2014 quantum-vulnerable cryptography report${c.reset}`);
  lines.push(`${c.dim}root: ${result.root}  \u2022  files scanned: ${filesScanned}  \u2022  qscan v${result.toolVersion}${c.reset}`);
  lines.push("");
  if (findings.length === 0) {
    lines.push(`${c.green}No quantum-vulnerable cryptography detected.${c.reset}`);
    lines.push(`${c.bold}Readiness score: ${readiness(inventory.readinessScore, c)}/100${c.reset}`);
    lines.push("");
    lines.push(`${c.dim}Next step:${c.reset} keep scanning in CI to catch regressions.`);
    return lines.join("\n");
  }
  const counts = SEVERITY_ORDER.map((sev) => {
    const n = inventory.bySeverity[sev] ?? 0;
    return n > 0 ? `${severityColor(sev, c)}${n} ${sev}${c.reset}` : null;
  }).filter((s) => s !== null);
  lines.push(`${c.bold}${findings.length} finding${findings.length === 1 ? "" : "s"}${c.reset}  (${counts.join(", ")})`);
  if (inventory.hndlCount > 0) {
    lines.push(`${c.yellow}${inventory.hndlCount}${c.reset} exposed to harvest-now-decrypt-later (HNDL).`);
  }
  lines.push(`${c.bold}Readiness score: ${readiness(inventory.readinessScore, c)}/100${c.reset}`);
  lines.push("");
  const top = [...findings].sort(compareFindings2).slice(0, topN);
  lines.push(`${c.bold}Top findings${c.reset}`);
  for (const f of top) {
    const loc = `${f.location.file}:${f.location.line}`;
    lines.push(`  ${severityColor(f.severity, c)}${f.severity.padEnd(8)}${c.reset} ${c.cyan}${f.ruleId}${c.reset}  ${loc}`);
    lines.push(`           ${f.message}`);
    if (f.remediation) {
      lines.push(`           ${c.dim}\u2192 ${f.remediation}${c.reset}`);
    }
  }
  if (findings.length > top.length) {
    lines.push(`  ${c.dim}\u2026and ${findings.length - top.length} more${c.reset}`);
  }
  lines.push("");
  lines.push(`${c.dim}Next step:${c.reset} ${nextStep(findings)}`);
  return lines.join("\n");
}
function nextStep(findings) {
  const worst = [...findings].sort(compareFindings2)[0];
  if (!worst)
    return "review the findings above.";
  if (worst.remediation) {
    return `migrate ${worst.location.file} \u2014 ${worst.remediation}`;
  }
  return `triage ${worst.ruleId} in ${worst.location.file}:${worst.location.line}.`;
}
function compareFindings2(a, b) {
  const bySev = severityRank(a.severity) - severityRank(b.severity);
  if (bySev !== 0)
    return bySev;
  const byFile = a.location.file.localeCompare(b.location.file);
  if (byFile !== 0)
    return byFile;
  return a.location.line - b.location.line;
}
function readiness(score, c) {
  const color = score >= 80 ? c.green : score >= 50 ? c.yellow : c.red;
  return `${color}${score}${c.reset}`;
}
function severityColor(severity, c) {
  switch (severity) {
    case "critical":
    case "high":
      return c.red;
    case "medium":
      return c.yellow;
    default:
      return c.dim;
  }
}

// ../qscan/dist/index.js
var EXIT = {
  /** No findings at/above threshold, or a baseline was written. */
  OK: 0,
  /** One or more findings at/above the severity threshold. */
  FINDINGS: 1,
  /** Usage error or I/O failure. */
  ERROR: 2
};
function toScanOptions(options) {
  const scanOptions = {
    root: options.path,
    source: options.source,
    dependencies: options.dependencies,
    config: options.config,
    noDefaultIgnores: options.noDefaultIgnores,
    scanMinified: options.scanMinified
  };
  if (options.ignore.length > 0)
    scanOptions.exclude = options.ignore;
  if (options.include.length > 0)
    scanOptions.include = options.include;
  if (options.maxFileSize !== void 0)
    scanOptions.maxFileSize = options.maxFileSize;
  if (options.concurrency !== void 0)
    scanOptions.concurrency = options.concurrency;
  return scanOptions;
}
async function runQscan(opts, hooks = {}) {
  const options = { ...defaultOptions(), ...opts };
  const scanFn = hooks.scanFn ?? (options.parallel ? scanParallel : scan);
  const resolveChanged = hooks.changedFilesFn ?? changedFiles;
  const scanOptions = toScanOptions(options);
  if (options.changed) {
    scanOptions.files = await resolveChanged(options.path, options.since);
  }
  const result = await scanFn(scanOptions);
  if (options.writeBaseline) {
    const baseline = await saveBaseline(options.writeBaseline, result.findings);
    return {
      result,
      suppressed: [],
      baselineWritten: baseline,
      exitCode: EXIT.OK
    };
  }
  let suppressed = [];
  if (options.baseline) {
    const baseline = await loadBaseline(options.baseline);
    const split = applyBaseline2(result.findings, baseline);
    result.findings = split.kept;
    suppressed = split.suppressed;
  }
  const exitCode = result.findings.some((f) => meetsThreshold(f.severity, options.severityThreshold)) ? EXIT.FINDINGS : EXIT.OK;
  return {
    result,
    suppressed,
    report: renderReport(result, options.format, hooks.color ?? false),
    exitCode
  };
}
function renderReport(result, format, color = false) {
  switch (format) {
    case "json":
      return renderJson(result);
    case "sarif":
      return renderSarif(result);
    case "cbom":
      return renderCbom(result);
    case "human":
    default:
      return renderHuman(result, { color });
  }
}

// src/io.ts
import { appendFileSync } from "node:fs";
import { EOL } from "node:os";
function inputEnvName(name) {
  return `INPUT_${name.replace(/ /g, "_").replace(/-/g, "_").toUpperCase()}`;
}
function getInput(name, env = process.env) {
  const raw = env[inputEnvName(name)];
  return raw === void 0 ? "" : raw.trim();
}
function getBooleanInput(name, defaultValue = false, env = process.env) {
  const value = getInput(name, env);
  if (value === "") return defaultValue;
  if (["true", "True", "TRUE"].includes(value)) return true;
  if (["false", "False", "FALSE"].includes(value)) return false;
  throw new TypeError(
    `Input "${name}" does not meet YAML 1.2 "Core Schema" specification: got "${value}"`
  );
}
function escapeData(value) {
  return value.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
}
function escapeProperty(value) {
  return value.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A").replace(/:/g, "%3A").replace(/,/g, "%2C");
}
function formatCommand(command, message, properties = {}) {
  const entries = [
    ["title", properties.title],
    ["file", properties.file],
    ["line", properties.line],
    ["col", properties.col],
    ["endLine", properties.endLine],
    ["endColumn", properties.endColumn]
  ];
  const props = entries.filter(([, v]) => v !== void 0 && v !== "").map(([k, v]) => `${k}=${escapeProperty(String(v))}`).join(",");
  const head = props ? `::${command} ${props}::` : `::${command}::`;
  return `${head}${escapeData(message)}`;
}
function issueCommand(command, message, properties) {
  process.stdout.write(formatCommand(command, message, properties) + EOL);
}
function info(message) {
  process.stdout.write(message + EOL);
}
function warning(message, properties) {
  issueCommand("warning", message, properties);
}
function error(message, properties) {
  issueCommand("error", message, properties);
}
function setOutput(name, value, env = process.env) {
  const filePath = env["GITHUB_OUTPUT"];
  if (filePath) {
    const delimiter = `ghadelimiter_${name}`;
    appendFileSync(filePath, `${name}<<${delimiter}${EOL}${value}${EOL}${delimiter}${EOL}`, {
      encoding: "utf8"
    });
    return;
  }
  process.stdout.write(formatCommand("set-output", value, { title: name }) + EOL);
}
function setFailed(message) {
  error(message);
  process.exitCode = 1;
}

// src/escape.ts
function mdCell(value) {
  const clipped = value.length > 512 ? `${value.slice(0, 512)}\u2026` : value;
  return clipped.replace(/\\/g, "\\\\").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/\|/g, "\\|").replace(/`/g, "\\`").replace(/[\r\n]+/g, " ");
}

// src/main.ts
var SEVERITY_ORDER2 = ["critical", "high", "medium", "low", "info"];
var DEFAULT_OUTPUT = "quantakrypto.sarif.json";
function readInputs(env = process.env) {
  const severityThreshold = getInput("severity-threshold", env) || "high";
  if (!SEVERITY_ORDER2.includes(severityThreshold)) {
    throw new TypeError(
      `Invalid severity-threshold "${severityThreshold}"; expected one of ${SEVERITY_ORDER2.join(", ")}`
    );
  }
  const format = getInput("format", env) || "sarif";
  if (format !== "sarif" && format !== "json") {
    throw new TypeError(`Invalid format "${format}"; expected "sarif" or "json"`);
  }
  const baseline = getInput("baseline", env);
  const githubToken = getInput("github-token", env);
  return {
    path: getInput("path", env) || ".",
    severityThreshold,
    failOnFindings: getBooleanInput("fail-on-findings", true, env),
    format,
    output: getInput("output", env) || DEFAULT_OUTPUT,
    baseline: baseline || void 0,
    commentPr: getBooleanInput("comment-pr", false, env),
    githubToken: githubToken || void 0
  };
}
function meetsThreshold2(severity, threshold) {
  return SEVERITY_ORDER2.indexOf(severity) <= SEVERITY_ORDER2.indexOf(threshold);
}
function shouldFail(blockingCount, failOnFindings) {
  return failOnFindings && blockingCount > 0;
}
function annotationLevel(severity) {
  if (severity === "critical" || severity === "high") return "error";
  if (severity === "medium" || severity === "low") return "warning";
  return "notice";
}
function annotateFindings(findings, threshold) {
  for (const f of findings) {
    const level = meetsThreshold2(f.severity, threshold) ? "error" : annotationLevel(f.severity);
    const message = f.remediation ? `${f.message} \u2192 ${f.remediation}` : f.message;
    const props = {
      title: `quantakrypto: ${f.title}`,
      file: f.location.file,
      line: f.location.line,
      col: f.location.column,
      endLine: f.location.endLine
    };
    if (level === "error") error(message, props);
    else warning(message, props);
  }
}
function buildSummary(result, newFindings, threshold) {
  const score = result.inventory.readinessScore;
  const blocking = newFindings.filter((f) => meetsThreshold2(f.severity, threshold));
  const lines = [];
  lines.push("## quantakrypto \u2014 Quantum Readiness Scan");
  lines.push("");
  lines.push(`**Readiness score:** ${score}/100`);
  lines.push(
    `**New findings:** ${newFindings.length} (${blocking.length} at or above \`${threshold}\`)`
  );
  lines.push("");
  if (blocking.length === 0) {
    lines.push("No new quantum-vulnerable cryptography at or above the threshold. \u2705");
    return lines.join("\n");
  }
  lines.push("| Severity | Rule | File | Message |");
  lines.push("| --- | --- | --- | --- |");
  for (const f of blocking.slice(0, 50)) {
    const loc = mdCell(`${f.location.file}:${f.location.line}`);
    const rule = mdCell(f.ruleId);
    const msg = mdCell(f.message);
    lines.push(`| ${f.severity} | \`${rule}\` | ${loc} | ${msg} |`);
  }
  if (blocking.length > 50) lines.push(`| \u2026 | | | _${blocking.length - 50} more_ |`);
  lines.push("");
  lines.push("<sub>Reported by [quantakrypto](https://quantakrypto.com/tools).</sub>");
  return lines.join("\n");
}
async function readPullRequestContext(env = process.env) {
  try {
    const repository = env["GITHUB_REPOSITORY"];
    const eventPath = env["GITHUB_EVENT_PATH"];
    if (!repository || !eventPath) return void 0;
    const [owner, repo] = repository.split("/");
    if (!owner || !repo) return void 0;
    const payload = JSON.parse(await readFile3(eventPath, "utf8"));
    const prNumber = payload.pull_request?.number ?? payload.number;
    if (typeof prNumber !== "number") return void 0;
    const apiUrl = env["GITHUB_API_URL"] || "https://api.github.com";
    return { owner, repo, prNumber, apiUrl };
  } catch {
    return void 0;
  }
}
async function commentOnPullRequest(ctx, token, body) {
  try {
    const url = `${ctx.apiUrl}/repos/${ctx.owner}/${ctx.repo}/issues/${ctx.prNumber}/comments`;
    const res = await fetch(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "Content-Type": "application/json",
        "User-Agent": "quantakrypto-action"
      },
      body: JSON.stringify({ body })
    });
    if (!res.ok) {
      warning(`Could not comment on PR #${ctx.prNumber}: ${res.status} ${res.statusText}`);
      return false;
    }
    return true;
  } catch (err) {
    warning(`Could not comment on PR: ${err.message}`);
    return false;
  }
}
function resolveInWorkspace(p, env) {
  if (isAbsolute(p)) return p;
  const workspace = env["GITHUB_WORKSPACE"] || process.cwd();
  return join4(workspace, p);
}
async function loadBaselineSet(baselinePath, env) {
  const abs = resolveInWorkspace(baselinePath, env);
  return loadBaseline(abs);
}
async function run(env = process.env) {
  const inputs = readInputs(env);
  const scanRoot = resolveInWorkspace(inputs.path, env);
  info(`quantakrypto: scanning ${scanRoot} (threshold: ${inputs.severityThreshold})`);
  const { result } = await runQscan({
    path: scanRoot,
    format: inputs.format,
    severityThreshold: inputs.severityThreshold
  });
  const baseline = inputs.baseline ? await loadBaselineSet(inputs.baseline, env) : { version: 1, fingerprints: [] };
  const { newFindings } = applyBaseline(result.findings, baseline);
  const outputPath = resolveInWorkspace(inputs.output, env);
  await mkdir(dirname3(outputPath), { recursive: true });
  await writeFile2(outputPath, renderReport(result, inputs.format), "utf8");
  info(`quantakrypto: wrote ${inputs.format} report to ${inputs.output}`);
  annotateFindings(newFindings, inputs.severityThreshold);
  const blocking = newFindings.filter((f) => meetsThreshold2(f.severity, inputs.severityThreshold));
  setOutput("findings-count", String(blocking.length), env);
  setOutput("readiness-score", String(result.inventory.readinessScore), env);
  setOutput("sarif-file", inputs.output, env);
  if (inputs.commentPr && inputs.githubToken) {
    const ctx = await readPullRequestContext(env);
    if (ctx) {
      const body = buildSummary(result, newFindings, inputs.severityThreshold);
      await commentOnPullRequest(ctx, inputs.githubToken, body);
    } else {
      info("quantakrypto: comment-pr enabled but no pull-request context found; skipping comment.");
    }
  }
  info(
    `quantakrypto: ${newFindings.length} new finding(s), ${blocking.length} at/above "${inputs.severityThreshold}"; readiness ${result.inventory.readinessScore}/100.`
  );
  if (shouldFail(blocking.length, inputs.failOnFindings)) {
    setFailed(
      `quantakrypto: ${blocking.length} quantum-vulnerable finding(s) at or above "${inputs.severityThreshold}".`
    );
    process.exit(1);
  }
}
var invokedDirectly = process.argv[1] !== void 0 && import.meta.url === pathToFileURL(resolve(process.argv[1])).href;
if (invokedDirectly) {
  run().catch((err) => {
    setFailed(`quantakrypto: ${err.message}`);
    process.exit(1);
  });
}
export {
  annotateFindings,
  buildSummary,
  commentOnPullRequest,
  fingerprintFinding as fingerprint,
  meetsThreshold2 as meetsThreshold,
  readInputs,
  readPullRequestContext,
  run,
  shouldFail
};
