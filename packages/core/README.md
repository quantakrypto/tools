# @qproof/core

Shared post-quantum readiness library for the qproof toolchain. It finds
**classical, non-quantum-safe asymmetric cryptography** in a codebase — inline
crypto calls, embedded keys/certificates, and quantum-vulnerable npm
dependencies — and turns the results into an inventory, a readiness score, and
machine- or human-readable reports.

- **Zero runtime dependencies.** Node built-ins only.
- **ESM + NodeNext**, TypeScript strict, Node ≥ 20.
- Powers `@qproof/qscan` (CLI), the MCP server, and the GitHub Action.

## Why it exists

Shor's algorithm breaks RSA, (EC)DH, ECDSA, DSA and EdDSA. Two threats follow:

- **Harvest now, decrypt later (HNDL).** Traffic protected by classical key
  exchange / public-key encryption (ECDH, DH, RSA-OAEP) can be recorded today
  and decrypted once a cryptographically relevant quantum computer exists.
  Findings carry an `hndl: true` flag.
- **Forgery.** Classical signatures (RSA-PSS, ECDSA, EdDSA, DSA, JWT `RS*/PS*/ES*/EdDSA`)
  can be forged by a quantum attacker. These are `hndl: false` but still high
  severity.

`@qproof/core` flags both, and points each finding at a NIST PQC replacement
(ML-KEM / FIPS 203, ML-DSA / FIPS 204, SLH-DSA / FIPS 205, hybrid
`X25519MLKEM768`).

## Install

```bash
npm install @qproof/core
```

## Quick start

```ts
import { scan, formatSummary, toSarif, toJson } from "@qproof/core";

const result = await scan({ root: "./", onFile: (f) => process.stderr.write(`scanning ${f}\n`) });

console.log(formatSummary(result, { color: true })); // human report
const sarif = toSarif(result);                        // SARIF 2.1.0 for CI
const json = toJson(result);                          // structured object
```

## API

### `scan(options: ScanOptions): Promise<ScanResult>`

Recursively scans a directory (or a single file) and returns findings, an
inventory, file count, timing, and the tool version.

```ts
interface ScanOptions {
  root: string;                 // directory or single file
  include?: string[];           // extra include patterns (substring/prefix)
  exclude?: string[];           // extra exclude patterns (substring/prefix)
  noDefaultIgnores?: boolean;   // disable node_modules/.git/dist/… ignores
  source?: boolean;             // scan source files (default true)
  dependencies?: boolean;       // scan package.json / package-lock.json (default true)
  config?: boolean;             // scan PEM/TLS/cert config (default true)
  maxFileSize?: number;         // bytes; default 2 MiB
  onFile?: (file: string) => void; // progress callback (relative POSIX path)
}
```

### `walkFiles(root, options?): AsyncGenerator<string>`

Recursive async generator yielding scannable text files as **relative POSIX
paths**. Skips default-ignored directories (`node_modules`, `.git`, `dist`,
`build`, `.next`, `out`, `coverage`, `vendor`, `.turbo`, `.cache`), honours
`exclude` patterns (substring or path-prefix), skips obvious binaries by
extension, and skips files larger than `maxFileSize` (default 2 MiB). `root`
may be a single file.

```ts
for await (const file of walkFiles("./src", { exclude: ["legacy"] })) {
  console.log(file); // e.g. "components/Button.tsx"
}
```

### `detectors: Detector[]`

The built-in, pure detectors. Each declares `appliesTo(filePath)` and
`detect({ file, content })`. Detector families:

| Detector | Catches |
| --- | --- |
| `node-crypto` | `generateKeyPair(Sync)('rsa'\|'ec'\|'dsa'\|'dh'\|'x25519'\|'ed25519')`, `createSign/createVerify`, `createDiffieHellman`, `createECDH`, `publicEncrypt/privateDecrypt`, `diffieHellman` |
| `webcrypto` | `subtle.{generateKey,importKey,deriveKey,deriveBits,sign,verify}` with `RSA-OAEP`, `RSA-PSS`, `RSASSA-PKCS1-v1_5`, `ECDH`, `ECDSA` |
| `crypto-libs` | `node-forge` (`pki.rsa.generateKeyPair`, `ed25519`), `elliptic` (`new EC(...)`), `jsrsasign`, `node-rsa` |
| `jwt-jose` | JWT/JOSE alg strings: `RS256/384/512`, `PS256/384/512`, `ES256/384/512`, `EdDSA` |
| `tls-config` | `minVersion/secureProtocol: 'TLSv1'/'TLSv1.1'`, `rejectUnauthorized: false`, weak ciphers (RC4/DES/3DES/MD5/NULL/EXPORT) |
| `pem-material` | PEM keys/certs in any file: `RSA/EC/PKCS#8/OPENSSH PRIVATE KEY`, `CERTIFICATE` |

### `vulnerableDependencies: VulnerableDependency[]`

Curated database (~20 entries) of npm packages whose purpose is classical
asymmetric crypto: `node-forge`, `elliptic`, `jsrsasign`, `node-rsa`, `ursa`,
`sshpk`, `jsonwebtoken`, `jose`, `jws`, `eccrypto`, `secp256k1`, `tweetnacl`,
`ed25519`, `@noble/curves`, `@noble/secp256k1`, `@noble/ed25519`, `paseto`,
`bcrypto`, `ecpair`, `keypair`. `scan()` matches these against `package.json`
and `package-lock.json` and emits `category: "dependency"` findings located at
the manifest.

### `buildInventory(findings: Finding[]): CryptoInventory`

Aggregates findings into per-algorithm / per-category / per-severity counts, the
HNDL count, and a `readinessScore` (0–100, 100 = no classical asymmetric crypto
found). The score starts at 100 and subtracts severity-weighted penalties with
diminishing returns per severity bucket, clamped to `[0, 100]`.

### Reporters

- `toSarif(result): SarifLog` — valid **SARIF 2.1.0** (`$schema`, `version`,
  `runs[0].tool.driver { name: "qScan", informationUri, version, rules[] }`,
  `results[]` with `ruleId`, `level` (error/warning/note), `message.text`,
  `locations[].physicalLocation` with `artifactLocation.uri` and
  `region.startLine/startColumn`).
- `toJson(result): Record<string, unknown>` — clean, JSON-serialisable object.
- `formatSummary(result, { color? }): string` — human report with the readiness
  score, severity/algorithm breakdown, top findings, and an HNDL note. Colour is
  off by default and uses raw ANSI codes when enabled.

### `remediationFor(algorithm: AlgorithmFamily): Remediation | undefined`

Returns the recommended PQC replacement for a classical family.

```ts
remediationFor("ECDH");
// { algorithm: "ECDH",
//   recommendation: "hybrid X25519MLKEM768 (ML-KEM-768)",
//   detail: "Elliptic-curve Diffie-Hellman is broken by Shor's algorithm…" }
```

### `VERSION: string`

Tool version surfaced in reports (kept in sync with `package.json`).

## Core types

See [`src/types.ts`](./src/types.ts) for the locked contract. Highlights:

```ts
type Severity = "critical" | "high" | "medium" | "low" | "info";

type AlgorithmFamily =
  | "RSA" | "ECDH" | "ECDSA" | "EdDSA"
  | "DH"  | "DSA"  | "X25519" | "ECIES" | "unknown";

type FindingCategory =
  | "kem" | "key-exchange" | "signature"
  | "tls" | "certificate"  | "dependency" | "hash" | "rng";

interface Finding {
  ruleId: string;
  title: string;
  category: FindingCategory;
  severity: Severity;
  confidence: "high" | "medium" | "low";
  algorithm?: AlgorithmFamily;
  hndl: boolean;          // harvest-now-decrypt-later exposure
  message: string;
  remediation?: string;
  location: { file: string; line: number; column?: number; endLine?: number; snippet?: string };
}

interface CryptoInventory {
  byAlgorithm: Partial<Record<AlgorithmFamily, number>>;
  byCategory: Partial<Record<FindingCategory, number>>;
  bySeverity: Record<Severity, number>;
  hndlCount: number;
  readinessScore: number; // 0–100
}
```

## Example

A runnable example lives in [`examples/scan-example.mjs`](./examples/scan-example.mjs):

```bash
node examples/scan-example.mjs ./path/to/project
```

## Development

```bash
npm run build   # tsc -b
npm test        # node --import tsx --test test/*.test.ts
```

Tests use only `node:test` + `node:assert`. The package has **zero runtime
dependencies**.

## License

Apache-2.0
