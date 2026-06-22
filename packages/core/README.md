# @quantakrypto/core

Shared post-quantum readiness library for the quantakrypto toolchain. It finds
**classical, non-quantum-safe asymmetric cryptography** in a codebase — inline
crypto calls, embedded keys/certificates, and quantum-vulnerable npm
dependencies — and turns the results into an inventory, a readiness score, and
machine- or human-readable reports.

- **Zero runtime dependencies.** Node built-ins only.
- **ESM + NodeNext**, TypeScript strict, Node ≥ 20.
- Powers `@quantakrypto/qscan` (CLI), the MCP server, and the GitHub Action.

## Why it exists

Shor's algorithm breaks RSA, (EC)DH, ECDSA, DSA and EdDSA. Two threats follow:

- **Harvest now, decrypt later (HNDL).** Traffic protected by classical key
  exchange / public-key encryption (ECDH, DH, RSA-OAEP) can be recorded today
  and decrypted once a cryptographically relevant quantum computer exists.
  Findings carry an `hndl: true` flag.
- **Forgery.** Classical signatures (RSA-PSS, ECDSA, EdDSA, DSA, JWT `RS*/PS*/ES*/EdDSA`)
  can be forged by a quantum attacker. These are `hndl: false` but still high
  severity.

`@quantakrypto/core` flags both, and points each finding at a NIST PQC replacement
(ML-KEM / FIPS 203, ML-DSA / FIPS 204, SLH-DSA / FIPS 205, hybrid
`X25519MLKEM768`).

## Install

```bash
npm install @quantakrypto/core
```

## Quick start

```ts
import { scan, formatSummary, toSarif, toJson } from "@quantakrypto/core";

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
  include?: string[];           // restrict the walk to matching paths (substring/prefix)
  exclude?: string[];           // extra exclude patterns (substring/prefix)
  noDefaultIgnores?: boolean;   // disable node_modules/.git/dist/… ignores
  source?: boolean;             // scan source files (default true)
  dependencies?: boolean;       // scan package.json / package-lock.json (default true)
  config?: boolean;             // scan PEM/TLS/cert config (default true)
  maxFileSize?: number;         // bytes; default 2 MiB (manifests are exempt)
  scanMinified?: boolean;       // scan minified/generated files (default false: skip them)
  files?: string[];             // explicit relative file list (incremental scans)
  detectors?: Detector[];       // override/extend the built-in detector set
  onFile?: (file: string) => void; // progress callback (relative POSIX path)
}
```

- **`include`** is now wired into the walker: when set, only paths matching one
  of the patterns are scanned.
- **`files`** bypasses the directory walk entirely and scans the given relative
  paths (used for incremental / changed-files scans — pair it with
  `changedFiles`). Binary and missing files are skipped; manifests over the size
  cap are still read.
- **`scanMinified`** is off by default; machine-minified / generated / bundled
  content (`*.bundle.js`, `*.generated.ts`, long single-line files, …) is
  skipped for speed unless you opt in.

### `scanParallel(options): Promise<ScanResult>`

A worker-thread pool over the file list with a **deterministic** result merge
(byte-identical to `scan`). Falls back automatically to the in-process `scan`
for small workloads (below ~200 files / ~2 MiB) and whenever `worker_threads`
is unavailable. Extra options:

```ts
interface ParallelScanOptions extends ScanOptions {
  concurrency?: number;            // worker count; default os.availableParallelism()
  parallelThresholdBytes?: number; // serial below this total size (default 2 MiB)
  parallelFileThreshold?: number;  // serial below this file count (default 200)
  chunkBytes?: number;             // target bytes per worker chunk (default 4 MiB)
}
```

### `changedFiles(root, since?): Promise<string[]>`

Returns relative POSIX paths that changed in a git work tree (uncommitted +
untracked, plus a `since` ref/range when provided). Tolerant of non-git
directories — returns `[]`. Feed the result into `ScanOptions.files` for
incremental scans.

```ts
const files = await changedFiles(".", "origin/main...HEAD");
const result = await scan({ root: ".", files });
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

### `detectors: Detector[]` / `defaultRegistry` / `DetectorRegistry`

The built-in, pure detectors. Each declares a `scope` (`"source"` | `"config"`),
a `language`, `appliesTo(filePath)`, and `detect({ file, content })`. `scan()`
drives the source/config scope toggles from the detector's **declared `scope`**
(not from ruleId prefixes). Detector families:

| Detector | Scope | Catches |
| --- | --- | --- |
| `node-crypto` | source | `generateKeyPair(Sync)('rsa'\|'ec'\|'dsa'\|'dh'\|'x25519'\|'x448'\|'ed25519'\|'ed448')`, `createSign/createVerify`, one-shot `crypto.sign/verify`, `createDiffieHellman`, `getDiffieHellman('modpN')`, `createECDH`, `publicEncrypt/privateDecrypt`, `diffieHellman` |
| `webcrypto` | source | `subtle.{generateKey,importKey,deriveKey,deriveBits,sign,verify,…}` with `RSA-OAEP`, `RSA-PSS`, `RSASSA-PKCS1-v1_5`, `ECDH`, `ECDSA` |
| `crypto-libs` | source | `node-forge` (`pki.rsa.generateKeyPair`, `ed25519`), `elliptic` (`new EC(...)`), `jsrsasign`, `node-rsa`, direct `secp256k1.*` usage |
| `jwt-jose` | source | JWT/JOSE alg strings (`RS/PS/ES*`, `EdDSA`) and `ECDH-ES*` key agreement (HNDL) |
| `tls-config` | config | `minVersion/secureProtocol: 'TLSv1'/'TLSv1.1'`, `rejectUnauthorized: false`, weak ciphers (RC4/DES/3DES/MD5/NULL/EXPORT) |
| `pem-material` | config | PEM keys/certs in any file: `RSA/EC/DSA/PKCS#8/OPENSSH/PGP PRIVATE KEY`, `PGP MESSAGE`, `CERTIFICATE` |
| `ssh-cert` | config | SSH public keys (`ssh-rsa`, `ssh-ed25519`, `ecdsa-sha2-*`) and X.509 certificate signature algorithms (`sha256WithRSAEncryption`, `ecdsa-with-SHA256`, …) |

`defaultRegistry` is a `DetectorRegistry` preloaded with these built-ins. The
registry is the plugin point:

```ts
import { DetectorRegistry, defaultRegistry, scan } from "@quantakrypto/core";

const registry = defaultRegistry.clone().register(myDetector);
const result = await scan({ root: ".", detectors: registry.all() });
```

`DetectorRegistry` exposes `register(d)`, `get(id)`, `has(id)`, `all()` and
`clone()`. Ids must be unique (duplicate registration throws).

#### Adding a detector / language

1. Create `src/detectors/<lang>.ts` exporting one or more `Detector`s. Set
   `language` (`"js" | "python" | "go" | "java" | "any"`), `scope`
   (`"source" | "config"`), an `appliesTo(path)` extension check, and a pure
   `detect({ file, content })` returning `Finding[]` (use `makeFinding` from
   `detect-utils` for consistent location/remediation/CWE handling).
2. If the language uses new file extensions, ensure the walker treats them as
   text (they are scanned unless listed as binary in `walk.ts`).
3. For a new dependency ecosystem, extend `VulnerableDependency.ecosystem` and
   add a manifest matcher in `dependencies.ts`.
4. Register it: `defaultRegistry.register(myDetector)`, or pass
   `{ detectors: [...] }` to `scan`. No edit to `scan()` is required — scope is
   honoured from the detector's declared `scope`.

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

### `remediationFor(algorithm): Remediation | undefined` / `remediationForTier(algorithm, tier?)`

`remediationFor` returns the recommended PQC replacement for a classical family.
`remediationForTier` adds a **security tier**: `"category-3"` (default,
commercial — ML-KEM-768 / ML-DSA-65) or `"category-5"` (CNSA 2.0 / long-lived —
ML-KEM-1024 / ML-DSA-87).

```ts
remediationFor("ECDH");
// { algorithm: "ECDH", recommendation: "hybrid X25519MLKEM768 (ML-KEM-768)", detail: … }

remediationForTier("ECDH", "category-5");
// recommendation mentions ML-KEM-1024; detail cites CNSA 2.0 (2030/2033 milestones)
```

`STATEFUL_HBS_NOTE` / `statefulHbsApplies(algorithm)` surface the SP 800-208
stateful hash-based signatures (LMS / XMSS / HSS) guidance for firmware / boot
signing (stateful — use only with rigorous state management).

### Baseline (`fingerprintFinding`, `baselineFromFindings`, `applyBaseline`, `loadBaseline`, `saveBaseline`)

The single canonical baseline scheme shared by qScan and the Action. A baseline
is `{ version, fingerprints: string[] }`. A fingerprint is the SHA-256 hex of
`ruleId|file|normalizedSnippet` — **line-insensitive** (survives line shifts)
and snippet-whitespace-normalized (survives reformatting).

```ts
import { saveBaseline, loadBaseline, applyBaseline } from "@quantakrypto/core";

await saveBaseline(".quantakrypto-baseline.json", result.findings);          // write
const baseline = await loadBaseline(".quantakrypto-baseline.json");          // read (tolerant)
const { newFindings, suppressed } = applyBaseline(result.findings, baseline);
```

### `toCbom(result): CycloneDxBom`

A CycloneDX 1.6 **cryptographic bill of materials** (CBOM): one
`cryptographic-asset` component per distinct (algorithm, primitive) pair, with
occurrence evidence and `quantumVulnerable` / `harvestNowDecryptLater` flags.
Deterministic output.

### CWE tagging

Every detector sets a `Finding.cwe` (`CWE-327` broken crypto, `CWE-326` weak
strength, `CWE-295` cert validation, `CWE-798` hardcoded key). `toSarif` maps it
into `rules[].properties`, result `taxa`, and a run-level CWE `taxonomies`
component; `toJson` includes it. Constants are exported (`CWE_BROKEN_CRYPTO`, …).

### `VERSION: string`

Tool version surfaced in reports (kept in sync with `package.json`).

## API reference

| Export | Kind | Summary |
| --- | --- | --- |
| `scan` | fn | Scan a dir / file / explicit file list → `ScanResult` |
| `scanParallel` | fn | Worker-pool scan with deterministic merge + serial fallback |
| `changedFiles` | fn | Git-aware changed-files list for incremental scans |
| `detectFile` | fn | Pure per-file detect (used by workers / tests) |
| `compareFindings` | fn | Stable finding comparator (file → line → ruleId) |
| `mergeChunkResults`, `chunkByBytes` | fn | Pure parallel merge / byte-chunking helpers |
| `walkFiles`, `isBinaryPath`, `isGeneratedPath`, `looksMinified` | fn | Walker + file-classification helpers |
| `detectors` | const | Built-in detector array (mirrors `defaultRegistry.all()`) |
| `DetectorRegistry`, `defaultRegistry`, `detectorScope` | class/const/fn | Detector plugin point |
| `buildInventory` | fn | Aggregate findings → `CryptoInventory` |
| `vulnerableDependencies` | const | Curated quantum-vulnerable npm DB |
| `toSarif`, `toJson`, `formatSummary` | fn | Reporters (SARIF 2.1.0 / JSON / human) |
| `toCbom` | fn | CycloneDX 1.6 CBOM export |
| `remediationFor`, `remediationForTier`, `TIER_PARAMS` | fn/const | PQC remediation (family + CNSA tier) |
| `STATEFUL_HBS_NOTE`, `statefulHbsApplies` | const/fn | SP 800-208 LMS/XMSS guidance |
| `fingerprintFinding`, `baselineFromFindings`, `applyBaseline`, `loadBaseline`, `saveBaseline`, `BASELINE_VERSION` | fn/const | Canonical baseline |
| `CWE_BROKEN_CRYPTO`, `CWE_WEAK_STRENGTH`, `CWE_CERT_VALIDATION`, `CWE_HARDCODED_KEY`, `CWE_RISKY_PRIMITIVE` | const | CWE identifiers |
| `VERSION` | const | Tool version |

Types: `Finding` (now with optional `cwe`), `ScanOptions`/`ParallelScanOptions`,
`ScanResult`, `Detector` (now with `scope`/`language`), `DetectorScope`,
`DetectorLanguage`, `Baseline`, `CycloneDxBom`, `CbomComponent`, `SecurityTier`,
`AlgorithmFamily` (now includes `X448`), and the rest of the locked contract in
[`src/types.ts`](./src/types.ts).

## Core types

See [`src/types.ts`](./src/types.ts) for the locked contract. Highlights:

```ts
type Severity = "critical" | "high" | "medium" | "low" | "info";

type AlgorithmFamily =
  | "RSA" | "ECDH" | "ECDSA" | "EdDSA"
  | "DH"  | "DSA"  | "X25519" | "X448" | "ECIES" | "unknown";

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
  cwe?: string;           // e.g. "CWE-327"
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

## Support & training

Questions, commercial support, or post-quantum readiness training for your team —
visit **[quantakrypto.com](https://quantakrypto.com)** or email
**[hello@quantakrypto.com](mailto:hello@quantakrypto.com)**.
