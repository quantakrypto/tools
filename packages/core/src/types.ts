/**
 * @quantakrypto/core — shared types (the locked public contract).
 *
 * These types are the stable interface between every tool in the monorepo
 * (qScan, the MCP server, the GitHub Action). Treat additions as backwards
 * compatible; treat renames/removals as breaking.
 */

/** How serious a finding is, ordered most → least severe. */
export type Severity = "critical" | "high" | "medium" | "low" | "info";

/** How sure the detector is that the finding is a real use of the algorithm. */
export type Confidence = "high" | "medium" | "low";

/** What kind of cryptographic concern a finding represents. */
export type FindingCategory =
  | "kem" // key encapsulation / public-key encryption (e.g. RSA-OAEP)
  | "key-exchange" // (EC)DH
  | "signature" // RSA/ECDSA/EdDSA signing
  | "tls" // transport configuration
  | "certificate" // X.509 / PKI material
  | "dependency" // a quantum-vulnerable library in the dependency tree
  | "hash" // weak / pre-quantum hash usage
  | "rng"; // randomness concerns

/** Classical asymmetric algorithm families that are not quantum-safe. */
export type AlgorithmFamily =
  | "RSA"
  | "ECDH"
  | "ECDSA"
  | "EdDSA"
  | "DH"
  | "DSA"
  | "X25519"
  | "X448"
  | "ECIES"
  | "unknown";

/** A precise location inside a scanned file. */
export interface SourceLocation {
  /** Path relative to the scan root, using POSIX separators. */
  file: string;
  /** 1-based line number. */
  line: number;
  /** 1-based column number, if known. */
  column?: number;
  /** 1-based end line, for multi-line matches. */
  endLine?: number;
  /** The matched source text (trimmed, single line). */
  snippet?: string;
}

/** A single detected concern. */
export interface Finding {
  /** Stable rule identifier, e.g. "rsa-keygen", "ecdh-usage", "tls-legacy-version", "dep-vulnerable". */
  ruleId: string;
  title: string;
  category: FindingCategory;
  severity: Severity;
  confidence: Confidence;
  /** The classical algorithm involved, when applicable. */
  algorithm?: AlgorithmFamily;
  /** True when this is exposed to "harvest now, decrypt later". */
  hndl: boolean;
  /** One-line human explanation of the concern. */
  message: string;
  /** Suggested post-quantum remediation (e.g. ML-KEM, hybrid X25519MLKEM768). */
  remediation?: string;
  /** Associated CWE identifier, e.g. "CWE-327" (broken crypto), "CWE-326" (weak strength). */
  cwe?: string;
  /**
   * True when the matched snippet IS the sensitive value (e.g. a PEM private/
   * public key block, an `ssh-rsa AAAA…` public key). Reporters ALWAYS drop the
   * snippet for such findings, regardless of any redaction flag.
   */
  sensitive?: boolean;
  location: SourceLocation;
}

/** A known quantum-vulnerable dependency entry. */
export interface VulnerableDependency {
  /** Package name. */
  name: string;
  ecosystem: "npm";
  /** Why it's flagged (what classical crypto it provides). */
  reason: string;
  /** Algorithm families the package primarily exposes. */
  algorithms: AlgorithmFamily[];
  severity: Severity;
}

/**
 * Which logical scope a detector belongs to. Drives the source/config scope
 * toggles in {@link ScanOptions} (replacing the old ruleId-prefix inference).
 */
export type DetectorScope = "source" | "config";

/**
 * The programming language / surface a detector targets. `"any"` means the
 * detector is language-agnostic (e.g. PEM material, config files).
 */
export type DetectorLanguage = "js" | "python" | "go" | "java" | "any";

/** A pluggable source detector. Detectors are pure and stateless. */
export interface Detector {
  /** Unique id, used as the Finding.ruleId prefix space. */
  id: string;
  /** Human description of what the detector looks for. */
  description: string;
  /**
   * Logical scope of this detector's findings. Used by `scan()` to honour the
   * `config` / `source` toggles. Defaults to `"source"` when omitted (for
   * backward compatibility with externally-defined detectors).
   */
  scope?: DetectorScope;
  /**
   * Language this detector targets, for documentation / registry filtering.
   * Defaults to `"js"` when omitted.
   */
  language?: DetectorLanguage;
  /** Whether this detector should run against the given file path. */
  appliesTo(filePath: string): boolean;
  /** Inspect a single file's contents and return zero or more findings. */
  detect(input: DetectorInput): Finding[];
}

export interface DetectorInput {
  /** Path relative to the scan root (POSIX). */
  file: string;
  /** Full file contents. */
  content: string;
}

/** Options controlling a scan. */
export interface ScanOptions {
  /** Absolute or relative directory (or single file) to scan. */
  root: string;
  /**
   * Restrict the walk to paths matching one of these include patterns
   * (substring or relative-path-prefix match). When omitted, all non-excluded
   * files are scanned. Wired into the walker.
   */
  include?: string[];
  /** Extra exclude patterns (in addition to the built-in defaults). */
  exclude?: string[];
  /** Disable the built-in ignore list (node_modules, .git, dist, …). */
  noDefaultIgnores?: boolean;
  /** Scan source files for inline crypto usage. Default: true. */
  source?: boolean;
  /** Scan dependency manifests/lockfiles for vulnerable libraries. Default: true. */
  dependencies?: boolean;
  /** Scan config files (TLS, certificates). Default: true. */
  config?: boolean;
  /** Max file size to read, in bytes. Default: 2 MiB. */
  maxFileSize?: number;
  /**
   * Scan minified / generated / bundled files (large single-line content)
   * instead of skipping them. Default: false (skip them for speed).
   */
  scanMinified?: boolean;
  /**
   * Explicit relative file list (POSIX, relative to `root`) to scan instead of
   * walking the tree. Used for incremental / changed-files scans. Each path is
   * still subject to the binary / size filters. When set, the directory walk is
   * bypassed entirely.
   */
  files?: string[];
  /**
   * Override / extend the built-in detector set. When omitted, the default
   * registry's detectors are used.
   */
  detectors?: Detector[];
  /** Optional progress callback. */
  onFile?: (file: string) => void;
  /**
   * Optional abort signal. When it fires mid-walk the scan stops cooperatively
   * and rejects with an `AbortError` (a `DOMException`-like error with
   * `name === "AbortError"`).
   */
  signal?: AbortSignal;
  /**
   * Work budget: maximum number of files to scan. When exceeded mid-walk the
   * scan stops and throws a `BudgetExceededError`. Unlimited when omitted.
   */
  maxFiles?: number;
  /**
   * Work budget: maximum cumulative bytes of scanned file content. When
   * exceeded mid-walk the scan stops and throws a `BudgetExceededError`.
   * Unlimited when omitted.
   */
  maxBytes?: number;
}

/** Extra options for {@link scanParallel}, layered onto {@link ScanOptions}. */
export interface ParallelScanOptions extends ScanOptions {
  /**
   * Number of worker threads. Default: `os.availableParallelism()`. A value of
   * 0 or 1 forces the in-process serial path.
   */
  concurrency?: number;
  /**
   * Combined-size floor (bytes) below which the scan always runs in-process.
   * Default: 2 MiB. Also stays serial below `parallelFileThreshold` files.
   */
  parallelThresholdBytes?: number;
  /** File-count floor below which the scan always runs in-process. Default: 200. */
  parallelFileThreshold?: number;
  /** Target bytes per worker chunk. Default: 4 MiB. */
  chunkBytes?: number;
}

/** Aggregated counts produced from a scan's findings. */
export interface CryptoInventory {
  byAlgorithm: Partial<Record<AlgorithmFamily, number>>;
  byCategory: Partial<Record<FindingCategory, number>>;
  bySeverity: Record<Severity, number>;
  /** Number of findings exposed to harvest-now-decrypt-later. */
  hndlCount: number;
  /** 0–100 readiness score (100 = no classical asymmetric crypto found). */
  readinessScore: number;
}

/** The full result of a scan. */
export interface ScanResult {
  /** The scan root (as provided). */
  root: string;
  findings: Finding[];
  filesScanned: number;
  inventory: CryptoInventory;
  /** ISO timestamps. */
  startedAt: string;
  finishedAt: string;
  /** Tool version that produced the result. */
  toolVersion: string;
}

/** Output formats qScan / reporters can emit. */
export type ReportFormat = "human" | "json" | "sarif";

/** A remediation recommendation for a classical algorithm. */
export interface Remediation {
  algorithm: AlgorithmFamily;
  /** Short recommended replacement, e.g. "ML-KEM-768 (hybrid X25519MLKEM768)". */
  recommendation: string;
  /** Longer rationale. */
  detail: string;
}
