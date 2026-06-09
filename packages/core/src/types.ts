/**
 * @qproof/core — shared types (the locked public contract).
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

/** A pluggable source detector. Detectors are pure and stateless. */
export interface Detector {
  /** Unique id, used as the Finding.ruleId prefix space. */
  id: string;
  /** Human description of what the detector looks for. */
  description: string;
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
  /** Extra glob-ish include patterns (substring/relative-prefix match). */
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
  /** Optional progress callback. */
  onFile?: (file: string) => void;
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
