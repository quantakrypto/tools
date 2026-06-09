/**
 * @qproof/core — public API (LOCKED CONTRACT).
 *
 * The exported NAMES and SIGNATURES below are the stable contract that
 * @qproof/qscan, @qproof/mcp and the GitHub Action depend on — do not change
 * them without updating all consumers. The implementations live in focused
 * modules under src/ and are re-exported here; the public surface is identical
 * to the original stub file.
 */
export * from "./types.js";

// Tool version, surfaced in reports. Keep in sync with package.json.
export { VERSION } from "./version.js";

// Minimal SARIF 2.1.0 log shape, defined alongside the reporters.
export type { SarifLog } from "./report.js";

// Core orchestration + built-in detector set.
export { scan, detectors, detectFile, compareFindings } from "./scan.js";

// Parallel scanning (worker_threads pool) + pure merge/chunk helpers.
export { scanParallel, mergeChunkResults, chunkByBytes } from "./parallel.js";
export type { ScanChunk, ChunkResult, SizedFile } from "./parallel.js";

// Detector registry (plugin point) + helpers.
export { DetectorRegistry, defaultRegistry, detectorScope } from "./registry.js";

// Canonical baseline (shared by qScan + the Action).
export {
  fingerprintFinding,
  baselineFromFindings,
  applyBaseline,
  loadBaseline,
  saveBaseline,
  BASELINE_VERSION,
} from "./baseline.js";
export type { Baseline } from "./baseline.js";

// Incremental scanning: changed-files helper (git-aware, tolerant).
export { changedFiles } from "./changed.js";

// Optional `qproof.config.json` loader (P2-9; see docs/CONFIG.md).
export { loadConfig, ConfigError, CONFIG_FILENAME } from "./config.js";
export type { QproofFileConfig, LoadConfigResult } from "./config.js";

// Filesystem walker (relative POSIX paths, default ignores, size/binary filters).
export { walkFiles, isBinaryPath, isGeneratedPath, looksMinified } from "./walk.js";

// Inventory + readiness score.
export { buildInventory } from "./inventory.js";

// Vulnerable-dependency database (the manifest scanner is used internally by scan()).
export { vulnerableDependencies } from "./dependencies.js";

// Reporters.
export { toSarif, toJson, formatSummary } from "./report.js";

// CycloneDX 1.6 cryptographic bill of materials (CBOM) export.
export { toCbom } from "./cbom.js";
export type { CycloneDxBom, CbomComponent } from "./cbom.js";

// Remediation lookup (family + tier-aware) and stateful-HBS guidance.
export {
  remediationFor,
  remediationForTier,
  TIER_PARAMS,
  STATEFUL_HBS_NOTE,
  statefulHbsApplies,
} from "./remediation.js";
export type { SecurityTier } from "./remediation.js";

// CWE identifier constants.
export {
  CWE_BROKEN_CRYPTO,
  CWE_WEAK_STRENGTH,
  CWE_CERT_VALIDATION,
  CWE_HARDCODED_KEY,
  CWE_RISKY_PRIMITIVE,
} from "./cwe.js";
