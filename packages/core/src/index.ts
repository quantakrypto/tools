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
export { scan, detectors } from "./scan.js";

// Filesystem walker (relative POSIX paths, default ignores, size/binary filters).
export { walkFiles } from "./walk.js";

// Inventory + readiness score.
export { buildInventory } from "./inventory.js";

// Vulnerable-dependency database (the manifest scanner is used internally by scan()).
export { vulnerableDependencies } from "./dependencies.js";

// Reporters.
export { toSarif, toJson, formatSummary } from "./report.js";

// Remediation lookup.
export { remediationFor } from "./remediation.js";
