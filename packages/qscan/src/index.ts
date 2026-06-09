/**
 * @qproof/qscan — programmatic API.
 *
 * `runQscan` is the single entry point shared by the CLI (`src/cli.ts`) and by
 * `@qproof/action`. It runs a scan via `@qproof/core`, applies an optional
 * baseline, decides an exit code from the severity threshold, and (optionally)
 * renders a report. The CLI is a thin shell around it.
 *
 * The module also re-exports the argument-parsing and baseline helpers so
 * downstream tools can reuse them without reaching into internal paths.
 */

import { scan } from "@qproof/core";
import type { Finding, ScanOptions, ScanResult } from "@qproof/core";

import { applyBaseline, buildBaseline, readBaseline, writeBaseline } from "./baseline.js";
import type { BaselineFile } from "./baseline.js";
import { defaultOptions, meetsThreshold } from "./args.js";
import type { QscanOptions } from "./args.js";
import { renderHuman, renderJson, renderSarif } from "./report.js";

export type { QscanOptions, ParsedArgs } from "./args.js";
export type { BaselineFile } from "./baseline.js";
export {
  ArgError,
  asFormat,
  asSeverity,
  defaultOptions,
  meetsThreshold,
  parseArgs,
  severityRank,
  SEVERITY_ORDER,
} from "./args.js";
export {
  applyBaseline,
  BASELINE_VERSION,
  buildBaseline,
  fingerprint,
  fingerprint as fingerprintFinding,
  readBaseline,
  writeBaseline,
} from "./baseline.js";
export { renderHuman, renderJson, renderSarif } from "./report.js";
export { HELP_TEXT, versionLine } from "./help.js";

/** Process-style exit codes qScan uses. */
export const EXIT = {
  /** No findings at/above threshold, or a baseline was written. */
  OK: 0,
  /** One or more findings at/above the severity threshold. */
  FINDINGS: 1,
  /** Usage error or I/O failure. */
  ERROR: 2,
} as const;

/** Outcome of {@link runQscan}. */
export interface QscanRun {
  /** The scan result, with the baseline already applied to `findings`. */
  result: ScanResult;
  /** Findings suppressed because their fingerprint was in the baseline. */
  suppressed: Finding[];
  /** Rendered report in the requested format (`undefined` for a baseline write). */
  report?: string;
  /** The baseline that was written, when `writeBaseline` was requested. */
  baselineWritten?: BaselineFile;
  /** Suggested process exit code. */
  exitCode: number;
}

/**
 * The scan implementation `runQscan` calls. Matches `@qproof/core`'s `scan`.
 * Injectable so the GitHub Action and tests can supply a custom scanner.
 */
export type ScanFn = (options: ScanOptions) => Promise<ScanResult>;

/** Behavioral hooks for {@link runQscan}, mainly for testing. */
export interface RunQscanHooks {
  /** Emit raw ANSI color in the human report. Default: false. */
  color?: boolean;
  /** Override the scanner. Default: `scan` from `@qproof/core`. */
  scanFn?: ScanFn;
}

/**
 * Run a complete qScan pass: scan → baseline → threshold → render.
 *
 * This never touches `process` or stdout; the CLI is responsible for printing
 * `report`/writing `output` and calling `process.exit(exitCode)`. That keeps
 * the function pure enough to unit-test and to embed in the GitHub Action.
 *
 * Behavior:
 *  - When `opts.writeBaseline` is set, the scan runs, a baseline is built from
 *    *all* findings, written to disk, and `exitCode` is {@link EXIT.OK}. No
 *    report is rendered.
 *  - When `opts.baseline` is set, its fingerprints are loaded and matching
 *    findings are moved to `suppressed` (and removed from `result.findings`).
 *  - `exitCode` is {@link EXIT.FINDINGS} when any *kept* finding meets the
 *    severity threshold, else {@link EXIT.OK}.
 *
 * @throws {Error} Propagates scan / baseline I/O errors; the CLI maps these to
 *   {@link EXIT.ERROR}.
 */
export async function runQscan(
  opts: Partial<QscanOptions> & { path: string },
  hooks: RunQscanHooks = {},
): Promise<QscanRun> {
  const options: QscanOptions = { ...defaultOptions(), ...opts };
  const scanFn: ScanFn = hooks.scanFn ?? scan;

  const result = await scanFn({
    root: options.path,
    exclude: options.ignore.length > 0 ? options.ignore : undefined,
    source: options.source,
    dependencies: options.dependencies,
    config: options.config,
  });

  // --write-baseline: snapshot every finding, persist, and exit cleanly.
  if (options.writeBaseline) {
    const baseline = buildBaseline(result.findings);
    await writeBaseline(options.writeBaseline, baseline);
    return {
      result,
      suppressed: [],
      baselineWritten: baseline,
      exitCode: EXIT.OK,
    };
  }

  // --baseline: suppress previously-accepted findings.
  let suppressed: Finding[] = [];
  if (options.baseline) {
    const accepted = await readBaseline(options.baseline);
    const split = applyBaseline(result.findings, accepted);
    result.findings = split.kept;
    suppressed = split.suppressed;
  }

  const exitCode = result.findings.some((f) =>
    meetsThreshold(f.severity, options.severityThreshold),
  )
    ? EXIT.FINDINGS
    : EXIT.OK;

  return {
    result,
    suppressed,
    report: renderReport(result, options.format, hooks.color ?? false),
    exitCode,
  };
}

/** Render a scan result in the requested format. */
export function renderReport(
  result: ScanResult,
  format: QscanOptions["format"],
  color = false,
): string {
  switch (format) {
    case "json":
      return renderJson(result);
    case "sarif":
      return renderSarif(result);
    case "human":
    default:
      return renderHuman(result, { color });
  }
}

/** Re-export the core result types consumers commonly need. */
export type { Finding, ScanResult } from "@qproof/core";
