/**
 * Zero-dependency command-line argument parsing for qScan.
 *
 * Hand-rolled rather than pulled from a library to keep the package free of
 * runtime dependencies. The grammar is deliberately small: long flags
 * (`--flag`, `--flag value`, `--flag=value`), a couple of short aliases
 * (`-o`, `-v`, `-h`), repeatable `--ignore`, and a single optional positional
 * path. Unknown flags are a usage error.
 */

import type { ReportFormat, Severity } from "@qproof/core";

/** Severities ordered most → least severe; index 0 is the most severe. */
export const SEVERITY_ORDER: readonly Severity[] = ["critical", "high", "medium", "low", "info"];

/**
 * Output formats qScan accepts on the command line. Extends core's
 * {@link ReportFormat} with `"cbom"` (a CycloneDX cryptographic bill of
 * materials), which qScan renders locally via core's `toCbom`.
 */
export type QscanFormat = ReportFormat | "cbom";

const FORMATS: readonly QscanFormat[] = ["human", "json", "sarif", "cbom"];

/** Fully-resolved options the CLI/programmatic runner operates on. */
export interface QscanOptions {
  /** Directory or file to scan. */
  path: string;
  /** Report format. */
  format: QscanFormat;
  /** Write the report to this file instead of stdout, when set. */
  output?: string;
  /** Findings at or above this severity cause a non-zero exit. */
  severityThreshold: Severity;
  /** Scan source files for inline crypto usage. */
  source: boolean;
  /** Scan dependency manifests for vulnerable libraries. */
  dependencies: boolean;
  /** Scan config files (TLS/certificates). */
  config: boolean;
  /** Extra exclude patterns (repeatable `--ignore`). */
  ignore: string[];
  /**
   * Restrict the walk to paths matching one of these include patterns
   * (repeatable `--include`). When empty, every non-excluded file is scanned.
   */
  include: string[];
  /** Max file size to read, in bytes (`--max-file-size`). */
  maxFileSize?: number;
  /** Disable the built-in ignore list (`--no-default-ignores`). */
  noDefaultIgnores: boolean;
  /** Scan minified/generated/bundled files instead of skipping them. */
  scanMinified: boolean;
  /**
   * Incremental mode: scan only the files git reports as changed
   * (`--changed`), optionally relative to {@link since}.
   */
  changed: boolean;
  /** Git ref/range the `--changed` diff is taken against (`--since`). */
  since?: string;
  /** Route the scan through core's worker-thread pool (`--parallel`). */
  parallel: boolean;
  /**
   * Worker count for parallel scanning (`--concurrency`). Implies parallel.
   * A value of 0 or 1 forces the in-process serial path.
   */
  concurrency?: number;
  /** Suppress findings whose fingerprint is in this baseline file. */
  baseline?: string;
  /** Write current findings as a baseline to this file, then exit 0. */
  writeBaseline?: string;
  /** Suppress the human summary banner (still writes reports/output files). */
  quiet: boolean;
  /**
   * Explicit path to a `qproof.config.json` (`--config <path>`). Overrides
   * auto-discovery at the scan root. Distinct from `--no-config`, which toggles
   * config/TLS *detector* scanning — this names the config FILE.
   */
  configFile?: string;
  /**
   * Disable `qproof.config.json` auto-discovery (`--no-config-file`). Distinct
   * from `--no-config` (which skips config-file *detectors*).
   */
  noConfigFile: boolean;
}

/**
 * Option keys that a `qproof.config.json` may also set. When such a key was set
 * by a CLI flag, the flag wins (precedence: flags > config > defaults); when it
 * was left at its default, config may fill it. {@link parseArgs} records which
 * of these keys came from an explicit flag in {@link ParsedRun.explicit}.
 */
export type ConfigurableKey =
  | "severityThreshold"
  | "source"
  | "dependencies"
  | "config"
  | "include"
  | "ignore"
  | "maxFileSize"
  | "noDefaultIgnores"
  | "scanMinified"
  | "baseline";

/** A successful parse: resolved options plus which configurable keys were explicit. */
export interface ParsedRun {
  kind: "run";
  options: QscanOptions;
  /** The set of {@link ConfigurableKey}s the user set via a flag. */
  explicit: Set<ConfigurableKey>;
}

/** Result of {@link parseArgs}: either resolved options or a meta action. */
export type ParsedArgs = ParsedRun | { kind: "help" } | { kind: "version" };

/** Thrown on malformed input; the CLI maps this to exit code 2. */
export class ArgError extends Error {
  override readonly name = "ArgError";
}

/** Default options, before any flags are applied. */
export function defaultOptions(): QscanOptions {
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
    noConfigFile: false,
  };
}

/**
 * Parse a raw argv slice (i.e. without `node` and the script path).
 *
 * @throws {ArgError} On unknown flags, missing values, or invalid enum values.
 */
export function parseArgs(argv: readonly string[]): ParsedArgs {
  const options = defaultOptions();
  const explicit = new Set<ConfigurableKey>();
  let positional: string | undefined;

  // Manual index walk so flags can consume the following token as a value.
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i] as string;

    // `--flag=value` → split into flag + inline value.
    let inlineValue: string | undefined;
    let flag = arg;
    if (arg.startsWith("--") && arg.includes("=")) {
      const eq = arg.indexOf("=");
      flag = arg.slice(0, eq);
      inlineValue = arg.slice(eq + 1);
    }

    /** Consume a value for `flag`: prefer the inline `=value`, else the next token. */
    const takeValue = (): string => {
      if (inlineValue !== undefined) return inlineValue;
      const next = argv[i + 1];
      if (next === undefined || (next.startsWith("-") && next !== "-")) {
        throw new ArgError(`option "${flag}" requires a value`);
      }
      i++;
      return next;
    };

    switch (flag) {
      case "-h":
      case "--help":
        return { kind: "help" };
      case "-v":
      case "--version":
        return { kind: "version" };

      case "--format":
        options.format = asFormat(takeValue());
        break;
      case "--cbom":
        options.format = "cbom";
        break;
      case "-o":
      case "--output":
        options.output = takeValue();
        break;
      case "--severity-threshold":
        options.severityThreshold = asSeverity(takeValue());
        explicit.add("severityThreshold");
        break;

      case "--no-source":
        options.source = false;
        explicit.add("source");
        break;
      case "--no-deps":
        options.dependencies = false;
        explicit.add("dependencies");
        break;
      case "--no-config":
        options.config = false;
        explicit.add("config");
        break;

      case "--ignore":
        options.ignore.push(takeValue());
        explicit.add("ignore");
        break;
      case "--include":
        options.include.push(takeValue());
        explicit.add("include");
        break;
      case "--max-file-size":
        options.maxFileSize = asInt(takeValue(), "--max-file-size");
        explicit.add("maxFileSize");
        break;
      case "--no-default-ignores":
        options.noDefaultIgnores = true;
        explicit.add("noDefaultIgnores");
        break;
      case "--scan-minified":
        options.scanMinified = true;
        explicit.add("scanMinified");
        break;

      // `qproof.config.json` FILE controls (distinct from `--no-config`, which
      // toggles config/TLS *detector* scanning above).
      case "--config":
        options.configFile = takeValue();
        break;
      case "--no-config-file":
        options.noConfigFile = true;
        break;

      case "--changed":
        options.changed = true;
        break;
      case "--since":
        options.since = takeValue();
        options.changed = true; // --since implies incremental mode
        break;

      case "--parallel":
        options.parallel = true;
        break;
      case "--concurrency":
        options.concurrency = asInt(takeValue(), "--concurrency");
        options.parallel = true; // an explicit worker count implies parallel
        break;

      case "--baseline":
        options.baseline = takeValue();
        explicit.add("baseline");
        break;
      case "--write-baseline":
        options.writeBaseline = takeValue();
        break;
      case "--quiet":
        options.quiet = true;
        break;

      default:
        if (flag.startsWith("-") && flag !== "-") {
          throw new ArgError(`unknown option "${flag}"`);
        }
        if (positional !== undefined) {
          throw new ArgError(
            `unexpected extra argument "${arg}" (path already set to "${positional}")`,
          );
        }
        positional = arg;
        break;
    }
  }

  if (positional !== undefined) options.path = positional;
  return { kind: "run", options, explicit };
}

/** Validate/normalize a `--format` value. */
export function asFormat(value: string): QscanFormat {
  if ((FORMATS as readonly string[]).includes(value)) return value as QscanFormat;
  throw new ArgError(`invalid --format "${value}" (expected one of: ${FORMATS.join(", ")})`);
}

/** Validate/normalize a non-negative integer flag value. */
export function asInt(value: string, flag: string): number {
  if (!/^\d+$/.test(value)) {
    throw new ArgError(`invalid ${flag} "${value}" (expected a non-negative integer)`);
  }
  return Number.parseInt(value, 10);
}

/** Validate/normalize a severity value. */
export function asSeverity(value: string): Severity {
  if ((SEVERITY_ORDER as readonly string[]).includes(value)) return value as Severity;
  throw new ArgError(`invalid severity "${value}" (expected one of: ${SEVERITY_ORDER.join(", ")})`);
}

/**
 * Rank a severity: lower number = more severe.
 * `critical` → 0, `info` → 4.
 */
export function severityRank(severity: Severity): number {
  return SEVERITY_ORDER.indexOf(severity);
}

/**
 * Whether `severity` is at or above `threshold` in seriousness.
 * E.g. `high` meets a `medium` threshold; `low` does not.
 */
export function meetsThreshold(severity: Severity, threshold: Severity): boolean {
  return severityRank(severity) <= severityRank(threshold);
}
