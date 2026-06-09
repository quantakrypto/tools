/**
 * `qproof.config.json` loader (ROADMAP P2-9, see docs/CONFIG.md).
 *
 * Reads an optional project configuration file, validates the *types* of known
 * keys, ignores unknown keys (forward compatibility), and maps it onto a
 * `Partial<ScanOptions>` plus the two policy keys qScan consumes
 * (`severityThreshold`, `baseline`). It performs NO scanning and has no
 * side-effects beyond a single `readFile`.
 *
 * Precedence (resolved by the consumer, not here): flags > config > defaults.
 *
 * The parsed object is treated as **untrusted input** in the same spirit as a
 * scanned manifest (THREAT-MODEL Q-09): we only membership-test known keys and
 * never deep-merge the parsed object into anything.
 */
import { readFile } from "node:fs/promises";
import * as path from "node:path";

import type { ScanOptions, Severity } from "./types.js";

/** Canonical config file name discovered at a scan root. */
export const CONFIG_FILENAME = "qproof.config.json";

/** Severity levels accepted by `severityThreshold`, for validation. */
const SEVERITIES: readonly Severity[] = ["critical", "high", "medium", "low", "info"];

/** Detector-family toggle names recognised in the `detectors` object. */
const DETECTOR_FAMILIES = [
  "node-crypto",
  "webcrypto",
  "crypto-libs",
  "jwt-jose",
  "tls-config",
  "pem-material",
  "dependencies",
] as const;

/**
 * The slice of options a `qproof.config.json` can set. A subset of
 * {@link ScanOptions} (the file-selection + scope keys) extended with the two
 * policy keys qScan owns: `severityThreshold` and `baseline`.
 *
 * `root`, `files`, `detectors` (the programmatic detector array), and `onFile`
 * are intentionally NOT configurable from a file — they are call-site concerns.
 */
export interface QproofFileConfig extends Partial<
  Pick<
    ScanOptions,
    | "include"
    | "exclude"
    | "noDefaultIgnores"
    | "maxFileSize"
    | "scanMinified"
    | "source"
    | "dependencies"
    | "config"
  >
> {
  /** Gate severity (drives the exit code). Maps to qScan's `severityThreshold`. */
  severityThreshold?: Severity;
  /** Path to a baseline file, relative to the config file's directory. */
  baseline?: string;
}

/** Result of {@link loadConfig}: the resolved config plus where it came from. */
export interface LoadConfigResult {
  /** Validated, mapped config. Empty object when no file was found. */
  config: QproofFileConfig;
  /** Absolute path of the file that was loaded, when one was. */
  path?: string;
  /**
   * Non-fatal warnings (unknown keys, unknown future `version`). The caller may
   * surface these; they never abort the load.
   */
  warnings: string[];
}

/** Thrown when a known key has a malformed *value* (a usage error: exit 2). */
export class ConfigError extends Error {
  override readonly name = "ConfigError";
  /** The config file path the error relates to, when known. */
  readonly path: string | undefined;
  constructor(message: string, configPath?: string) {
    super(message);
    this.path = configPath;
  }
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Validate an optional boolean field; returns it or undefined, or throws. */
function asBool(obj: Record<string, unknown>, key: string, file: string): boolean | undefined {
  if (!(key in obj)) return undefined;
  const v = obj[key];
  if (typeof v !== "boolean") {
    throw new ConfigError(`"${key}" must be a boolean (got ${typeof v})`, file);
  }
  return v;
}

/** Validate an optional non-negative-integer field. */
function asInt(obj: Record<string, unknown>, key: string, file: string): number | undefined {
  if (!(key in obj)) return undefined;
  const v = obj[key];
  if (typeof v !== "number" || !Number.isInteger(v) || v < 0) {
    throw new ConfigError(`"${key}" must be a non-negative integer`, file);
  }
  return v;
}

/** Validate an optional string[] field (every element must be a string). */
function asStringArray(
  obj: Record<string, unknown>,
  key: string,
  file: string,
): string[] | undefined {
  if (!(key in obj)) return undefined;
  const v = obj[key];
  if (!Array.isArray(v) || !v.every((x): x is string => typeof x === "string")) {
    throw new ConfigError(`"${key}" must be an array of strings`, file);
  }
  return [...v];
}

/**
 * Map the validated raw JSON object onto a {@link QproofFileConfig}. Throws
 * {@link ConfigError} on a malformed *value* for any known key; collects
 * warnings for unknown keys and unrecognised `version`.
 */
function mapConfig(
  raw: Record<string, unknown>,
  file: string,
  warnings: string[],
): QproofFileConfig {
  // Known top-level keys. Anything else is a warning, not an error.
  const KNOWN = new Set([
    "$schema",
    "version",
    "include",
    "exclude",
    "noDefaultIgnores",
    "maxFileSize",
    "scanMinified",
    "detectors",
    "languages",
    "severityThreshold",
    "baseline",
  ]);
  for (const key of Object.keys(raw)) {
    if (!KNOWN.has(key)) warnings.push(`unknown config key "${key}" ignored`);
  }

  // version: known forward-compat warning only.
  if ("version" in raw) {
    const version = raw["version"];
    if (typeof version !== "number" || !Number.isInteger(version)) {
      throw new ConfigError(`"version" must be an integer`, file);
    }
    if (version !== 1) {
      warnings.push(`config "version" ${version} is newer than supported (1); best-effort`);
    }
  }

  const out: QproofFileConfig = {};

  const include = asStringArray(raw, "include", file);
  if (include) out.include = include;
  const exclude = asStringArray(raw, "exclude", file);
  if (exclude) out.exclude = exclude;

  const noDefaultIgnores = asBool(raw, "noDefaultIgnores", file);
  if (noDefaultIgnores !== undefined) out.noDefaultIgnores = noDefaultIgnores;
  const scanMinified = asBool(raw, "scanMinified", file);
  if (scanMinified !== undefined) out.scanMinified = scanMinified;

  const maxFileSize = asInt(raw, "maxFileSize", file);
  if (maxFileSize !== undefined) out.maxFileSize = maxFileSize;

  // detectors.<family> bool map → source / dependencies / config scope toggles.
  // A family turned off is equivalent to its `--no-*` flag (per docs/CONFIG.md
  // §4.1). We collapse the per-family map onto the three scan-scope toggles:
  //   dependencies → ScanOptions.dependencies
  //   pem-material + tls-config → ScanOptions.config (config-scope detectors)
  //   the JS source families → ScanOptions.source (source-scope detectors)
  // Only an explicit `false` flips a toggle off; absent/true leaves the default.
  if ("detectors" in raw) {
    const det = raw["detectors"];
    if (!isObject(det)) {
      throw new ConfigError(`"detectors" must be an object of family→boolean`, file);
    }
    for (const key of Object.keys(det)) {
      if (!(DETECTOR_FAMILIES as readonly string[]).includes(key)) {
        warnings.push(`unknown detector family "${key}" ignored`);
        continue;
      }
      const v = det[key];
      if (typeof v !== "boolean") {
        throw new ConfigError(`"detectors.${key}" must be a boolean`, file);
      }
      if (v) continue; // true = default; nothing to disable.
      switch (key) {
        case "dependencies":
          out.dependencies = false;
          break;
        case "tls-config":
        case "pem-material":
          out.config = false;
          break;
        default:
          // node-crypto / webcrypto / crypto-libs / jwt-jose are source-scope.
          out.source = false;
          break;
      }
    }
  }

  // languages: forward-looking (inert until the plugin registry lands). Validate
  // the type so the file format is stable, but do not map it anywhere.
  const languages = asStringArray(raw, "languages", file);
  if (languages) warnings.push(`"languages" is accepted but inert until detector plugins land`);

  // severityThreshold: enum.
  if ("severityThreshold" in raw) {
    const sev = raw["severityThreshold"];
    if (typeof sev !== "string" || !(SEVERITIES as readonly string[]).includes(sev)) {
      throw new ConfigError(`"severityThreshold" must be one of: ${SEVERITIES.join(", ")}`, file);
    }
    out.severityThreshold = sev as Severity;
  }

  // baseline: path string, resolved relative to the config file's directory.
  if ("baseline" in raw) {
    const baseline = raw["baseline"];
    if (typeof baseline !== "string" || baseline.length === 0) {
      throw new ConfigError(`"baseline" must be a non-empty path string`, file);
    }
    out.baseline = path.isAbsolute(baseline) ? baseline : path.join(path.dirname(file), baseline);
  }

  return out;
}

/**
 * Load a `qproof.config.json` for a scan.
 *
 * By default reads `<root>/qproof.config.json`. Pass an explicit file path as
 * `root` (or via the caller's `--config` flag) to read a named file instead —
 * if the path's basename is `qproof.config.json` it is read directly; otherwise
 * the path is treated as a directory and the file is looked up inside it. When
 * an explicit path is given but missing, that is an error; an *absent*
 * auto-discovered file is tolerated (returns an empty config).
 *
 * @param root Directory to look in, OR an explicit config file path.
 * @param opts.explicit When true, a missing file is an error (the user named it).
 * @throws {ConfigError} On malformed JSON, a bad value for a known key, or a
 *   missing explicitly-named file.
 */
export async function loadConfig(
  root: string,
  opts: { explicit?: boolean } = {},
): Promise<LoadConfigResult> {
  // Resolve the file path: an explicit *.json file is used verbatim; otherwise
  // treat `root` as a directory and append the canonical name.
  const base = path.basename(root);
  const file =
    base === CONFIG_FILENAME || base.endsWith(".json")
      ? path.resolve(root)
      : path.resolve(root, CONFIG_FILENAME);

  let text: string;
  try {
    text = await readFile(file, "utf8");
  } catch {
    if (opts.explicit) {
      throw new ConfigError(`config file not found: ${file}`, file);
    }
    return { config: {}, warnings: [] }; // tolerant when auto-discovering.
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    throw new ConfigError(`invalid JSON in ${file}: ${(err as Error).message}`, file);
  }
  if (!isObject(parsed)) {
    throw new ConfigError(`config must be a JSON object, got ${typeof parsed}`, file);
  }

  const warnings: string[] = [];
  const config = mapConfig(parsed, file, warnings);
  return { config, path: file, warnings };
}
