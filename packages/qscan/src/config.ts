/**
 * qScan-side resolution of `qproof.config.json` (ROADMAP P2-9, docs/CONFIG.md).
 *
 * core's {@link loadConfig} does the reading + type-validation; this module
 * applies the file's values onto parsed CLI options with the documented
 * precedence:
 *
 *     CLI flags  >  qproof.config.json  >  built-in defaults
 *
 * Resolution is **per-key**: a key set by a flag (tracked in the `explicit` set
 * from `parseArgs`) is left alone; otherwise the config value fills it. The
 * list-valued keys (`include` / `ignore`→`exclude`) *append* — the config
 * provides a base set and any CLI flags add to it (docs/CONFIG.md §4.2).
 */

import { loadConfig } from "@qproof/core";
import type { QproofFileConfig } from "@qproof/core";

import type { ConfigurableKey, QscanOptions } from "./args.js";

/** What {@link resolveConfig} returns: the merged options + provenance. */
export interface ResolvedConfig {
  /** Options with config applied under the flags > config > defaults rule. */
  options: QscanOptions;
  /** Absolute path of the config file that was applied, when one was. */
  configPath?: string;
  /** Non-fatal warnings from parsing (unknown keys, future version, …). */
  warnings: string[];
}

/**
 * Load and merge `qproof.config.json` into the parsed CLI options.
 *
 * @param options Fully-resolved options from {@link parseArgs} (defaults filled).
 * @param explicit The set of configurable keys the user set via a flag.
 * @returns The merged options plus the applied config path + any warnings.
 * @throws {ConfigError} (from core) on a malformed config or a missing
 *   explicitly-named `--config` file. The CLI maps this to exit 2.
 */
export async function resolveConfig(
  options: QscanOptions,
  explicit: ReadonlySet<ConfigurableKey>,
): Promise<ResolvedConfig> {
  // `--no-config-file` disables discovery entirely; nothing to merge.
  if (options.noConfigFile && options.configFile === undefined) {
    return { options, warnings: [] };
  }

  // `--config <path>` names the file explicitly (a missing file is then fatal);
  // otherwise auto-discover at the scan root.
  const target = options.configFile ?? options.path;
  const loaded = await loadConfig(target, { explicit: options.configFile !== undefined });

  if (loaded.path === undefined) {
    // No file found (auto-discovery, tolerant): options unchanged.
    return { options, warnings: loaded.warnings };
  }

  const merged = applyConfig(options, loaded.config, explicit);
  return { options: merged, configPath: loaded.path, warnings: loaded.warnings };
}

/**
 * Apply a parsed config onto options under the precedence rule. Pure; returns a
 * new options object. Scalars: config fills only keys NOT set by a flag. Lists:
 * config provides the base and the CLI flag values are appended.
 */
export function applyConfig(
  options: QscanOptions,
  config: QproofFileConfig,
  explicit: ReadonlySet<ConfigurableKey>,
): QscanOptions {
  const out: QscanOptions = {
    ...options,
    ignore: [...options.ignore],
    include: [...options.include],
  };

  /** Set a scalar key from config only when the user didn't set it via a flag. */
  const fillScalar = <K extends ConfigurableKey & keyof QscanOptions>(
    key: K,
    value: QscanOptions[K] | undefined,
  ): void => {
    if (value === undefined) return;
    if (explicit.has(key)) return; // flag wins.
    out[key] = value;
  };

  fillScalar("severityThreshold", config.severityThreshold);
  fillScalar("source", config.source);
  fillScalar("dependencies", config.dependencies);
  fillScalar("config", config.config);
  fillScalar("noDefaultIgnores", config.noDefaultIgnores);
  fillScalar("scanMinified", config.scanMinified);
  fillScalar("maxFileSize", config.maxFileSize);
  fillScalar("baseline", config.baseline);

  // List-valued keys: config is the base, CLI flags append (config first so the
  // committed policy reads as the baseline, ad-hoc CLI excludes/includes after).
  if (config.exclude && config.exclude.length > 0) {
    out.ignore = [...config.exclude, ...options.ignore];
  }
  if (config.include && config.include.length > 0) {
    out.include = [...config.include, ...options.include];
  }

  return out;
}
