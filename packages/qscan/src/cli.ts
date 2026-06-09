#!/usr/bin/env node
/**
 * qScan command-line entry point.
 *
 * Thin shell over the programmatic API in `./index.ts`:
 *   parse argv → runQscan → print/write report → process.exit(code).
 *
 * All policy (scanning, baseline, thresholds, rendering) lives in `index.ts`;
 * this file only deals with argv, stdout/stderr, files, and exit codes.
 */

import { writeFile } from "node:fs/promises";
import process from "node:process";
import { pathToFileURL } from "node:url";

import { ArgError, parseArgs } from "./args.js";
import type { ParsedArgs } from "./args.js";
import { HELP_TEXT, versionLine } from "./help.js";
import { EXIT, runQscan } from "./index.js";
import type { QscanRun } from "./index.js";

/** Run the CLI and return the desired process exit code (never throws). */
export async function main(argv: readonly string[]): Promise<number> {
  let parsed: ParsedArgs;
  try {
    parsed = parseArgs(argv);
  } catch (err) {
    if (err instanceof ArgError) {
      process.stderr.write(`qscan: ${err.message}\n`);
      process.stderr.write(`Run "qscan --help" for usage.\n`);
      return EXIT.ERROR;
    }
    throw err;
  }

  if (parsed.kind === "help") {
    process.stdout.write(HELP_TEXT);
    return EXIT.OK;
  }
  if (parsed.kind === "version") {
    process.stdout.write(`${versionLine()}\n`);
    return EXIT.OK;
  }

  const { options } = parsed;

  // Color only when writing the human report to an interactive stdout.
  const color =
    options.format === "human" &&
    !options.output &&
    Boolean(process.stdout.isTTY) &&
    process.env.NO_COLOR === undefined;

  let run: QscanRun;
  try {
    run = await runQscan(options, { color });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`qscan: ${message}\n`);
    return EXIT.ERROR;
  }

  // --write-baseline: report what was written and stop.
  if (run.baselineWritten) {
    if (!options.quiet) {
      const n = run.baselineWritten.fingerprints.length;
      process.stderr.write(
        `qscan: wrote baseline with ${n} fingerprint${n === 1 ? "" : "s"} to ${options.writeBaseline}\n`,
      );
    }
    return run.exitCode;
  }

  const report = run.report ?? "";
  try {
    if (options.output) {
      await writeFile(options.output, report.endsWith("\n") ? report : `${report}\n`, "utf8");
      if (!options.quiet) {
        process.stderr.write(`qscan: wrote ${options.format} report to ${options.output}\n`);
      }
    } else if (!options.quiet || options.format !== "human") {
      // In quiet mode we still emit machine formats to stdout (the point of a
      // pipe), but suppress the human banner.
      process.stdout.write(report.endsWith("\n") ? report : `${report}\n`);
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`qscan: ${message}\n`);
    return EXIT.ERROR;
  }

  if (!options.quiet && run.suppressed.length > 0) {
    process.stderr.write(
      `qscan: suppressed ${run.suppressed.length} finding(s) via baseline\n`,
    );
  }

  return run.exitCode;
}

// Only auto-run when invoked as a script (not when imported by a test).
const invokedDirectly =
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(process.argv[1]).href;

if (invokedDirectly) {
  main(process.argv.slice(2))
    .then((code) => process.exit(code))
    .catch((err) => {
      const message = err instanceof Error ? (err.stack ?? err.message) : String(err);
      process.stderr.write(`qscan: fatal: ${message}\n`);
      process.exit(EXIT.ERROR);
    });
}
