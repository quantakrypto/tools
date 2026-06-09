/**
 * Static help / usage text for the qScan CLI.
 *
 * Kept in its own module so it can be unit-tested and reused without pulling in
 * filesystem or process side effects.
 */

import { VERSION } from "@qproof/core";

/** The full `--help` screen. */
export const HELP_TEXT = `qscan — find quantum-vulnerable cryptography in any codebase

USAGE
  qscan [path] [options]

ARGUMENTS
  path                          Directory or file to scan (default: ".")

OPTIONS
  --format <human|json|sarif>   Output format (default: human)
  -o, --output <file>           Write the report to a file instead of stdout
  --severity-threshold <level>  Fail (exit 1) on findings at/above this level;
                                one of critical|high|medium|low|info
                                (default: high)
  --no-source                   Skip scanning source files for inline crypto
  --no-deps                     Skip scanning dependency manifests
  --no-config                   Skip scanning config files (TLS/certificates)
  --ignore <pattern>            Exclude paths matching <pattern> (repeatable)
  --baseline <file>             Suppress findings listed in a baseline file
  --write-baseline <file>       Write current findings as a baseline, then exit 0
  --quiet                       Suppress the human summary banner
  -v, --version                 Print version and exit
  -h, --help                    Print this help and exit

EXIT CODES
  0   No findings at/above the threshold (or a baseline was written)
  1   One or more findings at/above the severity threshold
  2   Usage error or I/O failure

EXAMPLES
  qscan .                       Scan the current directory
  qscan src --format sarif -o qscan.sarif
  qscan . --severity-threshold critical
  qscan . --write-baseline qscan-baseline.json
  qscan . --baseline qscan-baseline.json
`;

/** The `--version` line. */
export function versionLine(): string {
  return `qscan ${VERSION}`;
}
