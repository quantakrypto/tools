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
  --format <human|json|sarif|cbom>
                                Output format (default: human)
  --cbom                        Alias for --format cbom (CycloneDX CBOM)
  -o, --output <file>           Write the report to a file instead of stdout
  --severity-threshold <level>  Fail (exit 1) on findings at/above this level;
                                one of critical|high|medium|low|info
                                (default: high)
  --no-source                   Skip scanning source files for inline crypto
  --no-deps                     Skip scanning dependency manifests
  --no-config                   Skip scanning config files (TLS/certificates)
  --ignore <pattern>            Exclude paths matching <pattern> (repeatable)
  --include <pattern>           Restrict the scan to matching paths (repeatable)
  --max-file-size <bytes>       Skip files larger than <bytes> (default: 2 MiB)
  --no-default-ignores          Don't skip node_modules/.git/dist by default
  --scan-minified               Scan minified/generated/bundled files too
  --changed                     Scan only files changed in the git work tree
  --since <git-ref>             With --changed, diff against <git-ref>
  --parallel                    Scan using a worker-thread pool when worthwhile
  --concurrency <n>             Worker count for --parallel (implies --parallel)
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
  qscan . --include src --include lib
  qscan . --changed --since origin/main
  qscan . --parallel --concurrency 4
  qscan . --cbom -o qscan-cbom.json
`;

/** The `--version` line. */
export function versionLine(): string {
  return `qscan ${VERSION}`;
}
