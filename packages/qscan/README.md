# @qproof/qscan

**Find quantum-vulnerable cryptography in any codebase.**

`qscan` walks a project and reports where it relies on classical asymmetric
cryptography (RSA, (EC)DH, ECDSA, EdDSA, DSA, …) — the algorithms broken by a
sufficiently large quantum computer, and the ones exposed to *harvest-now,
decrypt-later* (HNDL) attacks today. It scans source files, dependency
manifests, and configuration, then prints a readiness score and a concrete next
step.

- **Zero runtime dependencies.** Node built-ins only; the engine is
  [`@qproof/core`](../core).
- **CI-friendly.** Severity thresholds drive the exit code; baselines suppress
  known findings so the build only fails on *new* problems.
- **Multiple formats.** `human` (default), `json`, SARIF 2.1.0 for code-scanning
  dashboards, and a CycloneDX 1.6 **CBOM** for compliance tooling.
- **Fast on big repos.** Optional worker-thread parallelism (`--parallel`) and
  git-aware incremental scanning (`--changed`).

## Install

```bash
npm install -g @qproof/qscan
# or run without installing
npx @qproof/qscan .
```

Requires Node ≥ 20.

## Usage

```bash
qscan [path] [options]
```

`path` defaults to the current directory (`.`).

### Options

| Flag | Description | Default |
| --- | --- | --- |
| `--format <human\|json\|sarif\|cbom>` | Output format. | `human` |
| `--cbom` | Alias for `--format cbom` (CycloneDX 1.6 CBOM). | — |
| `-o, --output <file>` | Write the report to a file instead of stdout. | stdout |
| `--severity-threshold <level>` | Exit 1 if any finding is at/above this level. One of `critical`, `high`, `medium`, `low`, `info`. | `high` |
| `--no-source` | Skip scanning source files for inline crypto. | scan on |
| `--no-deps` | Skip scanning dependency manifests. | scan on |
| `--no-config` | Skip scanning config files (TLS/certificates). | scan on |
| `--ignore <pattern>` | Exclude paths matching `<pattern>`. Repeatable. | — |
| `--include <pattern>` | Restrict the scan to paths matching `<pattern>`. Repeatable. | all files |
| `--max-file-size <bytes>` | Skip files larger than `<bytes>`. | 2 MiB |
| `--no-default-ignores` | Don't skip `node_modules`/`.git`/`dist` by default. | ignores on |
| `--scan-minified` | Scan minified/generated/bundled files too. | skipped |
| `--changed` | Incremental: scan only files git reports as changed. | off |
| `--since <git-ref>` | With `--changed`, diff against `<git-ref>` (implies `--changed`). | working tree |
| `--parallel` | Scan using a worker-thread pool when the workload is large enough. | off |
| `--concurrency <n>` | Worker count for `--parallel` (implies `--parallel`). `0`/`1` forces serial. | CPU count |
| `--baseline <file>` | Suppress findings whose fingerprint is in the baseline file. | — |
| `--write-baseline <file>` | Write current findings as a baseline, then exit 0. | — |
| `--quiet` | Suppress the human summary banner. | off |
| `-v, --version` | Print version and exit. | — |
| `-h, --help` | Print help and exit. | — |

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | No findings at/above the threshold — or a baseline was written. |
| `1` | One or more findings at/above the severity threshold. |
| `2` | Usage error or I/O failure. |

## Example output

```
qScan — quantum-vulnerable cryptography report
root: ./examples/vulnerable-app  •  files scanned: 2  •  qscan v0.1.0

3 findings  (2 high, 1 medium)
2 exposed to harvest-now-decrypt-later (HNDL).
Readiness score: 70/100

Top findings
  high     rsa-keygen      src/crypto.js:5
           RSA is not quantum-safe.
           → Use ML-KEM-768 (hybrid X25519MLKEM768).
  high     dep-vulnerable  package.json:7
           Dependency "node-forge" provides classical asymmetric crypto.
  medium   ecdh-usage      src/crypto.js:13
           ECDH is not quantum-safe.
           → Use a hybrid KEM (X25519MLKEM768).

Next step: migrate src/crypto.js — Use ML-KEM-768 (hybrid X25519MLKEM768).
```

Color is emitted only when writing the human format to an interactive terminal
(and is suppressed by the `NO_COLOR` environment variable). Reports written to a
file or piped are always plain text.

## Baselines

A baseline records the **fingerprints** of findings you have already triaged.
qScan uses the **canonical baseline** shared across the whole monorepo
(`@qproof/core`, the GitHub Action, and this CLI): a single on-disk format and a
single fingerprint algorithm, so a baseline written by one tool is understood by
the others.

A fingerprint is a full SHA-256 of `ruleId|file|normalizedSnippet`. It is
deliberately **line-insensitive** — unrelated edits that shift line numbers no
longer invalidate it — and the snippet's whitespace is normalized so
reformatting doesn't either. It ignores volatile fields like severity wording or
timestamps.

```bash
# 1. Accept the current state of the world.
qscan . --write-baseline qscan-baseline.json

# 2. From now on, fail only on findings that are NOT in the baseline.
qscan . --baseline qscan-baseline.json
```

The baseline file is plain JSON:

```json
{
  "version": 1,
  "fingerprints": [
    "0f1e2d3c4b5a...full-sha256...",
    "a1b2c3d4e5f6...full-sha256..."
  ]
}
```

## Incremental scans

In CI you usually only care about what a change introduced. `--changed` restricts
the scan to the files git reports as modified, which is a large win on big repos:

```bash
# Files modified in the working tree (staged, unstaged, and untracked).
qscan . --changed

# Everything that changed since a base ref (e.g. a PR base).
qscan . --changed --since origin/main
```

Outside a git work tree the changed-file list is empty (nothing is scanned),
rather than an error.

## Parallel scans

For large trees, route the scan through a worker-thread pool. qScan automatically
stays serial for small inputs, so `--parallel` is safe to leave on:

```bash
qscan . --parallel               # auto worker count (CPU cores)
qscan . --concurrency 4          # pin the worker count (implies --parallel)
```

## CBOM (CycloneDX)

Emit a CycloneDX 1.6 **cryptographic bill of materials** — one
`cryptographic-asset` component per distinct (algorithm, primitive) pair, with
file:line occurrence evidence — for compliance and supply-chain tooling:

```bash
qscan . --cbom -o qscan-cbom.json
# equivalently:
qscan . --format cbom -o qscan-cbom.json
```

The output is deterministic (sorted components and occurrences, stable serial
number), so re-running on an unchanged tree produces byte-identical CBOMs.

## CI

Fail the build on any high-or-worse finding, while tolerating an accepted
baseline:

```yaml
# .github/workflows/qscan.yml
name: qscan
on: [push, pull_request]

jobs:
  quantum-readiness:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - name: Scan for quantum-vulnerable crypto
        run: npx @qproof/qscan . --severity-threshold high --baseline qscan-baseline.json

      # Optional: upload SARIF to GitHub code scanning.
      - name: Generate SARIF
        if: always()
        run: npx @qproof/qscan . --format sarif -o qscan.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: qscan.sarif
```

## Programmatic API

The CLI is a thin shell over `runQscan`, which `@qproof/action` reuses:

```ts
import { runQscan, EXIT } from "@qproof/qscan";

const { result, exitCode, suppressed } = await runQscan({
  path: "src",
  format: "json",
  severityThreshold: "high",
  baseline: "qscan-baseline.json",
});

console.log(`${result.findings.length} findings, exit ${exitCode}`);
if (exitCode === EXIT.FINDINGS) process.exitCode = 1;
```

`runQscan` never touches `process` or stdout — it returns the rendered `report`
string and a suggested `exitCode`, leaving I/O to the caller. The package also
re-exports the argument parser (`parseArgs`, `defaultOptions`), severity helpers
(`severityRank`, `meetsThreshold`), and the **canonical** baseline utilities from
`@qproof/core` (`fingerprintFinding`, `baselineFromFindings`, `applyBaseline`,
`loadBaseline`, `saveBaseline`) plus their legacy aliases (`fingerprint`,
`buildBaseline`, `readBaseline`, `writeBaseline`) for source compatibility.

## Examples

See [`examples/`](./examples) for a sample vulnerable project and the commands
to scan it.

## License

Apache-2.0
