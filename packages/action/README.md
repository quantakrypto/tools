# qproof Action

**Fail CI when new quantum-vulnerable cryptography lands.**

A zero-dependency GitHub Action that runs [qScan](../qscan) over your repository,
writes a [SARIF](https://sarifweb.azurewebsites.net/) report you can upload to
GitHub code scanning, annotates every finding inline in the diff, and (optionally)
comments a summary on the pull request. With a **baseline**, only *new*
quantum-vulnerable crypto fails the build — so you can adopt it on a legacy
codebase without drowning in pre-existing findings.

## Quick start

```yaml
name: Quantum Readiness
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write   # required to upload SARIF to code scanning
  pull-requests: write     # only if you enable comment-pr

jobs:
  qproof:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: qproof — Quantum Readiness Scan
        id: qproof
        uses: dandelionlabs-io/qproof-tools/packages/action@v1
        with:
          path: "."
          severity-threshold: "high"
          fail-on-findings: "true"
          format: "sarif"
          output: "qproof.sarif.json"
          # baseline: ".qproof/baseline.sarif.json"   # optional
          comment-pr: "true"
          github-token: ${{ github.token }}

      # Upload to GitHub code scanning (Security tab). Runs even if the scan failed.
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ steps.qproof.outputs.sarif-file }}
```

A ready-to-copy workflow lives at
[`examples/quantum-readiness.yml`](examples/quantum-readiness.yml).

## Inputs

| Input | Default | Description |
|---|---|---|
| `path` | `.` | Directory (or file) to scan, relative to the repo root. |
| `severity-threshold` | `high` | Minimum severity that fails the build: `critical`, `high`, `medium`, `low`, `info`. Findings below this never fail. |
| `fail-on-findings` | `true` | When `true`, exit non-zero if any finding at/above the threshold remains. Set `false` to report only. |
| `format` | `sarif` | Report format written to `output`: `sarif` or `json`. |
| `output` | `qproof.sarif.json` | Path of the report file to write (relative to the workspace). |
| `baseline` | _(none)_ | Path to a prior qproof report. Findings present in it are suppressed, so only **new** crypto fails. |
| `comment-pr` | `false` | When `true` (and a token + PR context exist), post a summary comment on the PR. Never fails the build. |
| `github-token` | _(none)_ | Token used to comment on the PR. Usually `${{ github.token }}`. |

## Outputs

| Output | Description |
|---|---|
| `findings-count` | Number of findings at/above the threshold, after baseline. |
| `sarif-file` | Path of the report file that was written. |
| `readiness-score` | Post-quantum readiness score, 0 (worst) – 100 (no classical asymmetric crypto found). |

## Exit behavior

The action **exits 1** (failing the job) when **both** are true:

1. `fail-on-findings` is `true`, **and**
2. at least one finding at or above `severity-threshold` survives the baseline.

Otherwise it exits 0. In all cases it writes the report file, sets outputs, and
emits inline annotations. Configuration errors (bad inputs, scan failures) also
fail the job with an `::error::` annotation. Severity ordering, most to least
severe: `critical` > `high` > `medium` > `low` > `info`.

Inline annotations are emitted per finding: blocking severities (at/above the
threshold) as `::error::`, lower severities as `::warning::`/`::notice::`, each
anchored to the finding's file and line so they appear in the PR diff.

## How baselines work

A baseline is simply a previously written qproof report (SARIF or JSON). On each
run, the action computes a stable **fingerprint** for every finding — its rule
id, file, algorithm, and message, *excluding line/column* so that unrelated
edits which merely shift code up or down a file don't resurface old findings.
Any finding whose fingerprint already appears in the baseline is suppressed;
only genuinely new quantum-vulnerable crypto can fail the build.

Typical adoption flow:

1. Run the scan once on `main` and commit the report as your baseline, e.g.
   `.qproof/baseline.sarif.json`.
2. Point `baseline:` at that file. From then on, pull requests fail only when
   they introduce **new** findings at/above the threshold.
3. Refresh the baseline whenever you remediate, by re-committing an updated report.

## Design

- **Zero runtime dependencies** — Node built-ins only. The small slice of the
  GitHub Actions toolkit this action needs (input parsing, outputs, annotations,
  PR comments) is implemented directly in [`src/io.ts`](src/io.ts) and
  [`src/main.ts`](src/main.ts); no `@actions/core` or `@actions/github`.
- **Testable core** — input parsing, the threshold→exit decision, baseline
  application, summary rendering, and the annotation wire format are pure
  functions, unit-tested with `node:test` (no real runner required).
