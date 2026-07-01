# quantakrypto Action

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
  quantakrypto:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: quantakrypto — Quantum Readiness Scan
        id: quantakrypto
        uses: quantakrypto/pqc-tools/packages/action@v1
        with:
          path: "."
          severity-threshold: "high"
          fail-on-findings: "true"
          format: "sarif"
          output: "quantakrypto.sarif.json"
          # baseline: ".quantakrypto/baseline.sarif.json"   # optional
          comment-pr: "true"
          github-token: ${{ github.token }}

      # Upload to GitHub code scanning (Security tab). Runs even if the scan failed.
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ steps.quantakrypto.outputs.sarif-file }}
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
| `output` | `quantakrypto.sarif.json` | Path of the report file to write (relative to the workspace). |
| `baseline` | _(none)_ | Path to a qScan baseline file (`{ version, fingerprints }`, as written by `qscan --write-baseline`). Findings whose fingerprint it lists are suppressed, so only **new** crypto fails. |
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

The Action and the [`qscan`](../qscan) CLI share **one** baseline format and
**one** fingerprint, defined in [`@quantakrypto/core`](../core). A baseline is a small
versioned file — `{ "version": 1, "fingerprints": [ … ] }` — written by
`qscan --write-baseline`. The fingerprint is a stable SHA-256 of the finding's
rule id, file, and (whitespace-normalized) code snippet, *excluding line/column*
so that unrelated edits which merely shift code up or down a file don't resurface
old findings. Any finding whose fingerprint already appears in the baseline is
suppressed; only genuinely new quantum-vulnerable crypto can fail the build.

Because the format is shared, a baseline produced locally with the CLI is
honoured byte-for-byte by the Action in CI, and vice versa.

Typical adoption flow:

1. Run `qscan --write-baseline .quantakrypto/baseline.json` once on `main` and commit
   the baseline file.
2. Point `baseline:` at that file. From then on, pull requests fail only when
   they introduce **new** findings at/above the threshold.
3. Refresh the baseline whenever you remediate, by re-running `--write-baseline`
   and re-committing it.

## Design

- **One code path with the CLI** — the scan, report rendering, and baseline are
  not re-implemented here. The Action calls `runQscan` / `renderReport` from
  [`@quantakrypto/qscan`](../qscan) and the shared baseline
  (`fingerprintFinding` / `applyBaseline` / `loadBaseline`) from
  [`@quantakrypto/core`](../core), so the Action and the `qscan` CLI produce identical
  findings, reports, and baseline semantics. This module is just the
  GitHub-runner glue (inputs, outputs, annotations, PR comment, exit policy).
- **Output-injection hardened** — a finding's `file`/`message`/`ruleId` come from
  the *scanned* repo, so in a fork PR they are attacker-controlled. Two sinks the
  Action writes with a token are escaped accordingly:
  - the **PR-comment Markdown table** — every cell is escaped by `mdCell`
    ([`src/escape.ts`](src/escape.ts)): pipes (`\|`), backticks, CR/LF, and HTML
    (`&`, `<`, `>`) so a crafted filename cannot break the table or inject HTML;
  - the **`::error file=…,line=…::message` workflow command** — the message is
    `escapeData`-encoded (`%`, CR, LF → `%25`/`%0D`/`%0A`) and command properties
    are `escapeProperty`-encoded (additionally `,` → `%2C`, `:` → `%3A`) in
    [`src/io.ts`](src/io.ts), so an attacker-named file cannot break out of the
    command.
- **Zero runtime dependencies** — only `@quantakrypto/core` + `@quantakrypto/qscan` (and Node
  built-ins). The small slice of the GitHub Actions toolkit this action needs
  (input parsing, outputs, annotations, PR comments) is implemented directly in
  [`src/io.ts`](src/io.ts) and [`src/main.ts`](src/main.ts); no `@actions/core`
  or `@actions/github`.
- **Testable core** — input parsing, the threshold→exit decision, summary
  rendering, the escaping helpers, and the annotation wire format are pure
  functions, unit-tested with `node:test` (no real runner required).

## License

Apache-2.0

## Support & training

Questions, commercial support, or post-quantum readiness training for your team —
visit **[quantakrypto.com](https://quantakrypto.com)** or email
**[hello@quantakrypto.com](mailto:hello@quantakrypto.com)**.
