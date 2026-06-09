<!--
SPDX-FileCopyrightText: 2025 Dandelion Labs <hello@dandelionlabs.io>
SPDX-License-Identifier: Apache-2.0
-->

# `scripts/` — repo tooling

Zero-dependency Node utilities that support development but are not part of any
published package. They use only Node built-ins plus, where noted, a workspace
package (`@qproof/core`).

## `bench.mjs` — scan benchmark harness (P2-4)

Generates a synthetic source tree seeded with sample quantum-vulnerable crypto
(RSA/EC key generation, ECDH, classical TLS ciphers, a vulnerable dependency
import), then times the serial `scan()` against the worker-pool
`scanParallel()` from the **built** `@qproof/core` and prints a small table:
`files`, `ms`, `files/s`, and the serial→parallel `speedup`.

### Prerequisites

It imports from `dist/` via the `@qproof/core` workspace package, so build
first:

```bash
npm run build
npm run bench
```

### Flags

| Flag | Default | Meaning |
|------|---------|---------|
| `--files=<N>` | `1000` | Number of synthetic files to generate. |
| `--runs=<N>` | `3` | Timed repetitions per mode; the **best** time is reported (reduces noise). |
| `--concurrency=<N>` | `os.availableParallelism()` | Worker count for `scanParallel`. |
| `--keep` | off | Keep the generated temp tree instead of deleting it. |

```bash
npm run bench -- --files=4000 --runs=5 --concurrency=8
```

### Notes & caveats

- The harness **forces the parallel path** (`parallelFileThreshold: 1`,
  `parallelThresholdBytes: 0`) so it measures the worker pool rather than the
  small-repo serial fallback that `scanParallel` uses by default. On small
  corpora the worker spin-up overhead can make parallel *slower* — that is
  expected and is called out in the printed speedup line.
- It does a single untimed warm-up scan first so JIT and filesystem caches do
  not skew the first measurement.
- It cross-checks that both modes scanned the same number of files and agreed
  on the same number of findings; a mismatch prints a warning and exits non-zero
  (the comparison would otherwise be meaningless).
- The generated tree lives under the OS temp dir and is removed on exit unless
  `--keep` is passed.

## `validate-sarif.mjs` — SARIF 2.1.0 structural validator (P2-6)

Asserts the load-bearing SARIF 2.1.0 structure that consumers (GitHub code
scanning, etc.) rely on, exiting non-zero with a clear, pathed message on the
first batch of violations.

```bash
npm run validate:sarif -- path/to/report.sarif.json   # validate a file
npm run validate:sarif                                  # scan ./packages, then
                                                        # produce + validate
```

It checks: `$schema`, `version === "2.1.0"`, a non-empty `runs[]`, each run's
`tool.driver.name` and `rules[]` (each rule has a non-empty `id`), and each
result's `ruleId`, `level` (`error|warning|note|none`), `message.text`, and
`locations[].physicalLocation.artifactLocation.uri`.

> **Honest scope:** this is a *structural* check, **not** full JSON-Schema
> validation against the official `sarif-schema-2.1.0.json`. Doing that would
> require a JSON-Schema engine, and this repo is zero-dependency. The check
> catches the field-presence/type mistakes that actually break consumers.

The no-argument mode imports the **built** `@qproof/core` (run `npm run build`
first) to scan `packages/` and validate the SARIF it emits — this is what the
CI **sarif** job runs end-to-end. CI invokes it directly against a produced
file: `node scripts/validate-sarif.mjs /tmp/q.sarif.json`.

## Coverage

There is no script file here for coverage — it is a one-liner wired directly in
the root `package.json` as `test:coverage` (P1-8). See the comment next to that
script for the npm-workspaces globbing caveat.
