# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html) from 1.0.0.

## [Unreleased]

Implements the full P0/P1/P2 roadmap (see [`docs/ROADMAP.md`](docs/ROADMAP.md)).
Build clean; **307 tests pass**; ESLint + Prettier clean; still zero runtime
dependencies.

### Added

- **core:** shared canonical baseline (`fingerprintFinding`/`applyBaseline`/…);
  `DetectorRegistry` + `Detector.scope`/`language`; wired `ScanOptions`
  (`include`/`files`/`scanMinified`); new detectors (DH MODP, SSH keys, TLS
  certificate signature algorithms, JOSE `ECDH-ES*`, one-shot `sign`/`verify`,
  `secp256k1`); CWE tags on findings; CycloneDX **CBOM** export (`toCbom`);
  `scanParallel` worker pool; `changedFiles` incremental helper; CNSA 2.0
  Category-5 + SP 800-208 remediation guidance.
- **qscan:** `--include`, `--max-file-size`, `--no-default-ignores`,
  `--scan-minified`, `--changed`/`--since` (incremental), `--parallel`/
  `--concurrency`, and `--cbom` output.
- **mcp:** safe-by-default HTTP transport (loopback bind, `QPROOF_MCP_TOKEN`
  auth, filesystem tools gated behind `QPROOF_MCP_ALLOW_FS`, per-request
  timeout + response cap); `generate_cbom` tool.
- **sieve:** SLH-DSA (FIPS 205); FIPS 203 §7.2 encapsulation-key modulus-range
  check; deeper ML-DSA + deterministic/hedged signing probe; bounded pipelining.
- **repo:** ESLint + Prettier, `test:coverage`, a benchmark harness, OpenSSF
  Scorecard + release workflows, `REUSE.toml`, threat model, ADRs, SemVer
  policy, config spec, and ISO 27001 A.8.24 / ACVP-provenance designs.

#### Follow-ups landed (previously documented designs)

- **core/qscan:** `qproof.config.json` support — `loadConfig` in core plus
  flags > config > defaults precedence in qScan, with `--config <path>` and
  `--no-config-file` (distinct from the `--no-config` *detector* toggle). [P2-9]
- **tests:** deterministic, seeded-PRNG fuzz targets for the hand-rolled parsers
  — manifest/dependency parsing + `toSarif` (core), `decodeResponse`/`fromB64`
  (sieve), and the argv parser (qscan), in each package's `test/fuzz.test.ts`. [P1-10]
- **repo:** a zero-dep `.githooks/pre-commit` hook (build → lint → format:check →
  test) [P2-5]; `scripts/validate-sarif.mjs` SARIF 2.1.0 structural validator +
  `validate:sarif` script [P2-6]; and advisory `bench` + gating `sarif` CI jobs.

### Fixed (security & correctness)

- EC key generation is now classified as key-exchange-capable (harvest-now
  exposure was under-reported). [P0-4]
- PR-comment Markdown and `::error::` workflow-command output are escaped against
  injection from attacker-controlled finding text. [P0-2]
- The Sieve runner spawns the SUT with a scrubbed minimal environment. [P0-3]
- `explain_finding` resolves library-rule findings (was "no matching detector"). [P0-5]
- Hardened the TLS cipher regex (ReDoS) and replaced the quadratic proximity
  scan with a binary search. [P0-6]
- The GitHub Action now reuses qScan's `runQscan` and the shared baseline instead
  of a divergent second implementation. [P1-3]

## [0.1.0] — 2026-06-03

Initial release of the `qproof-tools` monorepo — a zero-runtime-dependency
TypeScript toolset for post-quantum readiness.

### Added

- **`@qproof/core`** — shared engine: JavaScript/TypeScript + config crypto
  detectors, a vulnerable-dependency database, a cryptographic inventory with a
  0–100 readiness score, and SARIF 2.1.0 / JSON / text reporters.
- **`@qproof/qscan`** — CLI to scan any codebase for quantum-vulnerable
  cryptography, with baselines, severity gating, and SARIF output.
- **`@qproof/mcp`** — Model Context Protocol server (stdio JSON-RPC implemented
  in-house) exposing scan/inventory/explain/suggest tools to AI coding agents,
  plus a hostable HTTP transport scaffold.
- **`@qproof/action`** — GitHub Action that fails CI when newly introduced
  quantum-vulnerable cryptography lands, with baseline suppression and SARIF.
- **`@qproof/sieve`** — conformance battery for ML-KEM / ML-DSA implementations
  driven over a JSON protocol; ships no KAT vectors and never fabricates them.
- Project governance, CI, and a multi-discipline audit set under `docs/`.

[Unreleased]: https://github.com/dandelionlabs-io/qproof-tools/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/dandelionlabs-io/qproof-tools/releases/tag/v0.1.0
