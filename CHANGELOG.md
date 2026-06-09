# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html) from 1.0.0.

## [Unreleased]

Planned work is tracked in [`docs/ROADMAP.md`](docs/ROADMAP.md).

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
