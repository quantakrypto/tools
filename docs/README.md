# qproof-tools — documentation

Engineering, audit, and compliance docs for the [qproof-tools](../README.md)
monorepo. Start here.

## Roadmap & gaps

- **[ROADMAP.md](ROADMAP.md)** — the consolidated, prioritised plan (P0/P1/P2)
  and the "what's missing" gap matrix, distilled from every audit below. **Read
  this first to pick up the work.**

## Audits

A general audit plus five discipline-specific reviews, each by an independent
expert pass. They cite `file:line` and propose concrete fixes.

| Audit | Lens | File |
|---|---|---|
| Overview | Correctness, security, perf, hosting (first pass) | [AUDIT.md](AUDIT.md) |
| Security | Threat model, ReDoS, hosted-MCP, injection (CWE-mapped) | [audits/security.md](audits/security.md) |
| Cryptography | NIST PQC correctness, detector accuracy, Sieve methodology | [audits/cryptography.md](audits/cryptography.md) |
| Architecture | Contracts, extensibility, baseline schism, API design | [audits/architecture.md](audits/architecture.md) |
| Performance | Hot path, complexity, parallelism, incremental scans | [audits/performance.md](audits/performance.md) |
| Testing / DevEx | Coverage, CI, lint/format, OSS governance | [audits/testing-devex.md](audits/testing-devex.md) |

## Standards & compliance

- **[COMPLIANCE.md](COMPLIANCE.md)** — what the tools touch / help align with /
  would need to certify against: NIST FIPS 203/204/205, SP 800-208, CNSA 2.0,
  SARIF, CWE, ISO/IEC 27001 (A.8.24), Common Criteria, FIPS 140-3, EU DORA/NIS2,
  US M-23-02 / NSM-10, and OSS-assurance (SLSA, OpenSSF Scorecard, SPDX/REUSE).

## Per-package & protocol docs

- [`@qproof/core`](../packages/core/README.md) · [`qscan`](../packages/qscan/README.md) · [`mcp`](../packages/mcp/README.md) · [`action`](../packages/action/README.md) · [`sieve`](../packages/sieve/README.md)
- [MCP hosting design](../packages/mcp/HOSTING.md)
- [Sieve ↔ SUT protocol](../packages/sieve/PROTOCOL.md) · [obtaining NIST ACVP vectors](../packages/sieve/vectors/README.md)

## Project governance

- [Contributing](../CONTRIBUTING.md) · [Security policy](../SECURITY.md) · [Code of Conduct](../CODE_OF_CONDUCT.md) · [Changelog](../CHANGELOG.md)
