# 0002 — `@qproof/core` is the single shared contract

- **Status:** Accepted
- **Date:** 2025-06-09
- **Deciders:** qproof-tools maintainers
- **Supersedes / Superseded by:** —

## Context

Three of the four user-facing tools — `qscan` (CLI), `mcp` (agent server), and
`action` (CI) — answer the same question ("where is the quantum-vulnerable
crypto, and what replaces it?"). If each re-implemented detection, inventory, or
remediation logic, the tools would drift: a finding that fails CI might not appear
in the editor, and a remediation the agent suggests might differ from the one the
report prints. Sieve is the exception — it tests *other people's* crypto and
shares no detection logic (see [ADR-0004](0004-sieve-no-fabricated-vectors.md)).

The crypto-analysis knowledge — detectors, the vulnerable-dependency DB, the
inventory/readiness scoring, the remediation table, and the SARIF/JSON/human
reporters — is the asset. It must live in exactly one place.

## Decision

We will keep **all** cryptographic-analysis logic in `@qproof/core` and treat its
public surface (`src/index.ts` re-exports + the types in `src/types.ts`) as **the
contract**. `qscan`, `mcp`, and `action` are thin shells that consume `core`;
they do **I/O and policy**, never detection. The MCP [HOSTING.md](../../packages/mcp/HOSTING.md)
states the rule directly: *transports do I/O and policy; `McpServer` does
protocol; `@qproof/core` does cryptographic analysis.*

The locked contract is:
- `scan(ScanOptions): Promise<ScanResult>` and the walker `walkFiles`.
- The data types `Finding`, `CryptoInventory`, `Severity`, `AlgorithmFamily`,
  `FindingCategory`.
- The reporters `toSarif`, `toJson`, `formatSummary` and `buildInventory`.
- `remediationFor`, the `detectors` array, `vulnerableDependencies`, `VERSION`.

Consumers must **reuse** core's primitives rather than re-derive them. (The
[architecture audit](../audits/architecture.md) and [ROADMAP P1-1/P1-3](../ROADMAP.md)
flag two current violations: the qScan/Action **baseline fingerprint schism** and
the Action re-implementing `fingerprint`/`applyBaseline`/`renderReport` instead of
importing `runQscan`. Closing those is conformance to this ADR, not a new
decision.)

## Consequences

**Easier:** one definition of a finding; identical verdicts across CLI/agent/CI;
one place to add a detector, a CWE tag, or a CBOM exporter and have all three
tools benefit; a stable public API to version (see [VERSIONING.md](../VERSIONING.md)).

**Harder (costs accepted):** the `core` surface is now a compatibility commitment
— changes to `Finding`, `ScanResult`, or a reporter's output shape ripple to every
consumer and, post-1.0, are **breaking**. We accept the discipline of treating
`src/types.ts` as load-bearing and gating changes to it through SemVer.

**Enforcement:** the build's project references (see [ADR-0003](0003-monorepo-and-build.md))
make the dependency direction explicit; a future public-API reference + a
review rule ("does this PR add detection logic outside core?") keep consumers
thin. The baseline-unification work (P1-1) extracts the one shared baseline module
*into core* so the two divergent copies cannot persist.

## Alternatives considered

- **Let each tool own its slice of logic** for independence. Rejected: it
  guarantees the drift this ADR exists to prevent and multiplies the maintenance
  and audit surface by three.
- **A looser "core is a library, copy what you need" convention** without treating
  the surface as a contract. Rejected: that is the status quo that produced the
  baseline schism; an explicit contract with versioning is the fix.
