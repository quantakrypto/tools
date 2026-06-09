# 0001 — Zero runtime dependencies (Node built-ins only)

- **Status:** Accepted
- **Date:** 2025-06-09
- **Deciders:** qproof-tools maintainers
- **Supersedes / Superseded by:** —

## Context

`qproof-tools` is security-positioning software: it tells users where their
quantum-vulnerable cryptography lives and it runs in privileged contexts (CI with
write tokens, AI agents with filesystem access, a potential hosted MCP service).
For such a tool, the **supply chain is part of the threat model**. The dominant
class of JavaScript-ecosystem risk is transitive dependencies and npm lifecycle
scripts (`postinstall`/`prepare`), as the [security audit §6](../audits/security.md)
records. A scanner that itself drags in a deep dependency tree would undermine
the assurance it sells.

Most of what the tools need — JSON-RPC/MCP framing, the GitHub Actions toolkit
surface (input parsing, annotations, PR comments), CLI argument parsing, SARIF
emission, NDJSON protocol handling, base64 — is small enough to hand-roll on Node
built-ins (`node:fs`, `node:http`, `node:readline`, `node:crypto`,
`node:child_process`, global `fetch` on Node ≥ 18/20).

## Decision

We will ship **zero runtime dependencies** across every published package. The
only permitted runtime imports are Node built-ins and internal `@qproof/*`
workspace packages. No package may declare a third-party `dependencies` entry.

We will also keep the **dev-tooling surface minimal** (`typescript`, `tsx`,
`@types/node`) and ship **no `postinstall`/`preinstall`/`prepare`/`install`
lifecycle scripts** in any package.

Any future feature that wants a runtime dependency must justify it in a new ADR
against this baseline; the default answer is "hand-roll it on built-ins or do
without."

## Consequences

**Easier:** a near-nil dependency attack surface (no transitive CVEs, no
typosquats, no lifecycle-script execution vector); trivial `npm ci` reproducibility;
strong free wins on OpenSSF Scorecard (`Pinned-Dependencies`, `Vulnerabilities`);
a credible posture for the security claim the tools make.

**Harder (costs accepted):** we re-implement and maintain functionality that
mature libraries provide — JSON-RPC dispatch, Actions shims, arg parsers, SARIF.
These hand-rolled parsers are an *input-handling* risk concentrated in our own
code (which is why [ROADMAP P1-10](../ROADMAP.md) calls for fuzz targets over the
four of them: Sieve protocol/base64, manifest JSON, SARIF, qScan args). We accept
this tradeoff: a small amount of audited first-party parsing code is preferable to
a large unaudited dependency tree.

**Enforcement:** keep `dependencies` empty (sans `@qproof/*`) in every
`package.json`; build/release with `npm ci` (lockfile integrity); a CI check that
fails on any non-`@qproof/*` runtime dependency or any lifecycle script keeps the
invariant from eroding. The `runtime deps: 0` README badge is a public commitment.

## Alternatives considered

- **Allow a small, vetted dependency set** (e.g. `@actions/core`, an MCP SDK, a
  SARIF builder). Rejected: it reintroduces transitive trust and lifecycle-script
  exposure for code we can write in a few hundred lines, and weakens the headline
  assurance property.
- **Bundle dependencies at build time** (vendoring). Rejected for runtime code as
  unnecessary given the built-ins suffice; bundling *is* used for the Action's
  `dist/` for a different reason (a `node20` action must run committed JS — see
  [ROADMAP §5](../ROADMAP.md)).
