# Architecture Decision Records

This directory records the **load-bearing** architectural decisions for
`qproof-tools` — the ones a future contributor would otherwise have to
reverse-engineer or, worse, accidentally violate. Each ADR captures one decision,
its context, and its consequences. ADRs are **immutable once accepted**: to
change a decision, write a new ADR that supersedes the old one (and mark the old
one `Superseded by NNNN`).

Format: a lightweight [MADR](https://adr.github.io/madr/)-style record.

## Index

| ADR | Title | Status |
|---|---|---|
| [0001](0001-zero-runtime-dependencies.md) | Zero runtime dependencies (Node built-ins only) | Accepted |
| [0002](0002-shared-core-contract.md) | `@qproof/core` is the single shared contract | Accepted |
| [0003](0003-monorepo-and-build.md) | npm-workspaces monorepo + `tsc -b` project references | Accepted |
| [0004](0004-sieve-no-fabricated-vectors.md) | Sieve ships no KAT vectors and never fabricates expected values | Accepted |

## Related governance

- [VERSIONING.md](../VERSIONING.md) — SemVer + deprecation policy (operationalises ADR-0002).
- [CONFIG.md](../CONFIG.md) — the optional `qproof.config.json` spec.
- [ROADMAP.md](../ROADMAP.md) — open work, several items of which test these decisions.

---

## Template

Copy this for new ADRs. Number sequentially, zero-padded to four digits.

```markdown
# NNNN — <short decision title>

- **Status:** Proposed | Accepted | Deprecated | Superseded by NNNN
- **Date:** YYYY-MM-DD
- **Deciders:** <roles/people>
- **Supersedes / Superseded by:** <ADR refs, if any>

## Context

What forces are at play? The problem, constraints, and assumptions. State the
facts that make the decision non-obvious.

## Decision

The position taken, in the active voice ("We will …"). Be specific enough that a
reviewer can tell whether a future PR violates it.

## Consequences

What becomes easier and what becomes harder. Include the *costs accepted* — an
ADR that lists only benefits is incomplete. Note how the decision is *enforced*
(CI gate, review rule, type) so it does not erode silently.

## Alternatives considered

The realistic options rejected, and why.
```
