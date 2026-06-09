# 0003 — npm-workspaces monorepo + `tsc -b` project references

- **Status:** Accepted
- **Date:** 2025-06-09
- **Deciders:** qproof-tools maintainers
- **Supersedes / Superseded by:** —

## Context

Four of the five packages share `@qproof/core` ([ADR-0002](0002-shared-core-contract.md)),
and the tools are developed, audited, and released together. They must build and
test as one unit, with the shared contract built before its consumers, while still
being **independently publishable** under the `@qproof/*` npm scope. The
zero-dependency rule ([ADR-0001](0001-zero-runtime-dependencies.md)) means the
toolchain itself should stay tiny.

## Decision

We will use a **single Git repository** with **npm workspaces** under
`packages/*` (`core`, `qscan`, `mcp`, `action`, `sieve`), and build with
**TypeScript project references** via `tsc -b`. The toolchain is intentionally
minimal: `typescript` + `tsx` (to run `node:test` directly on `.ts`) are the only
dev dependencies; tests use `node:test` + `node:assert` exclusively.

- `npm install` links the workspaces; `npm run build` runs `tsc --build` across
  the reference graph (core → consumers) so the contract is always compiled first.
- Every package targets **ESM + NodeNext**, TypeScript **strict**, **Node ≥ 20**.
- Each package keeps its own `package.json`, README, and `files` allow-list so it
  publishes cleanly and independently.

## Consequences

**Easier:** atomic cross-package changes and audits; the build graph enforces the
core→consumers dependency direction; one CI matrix (Node 20/22) covers everything;
contributors run three commands (`npm install` / `npm run build` / `npm test`).

**Harder (costs accepted):**
- **Project references add ceremony** — each new package needs its `references`
  wired and an entry in the root build. Accepted as the price of correct,
  incremental, contract-first builds.
- **The Action's `dist/` must be committed/bundled to publish.** A `node20`
  GitHub Action runs `dist/main.js` directly, so `uses: …/packages/action@v1`
  does not work until the built JS is committed or single-file-bundled. This is a
  known release-readiness gap captured in [ROADMAP §5](../ROADMAP.md) and the
  [release workflow](../../.github/workflows/release.yml) scaffold; it is a
  consequence of choosing a monorepo + a compiled action, accepted deliberately.
- **Shared versioning discipline.** Independent publish + a shared contract means
  version bumps must follow [VERSIONING.md](../VERSIONING.md) so a core change and
  its consumers move together.

**Enforcement:** the root `tsconfig`/build script encodes the reference graph; CI
builds + tests the whole workspace on every push (`.github/workflows/ci.yml`); a
"dist is fresh" gate is planned for the Action (ROADMAP §5).

## Alternatives considered

- **Polyrepo (one repo per package).** Rejected: the packages share a contract and
  are audited/released together; polyrepo would scatter atomic changes across PRs
  and complicate the shared-core invariant.
- **A heavier monorepo tool (Nx/Turborepo/Lerna).** Rejected: it adds dependencies
  and config for orchestration that `npm workspaces` + `tsc -b` already provide at
  this scale, conflicting with [ADR-0001](0001-zero-runtime-dependencies.md)'s
  minimal-toolchain goal.
- **A bundler for all packages (esbuild/rollup).** Rejected for library/CLI output
  (plain `tsc` ESM is sufficient and dependency-free); bundling is reserved for the
  single case that needs it — the Action's committed `dist/`.
