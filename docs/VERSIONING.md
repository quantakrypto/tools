# Versioning & Deprecation Policy

How the `@qproof/*` packages are versioned and how breaking changes are
introduced. This policy operationalises [ADR-0002](adr/0002-shared-core-contract.md)
(`@qproof/core` is the shared contract) and [ADR-0003](adr/0003-monorepo-and-build.md)
(independent publish from one monorepo).

## 1. SemVer

All packages follow [Semantic Versioning 2.0.0](https://semver.org): `MAJOR.MINOR.PATCH`.

- **MAJOR** — a backward-incompatible change to a package's public surface.
- **MINOR** — backward-compatible new functionality.
- **PATCH** — backward-compatible bug fixes (including detection-accuracy fixes
  that do not change the data contract).

### Pre-1.0 reality (today: all packages `0.1.0`)

Under SemVer's 0.x rule, **anything may change in a minor release** and the public
API is explicitly **pre-stable**. We make **no compatibility promises before 1.0**
— in particular, the known pre-1.0 honesty items (the baseline-fingerprint schism
P1-1, dead `ScanOptions.include` P1-2) may be fixed in a `0.x` minor even though
they would be breaking post-1.0. Reaching **1.0.0 requires** a documented, frozen
public API surface (the [core contract](#3-what-counts-as-breaking-on-the-core-contract)),
a generated API reference, and a maintained [CHANGELOG](../CHANGELOG.md).

### Independent versions, coordinated bumps

Each package versions independently (it has its own `package.json` and publishes
on its own line). But because three tools consume `@qproof/core`
([ADR-0002](adr/0002-shared-core-contract.md)):

- A **MAJOR** bump of `@qproof/core` that changes the contract forces, at minimum,
  a **MINOR** bump of every consumer that adopts the new core (a new compatible
  feature) or a **MAJOR** bump where the consumer's own surface changes as a result.
- Consumers declare their `@qproof/core` dependency with a range that **does not
  cross a core MAJOR** (e.g. `^1`). Crossing a core MAJOR is itself a breaking
  change for the consumer.

## 2. The public surface, per package

Only the documented surface is covered by SemVer. Internal modules (anything not
re-exported from a package entry point, anything under a `src/internal`-style
path, `dist` layout) are **not** part of the contract and may change in a PATCH.

| Package | Public surface (SemVer-covered) |
|---|---|
| `@qproof/core` | The exports of `src/index.ts` + the types in `src/types.ts` (see §3). |
| `@qproof/qscan` | The **CLI** (flags, exit codes, output-format *shape*) **and** the programmatic API: `runQscan`, `EXIT`, `parseArgs`, `defaultOptions`, severity + baseline helpers. |
| `@qproof/mcp` | The **MCP tool contract**: tool names, their `inputSchema`, and result shape; the supported JSON-RPC methods. The bin name `qproof-mcp`. |
| `@qproof/action` | The **action interface**: `action.yml` inputs, outputs, and documented exit behavior; the `uses:` ref. |
| `@qproof/sieve` | The **SUT protocol** (`PROTOCOL.md`, `PROTOCOL_VERSION`), the CLI flags/exit codes, and `runSieve`/`formatHuman`. |

Non-API-but-still-contract surfaces — the **qScan exit codes** (0/1/2), the
**SARIF 2.1.0** output schema, the **Sieve wire protocol**, the **baseline file
format** — are versioned too: changing them is breaking. The Sieve protocol
additionally carries its own `PROTOCOL_VERSION` integer that bumps on any breaking
wire change independently of the package version.

## 3. What counts as breaking on the core contract

A change to `@qproof/core` is **MAJOR (breaking)** if it alters the meaning or
shape that a consumer relies on. Concretely, breaking:

- **Removing or renaming** any `src/index.ts` export (`scan`, `walkFiles`,
  `toSarif`, `toJson`, `formatSummary`, `buildInventory`, `remediationFor`,
  `detectors`, `vulnerableDependencies`, `VERSION`).
- **Narrowing** an input or **widening** an output type incompatibly — e.g.
  removing a `Finding` field, making an optional field required, or removing a
  member from the **`Severity`**, **`AlgorithmFamily`**, or **`FindingCategory`**
  string-literal unions.
- Changing the **shape** of `ScanResult`, `CryptoInventory`, or a reporter's
  output object in a way existing consumers cannot read.
- Changing the **semantics** of a stable field — e.g. flipping the meaning of an
  `hndl` flag, or changing the `readinessScore` *formula* (the score is a
  contract output; tweaks that move existing scores are breaking).
- Changing **SARIF output structure** in a way a conformant consumer would reject.

**Not** breaking (MINOR or PATCH):

- **Adding** a new `src/index.ts` export, a new optional `Finding` field, or a new
  detector (MINOR — new findings may appear; see the note below).
- **Adding** a new member to an *output-only* union that consumers switch on with
  a default branch — treated as MINOR, and called out in the CHANGELOG, because a
  consumer that exhaustively switches may need a new case.
- A detection **accuracy fix** (fixing a false positive/negative) that does not
  change any type — PATCH. *Detection-result changes are expected within a major*:
  new detectors and accuracy fixes mean the *set of findings* on a given codebase
  can change between MINORs/PATCHes by design. The **data contract** is stable;
  the **set of findings** is not promised stable, and baselines exist precisely to
  absorb that. This distinction is the contract.

## 4. Deprecation policy

We deprecate before we remove. The window scales with the change's blast radius.

1. **Mark** — annotate the symbol/flag with `@deprecated` (JSDoc) and/or a
   runtime warning (CLI/MCP), naming the replacement. Add a CHANGELOG entry.
2. **Keep working** — the deprecated surface keeps functioning for at least the
   window below.
3. **Remove** — only in a subsequent **MAJOR** release, never in a MINOR/PATCH.

| Surface | Minimum deprecation window before removal |
|---|---|
| `@qproof/core` public export / type field | **one MAJOR cycle**, ≥ 6 months, whichever is longer. |
| qScan / Sieve **CLI flag** | one MINOR with a deprecation warning, removed no earlier than the next MAJOR. |
| MCP **tool** or tool input field | one MINOR announcing it; removal in the next MAJOR. Hosted clients get the longer of one MAJOR or 6 months. |
| Action input/output | one MINOR with a warning in the job log; removal in the next MAJOR of the action. |
| Sieve **wire protocol** field | bump `PROTOCOL_VERSION`; keep the prior version accepted for one MAJOR where feasible (SUTs are external code). |
| **File formats** (baseline, SARIF additions) | additive only within a MAJOR; format removal/restructuring is MAJOR with a documented migration. |

Security fixes are exempt from deprecation windows where a window would prolong an
exposure: a [P0 security change](../THREAT-MODEL.md#8-mitigations--roadmap-p0-mapping)
may change behavior in a MINOR (e.g. hosting filesystem MCP tools OFF by default),
documented clearly in the CHANGELOG as a security-driven break.

## 5. Process

- Every release updates the [CHANGELOG](../CHANGELOG.md) ("Keep a Changelog"
  style) with an explicit **Breaking** section when MAJOR.
- Breaking changes to `@qproof/core` reference (or add) an
  [ADR](adr/README.md) when they reflect a decision, not just a fix.
- Releases are cut through the gated [release workflow](../../.github/workflows/release.yml)
  with npm provenance (see [SUPPLY-CHAIN.md](SUPPLY-CHAIN.md)).
