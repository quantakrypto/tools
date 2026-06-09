# qproof-tools — Architecture & API-Design Audit

Read-only audit of the `qproof-tools` monorepo (v0.1.0), focused on **structure,
contracts, and extensibility** — not correctness/perf/security, which
[`docs/AUDIT.md`](../AUDIT.md) already covers well. Where this overlaps that doc
(dead `ScanOptions.include`, the qscan↔action baseline split, the ruleId-prefix
scope toggle) it goes *deeper* with concrete interface designs rather than
re-listing the finding. No source was modified.

Scope: `@qproof/core`'s public boundary, the detector extensibility model, cross-
package coherence (baselines, option forwarding, the action↔qscan relationship),
the MCP transport/protocol/engine split, the sieve protocol/runner/category
layering, type-safety at the seams, and monorepo mechanics (project references,
`exports`/`bin`, versioning).

---

## 1. Summary

The monorepo has a **genuinely good spine**: a pure, side-effect-free `@qproof/core`
analysis engine that three downstream packages (qscan CLI, MCP server, GitHub
Action) consume through one re-exported `index.ts` barrel, plus a standalone
`sieve` conformance harness. Two subsystems are exemplary architecture — the MCP
**transport ↔ protocol ↔ engine** split (`server.ts` is pure and I/O-free,
`stdio.ts`/`http.ts` only frame bytes) and sieve's **`Category` registry**
(`categories/index.ts`), which is the *one* place in the repo that does
extensibility right. The type discipline is high: strict mode, `isolatedModules`,
zero `any`, JSON boundaries narrowed through type guards, and a correct
`DistributiveOmit` utility.

The architectural weaknesses are concentrated in two areas. **First, `@qproof/core`
extensibility is asymmetric**: sieve has a registry but core's detectors are a
flat hardcoded `Detector[]` (`scan.ts:23`) with no registration API, no language
abstraction, and scope (`source` vs `config`) inferred from **ruleId string
prefixes** (`scan.ts:26`) — adding Python/Go/Java today means editing core's
source and the detection model is JS/TS-only by construction. **Second,
cross-package contracts have drifted**: qscan and the action ship **two
incompatible baseline fingerprint schemes and two on-disk formats**, the action
declares a dependency on `@qproof/qscan` it never imports (it reimplements
`fingerprint`/`applyBaseline`/`meetsThreshold`/`renderReport`), and three
`ScanOptions` (`include`, `maxFileSize`, `noDefaultIgnores`) are unreachable from
any consumer. `core` calls its public surface a "LOCKED CONTRACT" (`index.ts:1`)
but ships **no semver/deprecation policy, no public API reference, and no ADRs** to
make that lock real.

Verdict: **B+ structure, C+ contract hygiene.** The boundaries are in the right
places; the seams between them have rusted and the extensibility story is half-
built. Everything below is additive and back-compatible.

---

## 2. Design decisions — good vs risky

| Decision | Where | Verdict | Note |
|---|---|---|---|
| Pure core, all I/O at the edges | `scan.ts`, `report.ts` | **Good** | Reporters/inventory take data, return data. Trivially testable. |
| Single barrel as the public contract | `core/src/index.ts` | **Good (boundary) / Risky (no policy)** | Right surface; but "LOCKED CONTRACT" is a comment, not a mechanism. |
| MCP transport/protocol/engine split | `server.ts` vs `stdio.ts`/`http.ts` vs `protocol.ts` | **Good** | `McpServer.handle(message): Promise<Response|null>` is pure. Textbook. |
| Sieve `Category` registry | `categories/index.ts:30` | **Good** | Family-scoped, `defaultOn` toggles, DI via `CategoryContext`. The model core's detectors *should* copy. |
| Detector plugin interface exists… | `types.ts:84` | **Good shape** | `Detector` is a clean pure contract. |
| …but no registry; flat hardcoded array | `scan.ts:23` | **Risky** | Consumers can't register detectors; `scan()` takes no detector list. |
| Scope classified by ruleId **prefix** | `scan.ts:26` `CONFIG_RULE_PREFIXES` | **Risky** | A detector whose ruleId doesn't start `pem-`/`tls-` is silently mis-scoped as "source". |
| Toggles filter output, not work | `scan.ts:78-87` | **Risky** | `--no-config` still runs every detector. Scope is a property of *findings*, not *detectors*. |
| `SarifLog.runs: unknown[]` | `report.ts:13` | **Risky** | "Permissive on purpose" but the type now guarantees nothing — see §6. |
| Two baseline fingerprint schemes | `qscan/baseline.ts:40` vs `action/main.ts:83` | **Risky (the worst)** | Incompatible inputs + incompatible on-disk formats across sibling tools. |
| Action depends on qscan but never imports it | `action/package.json` + `main.ts` | **Risky** | Phantom dep + tsconfig ref; logic duplicated instead of reused. |
| `VERSION` hand-synced to package.json | `version.ts`, comment | **Risky** | Manual sync; nothing enforces it. |
| Errors thrown, caught at edges | `scan.ts` → `cli.ts:57`, `action/main.ts:348` | **Acceptable** | Works, but no typed failure surface — see §7. |
| `DistributiveOmit` for the request union | `sieve/protocol.ts:104` | **Good** | Correct; plain `Omit` would collapse the union. Keep. |
| Discriminated-union wire protocol | `sieve/protocol.ts:93` | **Good** | `op`/`family` discriminators; `decodeResponse` validates shape. |

---

## 3. `@qproof/core` public contract

### 3.1 The barrel is the right boundary, the lock is not real

`core/src/index.ts` re-exports types, `VERSION`, `SarifLog`, `scan`/`detectors`,
`walkFiles`, `buildInventory`, `vulnerableDependencies`, the three reporters, and
`remediationFor`. This is a **well-chosen surface** — it's data-in/data-out, it
hides the detector internals, and `package.json` `exports` correctly pins `.` →
`dist/index.{js,d.ts}` with no deep-import escape hatch (`core/package.json`
`exports`). Consumers import named symbols, never reach into `dist/detectors/*`.

The problem is the word **"LOCKED CONTRACT"** (`index.ts:1`) and "treat
renames/removals as breaking" (`types.ts:6`). These are *aspirations with no
enforcement*: there's no `CHANGELOG`, no semver discipline beyond every package
sitting at `0.1.0`, no `@deprecated` tags, no API-extractor/`tsd` snapshot, and no
ADR recording what's intentionally stable. A "locked" contract that lives only in
a doc-comment will drift the first time someone renames a `Finding` field — and
because `0.x` semver permits breaking changes on minors, downstreams pinned at
`0.1.0` (qscan/mcp/action all hard-pin `"@qproof/core": "0.1.0"`) get no warning.

### 3.2 API ergonomics — strong, with two rough edges

`scan(options: ScanOptions): Promise<ScanResult>` is a clean single entry point.
`ScanResult` is fully serializable plain data (good — it survives JSON, SARIF, and
`structuredClone` for a future worker pool). `Finding`/`SourceLocation` are
disciplined. Rough edges:

- **`onFile` is the only injection point.** There's no way to pass a custom
  detector set, a custom ignore predicate, or an abort signal. For a library
  marketed as extensible (`Detector` is a *public* type), `scan()` not accepting
  `detectors?: Detector[]` is the central ergonomic gap (see §4).
- **`SarifLog` is barely a type.** `runs: unknown[]` (`report.ts:13`) means a
  consumer that reads `sarif.runs[0].results` gets `unknown` and must re-narrow
  everything `toSarif` just built. The function internally constructs precise
  shapes (`report.ts:80-105`) then erases them at the boundary.

### 3.3 Error strategy — throw + catch-at-edges, no typed failures

Core **throws**. `scan()` calls `await stat(options.root)` (`scan.ts:46`) with no
guard, so a nonexistent root throws raw `ENOENT`; `readBaseline` throws wrapped
errors (`qscan/baseline.ts:84`). Each consumer re-implements the catch:

- qscan: `cli.ts:55-61` wraps `runQscan` in try/catch → `EXIT.ERROR` (2).
- action: `main.ts:348` top-level `.catch` → `setFailed` + `process.exit(1)`.
- mcp: a per-call `safe()` wrapper (`tools.ts:49`) converts throws to `isError`
  tool results — the **only** structured-failure handling in the repo.

This works but the contract is implicit: nothing in the *type* of `scan` tells a
new consumer it can throw, what it throws, or which errors are user-fault
(bad path) vs bug. The three consumers each rediscovered this by hand, and they
disagree on the exit code for "scan failed" (2 vs 1). A typed result or a small
error taxonomy (§9) would make the failure surface part of the contract instead
of tribal knowledge.

---

## 4. Extensibility — the detector model

### 4.1 The interface is pluggable; the wiring is not

`Detector` (`types.ts:84`) is a good pure contract: `id`, `description`,
`appliesTo(filePath)`, `detect(input): Finding[]`. But the **only** way detectors
reach `scan()` is the module-level constant:

```ts
// scan.ts:23
export const detectors: Detector[] = [...sourceDetectors, pemDetector];
```

`scan()` closes over this array directly (`scan.ts:78`). There is **no registry,
no `registerDetector`, and `scan()` accepts no detector list**. To add a rule you
must edit `core/src/detectors/source.ts` and rebuild core. A downstream team
cannot ship a custom rule without forking. Contrast sieve, which *does* have a
registry (`categories/index.ts:30`, `RegisteredCategory[]` with `family` scoping
and `categoriesFor()`), proving the team knows the pattern — it just wasn't
applied to core.

### 4.2 Adding a language (Python/Go/Java) is effectively blocked

Detection is **JS/TS-only by construction**, in three independent places:

1. Every source detector's `appliesTo` is `hasExtension(f, JS_TS_EXTENSIONS)`
   (`source.ts:32,183,242,343,389`), and `JS_TS_EXTENSIONS` (`detect-utils.ts:114`)
   lists only `.js/.jsx/.ts/.tsx/.mjs/.cjs`.
2. The detector *bodies* match JS/TS syntax — `generateKeyPair('rsa')`,
   `subtle.*`, `new NodeRSA(`, JWT `alg` string literals. None transfer to Python's
   `cryptography`/`rsa`, Go's `crypto/ecdsa`, or Java's `KeyPairGenerator`.
3. The walker's binary skip-list (`walk.ts`) and manifest detection
   (`dependencies.ts` — npm only, `VulnerableDependency.ecosystem: "npm"`,
   `types.ts:75`) are ecosystem-bound.

So "add Python" today = add a new detector file, extend the extension list, add a
PyPI dependency DB with a *new* ecosystem literal (a breaking change to the
`"npm"`-only union), and wire all of it into the hardcoded array. There is no
seam that makes this a *plugin* rather than a *core edit*.

### 4.3 Scope-by-ruleId-prefix is fragile

`scan.ts:26` hardcodes `CONFIG_RULE_PREFIXES = ["pem-", "tls-"]` and
`isConfigFinding` (`scan.ts:29`) string-matches `f.ruleId.startsWith(p)`. Scope is
thus a property *inferred from a string*, not declared. Two concrete fragilities:

- The TLS detector emits `tls-legacy-version`, `tls-reject-unauthorized`,
  `tls-weak-cipher` — matched. The PEM detector emits `pem-*` — matched. But the
  *node-crypto* detector emits `node-crypto-*`, the lib detector emits
  `forge-rsa-keygen`/`elliptic-ec`/`node-rsa` — a future config-style detector
  that doesn't happen to start `pem-`/`tls-` is silently classified **source**,
  so `--no-source` would wrongly drop it and `--no-config` would wrongly keep it.
- The MCP `explain_finding` tool matches detector id against ruleId by prefix
  (`tools.ts:252`: `ruleId.startsWith(d.id)`). This *also* breaks for the lib
  detector (id `crypto-libs`, ruleIds `forge-*`/`elliptic-*`/`node-rsa`) — so
  `explain_finding` reports "no matching detector" for real findings. The same
  ruleId↔detector-id coupling assumption is wrong in two packages.

The fix in both cases is to make **scope and detector-identity declared data**, not
prefix archaeology.

### 4.4 Proposal — a `DetectorRegistry` + language abstraction

Make `scan()` accept detectors and give `Detector` a declared scope and language:

```ts
// types.ts — additive
export type DetectorScope = "source" | "dependency" | "config";
export type Language = "js" | "python" | "go" | "java" | "any";

export interface Detector {
  id: string;
  description: string;
  scope: DetectorScope;        // replaces ruleId-prefix inference
  language: Language;          // replaces hardcoded JS/TS appliesTo
  appliesTo(filePath: string): boolean;
  detect(input: DetectorInput): Finding[];
}

// scan.ts — additive option, defaults to the built-in set
export interface ScanOptions {
  // ...existing...
  detectors?: Detector[];      // override/extend the built-in registry
}
```

```ts
// new: core/src/registry.ts
export class DetectorRegistry {
  private readonly byId = new Map<string, Detector>();
  register(d: Detector): this {
    if (this.byId.has(d.id)) throw new Error(`duplicate detector: ${d.id}`);
    this.byId.set(d.id, d); return this;
  }
  forFile(path: string, scopes: ReadonlySet<DetectorScope>): Detector[] {
    return [...this.byId.values()]
      .filter(d => scopes.has(d.scope) && d.appliesTo(path));
  }
}
export const builtinRegistry = new DetectorRegistry();
// register node-crypto, webcrypto, libs, jwt, tls, pem at module load
```

`scan()` then filters by **declared** scope (no string prefixes) and skips work for
disabled scopes instead of filtering output (`scan.ts:84` → `forFile(path, enabled)`).
This also fixes §4.3 and the `explain_finding` mismatch (look up by `id`, exact).

**"Add a language" guide** (the missing doc): (1) create
`core/src/detectors/<lang>.ts` exporting `Detector`s with `language: "<lang>"` and
`scope`; (2) add file extensions the walker recognizes as text (a `textExtensions`
walker option, not a hardcoded list); (3) for dependencies, generalize
`VulnerableDependency.ecosystem` to `"npm" | "pypi" | "go" | "maven"` and add a
manifest matcher; (4) `builtinRegistry.register(...)`. Step 4 is the whole
integration — no edits to `scan()`.

---

## 5. Cross-package coherence

### 5.1 The baseline schism (the single biggest contract break)

Two sibling tools implement *baselines* and they are mutually unintelligible:

| | qscan (`baseline.ts`) | action (`main.ts`) |
|---|---|---|
| Fingerprint inputs | `ruleId\|file\|snippet\|line` (`baseline.ts:40`) | `ruleId file message` (`main.ts:84`) |
| Hash | `sha256(...).slice(0,12)` | none — raw space-joined string |
| Includes line? | **yes** (line-shift invalidates) | **no** (line-shift safe) |
| On-disk format | `{version, fingerprints[]}` (`baseline.ts:22`) | a **prior full report** (SARIF/JSON), re-fingerprinted on read (`main.ts:99,283`) |
| Semantics | fingerprint set, written by `--write-baseline` | diff-against-last-report |

A baseline produced by `qscan --write-baseline` is unreadable by the action and
vice versa, and even the *meaning* differs (qscan's is line-sensitive; the
action's is message-sensitive — `fingerprintsFromReport` keys on `message.text`,
`main.ts:120`, so any message wording change invalidates it). The action's scheme
is the better one (immune to line shifts), but the duplication guarantees they
diverge further.

**Proposal — one shared baseline module in `@qproof/core`** (or a new
`@qproof/baseline`), consumed by both:

```ts
// core/src/baseline.ts
export const BASELINE_VERSION = 2 as const;
export interface BaselineFile { version: 2; fingerprints: string[]; }

/** Line-insensitive, message-stable identity. Pick ONE scheme. */
export function fingerprint(f: Finding): string {
  const input = `${f.ruleId} ${f.location.file} ${f.message}`;
  return createHash("sha256").update(input).digest("hex").slice(0, 16);
}
export function buildBaseline(fs: Finding[]): BaselineFile;
export function applyBaseline(fs: Finding[], accepted: ReadonlySet<string>):
  { kept: Finding[]; suppressed: Finding[] };
export function readBaseline(path: string): Promise<Set<string>>;   // validated
export function writeBaseline(path: string, b: BaselineFile): Promise<void>;
```

qscan re-exports these (it already re-exports its own, `qscan/index.ts:34`); the
action imports them instead of reimplementing. One fingerprint, one format, one
test surface. The action's "baseline = prior report" convenience can stay as a
*reader adapter* (`fingerprintsFromReport`) that calls the shared `fingerprint`.

### 5.2 The action↔qscan phantom dependency

`action/package.json` declares `"@qproof/qscan": "0.1.0"` and `action/tsconfig.json`
lists `{ "path": "../qscan" }` as a project reference — but **`main.ts` never
imports qscan** (its only `@qproof/*` import is `@qproof/core`, `main.ts:16`).
Instead it **reimplements** `SEVERITY_ORDER` (`main.ts:30` ≈ qscan
`args.ts`/`tools.ts`), `meetsThreshold` (`main.ts:74` ≈ qscan `meetsThreshold`),
`fingerprint`/`applyBaseline` (≈ qscan `baseline.ts`), and `renderReport`
(`main.ts:163` ≈ qscan `renderReport`, `qscan/index.ts:154`). `qscan/index.ts`'s
header even claims `runQscan` is "the single entry point shared by the CLI and by
`@qproof/action`" — but the action doesn't call it.

So either the action *should* depend on qscan (consume `runQscan` and the shared
baseline, deleting ~80 lines of duplicated decision logic) or the dependency and
project reference are dead weight that slow the build graph and mislead readers.
Given `runQscan` was explicitly designed to be reused (injectable `scanFn`,
`QscanRun.exitCode`, `index.ts:74-82`), **the action should consume it.** That also
auto-resolves §5.1 by funnelling both tools through one baseline path.

### 5.3 Dead / unreachable options

`ScanOptions` exposes three options no consumer can use:

- **`include`** (`types.ts:107`) is never read in `scan.ts`, and `WalkOptions`
  (`walk.ts:51`) has **no `include` field at all** — so it's not merely unwired,
  it's unwireable without a walker change. It's a documented no-op in the public
  contract. Either implement it in the walker or delete it from the public type
  (a *breaking* removal under the "locked contract" — which is exactly why a
  deprecation policy matters).
- **`maxFileSize`** and **`noDefaultIgnores`** are honored by `scan()`
  (`scan.ts:55-57`) but `runQscan` forwards only `exclude/source/dependencies/
  config` (`index.ts:110-116`), and `QscanOptions` (`args.ts`) has no field for
  them. So files >2 MiB and ignored dirs can't be overridden from the CLI even
  though core supports it. `runQscan` should spread the full option set and the
  arg parser should add `--max-file-size` / `--no-default-ignores`.

---

## 6. MCP layering (strength) & sieve layering

### 6.1 MCP — the model the rest of the repo should follow

The **transport ↔ protocol ↔ engine** separation is the best architecture in the
repo. `McpServer.handle(message): Promise<JsonRpcResponse | null>` (`server.ts:87`)
is **pure**: it takes an already-parsed value, validates it, dispatches, and
returns an envelope — no sockets, no streams, no `JSON.parse`. The transports own
*only* framing and policy: `stdio.ts` does NDJSON over readline, `http.ts` does
request/response with a 1 MiB body cap, and both share the same `server.handle`.
`protocol.ts` is pure shape+helpers (`makeSuccess`/`makeFailure`, spec-correct
`-32700…-32603`). This means the entire protocol surface is unit-testable without
a socket, and a third transport (WebSocket, in-process) is a drop-in. Keep this
exactly; it's the template for what core's detector layer is missing (a pure
engine the edges configure).

Two contract nits, not structural: `initialize` ignores the client's requested
`protocolVersion` (`server.ts:132` always returns the constant, contradicting the
`protocol.ts:18` comment), and `inputSchema` (`tools.ts`) is advertised with
`additionalProperties:false` but never enforced server-side — each handler hand-
checks `typeof args.path === "string"`. A small `validate(schema, args)` step in
`onToolsCall` (`server.ts:147`) would make the advertised schema load-bearing.

### 6.2 Sieve — clean layering and the only real registry

Sieve layers correctly: `protocol.ts` (pure wire types + (de)serialization, no
crypto) → `runner.ts` (child-process I/O, id-correlated, timeouts) → `categories/*`
(pure drivers over a `Runner`) → `report.ts` (verdict). `CategoryContext`
(`categories/types.ts:50`) is dependency injection done right — categories receive
`runner`, `sizes`, `iterations`, `vectorsDir` and never reach for globals. The
`CATEGORIES` registry (`categories/index.ts:30`) tags each entry with `family`
scope and a `defaultOn` flag, and `categoriesFor(family, includeTiming)` selects
them — this is precisely the registry pattern core's detectors lack. The
`BugClass` taxonomy (`types.ts:22`, `AF-02`/`AF-05`) even links checks to a
documented antiform catalog. The one wart is `RegisteredCategory.family: Family |
"any"` using a string literal for "all", mirroring core's "unknown"/"any"
string-as-enum habit — fine, but worth a shared convention.

---

## 7. Type safety

Overall **high**. Strict mode, `isolatedModules`, `noImplicitOverride`,
`forceConsistentCasingInFileNames` are all on (`tsconfig.base.json`). Findings:

- **Zero `any`** anywhere in `src` (grep confirms). No `as any`. The casts that
  exist are principled `unknown`→`Record<string, unknown>` narrowings at JSON
  boundaries (`dependencies.ts:225,229,243`, `baseline.ts:113`,
  `protocol.ts:107`) and `err as Error` in catch blocks — both idiomatic.
- **JSON parsing boundaries are consistently guarded.** `scanManifest`
  (`dependencies.ts:217`) and `readBaseline` (`qscan/baseline.ts:88`) try/catch
  `JSON.parse` and then *type-guard* the result (`isBaselineFile`,
  `isJsonRpcRequestLike`) before trusting it. The MCP server narrows untrusted
  params structurally (`server.ts:148-165`). This is the right pattern, applied
  uniformly.
- **`DistributiveOmit`** (`sieve/protocol.ts:104`) is correct and *necessary* —
  plain `Omit<Request, "id">` over the 5-variant request union would collapse to
  the common `RequestBase` keys and lose `pk`/`sk`/`msg`/`sig`. Good call, well
  commented. No change.
- **The two real type-erasure leaks** are `SarifLog.runs: unknown[]`
  (`report.ts:13`) and `ScanResult`-via-`scan` having no declared error channel
  (§3.3). `runs: unknown[]` makes the *output* of `toSarif` unusable to typed
  consumers (the action immediately `JSON.stringify`s it, `main.ts:165`, dodging
  the issue; a programmatic consumer can't). Define a minimal `SarifRun` /
  `SarifResult` and type `runs: SarifRun[]` — `toSarif` already builds that shape.
- `action/main.ts:222` casts the parsed GitHub event payload to a hand-written
  shape with no guard — low risk (it's `try`-wrapped, `readPullRequestContext`
  never throws) but it's the one JSON boundary that *doesn't* validate before use.

---

## 8. Monorepo mechanics

**Project references / build graph.** Root `tsconfig.json` lists all five packages
as solution references; each package `extends` `tsconfig.base.json`, sets
`composite: true` (inherited), and declares its own `references`: qscan→core,
mcp→core, action→**core + qscan**, sieve→(none). `npm run build` = `tsc --build`
walks this graph. The graph is correct **except** action→qscan is a reference to a
package action never imports (§5.2) — so qscan is rebuilt as an action dependency
for nothing. sieve is correctly standalone (no core dependency — it's a different
domain).

**`exports` / `bin` / `main` maps.** Clean and consistent: every published package
pins `exports["."]` to `dist/index.{d.ts,js}` with `types` first (correct
ordering), `bin` maps are right (`qscan`→`dist/cli.js`, `qproof-mcp`→`dist/stdio.js`,
`sieve`→`dist/cli.js`), and `files` ships `dist` (+ `src` for core sourcemaps).
`action` is correctly `private: true` (not published; runs from `dist/main.js`).
No deep-import surface is exposed — the `exports` map is the enforcement that makes
the index.ts barrel the *real* boundary. Good.

**Versioning / semver — the gap.** Every package is `0.1.0` and downstreams
**hard-pin** `"@qproof/core": "0.1.0"` (exact, not `^`). Combined with `0.x` semver
(where minors may break) and a "LOCKED CONTRACT" enforced only by a comment, this
is fragile: there is **no policy** for what a core API change does to consumers, no
changelog, no `@deprecated` window, and `VERSION` in `core/src/version.ts` is
**hand-synced** to `core/package.json` (the comment literally says "keep in sync")
— nothing enforces it, and it's duplicated against the SARIF `informationUri`
inconsistency already noted in AUDIT.md. **What breaks on a core API change:** a
rename to any `Finding`/`ScanResult` field silently breaks qscan's reporters, the
action's `fingerprintsFromReport`, and mcp's `summarizeScan` *at runtime* if
versions drift, or *at build time* if they're locked — with no migration signal
either way. A semver policy + a `tsd`/api-extractor snapshot test in core's CI
would turn "locked" from aspiration into a gate.

---

## 9. A `Result`/error type (proposal)

Today failure is "throw and let each edge catch." To make the failure surface part
of the contract without forcing a rewrite, add an *optional* typed channel:

```ts
// core/src/result.ts
export type ScanError =
  | { kind: "path-not-found"; path: string }
  | { kind: "path-not-readable"; path: string; cause: string }
  | { kind: "internal"; message: string };

export type Result<T, E = ScanError> =
  | { ok: true; value: T }
  | { ok: false; error: E };

/** Non-throwing variant of scan(); scan() can be a thin throwing wrapper. */
export function tryScan(options: ScanOptions): Promise<Result<ScanResult>>;
```

`scan()` stays for back-compat (throws); `tryScan()` is the typed path the MCP
`safe()` wrapper (`tools.ts:49`) and the action want. The discriminated `ScanError`
also lets qscan and the action *agree* on the exit code for "path not found"
(currently qscan→2, action→1) by mapping `error.kind` consistently.

---

## 10. A config-file format (proposal)

There is **no settings file** today — all configuration is CLI flags (qscan) or
action `inputs`, and the two don't share a schema. Worse, `--no-config` is about
*scanning config files*, not *reading a config file* — the namespace is already
overloaded. A single `qproof.config.json`, read by core and honored by every
consumer, would unify ignores, scope toggles, severity threshold, baseline path,
and (post-§4) custom detector enablement:

```jsonc
// qproof.config.json — discovered upward from the scan root
{
  "$schema": "https://qproof.com/schema/config-1.json",
  "version": 1,
  "exclude": ["vendor/**", "**/*.generated.ts"],
  "scopes": { "source": true, "dependencies": true, "config": true },
  "maxFileSizeBytes": 2097152,
  "severityThreshold": "high",
  "baseline": "qproof-baseline.json",
  "detectors": { "disable": ["jwt-jose"], "languages": ["js", "python"] }
}
```

Core gains `loadConfig(root): Promise<ResolvedConfig>` and `scan()` merges
`config < CLI/action inputs` (flags win). This is the natural home for the §5.3
unreachable options and the §4 language/detector toggles, and it gives qscan and
the action **one** source of truth instead of two flag dialects.

---

## 11. What's required to improve

1. **Unify baselines** — one shared `fingerprint` + format in core; qscan and the
   action both consume it (§5.1). Resolve the line-vs-message divergence by picking
   the action's line-insensitive scheme.
2. **Make the action consume qscan** (`runQscan` + shared baseline) or drop the
   phantom dependency and project reference (§5.2).
3. **Introduce `DetectorRegistry` + declared `scope`/`language` on `Detector`**;
   make `scan()` accept `detectors?` and filter by declared scope, deleting the
   ruleId-prefix inference (§4.3/§4.4). Fixes the `explain_finding` mismatch too.
4. **Resolve the three unreachable `ScanOptions`** — wire `include` into the walker
   or remove it; forward `maxFileSize`/`noDefaultIgnores` through `runQscan` and add
   CLI flags (§5.3).
5. **Type the SARIF output** (`SarifRun`/`SarifResult`, not `unknown[]`) and add an
   optional `tryScan`/`Result` failure channel (§3.2/§9).
6. **Establish a semver + deprecation policy** and a core public-API snapshot test
   so "LOCKED CONTRACT" is enforced, not narrated (§8).

---

## 12. What's missing (artifacts, not code)

- **Semver / deprecation policy.** No statement of what `0.x` → `1.0` means, no
  `@deprecated` convention, no changelog. The "locked contract" comment is the only
  governance and it isn't a gate.
- **A public API reference.** `index.ts` is the surface but there's no generated
  API doc (typedoc/api-extractor) and no `tsd` snapshot to catch accidental
  breaks. New consumers reverse-engineer the contract from source.
- **Config-file support.** No `qproof.config.json` (§10); configuration is split
  across CLI flags and action inputs with no shared schema.
- **Plugin / "add a language" / "add a detector" docs.** `Detector` is a public
  type with no documented way to register one, and no Python/Go/Java guide — the
  extensibility story is undocumented *and* unwired.
- **ADRs.** None. The genuinely good decisions (MCP transport split, sieve registry,
  zero-dependency posture, throw-at-edges, exact version pinning) and the
  deliberate trade-offs (lexical detection, JS/TS-only) are uncaptured, so the next
  contributor can't tell intent from accident — which is how the baseline schism
  and the phantom dependency happened in the first place.

---

*Written to `docs/audits/architecture.md`; no source files were modified.*
