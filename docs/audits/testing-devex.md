# quantakrypto-tools — Testing, DevEx & OSS-Quality Audit

Read-only audit of **testing, developer experience, and OSS/repo quality**. It
does **not** re-cover the architecture/security/perf/hosting analysis in
[`../AUDIT.md`](../AUDIT.md); where points overlap it cites that audit and adds
only the testing/DevEx/governance angle.

Scope: `quantakrypto-tools` v0.1.0 (`core`, `qscan`, `mcp`, `action`, `sieve`). 183
`test()` cases across 22 files (matches "182 passing"; one is aggregate).
Toolchain is TypeScript + `tsx` only; tests are `node:test`. No source or config
was modified.

---

## 1. Summary scorecard

| Area | Status | Notes |
|---|---|---|
| Unit tests (logic) | ✅ Strong | 183 cases, pure-function coverage is broad and disciplined |
| Integration / E2E (real core over a fixture tree) | ❌ Missing | qscan e2e uses `fakeScan`, not the real `scan()` — no test runs real detectors over real files |
| HTTP transport tests (`mcp/http.ts`) | ❌ Missing | Zero socket-level tests; entire file untested |
| Action runtime path (`run`, PR comment, annotations) | ⚠️ Partial | Pure decision logic covered; `run`/`commentOnPullRequest`/`annotateFindings`/`readPullRequestContext` untested |
| Runner failure paths (sieve `TimeoutError`/`SutCrashError`) | ⚠️ Partial | Mock SUT covers bug-classes; no hang/crash-mid-request test |
| Coverage tooling | ❌ Missing | No `--experimental-test-coverage`, no c8, no coverage gate, no badge |
| Property-based / fuzz tests | ❌ Missing | Hand-rolled parsers (protocol, manifest, SARIF, args) are example-tested only |
| ESLint | ❌ Missing | No linter at all |
| Prettier / formatter | ❌ Missing | No formatter; style is enforced only by reviewer discipline |
| EditorConfig | ❌ Missing | No `.editorconfig` |
| Commit hooks / pre-commit | ❌ Missing | No husky / lint-staged / lefthook |
| Per-package typecheck-only script | ⚠️ Weak | Only a root `typecheck: tsc --build` (emits); no noEmit fast path |
| CI workflow | ❌ Missing | No `.github/` at all — no build/test/typecheck on push or PR |
| Node matrix testing | ❌ Missing | `engines: >=20` but nothing tests on 20 **and** 22 |
| CodeQL / SARIF self-scan | ❌ Missing | The repo ships a SARIF scanner but does not scan itself |
| CONTRIBUTING.md | ❌ Missing | |
| SECURITY.md | ❌ Missing | No vuln-disclosure path for a security tool |
| CODE_OF_CONDUCT.md | ❌ Missing | |
| Issue / PR templates | ❌ Missing | |
| CHANGELOG.md | ❌ Missing | |
| Release process / semver policy | ❌ Missing | Single commit, no tags, no documented release flow |
| README badges | ❌ Missing | Root README has none |
| Per-package READMEs | ✅ Strong | All five packages have 118–198-line READMEs |
| `examples/` directory | ❌ Empty | Root README advertises it for "end-to-end examples"; it is empty |
| Committed Action `dist/` | ❌ Blocker | `dist/` is gitignored; a `node20` action **cannot run** from a pinned ref |
| Lockfile | ✅ Present | `package-lock.json` lockfileVersion 3 (good for reproducibility) |
| `engines` / `files` / `exports` correctness | ✅ Mostly | All publishable packages set them; minor gaps noted below |
| npm provenance / publishing | ⏸️ Deferred | No `.npmrc`, no publish workflow — acceptable per stated deferral |

Legend: ✅ good · ⚠️ partial / needs work · ❌ missing · ⏸️ intentionally deferred.

**One-line verdict:** the *code and unit tests* are A-grade, but the repo is
**not yet "finalized tech"** for an OSS release — it has **no CI, no
lint/format, no coverage, no governance docs, and a release-blocking missing
Action `dist/`**. Everything here is additive; none requires touching source.

---

## 2. Test coverage gaps

### 2.1 No coverage tooling is configured

There is no coverage measurement anywhere: no `--experimental-test-coverage`
flag in any `test` script (`packages/*/package.json` all run
`node --import tsx --test test/*.test.ts`), no `c8`/`nyc`, no `coverage/` output
(it is gitignored at `.gitignore:6` but never produced). So the "182 passing"
number says nothing about *which lines/branches* are exercised.

**Recommendation (zero new runtime deps, matches the ethos):** use Node's
built-in coverage. Per package:

```jsonc
// packages/<pkg>/package.json
"scripts": {
  "test": "node --import tsx --test test/*.test.ts",
  "test:coverage": "node --import tsx --experimental-test-coverage --test test/*.test.ts"
}
```

Node ≥ 20 ships `--experimental-test-coverage`; it prints a per-file
line/branch/function table and needs **no dependency**. For an HTML report or a
machine-readable lcov to upload, add `c8` as the *only* new devDependency
(`c8 --reporter=lcov node --import tsx --test ...`) — but the built-in summary
plus a CI threshold is enough to start. Gate it in CI (see §4) at a deliberately
low initial bar (e.g. 70% lines) and ratchet up.

### 2.2 Under-tested modules and branches (concrete)

- **`packages/core/src/walk.ts` error paths.** `walk.test.ts` covers ignores,
  excludes, size, binary, and single-file mode, but **not**:
  - the `readdir` failure branch (`walk.ts:127-132`, unreadable dir → silent
    skip) — needs a chmod-0 dir or a mocked rejection;
  - the per-file `stat` failure branch (`walk.ts:160-162`);
  - the **symlink skip** (`walk.ts:141-144`) — no test creates a symlink and
    asserts it is not followed (this is a security-relevant branch: it prevents
    cycles and root-escape, per `../AUDIT.md` §2.1);
  - the single-file **oversized / binary** rejection (`walk.ts:105`).
- **`packages/sieve/src/runner.ts` timeout & crash paths.** `harness.test.ts`
  drives `mock-sut.ts` through every *bug-class*, but never exercises the
  runner's own failure machinery directly:
  - `TimeoutError` (`runner.ts:42`, `174-177`) — no SUT that *hangs* on a
    request;
  - `SutCrashError` on mid-request `exit` (`runner.ts:97-104`) and on spawn
    `error` (`runner.ts:93-95`, e.g. a non-existent bin);
  - `failAll` on an undecodable line (`runner.ts:134-139`);
  - the SIGTERM→SIGKILL escalation in `close()` (`runner.ts:221-230`) — no SUT
    that *ignores* stdin-end and SIGTERM.
  These are the highest-risk untested branches because they are exactly the
  paths a misbehaving SUT triggers, and they involve real process teardown.
- **`packages/mcp/src/http.ts` — entirely untested.** `transport.test.ts` only
  exercises the **stdio** loop in-memory; there is **no** test that binds a
  socket via `createHttpServer`/`startHttpServer` and asserts:
  - `GET /health` → 200 `{status:"ok"}` (`http.ts:108`);
  - `POST /mcp` happy path returns the JSON-RPC result + `mcp-session-id`
    header (`http.ts:158-165`);
  - notification → **202 no body** (`http.ts:159-163`);
  - non-POST `/mcp` → **405** with `Allow: POST` (`http.ts:114-120`);
  - unknown route → **404** (`http.ts:125`);
  - malformed JSON → **400** parse error (`http.ts:151-155`);
  - **body over 1 MiB** → **413** and the socket is destroyed
    (`http.ts:52-57`, `144-148`) — this is the only abuse guard and it is
    unverified;
  - session-id echo vs. mint (`http.ts:136-139`).
  A `createHttpServer(createQuantakryptoServer())` listening on port 0 with `fetch`
  against it would cover all of the above with no new dependency.
- **`packages/action/src/main.ts` — the PR-comment & orchestration path.**
  `main.test.ts` covers the pure helpers thoroughly (`readInputs`, `fingerprint`,
  `applyBaseline`, `buildSummary`, `meetsThreshold`, `shouldFail`,
  `fingerprintsFromReport`), but **not**:
  - `commentOnPullRequest` (`main.ts:239-266`) — the `fetch` to the GitHub API.
    Inject a fake `fetch` (or run a throwaway `http` server as the API) to assert
    URL shape (`/repos/{owner}/{repo}/issues/{n}/comments`), `Authorization:
    Bearer`, the non-2xx warning branch, and the thrown-error swallow branch;
  - `readPullRequestContext` (`main.ts:213-233`) — feed a temp `GITHUB_EVENT_PATH`
    JSON with `pull_request.number`, with `number`, and with neither;
  - `annotateFindings` (`main.ts:142-156`) — assert error vs. warning vs. notice
    routing per severity;
  - `run` (`main.ts:291`) end-to-end over a temp workspace (the `process.exit(1)`
    on failure, `main.ts:340`, makes this awkward — factor the exit out or test
    via a subprocess).
  Note `../AUDIT.md` §2.4 flags that PR commenting has **no de-dup** (one comment
  per push); a `commentOnPullRequest` test is the natural place to lock in the
  fix when it lands.
- **SARIF edge cases (`packages/core/src/report.ts`).** `report.test.ts` covers
  the happy path and the level mapping, but not:
  - **zero findings** → empty `results`/`rules` arrays still produce a valid log;
  - a finding **without `column`/`region` detail** (the CRLF off-by-one column
    noted in `../AUDIT.md` §2.1 lives here and is unverified);
  - **message-text escaping** for findings whose `message`/`snippet` contains
    quotes, backslashes, newlines, or non-ASCII (the `✅`/`…` chars in the
    action's `buildSummary`, `main.ts:185,195`, hint that non-ASCII flows through
    report text — see §7.4);
  - very long snippets / many findings (SARIF size).
- **The E2E gap (most important).** `packages/qscan/test/e2e.test.ts` builds a
  realistic vulnerable fixture (RSA keygen, ECDH, `node-forge` dependency) but
  runs it through **`fakeScan`** (`e2e.test.ts:21,78` → `test/helpers.ts`), not
  the real `@quantakrypto/core` `scan()`. So **no test in the repo runs the real
  detectors over a real file tree and asserts the finding set.** This is the
  single biggest coverage hole: a regression in `source.ts`/`pem.ts`/`scan.ts`
  detection logic against real files would pass CI. `../AUDIT.md` §1 (line 42)
  and roadmap P3 note the same; from a *testing* standpoint it should be P1. Add
  one `core`-level test: materialize a temp tree, call the real `scan({root})`,
  assert the sorted `ruleId` set, `filesScanned`, and inventory.

### 2.3 Property-based / fuzz opportunities

These hand-rolled parsers are ideal for property testing — and `node:test`
supports a trivial in-process generator loop, so this needs **no new dependency**
(a small seeded PRNG + 1k iterations). Optionally add `fast-check` as a
dev-only dep if richer shrinking is wanted.

- **Sieve protocol (`packages/sieve/src/protocol.ts`).**
  - *Round-trip:* for arbitrary valid `Response` objects,
    `decodeResponse(JSON.stringify(x)+"\n")` deep-equals `x`
    (`protocol.ts:219`). Today only fixed examples are checked
    (`protocol.test.ts:26-49`).
  - *Base64 round-trip:* `fromB64(toB64(bytes)) === bytes` for arbitrary
    `Uint8Array` (`protocol.ts:290+`), and `fromB64` rejects any string whose
    re-encode differs (the canonical-form check) — fuzz random near-base64
    strings.
  - *Never-crash:* `decodeResponse(randomString)` only ever returns a `Response`
    or throws `ProtocolError` (never another error type) — fuzz arbitrary bytes
    and assert that invariant. The discriminated-union branch order
    (`protocol.ts:262-276`) is subtle and worth fuzzing.
- **Dependency manifest parser (`packages/core/src/dependencies.ts`,
  `scanManifest`).** `../AUDIT.md` §2.1 notes it "tolerates invalid JSON"
  (`dependencies.ts:219`). Fuzz with: truncated JSON, deeply nested objects,
  huge dependency maps, non-string versions, duplicate keys, BOM, and assert it
  never throws and never emits a finding for a name not in `BY_NAME`.
- **SARIF reporter (`packages/core/src/report.ts`).** Property: for any
  `ScanResult` built from arbitrary `Finding[]`, `JSON.parse(JSON.stringify(
  toSarif(r)))` succeeds and `runs[0].results.length === findings.length` and
  every `ruleId` referenced by a result exists in `rules[]`. This catches
  escaping and rule-dedup bugs that example tests miss.
- **qscan arg parser (`packages/qscan/src/args.ts`).** Fuzz random argv arrays
  (mix of `--flag`, `--flag=v`, repeated `--ignore`, leading `-` values) and
  assert it either returns a `ParsedArgs` or throws `ArgError` — never anything
  else. `args.test.ts` is strong (20 cases) but enumerated.

---

## 3. Quality tooling that is missing

The repo has **no linter, no formatter, no EditorConfig, no commit hooks**, and
only a root build-as-typecheck. For a project whose pitch is "simple, clean,
reusable code … everything documented, tested" (root `README.md`), automated
style/lint enforcement is the missing leg.

### 3.1 ESLint (flat config + typescript-eslint)

Add `eslint`, `typescript-eslint`, and `@eslint/js` as devDependencies and an
`eslint.config.mjs` at the root. Flat config is the current standard and plays
well with a TS monorepo:

```js
// eslint.config.mjs
import js from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  js.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,
  {
    languageOptions: {
      parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname },
    },
    rules: {
      // Matters most for a zero-dep, type-strict, security-adjacent codebase:
      "@typescript-eslint/no-floating-promises": "error",   // unhandled async (see http.ts/stdio.ts void usage)
      "@typescript-eslint/no-misused-promises": "error",
      "@typescript-eslint/await-thenable": "error",
      "@typescript-eslint/no-explicit-any": "warn",         // report.test.ts uses `any`; keep src clean
      "@typescript-eslint/consistent-type-imports": "error",// the code already does `import type` consistently
      "no-console": ["error", { allow: ["warn", "error"] }],// CLIs write via process.stdout/stderr, not console
      "eqeqeq": ["error", "smart"],
    },
  },
  { ignores: ["**/dist/**", "**/node_modules/**", "coverage/**"] },
);
```

Why these rules specifically: `no-floating-promises`/`no-misused-promises` are
the highest-value checks for this codebase — it uses `void handleRequest(...)`
(`http.ts:87`) and async transport loops where a dropped rejection is a real
hazard. `consistent-type-imports` simply codifies a convention the source
already follows. `noUnusedLocals` is already on in `tsconfig.base.json:18`, so
ESLint should defer to TS there (don't double-report).

Add scripts:

```jsonc
// root package.json
"lint": "eslint .",
"lint:fix": "eslint . --fix"
```

### 3.2 Prettier

Add `prettier` (dev-only) and a `.prettierrc.json`. The codebase already looks
Prettier-shaped (2-space, double quotes, trailing commas), so adoption should be
near-noop:

```json
{ "printWidth": 100, "singleQuote": false, "trailingComma": "all", "semi": true }
```

Scripts: `"format": "prettier --write ."`, `"format:check": "prettier --check ."`.
Add `eslint-config-prettier` to the flat config's tail to disable stylistic
ESLint rules that would fight Prettier.

### 3.3 `.editorconfig`

Cheap, editor-agnostic, no dependency:

```ini
root = true
[*]
charset = utf-8
end_of_line = lf
insert_final_newline = true
trim_trailing_whitespace = true
indent_style = space
indent_size = 2
[*.md]
trim_trailing_whitespace = false
```

### 3.4 Per-package typecheck-only script

Today the only typecheck is the root `typecheck: tsc --build`
(`package.json:21`), which **emits** declarations and `.tsbuildinfo`. There is no
fast noEmit check. Add per-package and a fast root variant:

```jsonc
// each packages/*/package.json
"typecheck": "tsc -p tsconfig.json --noEmit"
```

This gives a quick "does it type-check" signal in CI and pre-commit without
producing `dist/`, and isolates which package broke.

### 3.5 Commit hooks (optional, low-dep)

For OSS, a pre-commit that runs `format:check`, `lint`, and `typecheck` on staged
files keeps the tree clean. `lefthook` (single binary, fast) or `husky` +
`lint-staged` are the usual choices. This is the *only* recommendation here that
adds tooling weight; it is optional and can be CI-only instead (CI is the
non-negotiable, hooks are convenience).

---

## 4. CI/CD — there is no CI today

`.github/` does not exist. Nothing builds, type-checks, tests, lints, or scans on
push or PR. This is the **highest-priority** gap for "finalized tech": the 182
tests only protect the project if they run automatically.

### 4.1 Core CI matrix (Node 20 × 22, build + typecheck + test)

```yaml
# .github/workflows/ci.yml
name: CI
on:
  push: { branches: [main] }
  pull_request:
permissions:
  contents: read
jobs:
  build-test:
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        node: [20, 22]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: "${{ matrix.node }}", cache: npm }
      - run: npm ci
      - run: npm run typecheck
      - run: npm run build
      - run: npm test
      - run: npm run lint        # once §3.1 lands
      - run: npm run format:check # once §3.2 lands
```

`engines.node` is `>=20` everywhere; testing **both 20 and 22** is the matrix the
project implicitly promises. Add `windows-latest` to the matrix if Windows is a
target — the walker uses POSIX-path normalization (`walk.ts:61`,
`toPosix`/`path.sep`) and the runner spawns processes, so cross-platform
behavior is worth one extra cell.

### 4.2 Coverage upload (optional)

After §2.1, add a coverage job that runs `--experimental-test-coverage` (or
`c8 --reporter=lcov`) and uploads to Codecov/Coveralls, or simply prints the
table and fails under a threshold. Keep it advisory at first.

### 4.3 CodeQL + quantakrypto self-scan (dogfooding)

Two cheap, high-signal additions for a security tool:

```yaml
# .github/workflows/codeql.yml — standard CodeQL for JS/TS
# (github/codeql-action init → analyze on a schedule + PR)
```

And **dogfood the action on its own repo** — the strongest possible demo and a
real regression guard:

```yaml
# .github/workflows/self-scan.yml
name: quantakrypto self-scan
on: [pull_request]
permissions: { contents: read, security-events: write }
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 20, cache: npm }
      - run: npm ci && npm run build
      - run: node packages/qscan/dist/cli.js . --format sarif --output quantakrypto.sarif.json --fail-on-findings false
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with: { sarif_file: quantakrypto.sarif.json }
```

This proves the SARIF output is GitHub-ingestible and that qscan runs clean on
its own source.

---

## 5. OSS governance — what's missing

For a public, security-adjacent project under Apache-2.0, the governance set is
nearly empty. Each item below is a missing *file*, not a code change.

### 5.1 Required documents

- **`SECURITY.md`** — *most important for a crypto/security tool.* Define a
  private disclosure channel (GitHub private vulnerability reporting and/or a
  `security@quantakrypto.com` mailbox), supported versions, and response-time
  expectations. A scanner that finds crypto problems must itself have a vuln
  intake path.
- **`CONTRIBUTING.md`** — dev setup (`npm ci`, `npm run build`, `npm test`), the
  **zero-runtime-dependency rule** (this is the project's identity — make it an
  explicit contribution gate), coding conventions, how to run lint/format/typecheck,
  and the "no fabricated KAT vectors" honesty rule that `sieve` already embodies.
- **`CODE_OF_CONDUCT.md`** — adopt Contributor Covenant 2.1 verbatim.
- **`CHANGELOG.md`** — Keep a Changelog format; start at `0.1.0`. The repo has a
  single commit and no tags, so the history is a clean slate to start one.

### 5.2 Templates (`.github/`)

- `.github/ISSUE_TEMPLATE/bug_report.yml` and `feature_request.yml` (issue
  forms). A bug template that asks for "command, Node version, OS, and a minimal
  repro tree" suits a scanner.
- `.github/PULL_REQUEST_TEMPLATE.md` with a checklist: tests added, `npm test`
  green, **no new runtime dependency**, docs/README updated.
- `.github/CODEOWNERS` (optional) and `.github/FUNDING.yml` (optional).

### 5.3 Release process & semver policy

There is no documented release flow, no tags, no version-bump strategy. For a
5-package workspace with internal `0.1.0` pins (e.g. `@quantakrypto/qscan` →
`"@quantakrypto/core": "0.1.0"`), define:

- **Versioning:** either lockstep (all packages move together — simplest given
  the tight `0.1.0` pins) or independent with a tool. Given the size, **lockstep
  + a single git tag `vX.Y.Z`** is the pragmatic choice; document it.
- **Semver policy:** what counts as breaking — notably the **`@quantakrypto/core`
  `ScanResult`/`Finding` contract** (the README calls it "the contract"), the
  **MCP tool I/O schemas**, the **sieve NDJSON protocol** (`PROTOCOL_VERSION`,
  currently 1), and the **action inputs/outputs** (`action.yml`). State that
  these surfaces are semver-governed.
- **Release checklist** in `CONTRIBUTING.md` or `RELEASING.md`: bump versions,
  update `CHANGELOG.md`, tag, build the action `dist/` (see §6.4), publish.

### 5.4 Badges (root README)

Root `README.md` has zero badges. Add, once CI exists: CI status, Node version
(`>=20`), license (Apache-2.0), and (when published) npm version per package and
an OpenSSF Scorecard badge (§6.1). Badges are the quickest "this is maintained"
signal for a new visitor.

---

## 6. Supply-chain / release readiness

### 6.1 OpenSSF Scorecard

Run the Scorecard action on a schedule and display the badge. The repo already
scores well on several checks once CI lands: **Pinned-Dependencies** (lockfile
v3 present — good), **Dangerous-Workflow** (none yet), **License** (Apache-2.0
present). It currently *fails*: **CI-Tests**, **Branch-Protection**,
**Code-Review** (single commit, no PR history), **SAST** (no CodeQL),
**Security-Policy** (no `SECURITY.md`), **Fuzzing** (none). §§2.3, 4, 5 close
most of these.

### 6.2 SLSA provenance & npm provenance (deferred — noted)

Publishing is explicitly deferred, so this is forward-looking: when publishing,
build on GitHub Actions with `id-token: write` and `npm publish --provenance` to
emit npm provenance, and consider the SLSA generator for build provenance. No
action needed now beyond *not* publishing from a developer laptop later.

### 6.3 `engines` / `files` / `exports` correctness (per package)

Reviewed all five `package.json`:

- **`engines.node: ">=20"`** — set on all five. ✅ Consistent with the action's
  `runs.using: node20`.
- **`exports`** — `core`, `qscan`, `mcp`, `sieve` each declare a correct
  `exports["."]` with `types` then `default` ordering. ✅ `action` is `private`
  and has no `exports` (correct — it is not a library).
- **`files`** — mostly correct, with two notes:
  - `@quantakrypto/core` ships **`"src"`** in `files` (`packages/core/package.json`),
    so the published tarball includes source. Intentional? It enlarges the
    package; if it is for source-maps/debugging, fine — otherwise drop it. The
    other libs ship only `dist` + docs.
  - `@quantakrypto/sieve` lists **`"vectors"`** in `files`, but `packages/sieve/vectors/`
    contains only a `README.md` (no vectors ship, by design per `../AUDIT.md`
    §2.5). Harmless, but the entry exists for content that is deliberately absent.
- **`bin`** — `qscan`, `quantakrypto-mcp`, `sieve` declare `bin`; all point at `dist/`
  files that exist post-build. ✅
- **`repository`** is set at the **root** (`package.json`) but **not on the
  individual packages** — npm will warn and the per-package npm page won't link
  to source. Add `repository` (with `directory`) to each publishable package.
- **`homepage`/`bugs`** — only the root sets `homepage`; packages set neither.
  Add `bugs` (issues URL) and `homepage` per package for npm-page quality.

### 6.4 Release blocker: the Action `dist/` is not committed

**This is the most consequential release-readiness finding.** `.gitignore:2`
ignores `dist/`, and `git ls-files` shows **0 tracked `dist/` files**. But a
`node20` JavaScript GitHub Action runs `dist/main.js` **directly from the
checked-out ref** — there is no build step on the runner. The root README tells
users to consume it as
`uses: quantakrypto/tools/packages/action@v1`
(root `README.md` table), which **will fail** at that ref because
`packages/action/dist/main.js` won't exist.

Options (pick one, document it in the release process):
1. **Commit the built `dist/`** for the action only (the standard pattern;
   un-ignore `packages/action/dist/`), and add a CI check that fails if
   `dist/` is stale vs. `src/` (the `@vercel/ncc` + "dist is up to date"
   pattern). This usually means bundling to a single `dist/main.js` so the
   action has no `node_modules` at runtime — which fits the zero-runtime-dep
   ethos perfectly (the action's only deps are the internal `@quantakrypto/*`
   packages, which must be bundled in).
2. **Use a Docker or composite action** that builds on the runner (slower, more
   moving parts).

Without (1) or (2), the published action is non-functional regardless of test
status. Recommend (1) with `ncc`-style bundling + a "dist up to date" CI gate.

### 6.5 Reproducibility

`package-lock.json` (lockfileVersion 3) is present and should be committed and
used via `npm ci` in CI (the §4 workflow does). ✅ This is the one supply-chain
fundamental already in place. Consider a `.nvmrc`/`.node-version` (`20`) so
local dev matches CI without thinking.

---

## 7. DX of the tools themselves

### 7.1 CLI help & errors — strong

- **qscan** (`packages/qscan/src/cli.ts`) is exemplary: usage errors print
  `qscan: <message>` + `Run "qscan --help" for usage.` and exit `2`
  (`cli.ts:28-33`); runtime errors print `qscan: <message>` and exit `2`
  (`cli.ts:57-61`); a top-level catch prints `qscan: fatal: …` (`cli.ts:109-112`).
  `--help`/`--version` short-circuit cleanly. Color is correctly gated on
  `format===human && !output && isTTY && NO_COLOR===undefined` (`cli.ts:48-52`).
  This is the model the other CLIs should match.
- **sieve** has a documented `--impl` quirk: it whitespace-splits the command
  (`../AUDIT.md` §2.5, `cli.ts:80`), so a path with spaces breaks. That is a real
  DX papercut for a new user pointing at `"node /My Impl/x.js"`; the audit's
  quote-aware / `--` passthrough fix is the right call. From a *testing* angle,
  add a case asserting the current behavior so the fix is a deliberate change.

### 7.2 Examples quality

- The **root `examples/` directory is empty**, yet the root README's workspace
  layout advertises it as `examples/ end-to-end examples` and the design-goals
  blurb says "example-driven." This is a visible broken promise to a new
  contributor. Either populate it (a tiny vulnerable sample repo + a
  `qscan`/action/sieve walkthrough) or remove the reference.
- **MCP examples are good:** `packages/mcp/examples/` has a `README.md` and a
  `transcript.jsonl` showing a real session — exactly the right artifact for an
  MCP server.
- **Sieve** ships `examples/mock-sut.ts` (referenced by `harness.test.ts:10`),
  which doubles as a reference SUT implementation — excellent, it shows
  implementers the protocol concretely.

### 7.3 README completeness — strong per package, thin at root

All five packages have substantial READMEs (118–198 lines). The **root README
is only 54 lines** and lacks badges, a "Testing" section, a contribution
pointer, and a `docs/` index beyond one line. Add a short "Contributing &
Security" section linking the new governance docs, and badges (§5.4).

### 7.4 The macOS `file`-reports-"data" emoji quirk (cosmetic)

`packages/action/src/main.ts` embeds non-ASCII in the PR-comment summary:
`"… ✅"` at `main.ts:185` and the `…` ellipsis at `main.ts:195`. When that
output is written to a file, the macOS `file(1)` utility reports it as
`data` rather than `ASCII text`/`UTF-8 Unicode text` in some cases, and some
naive "is this a text file" heuristics get confused. Purely cosmetic, and it
renders fine in a GitHub PR comment. If you want every tool output to be
plain-ASCII-clean (helps shell pipelines and `file`-based tooling), replace the
`✅` with `OK`/`[ok]` and `…` with `...`. Low priority; noted because the task
called it out.

### 7.5 New-contributor rough edges (summary)

A first-time contributor today would hit, in order: (1) no `CONTRIBUTING.md` so
they guess the workflow; (2) `npm test` works but there's no `lint`/`format` to
tell them the style; (3) the empty `examples/` dir contradicts the README; (4)
no CI, so a PR gets no automated signal; (5) if they touch the action, they
won't know `dist/` must be rebuilt/committed (§6.4). All five are closed by the
docs and CI recommended above — none require source changes.

---

## 8. Minimum bar to "finalized tech" — checklist

Concrete, additive, **no source edits**. Ordered by leverage.

- [ ] **CI workflow** (`.github/workflows/ci.yml`): Node **20 × 22** matrix
      running `npm ci → typecheck → build → test` (§4.1). *Non-negotiable.*
- [ ] **Commit/bundle the Action `dist/`** + a "dist up to date" CI gate (§6.4).
      *Release blocker — the action is otherwise non-functional.*
- [ ] **Coverage**: add `test:coverage` per package via
      `--experimental-test-coverage`; print + gate at a starting threshold (§2.1).
- [ ] **E2E test through the real `core.scan()`** over a fixture tree (§2.2).
- [ ] **HTTP transport tests** for `mcp/http.ts` (health/405/404/413/202/echo)
      (§2.2).
- [ ] **Runner failure-path tests** (timeout, crash, SIGKILL escalation) (§2.2).
- [ ] **ESLint flat config** + `typescript-eslint` with `no-floating-promises`
      et al.; `lint` script + CI step (§3.1).
- [ ] **Prettier** + `.editorconfig`; `format:check` script + CI step (§3.2–3.3).
- [ ] **Per-package `typecheck` (`tsc --noEmit`)** scripts (§3.4).
- [ ] **`SECURITY.md`** with a private disclosure path (§5.1). *Highest-priority
      governance doc for a security tool.*
- [ ] **`CONTRIBUTING.md`** (with the zero-dep rule as a gate), **`CODE_OF_CONDUCT.md`**,
      **`CHANGELOG.md`** (§5.1).
- [ ] **Issue + PR templates** under `.github/` (§5.2).
- [ ] **Documented semver policy + release process** (lockstep tags) (§5.3).
- [ ] **Per-package `repository`/`bugs`/`homepage`** fields (§6.3).
- [ ] **README badges** (CI, license, Node) once CI exists (§5.4).
- [ ] **Populate or remove `examples/`** to match the README (§7.2).
- [ ] **quantakrypto self-scan + CodeQL** workflows (dogfooding + SAST) (§4.3).
- [ ] **OpenSSF Scorecard** workflow + badge (§6.1).
- [ ] *(optional)* property/fuzz tests for protocol/manifest/SARIF/args (§2.3).
- [ ] *(optional)* commit hooks via lefthook/husky (§3.5).
- [ ] *(deferred)* npm provenance/publishing setup (§6.2).

---

## 9. What's required to improve (priority order)

1. **Stand up CI (Node 20×22: typecheck+build+test).** Nothing else matters
   until the existing 182 tests run automatically. (§4.1)
2. **Fix the Action `dist/` release blocker.** Commit/bundle `dist/` + staleness
   gate, or the published action cannot run. (§6.4)
3. **Close the three integration holes:** real-`scan()` E2E, `http.ts` socket
   tests, and `runner.ts` failure paths. These are where regressions will slip
   through today. (§2.2)
4. **Add lint + format + per-package typecheck** and wire into CI; turn on
   `no-floating-promises` given the async transport code. (§3)
5. **Add `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `CHANGELOG.md`,
   and templates.** A security tool without a disclosure policy is a credibility
   gap. (§5)
6. **Add coverage measurement + a (low, ratcheting) gate.** (§2.1)
7. **Define and document semver + release process; add per-package npm metadata
   and badges.** (§5.3, §6.3, §5.4)
8. **Dogfood:** quantakrypto self-scan + CodeQL + Scorecard. (§4.3, §6.1)

## 10. What's missing (inventory)

Files/configs that simply do not exist and should: `.github/workflows/*.yml`
(CI, CodeQL, self-scan, scorecard), `.github/ISSUE_TEMPLATE/*`,
`.github/PULL_REQUEST_TEMPLATE.md`, `eslint.config.mjs`, `.prettierrc.json`,
`.editorconfig`, `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`,
`CHANGELOG.md`, `.nvmrc`, committed Action `dist/`, README badges, populated
`examples/`, coverage scripts, per-package `typecheck` scripts, per-package
`repository`/`bugs`/`homepage`, and property/fuzz test suites for the four
hand-rolled parsers. Present and good (keep): `package-lock.json` (v3),
per-package READMEs, `LICENSE` (Apache-2.0), strong unit tests, clean CLI
error handling, MCP/sieve examples, and consistent `engines`/`exports`.

---

*This audit was written to `docs/audits/testing-devex.md`; no source or
configuration files were modified.*
