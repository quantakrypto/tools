# quantakrypto-tools — Post-Build Audit & Improvement Roadmap

Audit of the `quantakrypto-tools` monorepo (v0.1.0) at commit time of writing.
Scope: all five packages (`core`, `qscan`, `mcp`, `action`, `sieve`), READMEs,
sources, and tests. No code was modified.

---

## 1. Executive summary

`quantakrypto-tools` is a zero-runtime-dependency TypeScript monorepo (ESM, NodeNext,
strict, Node ≥ 20) that ships a post-quantum readiness toolchain:

- **`@quantakrypto/core`** — a lexical crypto-detection engine: a filesystem walker,
  six regex-based detector families, a curated vulnerable-dependency DB,
  inventory + readiness scoring, and SARIF/JSON/human reporters.
- **`@quantakrypto/qscan`** — a CLI shell over core, with baselines, severity-gated
  exit codes, and three output formats.
- **`@quantakrypto/mcp`** — a from-scratch JSON-RPC 2.0 / MCP server (stdio + HTTP
  transports) exposing five tools backed by core.
- **`@quantakrypto/action`** — a zero-dependency GitHub Action wrapping a scan, SARIF
  output, inline annotations, baselines, and optional PR comments.
- **`@quantakrypto/sieve`** — a standalone conformance battery that drives a
  user-supplied ML-KEM / ML-DSA implementation (the SUT) over an NDJSON
  child-process protocol and runs eight test categories.

**Zero-dependency posture: real and well-honored.** Every package uses Node
built-ins only (`node:fs`, `node:crypto`, `node:http`, `node:readline`,
`node:child_process`). The MCP JSON-RPC framing, the GitHub Actions toolkit
shims (`packages/action/src/io.ts`), and the CLI arg parsers are all hand-rolled
rather than pulled from libraries. The only dev dependencies are `typescript`,
`tsx`, and `@types/node`. This is the project's strongest selling point and it
is genuinely delivered.

**Test/coverage snapshot.** 183 `test()`/`it()` cases across the five packages
(the "182 tests" figure is consistent — likely one `it()` is a nested/skipped
case). Tests use only `node:test` + `node:assert`, drive pure functions and
in-memory streams, and avoid process spawning except where intrinsic (the sieve
harness test exercises the real child-process path against `mock-sut.ts`).
Coverage is **breadth-strong on logic, thin on integration**: there is no
end-to-end test that scans a fixture tree and asserts the full finding set, and
no test of the HTTP transport against a live socket. The action's
`commentOnPullRequest` (network) is untested by design.

**Overall quality verdict: high (B+ / A-).** The architecture is clean
(transport ↔ protocol ↔ engine separation in MCP; pure core in qscan/action),
the code is uniformly well-documented, naming is disciplined, and the honest
stance in sieve (ships no KAT vectors, never fabricates) is exactly right. The
weaknesses are (a) detection is purely lexical so accuracy is bounded, (b) some
declared options are dead, (c) two divergent baseline/fingerprint schemes exist
across packages, and (d) performance is single-threaded and re-reads/re-scans
without short-circuiting. None are blocking; all are addressable.

---

## 2. Per-package review

### 2.1 `@quantakrypto/core`

**Strengths.** Clear module boundaries (`walk` → `scan` → `detectors` →
`inventory` → `report`). Detectors are pure and stateless (`Detector` contract in
`types.ts`). `makeFinding` (`detect-utils.ts`) centralizes offset→line/col,
snippet extraction, and remediation defaulting. The walker is deterministic
(sorted dirents, `walk.ts:135`) and refuses to follow symlinks
(`walk.ts:141`) — a sound default that prevents cycles and root-escape.

**Correctness concerns.**
- **`ScanOptions.include` is declared but never consumed** (`types.ts:107`;
  no reference in `walk.ts`/`scan.ts`). It is a documented no-op — either wire
  it or remove it.
- **Config toggles filter output, not work.** In `scan.ts:78-87` every detector
  runs over every applicable file regardless of `source`/`config`; the toggle
  only decides whether to *keep* the finding (`isConfigFinding`,
  `scan.ts:29`). Functionally correct, but `--no-config` / `--no-source` save no
  CPU, and the source-vs-config partition is by ruleId prefix (`pem-`, `tls-`),
  so a future detector with a non-matching prefix would be silently
  misclassified as "source."
- **`offsetToLineCol` column on CRLF files** includes the CR offset
  (`detect-utils.ts:26` documents this as "harmless," and it is for reporting,
  but SARIF consumers that map columns precisely will be off by one on CRLF).
- **Readiness score is order-independent but not finding-identity-aware**
  (`inventory.ts:53`): N identical findings (e.g. the same key pasted twice) get
  diminishing-returns penalties as if distinct. Acceptable, worth documenting.

**Security concerns.**
- **ReDoS: low risk, but not zero.** Most detector regexes are linear (literal
  prefixes + bounded character classes). Two warrant a look: the TLS weak-cipher
  regex `ciphers\s*:\s*['"`][^'"`]*\b(...)\b[^'"`]*['"`]` (`source.ts:439`) has
  two unbounded `[^'"`]*` around an alternation — on a pathological multi-MB
  single-quoted string with no closing quote it backtracks, though the 2 MiB file
  cap and the negated class (which can't overlap the quote) keep it
  near-linear in practice. The WebCrypto "near a subtle call" scan
  (`source.ts:196`) is O(matches × calls) because `nearCall` does a linear scan
  of `callIndexes` per algo match — quadratic on a file with thousands of
  `subtle.*` calls. Bound both.
- **Path traversal: not applicable to the walker** (it only descends from
  `root` and skips symlinks). But **`scan()` reconstructs absolute paths from the
  walker's relative POSIX path via `path.join(baseDir, ...rel.split("/"))`
  (`scan.ts:62`)** — safe because `rel` comes from the walker, not user input.
  The MCP `scan_path` tool, however, passes an *arbitrary client-supplied path*
  straight to `scan({ root })` (see 2.3) — that is where traversal matters.
- **PEM detector reads every text file** (`pem.ts:85 appliesTo: () => true`) with
  a cheap `includes("-----BEGIN ")` fast-reject (`pem.ts:88`) — good.

**Robustness/edge cases.** Unreadable dirs/files are skipped silently
(`walk.ts:129`, `scan.ts:70`) — correct for a scanner. `scanManifest` tolerates
invalid JSON (`dependencies.ts:219`). Binary skip is extension-based only
(`walk.ts:79`); a `.txt` that is actually binary will be read and regex-scanned
(bounded by the 2 MiB cap). Minified/generated files are **not** skipped beyond
`.min.js` and `.map` (`walk.ts:47`) — a 1.9 MiB bundled vendor file in `src/`
gets fully scanned (see §3).

**Concrete smells.**
- `inventory.ts:85 void SEVERITIES;` — a dead reference kept only to silence an
  unused-var lint; the seeding it claims to guard is done inline above. Remove.
- SARIF `informationUri` previously diverged across the codebase (three
  different repo URLs for one project). It is now unified to the canonical
  repository `https://github.com/quantakrypto/tools` in both `core` (`report.ts:19`)
  and qscan's fallback SARIF (`qscan/src/report.ts`), matching the README.

### 2.2 `@quantakrypto/qscan`

**Strengths.** Clean separation: `cli.ts` does I/O + exit codes only; `index.ts`
(`runQscan`) is pure and injectable (`scanFn` hook, `index.ts:81`) — this is why
the action can reuse it. Arg parser (`args.ts`) is small and correct, including
`--flag=value`, repeatable `--ignore`, and "next token starting with `-` is not a
value" guarding (`args.ts:101`). Color is correctly gated on TTY + `NO_COLOR`
(`cli.ts:48`). Exit-code policy (0/1/2) is coherent and documented.

**Correctness concerns.**
- **`runQscan` drops three core options.** It forwards `exclude`, `source`,
  `dependencies`, `config` but **not** `maxFileSize`, `noDefaultIgnores`, or
  `include` (`index.ts:110-116`). The CLI has no flags for them either, so large
  files >2 MiB and ignored dirs can't be overridden from the CLI. Minor, but the
  README implies core's full option surface is reachable.
- **`renderJson`/`renderSarif` carry a "not implemented" fallback**
  (`report.ts:67 serialize()`) for a core that no longer stubs those functions.
  This is dead defensive code now that core implements both — harmless but
  misleading (the fallback SARIF has a *different* shape than core's, so a code
  path that "can't happen" would produce inconsistent output).

**Security concerns.** Baseline files are parsed with a type guard
(`baseline.ts:111`), good. `--output` writes wherever the user points
(`cli.ts:76`) — expected for a CLI. No shell invocation anywhere.

**Robustness.** Fingerprint is `sha256(ruleId|file|snippet|line).slice(0,12)`
(`baseline.ts:40`). **Note the divergence**: this includes `snippet` *and*
`line`, so reformatting that shifts a finding's line *invalidates* the baseline
entry (the README claims baselines "survive rescans," but a line shift will
resurface a finding). The action uses a *different* fingerprint (ruleId + file +
message, **excluding** line) — see 2.4. Two packages, two baseline semantics, two
on-disk formats (qscan: `{version,fingerprints[]}`; action: a whole prior
report). This is the single biggest cross-package inconsistency.

### 2.3 `@quantakrypto/mcp`

**Strengths.** Textbook transport/protocol/engine split: `McpServer.handle`
(`server.ts:87`) is pure and async, transports only frame I/O. JSON-RPC error
mapping is spec-correct (`-32700/-32600/-32601/-32602/-32603`,
`protocol.ts:67`), notifications correctly get no reply (`server.ts:99`),
duplicate-tool registration throws (`server.ts:60`). The HTTP body cap
(`MAX_BODY_BYTES = 1 MiB`, `http.ts:37`) and `isMainModule` symlink-resolving
guard (`http.ts:189`, `stdio.ts:86`) are thoughtful.

**Correctness concerns.**
- **`initialize` ignores the client's requested `protocolVersion`.** The README
  says it "echoes the client's requested version when we support it"
  (`README` / `HOSTING.md`), but `onInitialize` (`server.ts:132`) always returns
  the hard-coded `MCP_PROTOCOL_VERSION`. Either implement the echo/negotiation or
  fix the docs.
- **`inputSchema` is advertised but never enforced.** `additionalProperties:
  false` and `required` are sent to the client (`tools.ts:143`), but the server
  does no schema validation — each handler hand-checks `typeof args.path ===
  "string"`. Fine for trusted local stdio; a hosting risk (see below).

**Security concerns (these dominate for a hosted deployment).**
- **`scan_path` is an unauthenticated arbitrary-path file reader.** A client can
  call `scan_path` / `inventory_crypto` with `path: "/etc"`,
  `"../../secrets"`, or `"/"` and the server will walk and read those files
  (`tools.ts:152` → `scan({ root: path })`). Snippets of matched lines come back
  in the result. Locally (stdio, trusted user) this is acceptable; **hosted, it
  is a critical SSRF/LFI-class issue.** Path allow-listing / chroot / sandbox is
  mandatory before any hosting (see §6).
- **No request-level auth on `/mcp`** (`http.ts:129`) — by design for the
  scaffold, but the only abuse guard today is the body-size cap. No timeout on
  tool execution: a scan of a huge directory will hold the connection and a
  worker indefinitely.
- **Session id is echoed unvalidated** (`http.ts:136`): a client supplies any
  `mcp-session-id` and it's reflected. Harmless while stateless; becomes a
  session-fixation vector the moment sessions carry state.

**Robustness.** Tool failures are returned as `isError` results, not protocol
errors (`server.ts:166`) — correct MCP semantics, lets the model react. The
`safe()` wrapper (`tools.ts:49`) and "core may be stubbed" comments are now stale
(core is implemented) but harmless.

### 2.4 `@quantakrypto/action`

**Strengths.** The GitHub Actions toolkit reimplementation (`io.ts`) is
faithful: workflow-command escaping (`escapeData`/`escapeProperty`,
`io.ts:52-64`), heredoc `GITHUB_OUTPUT` writing (`io.ts:147`), boolean-input YAML
1.2 parsing (`io.ts:34`). Decision logic is pure and testable (`readInputs`,
`meetsThreshold`, `shouldFail`, `applyBaseline`, `buildSummary`). SARIF is
written from the **pre-baseline** result so code scanning sees the full picture,
while only **new** findings gate the build (`main.ts:163` comment + `main.ts:302`)
— a correct and subtle choice. PR commenting is best-effort and never fails CI
(`main.ts:239`).

**Correctness concerns.**
- **Divergent fingerprint from qscan.** `fingerprint` here is
  `ruleId + file + message`, space-joined, **excluding line/column**
  (`main.ts:83`). This is the *better* baseline semantics (immune to line
  shifts) — but it disagrees with qscan's snippet+line fingerprint, so a baseline
  written by `qscan --write-baseline` is **not** usable by the action and vice
  versa. The action also consumes a *prior full report* as its baseline, not a
  fingerprint file. Unify (see roadmap P1).
- **`fingerprintsFromReport` SARIF path uses `message.text`** (`main.ts:120`),
  which matches `fingerprint`'s use of `message` — internally consistent, good.
  But it does not read `properties.algorithm`, so it's purely message-string
  dependent; any wording change to a `Finding.message` silently invalidates
  baselines.

**Security concerns.**
- **PR-comment token handling is sound.** The token comes from the
  `github-token` input (`main.ts:60`), is sent as `Authorization: Bearer`
  (`main.ts:248`) over HTTPS to the GitHub API, and is **never logged** — failures
  log only status text (`main.ts:258`). Good. One gap: there is **no comment
  de-duplication** — every run posts a *new* comment (`main.ts:245` POSTs to
  `/issues/{n}/comments`), so a chatty PR accumulates one quantakrypto comment per push.
  Find-and-update (or a hidden marker + PATCH) is the expected behavior.
- **`comment-pr` requires `pull-requests: write`**, correctly documented in the
  README. No token is required for the core scan, limiting blast radius.

**Robustness.** `readPullRequestContext` never throws (`main.ts:213`).
`process.exit(1)` is called directly on failure (`main.ts:340`) — fine for an
action, but it bypasses the `setFailed`-then-let-caller-decide pattern the rest
of `io.ts` follows.

### 2.5 `@quantakrypto/sieve`

**Strengths.** The honest design is the headline: Sieve ships **no** KAT vectors
and refuses to fabricate them (`vectors.ts` header; `kat.ts:41` skips cleanly
without `--vectors`); the only hard-coded constants are public FIPS 203/204 sizes
(`sizes.ts`). Category design is excellent — self-consistency (correctness,
determinism), FO/implicit-rejection (AF-02), and size/format (AF-05) checks need
no external data, and the timing probe is correctly **advisory-only and excluded
from the verdict** (`timing.ts:86`, `report.ts:14`). The runner is robust:
per-request timeouts with `unref` (`runner.ts:174`), id-correlated responses
(out-of-order tolerant), stderr ring-buffer capped at 64 KiB
(`runner.ts:109`), and a graceful end→SIGTERM→SIGKILL teardown
(`runner.ts:197`).

**Correctness concerns.**
- **`--impl` is split on whitespace** (`cli.ts:80
  raw.split(/\s+/)`), so a command path or argument **containing spaces is broken
  apart** (e.g. `--impl "node /my impl/x.js"` → `["node","/my","impl/x.js"]`).
  Quote-aware tokenization or a `--` passthrough is needed.
- **`encaps` length-check is the SUT's job, but the `sizes` category sends a
  zeros sk to decaps** (`sizes.ts:116 skZeros`) and expects a defined error; a SUT
  that happens to accept an all-zeros valid-length sk and returns an
  implicit-rejection ss would (correctly per FO) *not* error — the test assumes
  zeros-sk is rejectable, which is implementation-dependent. Minor; the honest
  ML-KEM behavior is to accept any well-formed sk.

**Security concerns.**
- **Child-process handling is sound and injection-free.** `spawn(bin, args)` is
  used with an argv array, **not** `shell: true` (`runner.ts:87`), so there is no
  shell-injection surface from `--impl`. Env is the parent env merged with opts
  (`runner.ts:89`) — note this **passes the full parent environment (incl.
  secrets) to the SUT**; for a hardened harness, consider an allow-list env.
- **Oversize/garbage inputs are the SUT's problem, by design** — the harness
  generates a 1 MiB blob (`robustness.ts:25`) and expects a clean error; the
  harness itself bounds memory.
- **No total wall-clock budget.** Per-request timeout exists, but a SUT that
  answers every request just under the timeout across thousands of iterations can
  run for a very long time. A global deadline would help in CI.

**Robustness.** A category that throws is converted into a failing category
rather than aborting the run (`index.ts:96`). The ACVP loader is defensive
(`vectors.ts`): unknown algorithms/modes become non-fatal notes, hex is
validated (`vectors.ts:81`), nothing is invented. `decodeResponse`
(`protocol.ts:219`) validates structural shape before the runner trusts a line.

---

## 3. Efficiency improvements

Ranked by impact. Quantification assumes a typical JS/TS repo: thousands of
files, a handful of large bundles, six source detectors.

**(I1) Single-pass tokenization instead of N global regexes — High.**
Today each source file is scanned by ~12 independent global regexes
(`source.ts`), each a full pass over the file text, plus the PEM detector's 5
passes (`pem.ts`). That's **~17 linear scans per JS/TS file.** Combine the
literal-anchored patterns into one alternation with named groups (or a single
`RegExp` with a switch on which group matched), reducing to ~2-3 passes. On a
large file this is a 5-8× reduction in regex work. Lower-effort variant: keep the
detectors but add a **per-file pre-filter** — most files contain none of
`generateKeyPair|subtle|createSign|NodeRSA|elliptic|KEYUTIL|-----BEGIN|RS256|...`;
a single combined `test()` short-circuits the whole detector array when the file
has no candidate token at all (the PEM detector already does this at
`pem.ts:88`; generalize it).

**(I2) Skip minified/generated/vendored content — High.** `walk.ts` skips only
`.min.js` and `.map`. Add heuristics: files whose first KB has an average line
length > ~2000 chars (minified), `*.bundle.js`, `*-min.js`, `*.generated.*`,
source-map-embedded files, and lockfile-sized JSON. A single 2 MiB bundle costs
as much as ~1000 small source files across 17 passes; skipping it is the
single biggest real-world win on front-end repos.

**(I3) Memoize the dependency DB and avoid re-deriving per call — Medium.**
`BY_NAME` is already a `Map` (`dependencies.ts:158`) — good. But `offsetOfKey`
(`dependencies.ts:198`) compiles a fresh `RegExp` per vulnerable package per
manifest. Precompile an escaped-name → RegExp map once at module load, or do a
single tokenization pass over the manifest. Negligible per repo (few manifests),
but free.

**(I4) Precompile and freeze all detector regexes — Medium.** `eachMatch`
(`detect-utils.ts:132`) **clones the regex on every call** when it isn't already
global (`new RegExp(re.source, ...)`). All detector regexes *are* declared
global, so the clone branch is dead — but the per-call `g.lastIndex = 0` reset is
fine; the concern is the inline regex literals inside `detect()` bodies
(`source.ts:45,80,99,...`) which are **re-created on every file** because they're
literals inside the function. Hoist them to module-level `const`s so V8 compiles
them once. ~File-count× fewer regex compilations.

**(I5) Avoid re-reading and large-file streaming — Medium.** Each file is read
once with `readFile(..., "utf8")` (`scan.ts:69`) — no re-reads, good. For files
near the 2 MiB cap, the whole string is held in memory and every regex
materializes match arrays; a streaming/chunked scan with overlap windows would
cap memory, but PEM blocks and multi-line matches make this fiddly. Lower
priority than I1/I2.

**(I6) qScan startup time — Low/Medium.** Startup is dominated by ESM module
graph resolution (`@quantakrypto/core` pulls in all detectors, reporters, deps DB) and,
in dev, `tsx` transpilation. For `npx` users the install/resolve dominates. Wins:
ship prebuilt JS (already the plan via `dist`), lazy-import the SARIF/JSON
reporters only when that format is requested, and avoid importing the full deps
DB when `--no-deps`. Marginal (<50 ms) but cheap.

**(I7) Sieve runner throughput — Medium.** The runner is strictly serial:
`send()` awaits each response before the next request (categories `await` in a
loop). For 8 categories × tens of iterations × multiple sub-requests, that's
hundreds of round-trips, each paying IPC latency. **Pipelining** (the protocol
already correlates by `id`, `runner.ts:140`) — issue a batch of independent
requests and await them together — would cut wall-clock substantially for
correctness/determinism/sizes, where iterations are independent. The timing
category must stay serial (it measures latency). See §4 for the SUT-concurrency
plan.

---

## 4. Parallel processing

### 4.1 Parallelizing the scan across CPU cores

The scan is embarrassingly parallel: each file is read and regex-scanned
independently, and merging is a concatenation + a deterministic sort that already
exists (`scan.ts:96`). A `node:worker_threads` pool over the file list is the
right tool.

**Design.**
1. **Enumerate first, then dispatch.** Run `walkFiles` (cheap, I/O-bound) on the
   main thread to produce the relative-path list. Walking in parallel buys little
   and complicates ignore semantics.
2. **Chunk by work, not by count.** Pre-`stat` sizes are already known to the
   walker; bucket files into chunks of roughly equal *total bytes* (e.g. target
   ~4 MiB/chunk) so one giant file doesn't starve a worker. Fall back to
   round-robin when sizes are unknown.
3. **Workers run the existing pure pipeline.** Each worker imports the detectors
   and `scanManifest`, reads its files, returns `Finding[]` (structured-cloneable
   — `Finding` is plain data). No shared mutable state.
4. **Backpressure.** Bounded pool (default `os.availableParallelism()`), a work
   queue, and at most `poolSize` chunks in flight. Use `MessageChannel` or a
   simple "request next chunk on completion" protocol so a slow worker doesn't
   accumulate a backlog.
5. **Deterministic merge.** Collect all `Finding[]`, concatenate, then apply the
   **existing** `findings.sort` (file → line → ruleId). Result is identical to the
   serial scan regardless of completion order. `filesScanned` is summed.
6. **When it pays off.** Worker spawn + module-init cost is ~30-80 ms/worker.
   Below ~200 files or ~2 MiB total, stay single-threaded (the overhead exceeds
   the win). Gate on a threshold: `if (files.length < N || totalBytes < B) run
   serially`. Above that, expect near-linear speedup to core count for
   CPU-bound regex work (which dominates on large repos).

**Interface sketch (additive, back-compatible):**

```ts
interface ScanOptions {
  // ...existing...
  /** Worker threads to use. 0/1 = serial (default). "auto" = availableParallelism(). */
  concurrency?: number | "auto";
  /** Files below this combined size always run serially. Default 2 MiB. */
  parallelThresholdBytes?: number;
}

// internal
interface ScanChunk { files: string[]; baseDir: string; }
interface ChunkResult { findings: Finding[]; filesScanned: number; }

async function scanParallel(opts, files): Promise<ScanResult> {
  const pool = new WorkerPool("./scan-worker.js", resolveConcurrency(opts));
  const chunks = chunkByBytes(files, /* ~4 MiB */);
  const results = await pool.map<ScanChunk, ChunkResult>(chunks); // bounded in-flight
  const findings = results.flatMap(r => r.findings).sort(STABLE_ORDER);
  return assemble(findings, sum(results, "filesScanned"));
}
```

The public `scan()` signature is unchanged; `concurrency` defaults to serial so
existing behavior and determinism are preserved. The worker entry simply re-uses
`detectors` + `scanManifest` per file.

### 4.2 Parallelizing sieve iterations against a SUT

Two distinct axes, with different safety rules:

- **Within one SUT process: pipeline, don't fork.** The protocol is id-correlated
  (`runner.ts`), so independent requests (e.g. N correctness round-trips) can be
  in flight at once. Add `runner.sendMany(reqs[])` that writes all requests and
  `Promise.all`s their responses, bounded by a `maxInFlight` (default 16) to avoid
  unbounded stdin buffering and to keep the SUT's input queue sane. **Exclude the
  timing category** (must measure isolated latency) and any category that depends
  on ordering.
- **Across SUT processes: a pool for throughput/isolation.** For large iteration
  counts or to isolate crashes, spawn a small pool of SUT processes (each its own
  `Runner`) and shard independent iterations across them. **Per-process
  isolation** is the point: a SUT that corrupts internal state or crashes on one
  input doesn't poison the others, and `SutCrashError` (`runner.ts:50`) fails only
  that shard. Concurrency limit defaults to `min(availableParallelism, 4)` —
  crypto SUTs are CPU-heavy, so oversubscription hurts.

**Interface sketch:**

```ts
interface RunSieveOptions {
  // ...existing...
  /** Max concurrent in-flight requests per SUT process (pipelining). Default 1 (serial). */
  pipelineDepth?: number;
  /** Number of SUT processes to run in parallel. Default 1. */
  sutPool?: number;
}
```

Determinism of the **report** is preserved because categories aggregate counts,
not order-sensitive sequences; the timing category opts out of all concurrency.

---

## 5. Execution guidelines (running at scale)

**Large monorepos.**
- Always pass an explicit `path`/sub-tree per CI job rather than scanning the
  repo root when only part changed.
- Rely on default ignores (`node_modules`, `dist`, `build`, `.next`, `out`,
  `coverage`, `vendor`, `.turbo`, `.cache` — `walk.ts:12`) and add `--ignore`
  for generated trees. Add the minified/generated heuristics from §3 (I2) before
  scanning JS-heavy repos, or you pay for bundles.
- Use `--concurrency auto` (once §4 lands) for repos > a few thousand files.

**CI memory/time budgets.**
- The 2 MiB file cap (`DEFAULT_MAX_FILE_SIZE`) bounds per-file memory; with
  worker parallelism, peak memory ≈ `poolSize × 2 MiB` + result set. Size runners
  accordingly.
- For time budgets, prefer **changed-files-only** scans on PRs (below) and full
  scans on `main`/nightly.

**Incremental / changed-files-only scans (git diff integration).**
- Recommended pattern today: `git diff --name-only --diff-filter=ACMR
  origin/main...HEAD` → pass the resulting paths to qscan. qscan already supports
  a single file as `root` (`walk.ts:103`), but **not a file list** — so today you
  loop per file or scan a temp tree. **Roadmap item:** accept multiple positional
  paths / a `--from-stdin` file list so one process scans exactly the changed
  set. This is the highest-leverage execution feature for CI.

**Baseline workflow.**
- Adopt on legacy code: `qscan . --write-baseline quantakrypto-baseline.json`, commit
  it, then `qscan . --baseline quantakrypto-baseline.json` so only new findings fail.
- **Caveat (from §2.2/2.4):** qscan and the action use *different* fingerprints
  and *different* baseline file formats today. Pick one tool's baseline per
  pipeline; do not share a baseline file between the CLI and the action until they
  are unified (roadmap P1). For the action, the baseline is a *prior report file*.

**SARIF upload.**
- Generate SARIF even on failure (`if: always()`) and upload via
  `github/codeql-action/upload-sarif@v3` (README examples are correct). The action
  writes the **pre-baseline** SARIF so code scanning shows the full inventory
  while the build gate uses only new findings — keep that.

**Exit-code policy & recommended defaults.**
- Defaults are sensible: format `human` (CLI) / `sarif` (action),
  `severity-threshold: high`, `fail-on-findings: true`. Exit `0` clean / `1`
  findings at-or-above threshold / `2` usage|I/O.
- Recommended CI default: `--severity-threshold high --baseline <file>` on PRs;
  `critical` gating only if you want to allow `high` debt temporarily.
- For report-only adoption phases, set `fail-on-findings: false` (action) and
  collect SARIF for a few weeks before flipping the gate.

---

## 6. Hosted MCP

**Assessment of `HOSTING.md`.** It is unusually complete and correct for a
scaffold: it picks Streamable HTTP (right), describes the `Mcp-Session-Id`
lifecycle, a shared session store (Redis/Postgres), API-key→tenant mapping,
per-tenant concurrency limits over raw request rate, body caps, per-call
timeouts, sticky routing only for SSE, and a "transports do I/O+policy, server
does protocol, core does analysis" separation that the code already honors. The
doc is honest that `http.ts` implements only the JSON request/response half and
that SSE/`GET /mcp` are deferred until long-running scans need progress. Few
open-source MCP servers document hosting this well.

**Recommendation: yes, host it — but as a thin, sandboxed "advisory" service,
not as a remote code scanner.** The strategic value to quantakrypto (lead capture +
demonstrating technical authority) is real: a hosted quantakrypto MCP that any AI
agent can add gives the brand a permanent surface in developer workflows. But the
**`scan_path` tool must not run server-side against client-supplied paths** — that
is an arbitrary-file-read service (§2.3). Resolve the tension by splitting the
tool surface by where it runs:

- **Safe to host as-is (stateless, no filesystem):** `explain_finding`,
  `suggest_hybrid`, `list_rules`. These are pure knowledge lookups over core's
  remediation table and detector catalog — zero input sensitivity, trivially
  cacheable, and exactly the "technical authority" surface. This alone is a
  compelling hosted product.
- **`scan_path` / `inventory_crypto`: keep execution client-side.** The hosted
  server should expose them as tools whose **content is uploaded by the client**
  (the agent reads files locally and sends text), or run them only inside a
  strict sandbox (read-only mount, chrooted scratch dir, path allow-list, no
  network, hard CPU/wall-time/output-size caps) on content the tenant explicitly
  submits. Never let the server walk the server's own filesystem on behalf of a
  caller.

**Transport / session / auth.** Use Streamable HTTP per the doc. Phase 1 can stay
stateless (every request independent) for the knowledge tools — no session store
needed. Require `Authorization: Bearer <api-key>` on `/mcp`, validate before
`readBody` (the doc's `handleMcpPost` is the right gate, `http.ts:129`), map key →
tenant. Mint and validate `Mcp-Session-Id` only once scans/streaming arrive.
Defer OAuth 2.1 until third-party clients connect on a user's behalf; scoped API
keys are enough for first-party and for lead capture (the key *is* the lead).

**Rate limiting / abuse / cost.** Per-key token bucket at the edge + an
in-process backstop; limit by concurrent scans per tenant (scans are CPU-heavy),
not just RPS. Enforce per-call timeouts (missing today, §2.3) and an
output-size cap so a tool result can't be used to exfiltrate large files. Never
log request bodies (may contain source). Meter per key for billing and
abuse detection. The knowledge tools are cheap and cacheable; the scan tools are
the cost/abuse center — which is the other reason to keep scanning client-side or
tightly sandboxed.

**What executes where.** Server-side: auth, sessions, rate limiting, metering,
JSON-RPC dispatch (`McpServer`), and the stateless knowledge tools. Client-side
(or sandboxed-on-submitted-content): the actual filesystem walk + detection. This
maps cleanly onto the existing transport/server/core split — hosting adds only an
edge layer, exactly as `HOSTING.md` argues.

**Phased rollout.**
1. **P0 — Hosted knowledge MCP.** `explain_finding`, `suggest_hybrid`,
   `list_rules` over Streamable HTTP, API-key auth, edge rate limit, caching,
   `/health`. Stateless. Lead capture via key issuance. Low risk, fast to ship.
2. **P1 — Sessions + metering.** Add the session store, per-tenant quotas, usage
   dashboards. Still no server-side scanning.
3. **P2 — Sandboxed scan-on-submitted-content.** Accept uploaded file content
   (not paths), scan in a locked-down worker with hard caps, return findings +
   SARIF. SSE for progress on large submissions. This is the upsell into the
   paid quantakrypto audit practice.

Tie-in to the business is natural and not overreaching: the free hosted advisory
tools establish authority and capture leads (every API key is a contact), while
the gated scan service and the human audit/certificate practice are where revenue
lives — consistent with the repo's own framing ("the methodology is open; the
audits and certificates are where the practice lives").

---

## 7. Prioritized roadmap

| Pri | Item | Package | Effort | Impact |
|---|---|---|---|---|
| **P0** | Sandbox/allow-list `scan_path`/`inventory_crypto` paths (or move execution client-side) before any hosting | mcp | M | Critical — prevents arbitrary file read in a hosted server |
| **P0** | Add per-tool execution timeout + output-size cap | mcp | S | High — prevents hangs/exfiltration in HTTP transport |
| **P0** | Bound the two backtracking-prone regexes (TLS ciphers, WebCrypto nearCall) | core | S | High — removes ReDoS / quadratic edge cases |
| **P1** | Unify baseline fingerprinting + on-disk format across qscan and action | qscan, action | M | High — eliminates the biggest cross-package inconsistency |
| **P1** | Changed-files-only input: accept multiple paths / `--from-stdin` file list | qscan | M | High — the key CI/scale feature (git diff integration) |
| **P1** | Skip minified/generated/bundled files (line-length + name heuristics) | core | S | High — largest real-world scan-time win |
| **P1** | Single-pass / pre-filter detector dispatch; hoist inline regexes to module scope | core | M | High — 5-8× less regex work per file |
| **P1** | Worker-thread scan pool with byte-balanced chunking + deterministic merge | core | M/L | High — near-linear speedup on large repos |
| **P1** | PR-comment de-duplication (update existing comment instead of posting new) | action | S | Medium — avoids comment spam |
| **P2** | Wire or remove the dead `ScanOptions.include` option | core | S | Medium — API honesty |
| **P2** | Forward `maxFileSize`/`noDefaultIgnores` from qscan and add CLI flags | qscan | S | Medium — exposes core's full surface |
| **P2** | Make config/source toggles skip detector work, not just filter output; classify scope on the detector, not the ruleId prefix | core | S | Medium — correctness + minor perf |
| **P2** | Implement `initialize` protocol-version echo/negotiation (or fix docs) | mcp | S | Medium — spec/README alignment |
| **P2** | Quote-aware `--impl` tokenization (or `--` passthrough) | sieve | S | Medium — supports paths/args with spaces |
| **P2** | Request pipelining (`sendMany`) + optional SUT pool; global wall-clock budget | sieve | M | Medium — sieve throughput on large iteration counts |
| **P2** | Remove dead "not implemented" SARIF/JSON fallback in qscan; remove `void SEVERITIES` | qscan, core | S | Low — dead-code cleanup |
| **P2** | Reconcile the three `informationUri`/repo URLs to one canonical value | core, qscan | S | Low — consistency |
| **P3** | End-to-end fixture scan test + HTTP-transport-over-socket test | core, mcp | M | Medium — closes the integration-coverage gap |

**Legend:** Effort S ≈ <½ day, M ≈ 1-3 days, L ≈ 1 week+. Impact reflects
security/correctness/perf weight, not just size.
