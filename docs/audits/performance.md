# qproof-tools — Performance & Scalability Audit

Read-only deep dive into the runtime cost of `qproof-tools` (zero-dep TS
monorepo: `core`, `qscan`, `mcp`, `action`, `sieve`). No source was modified.
This goes one level deeper than `docs/AUDIT.md §3-4` (which is correct but
high-level): every claim below is tied to a `file:line`, given a complexity
class, and quantified with a rough estimate so the wins can be ranked by ROI.

Baseline assumptions used throughout (a "reference repo"):
- **R-small**: 500 files, ~1.5 MiB scannable text, ~300 JS/TS files.
- **R-mid**: 10k files, ~30 MiB text, ~6k JS/TS files.
- **R-large**: 100k files, ~300 MiB text, ~60k JS/TS, plus a handful of 1-2 MiB
  bundles.
- Scanning is **CPU-bound on regex**, not I/O-bound, once the page cache is warm
  (confirmed by the work profile: 18 regex passes per JS/TS file, §1).

---

## 1. Summary — top efficiency wins, ranked by impact

| # | Win | Where | Rough impact |
|---|-----|-------|--------------|
| **1** | **Skip minified/generated/bundled content** (size + line-length heuristic, not just `.min.js`/`.map`) | `walk.ts:79-85`, `walk.ts:32-48` | **2-10× wall-clock on front-end repos.** One 2 MiB bundle × 18 passes ≈ the cost of ~1,200 average source files. Today it is scanned in full. |
| **2** | **Per-file candidate pre-filter** — one combined `test()` short-circuits all 18 source passes when a file contains none of the trigger tokens | `scan.ts:78`, `source.ts` (all detectors) | **3-6× on the common case.** ~90-97% of source files contain zero crypto tokens; today each still pays 18 full scans + ~7 PEM checks. |
| **3** | **Worker-thread pool over the file list** (`scanParallel`, §3) | `scan.ts:54-93` | **Near-linear to core count** above the crossover (~200 files / 2 MiB). 4-8× on R-mid/R-large on typical CI runners. |
| **4** | **Collapse 18 regex passes → ~3-4 via a single combined alternation** with group dispatch | `source.ts:44-459` | **4-6× less regex work per scanned file**, compounding with #2. |
| **5** | **Incremental / changed-files mode** (`git diff --name-only` + hash cache, §4) | new; `scan.ts`, `qscan/src/index.ts:110` | **10-100× on PR CI.** A PR touching 20 files scans 20, not 60k. Highest leverage of all in CI. |
| **6** | **Sieve request pipelining** (bounded in-flight, §"Sieve") | `runner.ts:163-191`, `index.ts:85-93`, `correctness.ts:40-68` | **5-15× sieve wall-clock.** ~480 serial IPC round-trips/run today → batched. |
| **7** | **Hoist inline detector regexes to module scope** (stop re-creating literals per file) | `source.ts:45,80,99,116,133,151,…`; `eachMatch` `detect-utils.ts:132` | **5-15% per-file**, ~zero risk, ~zero effort. |
| **8** | **Precompile dependency-name regex map; drop `nearCall` quadratic** | `dependencies.ts:198-204`; `source.ts:196-197` | Quadratic→linear on pathological files; negligible on normal repos but removes a DoS cliff. |

The first two are the highest ROI: pure `walk`/`scan` changes, no API surface,
no determinism risk, and they attack the dominant cost (regex passes over bytes
that can't possibly match). #3 and #5 are the scalability story for large repos
and CI. #6 is the sieve story.

---

## 2. Core scanning hot path

### 2.1 How many regex passes per file (the "~17")

Per **JS/TS** file every one of these runs as a full linear pass over the file
text (each is a `g`-flag `RegExp.exec` loop in `eachMatch`, `detect-utils.ts:127`):

| Detector | File:line | Passes |
|----------|-----------|--------|
| node-crypto | `source.ts:44,80,99,116,133,151` | 6 |
| webcrypto | `source.ts:193` (callRe) + `source.ts:199` (ALGO_RE) | 2 (+ quadratic `nearCall`) |
| crypto-libs | `source.ts:256,268,280,293,304,317` | 6 |
| jwt-jose | `source.ts:348` | 1 |
| tls-config | `source.ts:394,418,438` | 3 |
| **source subtotal** | | **18** |
| pem (fast-reject `includes` then up to 5) | `pem.ts:88` + `pem.ts:91-92` (×5 rules in `PEM_RULES`) | 1 `includes` scan + 0-5 |

So **18 regex passes + 1 `String.includes` pass on every JS/TS file** even when
it contains no crypto at all, plus the PEM `includes` on *every* text file
(`pem.ts:85 appliesTo: () => true`). The prompt's "~17" is right; the exact
count is 18 source passes (the discrepancy is `nearCall` short-circuiting at
`source.ts:194` when there are no `subtle.*` calls, dropping the effective count
to 17 on most files).

**Complexity:** `O(F × P × L)` where F = files, P = 18 passes, L = avg file
length. P is a constant multiplier that is almost entirely wasted: the vast
majority of source files match nothing.

**Fix (ranked):**
1. **Pre-filter (win #2).** Before the detector loop at `scan.ts:78`, run one
   combined `test()`:
   ```
   /generateKeyPair|create(Sign|Verify|DiffieHellman|ECDH)|publicEncrypt|privateDecrypt|
    subtle\s*\.|pki\.rsa|forge\.ed25519|new\s+(elliptic\.)?ec|KEYUTIL|KJUR|NodeRSA|
    ['"`](RS|PS|ES)\d|EdDSA|minVersion|maxVersion|secureProtocol|rejectUnauthorized|ciphers/
   ```
   If it fails, skip all 18 passes for that file. One pass replaces 18 on
   ~90-97% of files. **Est. 3-6× on the common case**, and it composes with
   walk-level skipping. This generalizes the trick PEM already uses at
   `pem.ts:88`.
2. **Combine alternation (win #4).** Most of the 18 are literal-anchored single
   patterns; fold them into ~3 combined regexes with named/numbered groups and a
   `switch` on which group matched. Reduces 18 passes → 3-4. **4-6× less regex
   work** on files that *do* contain candidates.

### 2.2 Inline regexes recompiled per file vs module-level

The PEM rules (`pem.ts:22-78`) and the webcrypto `callRe`/`ALGO_RE`
(`source.ts:186-191`) are declared once and reused — good. But the **node-crypto,
crypto-libs, jwt-jose, and tls-config regexes are regex *literals inside the
`detect()` function body*** (`source.ts:45,80,99,116,133,151,256,268,280,293,304,317,347,395,418,439`).
A regex literal in a function body produces a **fresh `RegExp` object on every
call** to that function — i.e. **once per scanned file** (V8 does not hoist
`/…/g` literals out of the enclosing function; each `detect()` invocation
re-instantiates them).

`eachMatch` (`detect-utils.ts:132`) does *not* add extra clones here, because all
these literals carry `g` already, so the `new RegExp(re.source, …)` branch is
dead. The cost is purely the per-file object construction + V8 re-JIT of the
pattern.

**Complexity:** `O(F × 16)` regex constructions instead of `O(16)`.
**Impact:** ~5-15% of per-file CPU on R-mid/R-large (16 allocations + pattern
compile × 6k-60k files). **Fix:** hoist every literal to a module-level
`const RE_* = /…/g`. Zero behavioral change, near-zero effort (win #7).

### 2.3 Full-file reads into memory (no streaming)

`scan.ts:69` does `await readFile(absPath, "utf8")` — the entire file becomes one
JS string, capped at 2 MiB (`DEFAULT_MAX_FILE_SIZE`, `walk.ts:26`). Then 18
regexes each materialize match arrays over that string, and `makeFinding`
(`detect-utils.ts:72`) slices snippets out of it.

- **Memory:** peak per in-flight file = file bytes as UTF-16 (≈ 2× file size for
  ASCII) + transient match arrays. At the 2 MiB cap that is ~4 MiB resident per
  file being scanned. Serial today, so peak ≈ 4 MiB + the growing `findings[]`
  array (see §3). Under the worker pool (§3), peak ≈ `poolSize × ~4 MiB`.
- **No streaming.** Streaming with overlap windows would cap per-file memory but
  is genuinely awkward here: PEM blocks and the webcrypto 400-char proximity
  window (`source.ts:197`) are multi-line, so chunk boundaries can split a match.
  **Verdict:** keep full-file reads; the 2 MiB cap already bounds it. Lower
  priority than §2.1/§2.4. The one cheap win: detectors take a single `content`
  string but each re-scans it — that's the §2.1 problem, not a read problem.

### 2.4 The quadratic `nearCall` / proximity logic (webcrypto)

`source.ts:196-197`:
```
const nearCall = (idx) => callIndexes.some((c) => idx >= c && idx - c < 400);
...
eachMatch(ALGO_RE, content, (m) => { if (!nearCall(m.index)) return; … });
```
`nearCall` does a **linear scan of `callIndexes` for every algorithm match**.

**Complexity:** `O(A × C)` where A = `RSA-OAEP|RSA-PSS|…|ECDSA` matches and C =
`subtle.*` call sites. On a file that is dominated by WebCrypto usage (a crypto
library, a generated wrapper, a giant bundle that inlines a webcrypto polyfill),
both A and C scale with file size, so this is **quadratic in file length**. On a
2 MiB file with, say, 5,000 `subtle.*` calls and 5,000 algo tokens that is
~25M comparisons for this one detector — seconds of CPU on a single file.

**Fix:** `callIndexes` is already produced in ascending order (matches arrive
left-to-right from `eachMatch`). Replace the `.some` with a **two-pointer /
binary-search**: for each algo match, binary-search the largest `c ≤ idx` and
check `idx - c < 400`. `O((A + C) log C)`, effectively linear. Removes the
cliff. (`docs/AUDIT.md` flags this; here is the concrete fix and the magnitude.)

### 2.5 Catastrophic-backtracking regex (TLS weak-cipher)

`source.ts:439`:
```
/ciphers\s*:\s*['"`][^'"`]*\b(RC4|DES|3DES|MD5|NULL|EXPORT|aNULL|eNULL)\b[^'"`]*['"`]/gi
```
Two unbounded `[^'"`]*` flank an alternation. This is **not** classic
exponential ReDoS (the two `[^…]*` are separated by a literal `\b(alt)\b`, and
the negated classes can't match the closing quote), but it **does** backtrack
super-linearly on a pathological input: a multi-KB single-quoted string after
`ciphers:` that contains one of the tokens but never reaches a closing quote on
that line forces the engine to try the alternation at every position. Bounded by
the 2 MiB file cap, so worst case is "slow on one crafted file," not a hang.

**Fix:** anchor the value to a single line and bound the run length, e.g.
`ciphers\s*:\s*['"`][^'"`\n]{0,4096}\b(RC4|…)\b`. Drops the second `[^…]*`
entirely (the token presence is all that's needed) and caps the first. Linear,
same matches in practice.

### 2.6 No skipping for minified/generated/bundled files (win #1)

`walk.ts:79-85` skips only `.min.js` (compound) and the `BINARY_EXTENSIONS` set
(`walk.ts:32-48`, which includes `.map` and `.min.js`). It does **not** skip:
- `*.bundle.js`, `*-min.js`, `*.bundle.mjs`, `*.chunk.js` (webpack/rollup output)
- `*.generated.ts`, `*_pb.js` (protobuf), `*.d.ts` rollups
- machine-minified files with no telltale extension (a 1.9 MiB single-line
  `vendor.js` in `src/`)
- large lockfile-shaped JSON that isn't a manifest

A single 2 MiB bundle costs **~18 regex passes over 2 MiB ≈ the work of ~1,200
average (1.5 KB) source files**, and the matches it produces are almost always
noise (vendored crypto inside a bundle, not first-party usage).

**Fix:**
1. Extend the extension/glob skip list (cheap, deterministic).
2. Add a **content heuristic** in the walker or at read time: peek the first
   ~4 KB; if average line length > ~1,000 chars or there is a single line
   > ~50 KB, treat as minified/generated and skip (or scan PEM-only). This is the
   single biggest real-world win on front-end and monorepo repos (win #1).
   Make it overridable (`--scan-minified`).

### 2.7 Repeated dependency-DB scans

`scanManifest` (`dependencies.ts:215`) is called once per `package.json` /
`package-lock.json` (`scan.ts:90-91`). Two inefficiencies:
- **`offsetOfKey` compiles a fresh `RegExp` per found package per manifest**
  (`dependencies.ts:200-202`). On a big monorepo with many manifests each listing
  several vulnerable deps, that's many throwaway regex compiles. Precompile an
  escaped-name → `RegExp` map once at module load (the names are static), or do a
  single tokenizing pass. Negligible CPU overall (few manifests) but free.
- **`BY_NAME` lookup is already O(1)** (`dependencies.ts:158`) — good; the
  membership checks in `collectFromRecord` (`dependencies.ts:230`) are correct.
- On `package-lock.json` v2/v3 the `packages` map can have **tens of thousands of
  keys**; `scanManifest` iterates all of them (`dependencies.ts:243-249`) doing a
  `lastIndexOf` + slice + `Map.has` each. `O(K)` with K = lockfile entries — fine,
  but note that a 5 MB lockfile is *over* the 2 MiB cap and so is **silently
  skipped by the walker** (`walk.ts:159`), meaning lockfile dep findings are lost
  on large repos. Worth raising the cap for manifests specifically, or stat-ing
  manifests exempt from `maxFileSize`.

---

## 3. Memory profile & GC pressure

### 3.1 Findings accumulate in one array for the whole scan

`scan.ts:51` allocates `findings: Finding[]` and pushes into it across the entire
walk (`scan.ts:85,91`); it is never flushed until the scan ends. Each `Finding`
(`detect-utils.ts:92-104`) holds a `location` object with a `snippet` string
(capped at 200 chars, `detect-utils.ts:83`) plus several short strings.

- **Memory:** `O(total findings)` resident for the whole run. A crypto-heavy
  monorepo can produce 10k-100k findings; at ~300-500 bytes/finding that's
  ~3-50 MB held live until `buildInventory` + sort + return. Not catastrophic,
  but it is **all retained simultaneously**, and the single `findings.sort`
  (`scan.ts:96`) needs the whole array in memory at once.
- **GC pressure:** the dominant churn is **transient**, not the findings array:
  per file, 18 `RegExp.exec` loops allocate match arrays + capture-group strings,
  `makeFinding` allocates a `location` and slices snippet/line strings
  (`detect-utils.ts:73-83`, `lineAt`/`offsetToLineCol` scan char-by-char). On
  R-large that's tens of millions of short-lived allocations → heavy young-gen
  GC. The pre-filter (§2.1) and pass-collapsing (§2.4-/§2.1) cut this
  proportionally — files that match nothing allocate nothing.

**Fix for scale:** stream findings to the reporter incrementally (e.g. an async
generator `scanStream()` yielding `Finding`s, with the inventory updated
on-the-fly and only the reporter deciding what to retain). Determinism then
requires a final sort, so a fully streaming sort is hard; a pragmatic middle
ground is **per-file finding arrays merged at the end** (which is exactly what
the worker design in §4 produces for free).

### 3.2 The inventory pass

`buildInventory` (`inventory.ts:62`) is a single `O(findings)` pass building three
small count maps — cheap and correct. `readinessScore` (`inventory.ts:41`) is a
second `O(findings)` pass. Two passes over findings, both linear; no concern at
any scale. Minor: `void SEVERITIES;` (`inventory.ts:85`) is dead
(`docs/AUDIT.md` already flags it). The score's per-finding `Math.sqrt`
(`inventory.ts:33`) is trivial.

### 3.3 Peak-memory model

- **Serial (today):** `peak ≈ (worst in-flight file ≈ 4 MiB) + findings array`.
  Bounded and modest.
- **Parallel (§4):** `peak ≈ poolSize × 4 MiB + Σ findings`. Size CI runners as
  `poolSize × 4 MiB` headroom plus the result set. With `availableParallelism()`
  = 8 that's ~32 MiB of file buffers + findings — still small.

---

## 4. Parallelization design (worker_threads pool)

The scan is **embarrassingly parallel**: each file is read and regex-scanned
independently (`scan.ts:54-93`), and the merge is a concatenation + the existing
deterministic sort (`scan.ts:96-100`). `Finding` is plain structured-cloneable
data, so it crosses the worker boundary cleanly.

### 4.1 Design

1. **Enumerate on the main thread, dispatch to workers.** Run `walkFiles`
   (`walk.ts:92`, cheap and I/O-bound) once on the main thread to get the
   relative-path list + sizes. Walking in parallel complicates ignore/symlink
   semantics for little gain.
2. **Chunk by bytes, not by count.** The walker already `stat`s each file
   (`walk.ts:158`), so sizes are known. Bucket files into chunks of ~equal *total
   bytes* (target ~4 MiB/chunk) so one 2 MiB file doesn't starve a worker that
   otherwise holds 1,000 tiny files. Round-robin fallback if sizes are absent.
3. **Workers run the existing pure pipeline.** Each worker imports `detectors`
   (`scan.ts:23`) + `scanManifest` (`dependencies.ts:215`), reads its own files,
   returns `{ findings: Finding[]; filesScanned: number }`. No shared mutable
   state, no locks.
4. **Backpressure.** Bounded pool sized to `os.availableParallelism()` (default).
   At most `poolSize` chunks in flight; a worker requests its next chunk on
   completion (pull model), so a slow worker never accumulates a backlog. Use a
   simple work queue + `MessageChannel`, or `postMessage` "ready/here's-work".
5. **Deterministic merge.** `flatMap` all worker `findings`, then apply the
   **existing** comparator (`scan.ts:96-100`: file → line → ruleId). Result is
   **byte-identical to the serial scan regardless of completion order.**
   `filesScanned` is summed. Determinism preserved by construction.
6. **Serialization cost.** Crossing the worker boundary structured-clones
   `Finding[]`. On a noisy repo that's the result set (~3-50 MB, §3) copied once
   per chunk. This is cheap relative to the regex work it parallelizes, but it is
   why you **chunk** (amortize per-message overhead) rather than send one file
   per message.
7. **Crossover point (don't pay on small repos).** Worker spawn + ESM
   module-init is ~30-80 ms/worker (the core module graph: detectors, reporters,
   deps DB — `index.ts:10-34`). Below **~200 files or ~2 MiB total**, the spawn
   cost exceeds the win — stay serial. Above that, expect **near-linear speedup
   to core count** because the work is CPU-bound regex. Concretely: R-small stays
   serial (no regression); R-mid/R-large get ~4-8× on an 8-core runner.

### 4.2 Interface sketch (additive, back-compatible)

```ts
interface ScanOptions {
  // ...existing...
  /** Worker threads. 0/1 = serial (default). "auto" = availableParallelism(). */
  concurrency?: number | "auto";
  /** Combined-size floor below which the scan always runs serially. Default 2 MiB. */
  parallelThresholdBytes?: number;
  /** Target bytes per worker chunk. Default 4 MiB. */
  chunkBytes?: number;
}

interface ScanChunk  { files: string[]; baseDir: string; }
interface ChunkResult { findings: Finding[]; filesScanned: number; }

async function scanParallel(
  opts: ScanOptions,
  files: { rel: string; size: number }[],
): Promise<ScanResult> {
  if (totalBytes(files) < (opts.parallelThresholdBytes ?? 2 * 1024 * 1024)
      || files.length < 200) {
    return scanSerial(opts, files);          // identical existing path
  }
  const pool   = new WorkerPool("./scan-worker.js", resolveConcurrency(opts));
  const chunks = chunkByBytes(files, opts.chunkBytes ?? 4 * 1024 * 1024);
  const results = await pool.map<ScanChunk, ChunkResult>(chunks); // bounded in-flight
  const findings = results.flatMap(r => r.findings).sort(STABLE_ORDER); // == scan.ts:96
  return assemble(opts.root, findings, sum(results, "filesScanned"));
}
```

The public `scan()` signature is unchanged; `concurrency` defaults to serial, so
existing callers (qscan, action, mcp) and determinism are untouched until they
opt in. The worker entry re-uses the exact detector array — zero logic
duplication.

---

## 5. Incremental scanning (changed-files mode + hash cache)

The single highest-leverage CI feature. Today qscan scans a whole tree
(`runQscan` → `scan({ root })`, `qscan/src/index.ts:110`); `walkFiles` accepts a
directory **or one file** (`walk.ts:103`) but **not a file list** — so a
changed-files scan today requires N processes or a temp tree.

### 5.1 Changed-files mode (`git diff`)

- **CI invocation:**
  ```
  git diff --name-only --diff-filter=ACMR origin/main...HEAD
  ```
  feeds the changed paths to qscan. Pair with the action's existing
  pre-baseline-SARIF + new-findings-gate split (`action/src/main.ts:163,302`).
- **Code change needed:** accept **multiple positional paths** and/or
  `--from-stdin` in the qscan arg parser, and a `roots: string[]` / `files:
  string[]` mode in core. Core already builds absolute paths safely
  (`scan.ts:60-62`). A file-list mode bypasses `walkDir` entirely: for each
  given path, apply `isBinaryPath`/`maxFileSize` filters (`walk.ts:79,159`) then
  scan. This makes a 20-file PR scan **20 files instead of 60k** — **10-100×** on
  PR CI for R-mid/R-large.
- **Correctness constraint:** dependency findings need the *manifest*, not the
  diff line. If `package.json`/`package-lock.json` is in the changed set, scan it
  whole (already the unit of work). Cross-file findings don't exist in this
  engine (every detector is per-file, `types.ts` `Detector` contract), so a
  per-file changed set is sound.

### 5.2 Caching by file hash

- **Cache key:** `sha256(content)` (or `mtime+size+ruleset-version` for speed)
  → cached `Finding[]` for that file. Persist as a small JSON sidecar
  (`.qproof-cache.json`) or under the CI cache.
- **Invalidation:** include the **tool/ruleset version** (`version.ts` `VERSION`)
  in the key so a detector change busts the cache. Node's `crypto` is already a
  built-in (zero-dep posture preserved).
- **Payoff:** a full-repo scan where only 1% of files changed reads + hashes all
  files (I/O-bound, fast) but only **regex-scans the 1% that changed** —
  ~100× less CPU on warm runs. Hashing cost (`O(bytes)`, ~1-2 GB/s) is far below
  the 18-pass regex cost it avoids. Combine with §4: hash on the workers.
- **Determinism:** cache stores the same `Finding[]` the serial path produces;
  the final sort (`scan.ts:96`) makes order independent of cache hit/miss.

---

## 6. qScan CLI startup & Action per-run cost

### 6.1 qScan startup

`qscan/src/cli.ts` is a thin shell; cost is dominated by **ESM module-graph
resolution**. `@qproof/core`'s barrel (`core/src/index.ts:10-34`) eagerly pulls
**all** detectors, both reporters (SARIF + JSON, `report.ts`), the remediation
table, and the full vulnerable-deps DB (`dependencies.ts`, 20 entries) at import
time — whether or not the run needs them.

- **Measured-class estimate:** built `dist` cold start ≈ 60-120 ms node init +
  module eval; warm ≈ 30-60 ms. In **dev (`tsx`)** add transpile overhead. For
  `npx qscan` users, **install/resolve dominates** (seconds), dwarfing runtime.
- **Wins (all marginal, <50 ms, but cheap):**
  - Lazy-import the SARIF/JSON reporters only when `--format sarif|json`
    (`qscan/src/index.ts:154-167` already branches on format — defer the import
    into the branch).
  - Skip importing the deps DB when `--no-deps`.
  - Ship prebuilt JS (already the plan; `bin` → `./dist/cli.js`,
    `qscan/package.json`).
- **Verdict:** Low priority. Startup is noise next to scan time on any
  non-trivial repo; only matters for `qscan --version`-style invocations.

### 6.2 Action per-run cost

`action/src/main.ts` runs one `scan` (`main.ts:16`), writes SARIF, annotates each
finding inline (`io.ts` workflow commands), and optionally POSTs a PR comment.
Per run on R-mid:
- **Scan** dominates (seconds-minutes) → inherits every core win above (§2-§5).
  The action is the **prime consumer of incremental mode (§5)** — it already has
  the PR context (`readPullRequestContext`, `main.ts:213`) to compute the diff
  base.
- **Annotations:** one `::error::` line per finding (`io.ts`). On a noisy repo
  (thousands of findings) this is thousands of stdout writes; GitHub also caps
  visible annotations. Cheap CPU, but consider summarizing above a threshold.
- **PR comment:** one HTTPS POST (`main.ts:248`), best-effort
  (`main.ts:239`). Negligible. (Note `docs/AUDIT.md`: it posts a *new* comment
  each run — a correctness/noise issue, not perf.)

**Conclusion:** the action has no per-run cost of its own worth optimizing; its
performance *is* core's. Wiring §5 (changed-files) into the action is the win.

---

## 7. Sieve runner throughput

`packages/sieve/src/runner.ts` is **strictly serial**: `send()`
(`runner.ts:163`) writes one request and awaits its response before the next.
Every category loops and `await`s each round-trip:

- **correctness** (`correctness.ts:40-68`): **3 awaited requests per iteration**
  (`kemKeygen` → `kemEncaps` → `kemDecaps`) × 32 default iterations
  (`index.ts:67`) = **96 serial round-trips**.
- 5 categories loop over `ctx.iterations` (`correctness`, `determinism`,
  `implicit-rejection`, `dsa`, `timing`). Total per run ≈ **300-500 serial IPC
  round-trips**, each paying child-process stdin write + readline parse latency
  (`runner.ts:119-120,183`).

**Complexity / cost:** `O(R)` wall-clock where R = total requests, with a hard
floor of `R × (IPC latency + SUT compute)`. The IPC + scheduling latency
(~0.1-1 ms each) is pure overhead serialized R times → **tens to hundreds of ms
of dead time per run**, independent of SUT speed. With a slow SUT, the serial
*compute* also can't overlap across independent iterations.

### 7.1 Pipelining within one SUT process (recommended)

The protocol is **already id-correlated** (`runner.ts:140,170-171`; responses
matched by `id`, out-of-order tolerant), so independent requests can be in flight
simultaneously **today** — only the calling pattern is serial.

- Add `runner.sendMany(reqs[], { maxInFlight })`: write a bounded batch, hold
  each in `pending` (`runner.ts:73`), `Promise.all` the responses. Bound
  in-flight (default ~16) to avoid unbounded stdin buffering and to keep the
  SUT's input queue sane.
- Rewrite the independent-iteration categories (correctness, determinism,
  implicit-rejection, dsa, sizes) to issue their N iterations as a pipelined
  batch. **Est. 5-15× sieve wall-clock** depending on SUT per-op latency vs IPC
  latency.

**Correctness constraints:**
- **Exclude `timing`** (`timing.ts`) — it measures *isolated* per-op latency;
  concurrency destroys the measurement. Keep it strictly serial (already
  `defaultOn: false`, `index.ts:38`).
- **Exclude any order/state-dependent category.** The current categories are
  independent per iteration (each generates its own keypair), so they pipeline
  safely. Document the invariant so future categories declare
  `pipelineable: false` when they carry cross-request state.
- The per-request timeout + `unref` (`runner.ts:174-179`) already works per-`id`,
  so batching needs no timeout rework.

### 7.2 SUT-process pool (throughput + crash isolation)

For very large iteration counts or to isolate crashes, spawn a small pool of SUT
processes (each its own `Runner`) and shard independent iterations across them.

- **Why a pool, not just deeper pipelining:** a SUT that corrupts internal state
  or crashes on one input (`SutCrashError`, `runner.ts:50`,
  `failAll`/`failAll`-on-exit `runner.ts:97-104`) poisons **all** in-flight
  requests on that process. Per-process isolation contains the blast radius to
  one shard.
- **Concurrency default:** `min(availableParallelism(), 4)` — crypto SUTs are
  CPU-heavy; oversubscription hurts.
- **Correctness:** the report aggregates **counts**, not ordered sequences
  (`report.ts` rolls up category pass/fail), so sharding preserves the verdict.
  Each shard runs identical category logic.

### 7.3 Interface sketch

```ts
interface RunSieveOptions {
  // ...existing...
  /** Max concurrent in-flight requests per SUT process. Default 1 (serial). */
  pipelineDepth?: number;
  /** Number of SUT processes to run in parallel. Default 1. */
  sutPool?: number;
}
```

Defaults keep today's serial, deterministic behavior; opt-in unlocks throughput.

---

## 8. Benchmarking gap & proposed harness

There are **no perf tests, fixtures, or benchmarks** anywhere in the repo
(confirmed: all `test/*.test.ts` are correctness-only `node:test` cases; no
`bench/`, no fixture trees). Every estimate above is analytical; nothing in CI
would catch a perf regression (e.g. someone re-adding a per-file regex compile,
or a future detector with a quadratic scan).

### 8.1 Proposed bench harness (`packages/core/bench/`)

Zero-dep, mirroring the project's posture — use `node:test`'s timing or a tiny
`performance.now()` loop, no new deps.

1. **Synthetic fixture generator** (`bench/fixtures/gen.mjs`): deterministically
   emit fixture trees at parameterized scale — `--files N --crypto-density D
   --bundle-bytes B`. Produce:
   - `clean/` — N source files, **zero** crypto (measures the wasted-pass cost,
     the §2.1 win).
   - `dense/` — N files, D% containing crypto (measures detector throughput).
   - `bundles/` — a few large minified files (measures the §2.6 win).
   - `pathological/` — one file with thousands of `subtle.*` calls (measures the
     §2.4 quadratic) and one crafted `ciphers:` line (measures §2.5).
2. **Bench runner** (`bench/scan.bench.mjs`): for each fixture, `scan()` it K
   times (warm-up + measured), record median ms, files/s, MB/s, peak RSS
   (`process.memoryUsage().rss`), and findings count. Emit JSON to
   `bench/results/<git-sha>.json`.
3. **Sieve bench** (`packages/sieve/bench/`): run `runSieve` against
   `examples/mock-sut.ts` at `--iterations 256`, record wall-clock and
   requests/s. Re-run with the §7 pipelining to quantify the speedup.

### 8.2 Perf-regression CI check

- A `bench:check` script runs the harness, compares median ms and peak RSS
  against a **committed baseline** (`bench/baseline.json`), and **fails if any
  metric regresses > a threshold (e.g. +15% time or +20% RSS)**.
- Run it on a fixed-size runner on PRs (label-gated or nightly to avoid flaky
  noise on shared runners; use median-of-K + a generous threshold).
- Commit a fresh baseline intentionally when an optimization lands, so the
  numbers ratchet down. This is what turns the §1 wins into durable gains.

---

## 9. What's required to improve (ordered)

1. **Walk-level skipping of minified/generated/bundled files** — extend
   `BINARY_EXTENSIONS`/globs (`walk.ts:32-48`) + a first-KB line-length heuristic
   (`walk.ts:121-165`). Cheap, deterministic, biggest real-world win.
2. **Per-file candidate pre-filter** before the detector loop (`scan.ts:78`).
   One combined `test()` short-circuits 18 passes on ~90%+ of files.
3. **Hoist inline detector regex literals to module scope** (`source.ts`
   detector bodies). Trivial, zero-risk.
4. **Fix the two regex hazards:** binary-search `nearCall` (`source.ts:196`);
   line-anchor + bound the TLS cipher regex (`source.ts:439`).
5. **`scanParallel` worker pool** (§4) behind an opt-in `concurrency` option;
   serial default preserves determinism and small-repo cost.
6. **Changed-files / file-list mode + hash cache** (§5) — multi-path qscan args
   + a core file-list scan path. Highest CI leverage.
7. **Sieve `sendMany` pipelining** (§7) with a `pipelineDepth` option; exclude
   `timing`.
8. **Bench harness + perf-regression CI** (§8) so the above don't silently
   regress.

Items 1-4 are pure internal optimizations (no API change, no determinism risk)
and should land first; 5-7 are additive opt-in features; 8 is the guardrail.

## 10. What's missing

- **No benchmarks, fixtures, or perf CI** — nothing measures or protects
  performance (§8).
- **No parallelism** — single-threaded `for await` scan (`scan.ts:54`); no
  worker pool; cannot use multiple cores (§4).
- **No incremental/changed-files mode** — every scan is full-tree; qscan can't
  take a file list (`walk.ts:103` is dir-or-single-file only) (§5).
- **No result caching** — re-scanning an unchanged repo redoes all 18 passes ×
  every file (§5.2).
- **No streaming** of findings — the whole result set is held in memory until the
  end (`scan.ts:51`), capping how large a scan can grow (§3.1).
- **No detector-level fast-reject** beyond PEM's `includes` (`pem.ts:88`); the 18
  source passes always run (§2.1).
- **No sieve concurrency** — strictly serial round-trips despite an
  id-correlated, pipeline-ready protocol (§7).
- **Manifest scanning silently drops large lockfiles** over the 2 MiB cap
  (`walk.ts:159`), losing dependency findings on big repos (§2.7).

---

*docs/audits/performance.md was written.*
