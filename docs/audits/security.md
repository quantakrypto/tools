# qproof-tools — Security Audit (Application Security Lens)

**Scope:** all five packages (`core`, `qscan`, `mcp`, `action`, `sieve`) of the
zero-dependency TypeScript monorepo at commit time of writing.
**Type:** READ-ONLY application-security review. No source was modified.
**Method:** static reading of every security-relevant module, threat-modelled
against the tool's real usage: scanning *attacker-controlled* repositories,
hosting the MCP over HTTP, and running the Action in CI with a write-scoped
token.
**Relationship to `docs/AUDIT.md`:** the prior audit is a general
quality/architecture review that *flagged* several of these issues at a high
level (ReDoS "low risk," MCP arbitrary-path read, env passthrough). This
document goes deeper from a pure-security lens: it confirms or revises each, adds
findings the general audit missed (annotation/markdown injection, SARIF content
injection, prototype-pollution surface, MCP error leakage, missing per-tool
timeout as a concrete DoS), assigns CWE + severity, and gives concrete fixes.

Severity scale: **critical / high / medium / low**, judged against the *most
exposed supported deployment* for each component (hosted MCP; CI Action on
untrusted PRs; CLI over an attacker's repo).

---

## 1. Executive risk summary

qproof-tools is, from a supply-chain standpoint, **exemplary**: genuinely zero
runtime dependencies, no `postinstall`/`prepare`/`preinstall` scripts in any
package, Node built-ins only, and a tiny dev-tooling surface (`typescript`,
`tsx`, `@types/node`). That posture removes the single largest class of
JavaScript-ecosystem risk and is a real strength (see §6).

The residual risk is concentrated in **what the tool ingests and where it
runs**, not in third-party code:

1. **Hosted MCP is an unauthenticated arbitrary-file-read service.** `scan_path`
   and `inventory_crypto` take a client-supplied path straight into
   `scan({ root })`, with no auth, no path allow-list, no sandbox, no per-tool
   timeout, and matched-line *snippets* returned in the response. Over the HTTP
   transport bound to `0.0.0.0` by default, this is the dominant risk
   (**critical**). The general audit flagged the LFI; this audit adds the
   missing-timeout DoS, the snippet-exfiltration channel, and the default
   `0.0.0.0` bind as compounding factors.

2. **The Action trusts finding-derived text in two injection sinks.** A finding's
   `location.file` is an attacker-controlled path (it is the name of a file in
   the scanned PR). It flows unescaped into the PR-comment Markdown table and is
   only partially escaped into `::error::` workflow commands, and likewise into
   SARIF `artifactLocation.uri` / `snippet`. This enables workflow-command
   injection and Markdown/HTML injection into a comment the Action posts with a
   write token (**high**). The general audit reviewed token handling (sound) but
   did not analyse content injection from scanned filenames/contents.

3. **ReDoS exposure is bounded but real on hostile input.** The TLS weak-cipher
   regex has two unbounded `[^'"`]*` spans around an alternation; on a crafted
   file it is super-linear, and the WebCrypto `nearCall` scan is O(matches ×
   calls). The 2 MiB file cap caps the blast radius to per-file pauses, so this
   is **medium** for the CLI/Action but rises in importance for any
   future-hosted scan-on-content path (**high** if that ships without a regex
   timeout).

4. **Untrusted-JSON parsing is safe today but undefended in depth.** `scanManifest`
   and the MCP/Action JSON entry points use `JSON.parse` on untrusted input.
   Prototype pollution is *not* currently reachable (no recursive merge; keys are
   only `.has()`-tested against a fixed map), but there is no depth/size guard
   against a deeply-nested-JSON parser-DoS, and `__proto__` handling relies on
   the absence of any future `Object.assign`-style merge. **low–medium**,
   defense-in-depth.

5. **Sieve child-process handling is correct.** `spawn(bin, args)` with an argv
   array and **no** `shell: true` — no shell-injection surface. The real gaps
   are the lossy `--impl` whitespace split (breaks paths with spaces, *not* a
   security hole), full parent-env passthrough to the SUT (secret exposure to an
   untrusted SUT), and the lack of a global wall-clock budget. **low–medium**.

**Bottom line:** the local CLI is low-risk. The Action is medium-to-high pending
output-escaping fixes. The MCP **must not be hosted as-is**; doing so is a
critical exposure. None of these block the local/CLI use case; all are
addressable with bounded, well-scoped changes.

---

## 2. Findings table

| ID | CWE | Severity | Location | Description | Fix (summary) |
|----|-----|----------|----------|-------------|---------------|
| Q-01 | CWE-22 / CWE-73 | **critical** | `packages/mcp/src/tools.ts:152`, `:183` | `scan_path`/`inventory_crypto` pass a client-supplied `path` directly to `scan({ root: path })`. Hosted over HTTP this is an unauthenticated arbitrary-directory reader (`/etc`, `/`, `../../`), returning matched-line *snippets* in the result. | Path allow-list + canonicalize + sandbox; or accept uploaded content, not paths. Keep `scan_*` client-side when hosted. |
| Q-02 | CWE-306 / CWE-862 | **critical** | `packages/mcp/src/http.ts:113`, `startHttpServer:171` | No authentication on `POST /mcp`; default bind is `0.0.0.0`. Any network peer can invoke any tool, including Q-01. | Require `Authorization: Bearer` before `readBody`; default bind to `127.0.0.1`; document the trust boundary. |
| Q-03 | CWE-400 / CWE-770 | **high** | `packages/mcp/src/server.ts:168`, `tools.ts:152` | No per-tool execution timeout, no output-size cap, no concurrency limit. A `scan_path` of a huge tree (or symlink-free deep tree) holds the connection/worker indefinitely; large results are unbounded. | Wrap `tool.handler` in a deadline (`AbortController`/`Promise.race`); cap result bytes; bound concurrent scans per key. |
| Q-04 | CWE-117 / CWE-93 | **high** | `packages/action/src/io.ts:52-64`, `main.ts:147-153` | Workflow-command injection: `escapeData`/`escapeProperty` escape `%`, CR, LF (and `:`,`,` for props) but the **message** body only strips CR/LF/`%`. Finding-derived text reaching `::error::`/`::warning::` is otherwise trusted. The `title` is hard-coded but `message`/`remediation`/`file` can carry attacker bytes from a scanned repo. | Confirm all annotation fields route through `escapeData`/`escapeProperty` (they do for props); additionally sanitize/clip message text; never interpolate scanned content into a command name. |
| Q-05 | CWE-79 / CWE-74 | **high** | `packages/action/src/main.ts:190-193`, `buildSummary` | Markdown/HTML injection into the PR comment. `f.location.file` (attacker-named path in the PR) is interpolated into a table cell **unescaped**; only `f.message` has `|` escaped. A crafted filename can break the table, inject HTML, or spoof content in a comment the Action posts with a write token. | Escape `|`, backticks, and HTML in *every* interpolated cell (file, ruleId, loc); render file in backticks with escaping; clip length. |
| Q-06 | CWE-1333 (ReDoS) | **medium** | `packages/core/src/detectors/source.ts:439` | TLS weak-cipher regex `ciphers\s*:\s*['"`][^'"`]*\b(RC4|DES|...)\b[^'"`]*['"`]` has two unbounded `[^'"`]*` around an alternation. On pathological input the engine backtracks super-linearly. Bounded by the 2 MiB file cap, so per-file pause, not unbounded — but a repo full of such files multiplies pauses. | Bound the spans (`{0,256}`), anchor to a single quote style, or run with a regex timeout/`RE2`-style matcher. |
| Q-07 | CWE-1333 / CWE-407 | **medium** | `packages/core/src/detectors/source.ts:196-197` | `nearCall` does a linear scan of `callIndexes` for *every* algorithm match → O(matches × calls). A file with thousands of `subtle.*` calls and thousands of algo tokens is quadratic. Capped by the 2 MiB read. | Sort `callIndexes` once and binary-search the nearest call, or sweep both lists with a two-pointer merge → O(n log n). |
| Q-08 | CWE-1333 | **low–medium** | `packages/core/src/dependencies.ts:201` | `offsetOfKey` builds `new RegExp('"'+escaped+'"\\s*:')` per vulnerable package per manifest. Names are escaped (good — no injection), but `\s*` on a manifest with huge whitespace runs is a minor super-linear cost; regex is also recompiled per call. | Precompile escaped-name→RegExp map at module load; or single tokenization pass. |
| Q-09 | CWE-1321 (proto pollution) | **low–medium** | `packages/core/src/dependencies.ts:217-249`, `mcp/src/http.ts:152`, `action/src/main.ts:222` | All untrusted JSON enters via `JSON.parse`. *No* prototype-pollution sink is currently reachable (no recursive merge; keys are only membership-tested, `Object.keys` is used, not property access by attacker key). But there is no depth/size guard, and the safety depends on never introducing an `assign`/merge. | Keep the no-merge invariant; add a documented "never deep-merge parsed manifests" rule; consider a max-depth/size pre-check for parser-DoS. |
| Q-10 | CWE-400 | **low–medium** | `packages/core/src/walk.ts:159`, `scan.ts:69`, `dependencies.ts:218` | A single file is read whole into a JS string (`readFile(...,"utf8")`); the 2 MiB cap bounds it, but `JSON.parse` of a 2 MiB lockfile and regex match-array materialization both spike memory. With future worker parallelism, peak ≈ poolSize × 2 MiB. No global byte budget across the whole scan. | Keep the cap; add an aggregate-bytes/elapsed budget for hosted/CI use; stream or skip lockfiles above a JSON-specific size. |
| Q-11 | CWE-22 (symlink/escape) | **low** (info — control present) | `packages/core/src/walk.ts:141-144` | The walker explicitly **does not follow symlinks** (`entry.isSymbolicLink() → continue`), preventing cycle/root-escape during the walk. Correct. Caveat: `scan()` does **not** re-validate that resolved files stay under `root` (it trusts the walker's relative path), so the *only* guard is the no-follow rule; a TOCTOU swap of a dir→symlink between `readdir` and `stat`/`readFile` is theoretically possible but low-value. | Keep the no-follow default. Optionally `realpath` the root once and assert each opened file's realpath is under it (defense vs TOCTOU). |
| Q-12 | CWE-918 (SSRF) | **low** | `packages/action/src/main.ts:228`, `:245` | The PR-comment POST URL is built from `GITHUB_API_URL` (env) + `owner/repo` (from `GITHUB_REPOSITORY`). In a GitHub-hosted runner these are trusted; a self-hosted runner with a poisoned env could redirect the token-bearing request to an attacker host. The `Bearer` token would then leak to that host. | Pin/validate `GITHUB_API_URL` against an allow-list (github.com / known GHES host); reject non-HTTPS. |
| Q-13 | CWE-209 (info leak) | **low–medium** | `packages/mcp/src/http.ts:90`, `server.ts:107-108`, `tools.ts:57` | Internal error messages (`err.message`, including filesystem paths from core) are returned verbatim to the HTTP client (`makeFailure(..., messageText)`) and embedded in tool `isError` results (`${label} failed: ${detail}`). Hosted, this leaks server paths / internals. | Return a generic message + correlation id to clients; log detail server-side only. |
| Q-14 | CWE-384 (session fixation) | **low** | `packages/mcp/src/http.ts:136-139` | A client-supplied `mcp-session-id` is reflected unvalidated. Harmless while stateless, but becomes a fixation vector the moment sessions carry state/authz. | Mint server-side, validate format, bind to the authenticated principal once sessions hold state. |
| Q-15 | CWE-532 (secret in log) | **low** (info — handled well) | `packages/action/src/main.ts:248`, `:258`, `:263` | The `github-token` is sent as `Authorization: Bearer` over HTTPS and is **never logged**; failures log only `status`/`statusText`/`err.message`. Good. Residual: the token is read from an input and lives in env (`INPUT_GITHUB_TOKEN`) and could be surfaced by an unrelated env-dumping step. | Keep current handling; document that the token must not be echoed; rely on runner masking. |
| Q-16 | CWE-22 / CWE-78 | **low** (info — no shell) | `packages/sieve/src/runner.ts:87`, `cli.ts:80` | SUT is spawned via `spawn(bin, args)` (argv array), **not** `shell:true` — no shell injection from `--impl`. The `--impl` value is split on whitespace (`raw.split(/\s+/)`), which mangles paths with spaces but does not create an injection. | Quote-aware tokenization or `--` passthrough (correctness, not security). |
| Q-17 | CWE-526 / CWE-200 | **medium** | `packages/sieve/src/runner.ts:89` | The SUT inherits the **full parent environment** (`{...process.env, ...opts.env}`). An untrusted/third-party SUT binary receives all secrets in the harness's env (CI tokens, cloud creds). | Pass an allow-listed env (`PATH`, `HOME`, explicit `opts.env`) by default; document that the SUT is trusted code. |
| Q-18 | CWE-770 / CWE-400 | **low–medium** | `packages/sieve/src/runner.ts`, categories | Per-request timeout exists (good, with `unref`), but there is **no global wall-clock budget**. A SUT answering each request just under the timeout across thousands of iterations runs unbounded in CI. | Add a `RunSieveOptions.deadlineMs` enforced across the whole run. |
| Q-19 | CWE-117 (SARIF injection) | **medium** | `packages/core/src/report.ts:99`, `:84`, `main.ts:164` | `f.location.snippet`, `f.location.file`, and `f.message` are placed into SARIF as JSON string values. `JSON.stringify` neutralizes structural injection, but the *snippet* is a verbatim line from an attacker-controlled file; SARIF consumers (code-scanning UI) that render snippet/uri without their own escaping can be fed crafted content (e.g. misleading code-scanning alerts, homoglyph paths). | Clip snippet (already ≤200 chars), strip control chars from snippet/uri before emitting; document that snippet is untrusted. |
| Q-20 | CWE-20 (input validation) | **low** | `packages/mcp/src/tools.ts:129-145`, `server.ts:147` | `inputSchema` advertises `additionalProperties:false` + `required`, but the server performs **no** schema enforcement; each handler hand-checks `typeof args.path === "string"`. Fine for trusted stdio; a hosted server should validate against the advertised schema to reject malformed/oversized args early. | Add lightweight schema validation in `onToolsCall` before dispatch when hosted. |

---

## 3. Deep notes on the top 5

### 3.1 Q-01 — Hosted `scan_path` is an arbitrary-file-read service (critical, CWE-22/CWE-73)

`tools.ts:147-159`:

```ts
const path = args.path;
if (typeof path !== "string" || path.length === 0) return errorResult(...);
const scanned = await safe("scan", () => scan({ root: path }));
```

`path` is whatever the JSON-RPC client sends. It is canonicalized nowhere,
allow-listed nowhere, and not confined to any base directory. `scan()`
(`scan.ts:46`) calls `stat(options.root)` and then walks it; the walker reads
every text file ≤ 2 MiB under that root (`walk.ts:159`/`scan.ts:69`) and
`summarizeScan`/`format:"json"` returns matched-line **snippets** and full
findings to the caller (`tools.ts:155-158`, snippet built at
`detect-utils.ts:83`).

Over stdio (a trusted local user scanning their own machine) this is acceptable
and is the tool's purpose. Over the **HTTP transport** (`http.ts`), which
`startHttpServer` binds to `0.0.0.0:3000` by default (`http.ts:171`) with **no
auth** (Q-02), this becomes: *any network peer can read arbitrary
server-side files and exfiltrate matched lines.* Examples:
`scan_path {path:"/etc"}`, `{path:"/root/.ssh"}`, `{path:"/proc/self/environ"}`
(read as text, ≤2 MiB), `{path:"../../"}`. Because the PEM and TLS detectors
emit *snippets of matched lines*, a private key under the scanned root is
partially echoed back in the finding snippet — a direct secret-exfiltration
channel, not merely a metadata leak.

This is the single most important finding. The general audit identified the LFI;
this audit adds that the **snippet field turns the LFI into a content-disclosure
oracle**, and that the **default `0.0.0.0` bind** makes the exposure
network-wide the moment `http.js` is run.

**Remediation (in priority order):**
1. **Do not host `scan_path`/`inventory_crypto` that walk the server's
   filesystem.** Either keep their execution client-side (agent reads files
   locally, sends *content*), or accept uploaded content rather than a path.
2. If a server-side scan is required, run it in a strict sandbox: read-only
   bind-mount of a per-request scratch dir, chroot/namespace, no network, a path
   allow-list rooted at the scratch dir with `realpath` containment checks, and
   hard CPU/wall-time/output-size caps.
3. Strip or redact snippets in any hosted response (return locations, not line
   contents).
4. Gate behind auth (Q-02) and a per-tool timeout (Q-03) regardless.

### 3.2 Q-04 / Q-05 — Output injection from scanned content into the Action's sinks (high, CWE-117 / CWE-79)

The Action runs in CI, frequently on **pull requests from forks**, i.e. on code
an attacker controls. Two finding-derived fields are attacker-influenced:

- `f.location.file` — the *path of a file the attacker added to the PR*.
- `f.location.snippet` / `f.message` — `message` is hard-coded per rule, but the
  snippet (if it ever reaches an output) is a verbatim attacker line.

**Workflow-command sink (Q-04).** `annotateFindings` (`main.ts:142-156`) calls
`annotateError(message, props)` → `io.ts issueCommand` → `formatCommand`.
Properties (`file`, `line`, …) are run through `escapeProperty` (`io.ts:57-64`,
escapes `% \r \n : ,`) and the message body through `escapeData` (`io.ts:52-54`,
escapes `% \r \n`). This is the correct GitHub workflow-command escaping and it
**does** neutralize the classic `::set-output`/`::error::`-breakout via newline.
The residual risk: the escaping correctness is load-bearing and only covers those
sinks — any *new* code path that interpolates `f.location.file` or snippet into a
command string without going through these helpers reintroduces command
injection (CWE-117). The message body is otherwise emitted verbatim, so control
characters other than CR/LF (e.g. ANSI escapes, ` `) pass through into CI
logs. **Severity high** because the sink runs with the runner's trust and a
breakout could forge annotations or, historically, smuggle commands.

**Markdown/HTML sink (Q-05).** `buildSummary` (`main.ts:188-195`) builds a PR
comment table:

```ts
const loc = `${f.location.file}:${f.location.line}`;
const msg = f.message.replace(/\|/g, "\\|");
lines.push(`| ${f.severity} | \`${f.ruleId}\` | ${loc} | ${msg} |`);
```

Only `f.message` has `|` escaped. `f.location.file` (`loc`) is interpolated
**unescaped** into a table cell. A file named, e.g.,
`a | x](https://evil) <img src=x onerror=...> .ts` (filenames can legally contain
`|`, spaces, brackets, and angle-brackets on most systems and certainly in a Git
tree) breaks the Markdown table, injects a link/HTML, or spoofs additional rows.
This comment is then **posted by the Action using a `pull-requests: write`
token** (`commentOnPullRequest`, `main.ts:239-256`), so the injected content is
authored as the app/bot, lending it credibility for phishing maintainers.
GitHub sanitizes raw HTML in comments, which mitigates script execution, but
link/structure/row spoofing and obfuscated content remain. **Severity high** for
the spoofing/phishing potential on a trusted comment.

**Remediation:**
- In `buildSummary`, escape *every* interpolated cell: replace `|`→`\|`,
  backtick, leading/trailing whitespace, and angle brackets; wrap `file` in
  backticks after escaping backticks; clip to a max length.
- For annotations, keep routing all fields through `escapeData`/`escapeProperty`
  (add a unit test asserting a hostile filename round-trips safely); strip
  non-printable control characters from the message before emit.
- Add a fuzz/property test that feeds adversarial filenames and snippet bytes
  through `buildSummary` and `formatCommand` and asserts no unescaped
  `|`/`<`/newline survives.

### 3.3 Q-06 / Q-07 — ReDoS and quadratic detector cost on hostile repos (medium → high if hosted, CWE-1333)

The detectors run over **attacker-controlled file contents** (the entire premise
of the tool is scanning untrusted repos). Two patterns are not linear:

**TLS cipher regex (`source.ts:439`):**

```
/ciphers\s*:\s*['"`][^'"`]*\b(RC4|DES|3DES|MD5|NULL|EXPORT|aNULL|eNULL)\b[^'"`]*['"`]/gi
```

Two unbounded `[^'"`]*` spans straddle a `\b...\b` alternation. On input like
`ciphers:'` followed by a very long run of non-quote, non-alternation characters
and **no** closing quote, the engine tries each starting position and backtracks
across the first `[^'"`]*` to satisfy the trailing structure. The negated class
not overlapping the quote keeps the worst case from being fully exponential, but
it is clearly **super-linear** and a crafted ~2 MiB file (the cap) can stall the
scan for a noticeable interval. In a repo seeded with thousands of such files,
the stalls sum to a DoS of the CI job or the (future) hosted scanner.

**WebCrypto `nearCall` (`source.ts:196-197`):**

```ts
const nearCall = (idx) => callIndexes.some((c) => idx >= c && idx - c < 400);
eachMatch(ALGO_RE, content, (m) => { if (!nearCall(m.index)) return; ... });
```

For each of M algorithm matches it linearly scans C call indexes → **O(M·C)**.
A file with thousands of `subtle.*` calls and thousands of `ECDSA`/`RSA-OAEP`
tokens is quadratic. Again capped by the 2 MiB read, so per-file, but
multiplied across a hostile tree.

**Severity:** medium for the CLI/Action (2 MiB cap + single-threaded means
bounded per-file pauses; the operator chose to scan the repo). It rises to
**high** for any hosted scan-on-content path, where an attacker submits the worst
case directly and the server has no regex timeout.

**Remediation:**
- Bound the cipher-regex spans: `[^'"`]{0,256}` on both sides, and/or split into
  three single-quote-style alternatives so the negated class is unambiguous.
- Replace `nearCall` with a two-pointer / binary search over sorted
  `callIndexes` → O((M+C) log C).
- Strategically: run detector regexes under a wall-clock guard (e.g. a worker
  with a deadline) for hosted use, or adopt a linear-time matcher for the
  unbounded patterns. Add a fuzz target that throws adversarial strings at every
  detector regex and asserts a per-file time bound.

### 3.4 Q-03 — No per-tool timeout / output cap / concurrency limit in the MCP (high, CWE-400/CWE-770)

`McpServer.onToolsCall` (`server.ts:147-169`) validates argument shape and then
`return tool.handler(toolArgs)` with **no deadline**. The HTTP transport
(`http.ts handleMcpPost`) awaits `server.handle(parsed)` with no timeout and no
concurrency cap; the only guard is the 1 MiB **request** body cap
(`MAX_BODY_BYTES`, `http.ts:37`) — there is no **response** cap. Consequences,
hosted:

- A `scan_path` of a large tree (or one with the Q-06/Q-07 pathological files)
  holds the TCP connection and an event-loop-blocking synchronous regex pass for
  as long as it takes. No `AbortController`, no `Promise.race` deadline.
- The result (`format:"json"` returns the full `ScanResult` incl. all findings
  and snippets) is unbounded in size — an exfiltration and memory amplifier.
- Nothing limits concurrent tool calls; N parallel large scans exhaust CPU/RAM.

The general audit noted "no timeout"; this audit elevates it because, combined
with Q-01 (arbitrary path) and Q-13 (error leakage), it is the practical DoS +
disclosure lever on a hosted instance.

**Remediation:** wrap `tool.handler` in a `Promise.race` against a per-tool
deadline (cancel via `AbortController` threaded into `scan`); cap serialized
result bytes (truncate with an explicit marker); enforce a per-principal
concurrent-scan limit at the transport edge; keep the 1 MiB request cap and add a
matching response cap.

### 3.5 Q-17 — Full parent-env passthrough to an untrusted SUT (medium, CWE-526/CWE-200)

`runner.ts:87-91`:

```ts
this.child = spawn(bin, args, {
  cwd: opts.cwd,
  env: { ...process.env, ...opts.env },
  stdio: ["pipe", "pipe", "pipe"],
});
```

The SUT is *user-supplied code* that Sieve drives. Many CI invocations run Sieve
against a third-party or candidate implementation. Inheriting the **entire**
parent environment hands that process every secret in the harness's env —
`GITHUB_TOKEN`, `NPM_TOKEN`, cloud credentials, signing keys. A malicious or
merely curious SUT can read and exfiltrate them. There is no shell-injection
issue (argv array, no `shell:true` — Q-16), and oversize inputs are bounded by
design (`robustness.ts:25` generates a 1 MiB blob and expects a clean error),
but the env exposure is a genuine confidentiality finding given the
"drive untrusted implementations" threat model.

**Remediation:** default to an **allow-listed** env (`PATH`, `HOME`, `LANG`,
plus explicit `opts.env`), with an opt-in `inheritEnv: true` for trusted local
runs. Document clearly that the SUT executes with the harness's privileges and
should be treated as trusted code unless sandboxed. Pair with Q-18 (global
deadline) so an adversarial SUT cannot also burn unbounded CI time.

---

## 4. What's required to improve (controls)

**Input validation**
- Enforce the advertised MCP `inputSchema` server-side (Q-20) — reject unknown
  properties, missing required fields, and oversized strings before dispatch.
- Canonicalize and allow-list every filesystem path that originates from a
  network/client (`realpath` + prefix containment), never trust a raw `path`.
- Escape *all* finding-derived fields at every output boundary (annotations, PR
  Markdown, SARIF) — treat `location.file`, `snippet`, and `message` as tainted.

**Sandboxing / least privilege (hosted scan)**
- Run any server-side scan in a locked-down worker/namespace: read-only mount,
  chroot/scratch dir, no network, dropped capabilities; on Linux add a
  **seccomp** profile restricting syscalls to the read/stat/regex working set.
- Drop snippets from hosted responses; return locations only.
- For Sieve, allow-list the SUT's env and offer a container/seccomp wrapper for
  untrusted implementations.

**Regex hardening**
- Bound every unbounded quantifier in the detectors (Q-06); replace the
  quadratic `nearCall` (Q-07) with a sorted-index search; precompile per-name
  manifest regexes (Q-08).
- Run detector regexes under a per-file wall-clock guard for hosted use, or adopt
  a linear-time/RE2-style matcher for the patterns that cannot be made linear.

**Timeouts & resource limits**
- MCP: per-tool deadline + response-size cap + per-principal concurrency limit
  (Q-03); default HTTP bind to `127.0.0.1` (Q-02).
- Sieve: keep the per-request timeout; add a global run deadline (Q-18).
- Core: optional aggregate byte/time budget across a whole scan (Q-10).

**Authentication & transport**
- Require `Authorization: Bearer <api-key>` on `/mcp` before reading the body
  (Q-02); validate/mint `Mcp-Session-Id` server-side (Q-14); return generic
  errors with a correlation id, log detail server-side only (Q-13).
- Validate `GITHUB_API_URL` against an allow-list and require HTTPS before
  sending the token (Q-12).

**Process & disclosure**
- Add a `SECURITY.md` with a vulnerability-disclosure policy and a contact /
  GitHub private advisory channel (currently absent — see §5).
- Add a short `THREAT_MODEL.md` stating the trust boundaries already implicit in
  the code (scanned repo = untrusted; SUT = trusted-unless-sandboxed; MCP stdio =
  trusted local user; MCP HTTP = untrusted network).

**Fuzzing**
- Fuzz the **manifest parser** (`scanManifest`) with malformed/huge/deeply-nested
  JSON and prototype-pollution payloads (`__proto__`, `constructor`).
- Fuzz the **SARIF/JSON reporters** and the **Action output builders**
  (`buildSummary`, `formatCommand`) with adversarial filenames and snippet bytes,
  asserting no unescaped structural characters survive.
- Fuzz the **detector regexes** with a per-input time bound to catch ReDoS
  regressions (Q-06/Q-07).
- Fuzz the **sieve `decodeResponse`/`fromB64`** parser against hostile SUT lines.

---

## 5. What's missing (gaps to close)

- **`SECURITY.md` + disclosure policy** — none present in the repo root or any
  package. For a security-positioning tool this is table stakes; add a private
  reporting channel (GitHub Security Advisories) and an SLA.
- **Threat-model document** — the code embeds sound trust assumptions (no-follow
  symlinks, argv-not-shell, body caps) but never writes them down, so they erode
  silently as the code changes (e.g. a future deep-merge would open Q-09).
- **Fuzz targets** — there is broad unit coverage (182 tests) but **no**
  adversarial/fuzz testing of the parsers (manifest JSON, SARIF, `decodeResponse`)
  or the regexes, which is exactly where the untrusted-input risk lives.
- **Hosted-MCP authorization** — no auth, no tenancy, no rate limiting, no
  per-tool timeout in code; `HOSTING.md` describes the design but `http.ts` ships
  none of it. Hosting today is unsafe (Q-01/Q-02/Q-03).
- **Output-escaping tests for hostile filenames** — no test asserts that an
  attacker-named file cannot break the PR comment table or a workflow command
  (Q-04/Q-05).
- **Response-size cap on the MCP HTTP transport** — request bodies are capped at
  1 MiB; responses are not.
- **Snippet redaction policy** — snippets (verbatim attacker lines, possibly
  containing secrets/PII) flow into SARIF, JSON, MCP results, and potentially
  annotations with no redaction option.

---

## 6. Supply chain — strength (call it out)

The **zero-runtime-dependency posture is genuine and well-honored**, and it is
the project's strongest security property:

- Every package declares only internal `@qproof/*` workspace links as runtime
  deps; the root has *no* runtime deps. Confirmed across all `package.json`
  files.
- **No `postinstall` / `preinstall` / `prepare` / `install` scripts** exist in
  any package — the most common npm supply-chain execution vector is absent.
- Functionality that would normally pull in libraries is hand-rolled from Node
  built-ins: JSON-RPC/MCP framing (`mcp/src/protocol.ts`), the GitHub Actions
  toolkit shims (`action/src/io.ts`), CLI arg parsers, SARIF emission. This
  eliminates transitive-dependency CVE exposure and typosquat risk.
- Dev-tooling surface is minimal: `typescript`, `tsx`, `@types/node`. The only
  caveat is that `tsx`/`typescript` run at build/test time with developer
  privileges; pin them, enable lockfile integrity (`npm ci`), and ideally build
  releases in a clean, network-restricted CI step. The Action's PR comment uses
  the global `fetch` (Node ≥18) — no `node-fetch`/axios dependency, good.

Net: the dependency attack surface is essentially nil. Keep it that way — every
future feature should justify any new runtime dependency against this baseline,
and the build/release pipeline should enforce lockfile integrity and avoid
running arbitrary lifecycle scripts.

---

## 7. Prioritized remediation order

1. **Before any MCP hosting:** Q-01 (no server-side path scan / sandbox), Q-02
   (auth + bind `127.0.0.1`), Q-03 (timeout + caps), Q-13 (error redaction).
   *(critical/high)*
2. **Before the Action runs on untrusted PRs widely:** Q-05 (PR-comment
   escaping), Q-04 (annotation escaping hardening + tests). *(high)*
3. **Core robustness:** Q-06 + Q-07 (regex bounds), Q-19 (SARIF snippet
   sanitization), Q-10 (scan byte budget). *(medium)*
4. **Sieve hardening:** Q-17 (env allow-list), Q-18 (global deadline). *(medium)*
5. **Process & defense-in-depth:** add `SECURITY.md`, threat model, and fuzz
   targets; Q-08, Q-09, Q-12, Q-14, Q-20. *(low–medium)*

---

*This audit was conducted read-only; no source files were modified. The file
`docs/audits/security.md` was written as the sole output of this review.*
