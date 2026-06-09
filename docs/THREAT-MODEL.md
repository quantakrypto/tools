# qproof-tools — Threat Model

Scope: the five-package zero-dependency TypeScript monorepo (`@qproof/core`,
`@qproof/qscan`, `@qproof/mcp`, `@qproof/action`, `@qproof/sieve`). This document
states the trust boundaries the code already implies, the data flows that cross
them, and a STRIDE analysis per tool. It is the written companion to the
[security audit](audits/security.md), which carries the concrete `file:line`
findings (`Q-01`…`Q-20`); this document does not re-derive them, it frames them.

Method: data-flow modelling against the tools' *real* deployments — scanning
**attacker-controlled** repositories, hosting the MCP over HTTP, running the
Action in CI on untrusted pull requests, and driving an **untrusted SUT** under
Sieve. Severity language matches the audit (critical/high/medium/low).

---

## 1. Assets

| # | Asset | Why it matters |
|---|---|---|
| A1 | Server-side filesystem content (hosted MCP host) | Arbitrary files (`/etc`, SSH keys, `/proc/self/environ`) become readable if a path-taking tool is hosted. |
| A2 | Matched-line **snippets** | Verbatim lines from scanned files; can contain secrets/PII/private keys. Flow into SARIF, JSON, MCP results. |
| A3 | CI write-scoped token (`pull-requests: write`, `security-events: write`) | The Action posts PR comments and uploads SARIF with it; abuse forges trusted bot content. |
| A4 | Harness environment secrets (`GITHUB_TOKEN`, `NPM_TOKEN`, cloud creds) | Inherited by the Sieve-spawned SUT and exposed to any env-dumping CI step. |
| A5 | Scan integrity / verdict | A scan that hangs, crashes, or mis-reports degrades the security signal users rely on. |
| A6 | Conformance-result integrity (Sieve) | A PASS must be traceable to authentic inputs; a fabricated/laundered vector would be a correctness lie. |
| A7 | Host availability (CPU/RAM/event loop) | ReDoS, quadratic detector cost, and unbounded scans burn CI minutes or stall a hosted instance. |

## 2. Trust boundaries

```
        TB-1 untrusted repo content ─────────────┐
                                                  ▼
  attacker repo ─► walk()/detectors ─► findings ─► reporters ─► SARIF/JSON
                                                  │
        TB-2 CI sink boundary (write token) ──────┼─► PR comment / annotations
                                                  │
        TB-3 network boundary (hosted MCP) ───────┼─► POST /mcp (untrusted peer)
                                                  │
        TB-4 process boundary (Sieve) ────────────┴─► spawn(SUT)  [untrusted code]
```

| Boundary | Inside (trusted) | Outside (untrusted) | Crossing |
|---|---|---|---|
| **TB-1 Scanned content** | the scanner process & its operator | every byte under `root` — file *names*, *contents*, manifest JSON | file read → regex/`JSON.parse` → `Finding` |
| **TB-2 CI output sinks** | the runner & repo maintainers | finding-derived text reaching Markdown/workflow-command/SARIF | `Finding.location.file`/`snippet`/`message` → comment/annotation |
| **TB-3 Hosted MCP network** | the MCP host's filesystem & secrets | any network peer over `POST /mcp` | JSON-RPC args (esp. `path`) → `scan({root})` |
| **TB-4 Sieve↔SUT** | the Sieve harness & CI env | the SUT binary (third-party / candidate code) | `spawn(bin,args,{env})`; NDJSON over stdio |

**Stated trust assumptions (the model that the rest of this doc enforces):**
- Scanned repo = **untrusted**. Everything under `root` is attacker-influenced.
- MCP **stdio** = **trusted local user** scanning their own machine (the tool's purpose).
- MCP **HTTP** = **untrusted network**. Not safe to host as-is (TB-3, see §5).
- Sieve SUT = **trusted-unless-sandboxed**. It runs with the harness's privileges (TB-4, see §6).
- CI Action = runs with a **write token** on potentially untrusted PRs (TB-2).

## 3. Data flows that cross boundaries

1. **Scan flow (all tools):** `root` → `walkFiles` (no-follow symlinks, ≤2 MiB
   per file) → detectors (regex over content) + `scanManifest` (`JSON.parse`) →
   `Finding[]` → `buildInventory` → reporters. Tainted inputs: file *paths*,
   file *contents*, manifest JSON. (TB-1)
2. **Action sink flow:** `Finding[]` → `buildSummary` (Markdown table) +
   `annotateFindings` (`::error::`/`::warning::`) + `toSarif` → posted/uploaded
   with A3. Tainted: `location.file`, `snippet`, `message`. (TB-2)
3. **MCP flow:** JSON-RPC `params` → tool handler → `scan({root: params.path})`
   → result (incl. snippets) serialized back to caller. Tainted: the entire
   request, especially `path` and `Mcp-Session-Id`. (TB-3)
4. **Sieve flow:** `--impl` cmdline → `spawn(bin, args, {env: {...process.env}})`
   → NDJSON requests in / `decodeResponse`+base64 out. Tainted: every SUT
   response line; the SUT process itself holds A4. (TB-4)

---

## 4. STRIDE per tool

Each row links the threat to a concrete audit finding where one exists.

### 4.1 `@qproof/core` (the engine — runs inside every tool)

| STRIDE | Threat | Finding | Severity |
|---|---|---|---|
| **D**oS | ReDoS in the TLS-cipher regex (two unbounded spans around an alternation); quadratic `nearCall` (O(matches×calls)) on hostile files. | Q-06, Q-07 | medium (high if hosted) |
| **D**oS | No aggregate byte/time budget across a scan; 2 MiB `JSON.parse`/match-array spikes; with future worker pools peak ≈ poolSize × 2 MiB. | Q-10 | low–medium |
| **T**amper | Prototype-pollution surface via `JSON.parse` of manifests — *not currently reachable* (no recursive merge), but undefended in depth; a future `assign`/merge opens it. | Q-09 | low–medium |
| **I**nfo | Snippets are verbatim attacker lines (A2); no redaction option before they enter reporters. | Q-19 (sink) | medium |
| **E**oP | Symlink no-follow is correct, but `scan()` doesn't re-validate resolved files stay under `root` (TOCTOU dir→symlink swap is theoretically possible). | Q-11 | low |

### 4.2 `@qproof/qscan` (CLI — trusted local operator over an untrusted repo)

| STRIDE | Threat | Notes | Severity |
|---|---|---|---|
| **D**oS | Inherits core's ReDoS/quadratic cost (Q-06/Q-07) per file; single-threaded + 2 MiB cap bound it to per-file pauses. | The operator chose to scan the repo; blast radius is their own CI minutes. | medium |
| **I**nfo | SARIF/JSON output carries snippets (A2); writing to a shared artifact store can disclose secrets from the scanned tree. | Q-19 | low–medium |
| **T**amper | The arg parser (`parseArgs`) is a hand-rolled parser — a fuzz target per ROADMAP P1-10. | No injection today (argv array). | low |

The CLI is the **lowest-risk** deployment: trusted operator, local filesystem,
no network, no write token.

### 4.3 `@qproof/mcp` (HOSTED HTTP transport is the dominant risk surface)

| STRIDE | Threat | Finding | Severity |
|---|---|---|---|
| **S**poof | No authentication on `POST /mcp`; default bind `0.0.0.0`. Any network peer invokes any tool. | Q-02 | **critical** |
| **T**amper | Client-supplied `Mcp-Session-Id` reflected unvalidated — a fixation vector once sessions carry state. | Q-14 | low |
| **I**nfo | `scan_path`/`inventory_crypto` read **arbitrary server paths** and return matched-line snippets → content-disclosure oracle (A1, A2). | Q-01 | **critical** |
| **I**nfo | Internal error messages (incl. filesystem paths) returned verbatim to the client. | Q-13 | low–medium |
| **D**oS | No per-tool timeout, no response-size cap, no concurrency limit; a big/pathological scan holds the connection and blocks the event loop. | Q-03 | high |
| **E**oP | No server-side enforcement of the advertised `inputSchema`; handlers hand-check `typeof`. | Q-20 | low |

Over **stdio** these collapse to the trusted-local-user case (the tool's intended
mode) and are acceptable. See §5 for the hosted boundary in detail.

### 4.4 `@qproof/action` (CI, frequently on untrusted fork PRs, holds A3)

| STRIDE | Threat | Finding | Severity |
|---|---|---|---|
| **T**amper | Markdown/HTML injection: `location.file` (attacker-named path in the PR) interpolated **unescaped** into the PR-comment table; only `message` has `\|` escaped. Posted as the bot (A3) → row-spoofing/phishing. | Q-05 | high |
| **T**amper | Workflow-command injection: annotation message body strips only CR/LF/`%`; other control bytes (ANSI/`\0`) pass into logs; any *new* sink bypassing `escapeData`/`escapeProperty` reintroduces breakout. | Q-04 | high |
| **I**nfo | SARIF content injection: verbatim snippet/uri into `artifactLocation`/`snippet`; a consumer that renders without escaping is fed crafted/homoglyph content. | Q-19 | medium |
| **I**nfo (SSRF) | PR-comment POST URL built from `GITHUB_API_URL` env; a poisoned self-hosted-runner env could redirect the token-bearing request to an attacker host (A3 leak). | Q-12 | low |
| **R**epudiation | Token is never logged; failures log only status/`err.message`. Good — residual is an unrelated env-dumping step. | Q-15 | low (handled) |

### 4.5 `@qproof/sieve` (drives an UNTRUSTED SUT with full harness privileges)

| STRIDE | Threat | Finding | Severity |
|---|---|---|---|
| **I**nfo | SUT inherits the **full parent environment** (`{...process.env}`) → all harness secrets (A4) handed to untrusted SUT code. | Q-17 | medium |
| **D**oS | Per-request timeout exists, but **no global wall-clock budget**; a SUT answering just under the timeout across thousands of iterations runs unbounded in CI. | Q-18 | low–medium |
| **T**amper | `decodeResponse`/`fromB64` parse hostile SUT output lines — hand-rolled parser, a fuzz target per P1-10. | (no shell: argv array) | low |
| **E**oP | `spawn(bin, args)` with an argv array and **no** `shell:true` — no shell-injection surface; `--impl` whitespace split is a *correctness* bug, not a hole. | Q-16 (info) | low (control present) |
| **R**epudiation | A passing `kat` run is not yet traceable to a specific vector file (provenance) — see [compliance/acvp-provenance.md](compliance/acvp-provenance.md). | — (design gap) | low |

---

## 5. The hosted-MCP boundary (TB-3) — deep treatment

This is the single most important boundary in the toolset. Over **stdio**, the
client is a local agent the user already trusts with their filesystem; the
path-taking tools (`scan_path`, `inventory_crypto`) are the *point* of the tool.
The moment the same `McpServer` is exposed over the **HTTP transport**
(`http.ts`, default bind `0.0.0.0`, no auth), the trust model inverts: the caller
is an **untrusted network peer**, but the tools still take a server-side `path`
and still return matched-line snippets.

**Attacker capability if hosted as-is:** `scan_path {path:"/etc"}`,
`{path:"/root/.ssh"}`, `{path:"/proc/self/environ"}`, `{path:"../../"}` —
arbitrary-directory read (A1) with **secret exfiltration** through the snippet
field (A2), no auth (Q-02), no timeout (Q-03), and server paths leaked in errors
(Q-13). The PEM/TLS detectors echo matched lines, so a private key under the
scanned root is partially returned in the finding snippet.

**Boundary controls required before hosting** (maps to audit §7 order):
1. **Do not host filesystem-walking tools.** Keep `scan_*` client-side (agent
   reads files locally, sends *content*), or accept *uploaded content*, not a path.
2. If a server-side scan is unavoidable: strict sandbox — per-request read-only
   scratch dir, `realpath` containment, no network, hard CPU/wall-time/output caps.
3. **Strip snippets** from hosted responses (return locations only).
4. Require `Authorization: Bearer`, default-bind `127.0.0.1`, validate/mint the
   session id, per-tool deadline + response cap + per-principal concurrency, and
   generic errors with a correlation id.

The design path for these controls is documented in
[`packages/mcp/HOSTING.md`](../packages/mcp/HOSTING.md); the gap is that the
*shipped* `http.ts` implements none of them yet.

## 6. The Sieve-spawns-SUT boundary (TB-4) — deep treatment

Sieve's premise is **driving someone else's implementation**: many invocations
run a third-party or candidate ML-KEM/ML-DSA SUT, frequently in CI. The SUT is a
child process launched via `spawn(bin, args, {env: {...process.env, ...opts.env}})`.

- **No shell-injection surface** (argv array, no `shell:true`) — Q-16, a control
  that is *present and correct*; the `--impl` whitespace split is a correctness
  bug for paths-with-spaces, not a security hole.
- **The real exposure is confidentiality (A4):** the SUT receives the **entire**
  harness environment — `GITHUB_TOKEN`, `NPM_TOKEN`, cloud creds, signing keys.
  A malicious or merely curious SUT reads and exfiltrates them (Q-17).
- **Availability (A7):** the per-request timeout (with `unref`) bounds a single
  hang, but there is no global run deadline (Q-18); an adversarial SUT can burn
  unbounded CI time by staying just under the per-request limit.

**Boundary controls:** default to an **allow-listed** env (`PATH`, `HOME`,
`LANG`, plus explicit `opts.env`) with an opt-in `inheritEnv` for trusted local
runs; add a `deadlineMs` enforced across the whole run; document that an
unsandboxed SUT runs with the harness's privileges and should be treated as
trusted code (or wrapped in a container/seccomp profile) unless sandboxed.

## 7. Attacker scenarios (scanning untrusted repos)

| # | Scenario | Path through the model | Outcome | Mitigation |
|---|---|---|---|---|
| S1 | **Comment-spoof via filename.** Attacker opens a fork PR adding a file named `` a \| [x](https://evil) <img src=x> .ts``. | TB-1 → `buildSummary` (unescaped `location.file`) → posted with A3 (TB-2). | Forged/phishing rows in a bot-authored PR comment. | Escape every Markdown cell; clip length (Q-05). |
| S2 | **CI DoS via ReDoS corpus.** Attacker seeds the repo with thousands of ~2 MiB files crafted for the TLS-cipher regex / quadratic `nearCall`. | TB-1 → detectors → super-linear backtracking per file. | Summed per-file stalls exhaust CI minutes (A7). | Bound regex spans `{0,256}`; two-pointer `nearCall`; per-file wall-clock guard (Q-06/Q-07). |
| S3 | **Snippet exfiltration (hosted).** Network peer calls `scan_path {path:"/proc/self/environ"}` against a hosted MCP. | TB-3 → `scan({root})` → snippet field. | Server secrets/paths returned to an unauthenticated caller (A1/A2). | Don't host path tools; auth; strip snippets (Q-01/Q-02/Q-13). |
| S4 | **Secret theft via SUT.** Attacker submits a candidate ML-KEM SUT to a CI conformance job that dumps `process.env` on first request. | TB-4 → full-env passthrough. | `GITHUB_TOKEN`/`NPM_TOKEN` exfiltrated to attacker (A4). | Allow-listed SUT env; sandbox untrusted SUTs (Q-17). |
| S5 | **Workflow-command breakout.** A finding-derived field reaches a new `::command::` sink without going through the escapers. | TB-2 → unescaped annotation. | Forged annotations / smuggled workflow commands under runner trust (A3). | Route all fields through `escapeData`/`escapeProperty`; strip control chars (Q-04). |
| S6 | **Parser-DoS / proto-pollution probe.** Attacker commits a deeply-nested or `__proto__`-laden `package.json`. | TB-1 → `scanManifest` (`JSON.parse`). | Not reachable today; defense-in-depth gap (A5). | Keep the no-merge invariant; max depth/size pre-check (Q-09). |

---

## 8. Mitigations → ROADMAP P0 mapping

The threat model's controls are tracked as concrete work in the
[ROADMAP](ROADMAP.md). The P0 items are the boundary controls above.

| Threat / boundary | Audit finding(s) | Control | ROADMAP item |
|---|---|---|---|
| Hosted MCP arbitrary read + DoS + leak (TB-3, S3) | Q-01, Q-02, Q-03, Q-13 | Gate FS tools OFF by default on HTTP; require auth + per-tool timeouts; default-bind `127.0.0.1`; strip snippets; generic errors. | **P0-1** |
| Action output injection (TB-2, S1, S5) | Q-04, Q-05 | Escape `file`/`message` for Markdown and workflow-command syntax; clip; route all fields through escapers. | **P0-2** |
| Untrusted SUT inherits env (TB-4, S4) | Q-17 | Pass a scrubbed, allow-listed env; document SUT trust. | **P0-3** |
| EC keys under-report HNDL (correctness → A5) | (cryptography audit) | Classify EC keygen as key-exchange-capable (`hndl:true`) or emit both concerns. | **P0-4** |
| `explain_finding` broken for library findings (A5) | (architecture audit) | Look findings up by rule, not ruleId prefix. | **P0-5** |
| ReDoS / quadratic detector cost (TB-1, S2) | Q-06, Q-07 | Bound regex spans; binary-search `callIndexes`; per-file deadline before any scan-on-content path ships. | **P0-6** |

Defense-in-depth and process items (threat-model doc itself, fuzz targets for the
four hand-rolled parsers, Sieve global deadline Q-18, SARIF sanitization Q-19,
scan byte budget Q-10, schema enforcement Q-20) are tracked under **P1-10** and
the audit's prioritized remediation order (§7).

---

*Companion to [`docs/audits/security.md`](audits/security.md). This document is
documentation only; no source was modified. Trust boundaries here reflect the
behaviour of the code at the time of writing and must be revisited whenever a new
transport, sink, or merge operation is added.*
