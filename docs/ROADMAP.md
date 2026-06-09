# qproof-tools — Roadmap & Gap Analysis

This is the consolidated, prioritised plan, distilled from the multi-discipline
audits in [`docs/audits/`](audits/) and [`COMPLIANCE.md`](COMPLIANCE.md). It is
the single place to **pick up the work**. Nothing here changes behaviour yet —
the code is intentionally untouched so each item can be picked up deliberately.

Sources: [security](audits/security.md) · [cryptography](audits/cryptography.md)
· [architecture](audits/architecture.md) · [performance](audits/performance.md)
· [testing/devex](audits/testing-devex.md) · [overview](AUDIT.md).

**Current state:** builds clean, **182 tests pass**, zero runtime dependencies,
all four tools verified end-to-end. The items below are improvements and gaps —
not regressions.

---

## 1. What's missing (gap matrix)

| Area | Item | Status |
|---|---|---|
| Governance | `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `CHANGELOG.md`, issue/PR templates, `.editorconfig` | ✅ **added** |
| CI | GitHub Actions: build + test on Node 20/22, self-scan dogfood | ✅ **added** (`.github/workflows/ci.yml`) |
| Docs | Discipline audits, compliance mapping, docs index, README badges | ✅ **added** |
| Quality | Code coverage tooling + gate | ❌ open (P1) |
| Quality | ESLint + Prettier + commit hooks | ❌ open (P2) |
| Tests | A test that runs the **real** `core.scan()` over a real tree (qScan e2e uses a fake) | ❌ open (P1) |
| Tests | Coverage for `mcp/http.ts`, the action PR-comment path, runner timeouts | ❌ open (P1) |
| Crypto | SLH-DSA (FIPS 205) + SP 800-208 conformance in Sieve | ❌ open (P2) |
| Crypto | Detectors for DH groups, SSH keys, TLS cert sig algs, JOSE/COSE | ❌ open (P1) |
| Perf | Benchmark harness + perf-regression CI | ❌ open (P2) |
| Perf | Parallel (worker pool) + incremental (changed-files) scanning | ❌ open (P2) |
| Security | Threat-model doc, fuzz targets for the hand-rolled parsers | ❌ open (P1/P2) |
| Compliance | CBOM (CycloneDX) output, CWE tagging, SARIF schema validation | ❌ open (P2) |
| Supply chain | OpenSSF Scorecard, SLSA provenance, SPDX/REUSE headers | ❌ open (P2) |
| Release | Commit/bundle the Action `dist/`; npm publish under `@qproof` (deferred) | ⏸ deferred (see §5) |

---

## 2. P0 — security & correctness (do before hosting / 1.0)

These are confirmed bugs or real risks, each cited to source.

| # | Item | Package | Audit | Effort | Impact |
|---|---|---|---|---|---|
| P0-1 | **Hosted MCP = unauthenticated arbitrary read.** `scan_path`/`inventory_crypto` pass a client path into `core.scan` (`mcp/src/tools.ts:152,183`); `http.ts` binds `0.0.0.0` with no auth/timeout/size cap (`http.ts:171`, `server.ts:168`); the `snippet` field turns it into a content-disclosure oracle. **Gate the filesystem tools OFF by default on the HTTP transport; require auth + per-tool timeouts before exposing.** | mcp | security | M | Critical |
| P0-2 | **Output injection.** Attacker-named files / finding text flow unescaped into the PR-comment Markdown table and `::error::` workflow commands (`action/src/main.ts:190-193`), posted with a write token. **Escape `file`/`message` for Markdown and for workflow-command syntax.** | action | security | S | High |
| P0-3 | **Untrusted SUT inherits full env.** The Sieve runner spawns the SUT with the parent environment (`sieve/src/runner.ts:~89`), exposing secrets. **Pass a scrubbed, minimal env.** | sieve | security | S | High |
| P0-4 | **EC keys under-report harvest-now exposure.** `generateKeyPair('ec', …)` is hard-classified signature-only with `hndl:false` (`core/src/detectors/source.ts:54`), but EC keys feed **both ECDSA and ECDH** — so ECDH HNDL exposure is silently missed. **Classify EC keygen as key-exchange-capable (`hndl:true`) or emit both concerns.** | core | cryptography | S | High |
| P0-5 | **`explain_finding` is broken for library findings.** It maps `ruleId`→detector by prefix (`mcp/src/tools.ts:252`) and returns "no matching detector" for real `crypto-libs` findings (`forge-*`, `elliptic-ec`, `node-rsa`). **Look findings up by rule, not prefix.** | mcp | architecture | S | Medium |
| P0-6 | **ReDoS surface.** The TLS cipher regex has two unbounded spans around an alternation → super-linear backtracking (`core/src/detectors/source.ts:439`); `nearCall` is O(matches×calls) quadratic (`source.ts:196`). Bounded today by the 2 MiB cap, but **harden the regex and binary-search `callIndexes`** before any scan-on-content path ships. | core | security/perf | S | Medium |

---

## 3. P1 — correctness coverage & architecture

| # | Item | Package | Audit | Effort |
|---|---|---|---|---|
| P1-1 | **Unify the baseline.** qScan (`baseline.ts:40`, sha256 of `ruleId\|file\|snippet\|line`) and the Action (`main.ts:84`, raw `ruleId file message`) use incompatible fingerprints, semantics, and on-disk formats. Extract one shared baseline module in `@qproof/core`. | core/qscan/action | architecture | M |
| P1-2 | **Repair `ScanOptions`.** `include` is declared but **unwireable** (`WalkOptions` has no field; `types.ts:107`); `runQscan` drops `maxFileSize`/`noDefaultIgnores` (`qscan/src/index.ts:110`) and there are no CLI flags. Wire them through. | core/qscan | architecture | S |
| P1-3 | **Action should reuse qScan.** It declares `@qproof/qscan` + a project reference but never imports it, re-implementing `fingerprint`/`applyBaseline`/`renderReport`. Use `runQscan` (or drop the unused reference). | action | architecture | S |
| P1-4 | **Make detectors a real plugin point.** `scan()` closes over a hardcoded array and classifies scope by ruleId prefix (`scan.ts:23,26`). Add a `DetectorRegistry`, declare `language`/`scope` on `Detector`, and write an "add a language" guide (Python/Go/Java). | core | architecture | M |
| P1-5 | **New detectors** (false-negative closure): DH MODP groups (`getDiffieHellman`), SSH keys, TLS certificate signature algorithms, JOSE `ECDH-ES*` / COSE / WebAuthn, one-shot `crypto.sign`/`verify`, `secp256k1`. | core | cryptography | M |
| P1-6 | **Remediation nuance.** Surface the CNSA 2.0 Category-5 tier (ML-KEM-1024 / ML-DSA-87) and SP 800-208 (LMS/XMSS) where relevant, not only Category-3 defaults. | core | cryptography | S |
| P1-7 | **Sieve depth.** Add the FIPS 203 §7.2 encapsulation-key modulus-range check (deepens AF-05), deeper ML-DSA probes, and a deterministic-vs-hedged signing test. | sieve | cryptography | M |
| P1-8 | **Real integration test.** qScan's e2e runs through a `fakeScan` — add a test that runs the real `core.scan()` over a fixture tree. Add tests for `mcp/http.ts`, the action PR-comment path, and runner timeout/crash escalation. Add coverage tooling (`node --test --experimental-test-coverage`) + a CI gate. | all | testing | M |
| P1-9 | **Cheap perf wins.** Precompile the ~16 per-file inline regexes at module scope; skip minified/generated files beyond `.min.js`/`.map` (`walk.ts:79-85`); handle lockfiles > 2 MiB instead of silently skipping (`walk.ts:159`). | core | performance | S |
| P1-10 | **Threat model doc** + fuzz targets for the four hand-rolled parsers (Sieve protocol/base64, manifest, SARIF, qScan args). | all | security/testing | M |

---

## 4. P2 — scale, polish, assurance

| # | Item | Package | Audit |
|---|---|---|---|
| P2-1 | Parallel scanning: a `node:worker_threads` pool (`scanParallel(opts, { concurrency })`) with chunking, backpressure, deterministic merge, and a small-repo crossover guard. | core | performance |
| P2-2 | Incremental scanning: `git diff --name-only` changed-files mode + per-file hash cache (big CI win). | core/qscan | performance |
| P2-3 | Sieve throughput: pipeline / bounded-concurrency pool over the id-correlated protocol. | sieve | performance |
| P2-4 | Benchmark harness (zero-dep) + a perf-regression CI check on representative corpora. | all | performance |
| P2-5 | ESLint flat config + typescript-eslint (`no-floating-promises` for the async transports), Prettier, commit hooks. | all | testing |
| P2-6 | **CBOM** (CycloneDX cryptographic bill of materials) output from the inventory; CWE tagging on findings; SARIF schema validation in CI. | core/compliance | compliance |
| P2-7 | OpenSSF Scorecard workflow, SLSA build provenance, SPDX/REUSE license headers, npm publish provenance. | repo | compliance/testing |
| P2-8 | ISO/IEC 27001 **A.8.24 evidence-chain** export (a signed, timestamped readiness report); ACVP vector-provenance pipeline; SLH-DSA (FIPS 205) conformance category. | core/sieve | compliance/crypto |
| P2-9 | Semver + deprecation policy, a generated public API reference, and ADRs; an optional `qproof.config.json`. | all | architecture |

---

## 5. Release readiness (publishing — deferred)

Out of scope for now (per the plan to finalize tech first), captured so it's ready:

- **Action `dist/` is not committed** and is gitignored — a `node20` action runs
  `dist/main.js` directly, so `uses: …/packages/action@v1` will not work until the
  built JS is committed or bundled (recommend a single-file `esbuild`-free bundle
  step + a CI "dist is fresh" gate). See [testing/devex audit §6.4](audits/testing-devex.md).
- Publish under the real `@qproof` npm scope with **npm provenance**; tag `v0.1.0`.
- Add `repository` / `bugs` / `homepage` to each package `package.json`; unify the
  three divergent `informationUri` / repo URLs noted across the codebase.

---

## 6. New audit vectors to run on a cadence

Beyond this one-off review, fold these recurring lenses in (the "add new vectors
of auditing" ask):

- **Fuzz / property-based testing** of every parser, in CI.
- **Supply-chain posture** as a gate: OpenSSF Scorecard + dependency review (even
  with zero runtime deps, dev-deps and Actions are surface).
- **Detection-quality benchmark:** a curated corpus measuring false-positive /
  false-negative rates of the crypto detectors over time (regression-tested).
- **Reproducible-build** verification for published artifacts.
- **Standards drift:** re-check against NIST/CNSA/BSI updates each quarter (the PQC
  landscape moves — see [COMPLIANCE.md](COMPLIANCE.md)).
- **CLI/output accessibility & i18n** of human-facing reports.
