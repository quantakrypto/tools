# qproof-tools — Compliance & Standards Mapping

A standards-and-compliance reference for the `qproof-tools` monorepo (v0.1.0):
`@qproof/core`, `@qproof/qscan`, `@qproof/mcp`, `@qproof/action`, `@qproof/sieve`.

This document maps the toolset against post-quantum cryptography standards,
interchange/output formats, information-security and evaluation standards,
PQC-migration regulations, and software-supply-chain assurance frameworks for the
project itself. It is a **READ-ONLY analysis**; no source was modified.

---

## How to read this document — scope and honesty rules

This toolset is a **post-quantum readiness and conformance-testing** suite. To
avoid overclaiming, every mapping below uses one of three explicit relationship
verbs. Read them precisely:

| Verb | Meaning | Example |
|---|---|---|
| **Touches / relates to** | The standard is *referenced, targeted, or contextually relevant*, but the tool neither implements nor validates it. | qscan points findings at FIPS 203 as a *remediation target*; it does not implement ML-KEM. |
| **Helps you align with** | The tool produces *evidence or controls* that materially support a compliance activity a person/organization still owns. | qscan inventory + SARIF supports ISO/IEC 27001 A.8.24 cryptography-control evidence. |
| **Would require X to certify / claim alignment** | A concrete, currently-missing capability that must be built before any formal claim is defensible. | CWE tagging, a CBOM exporter, signed provenance, a security policy, CI gates. |

**Hard limits — what this toolset does NOT do (stated up front):**

- It does **not** implement ML-KEM/ML-DSA/SLH-DSA. `@qproof/sieve` *tests other
  people's* implementations and ships **no** Known-Answer-Test (KAT) vectors.
- It does **not** validate, certify, or accredit a FIPS 140-3 / ISO 19790
  cryptographic module. Module validation is a CMVP/lab process; Sieve is a
  *pre-screen / conformance battery*, not a CAVP/CMVP test harness.
- It does **not** grant any accreditation (Common Criteria EAL, FIPS certificate,
  CNSA compliance attestation, etc.).
- qscan detection is **purely lexical** (regex/heuristic). It finds *candidate*
  classical-crypto usage; it does not prove cryptographic correctness, key
  strength, or runtime behavior. Findings are evidence to triage, not verdicts.

Where the underlying tool behavior is documented, citations point at the package
READMEs and `docs/AUDIT.md` in this repo.

---

## 1. Post-quantum cryptography standards

These define the algorithms and the migration the toolset is built around. qscan
/ core **target** them as remediation destinations; Sieve **conformance-tests**
the two that have finalized FIPS standards (ML-KEM, ML-DSA).

| Standard | What it is (one line) | How qproof-tools relates / supports / what'd be needed to claim alignment |
|---|---|---|
| **NIST FIPS 203 (ML-KEM)** | Finalized standard for Module-Lattice KEM (key encapsulation), derived from CRYSTALS-Kyber. | **Touches** as a remediation target: core's `remediationFor()` points key-exchange/KEM findings at ML-KEM-768 / hybrid `X25519MLKEM768`. **Helps align** via `@qproof/sieve`, which conformance-tests an ML-KEM SUT (correctness, determinism, implicit-rejection, sizes, robustness, ACVP-KAT when vectors supplied). Sieve hard-codes only the **public** FIPS 203 parameter sizes (e.g. ML-KEM-768 pk = 1184 B). To **claim ML-KEM conformance** for an implementation you must run Sieve with official NIST ACVP vectors (`--vectors`); without them the `kat` category is SKIPPED. |
| **NIST FIPS 204 (ML-DSA)** | Finalized standard for Module-Lattice digital signatures, derived from CRYSTALS-Dilithium. | **Touches** as remediation target for signature findings. **Helps align** via Sieve's `dsa` category (sign→verify, tamper-rejection, size/format) and `sigVer` ACVP-KAT. Note Sieve deliberately uses **sigVer** vectors (verification verdicts), not sigGen, because ML-DSA signing is randomized/hedged. Exact-value conformance again **requires official ACVP vectors**. |
| **NIST FIPS 205 (SLH-DSA)** | Finalized stateless hash-based signature standard (SPHINCS+). | **Touches** only: listed by core as a recommended PQC signature replacement in remediation text. **No Sieve category** exists for SLH-DSA today. To support SLH-DSA conformance, Sieve **would require** a new category + ACVP sigVer/keyGen loader for FIPS 205 (sizes, sign/verify self-consistency). |
| **NIST SP 800-208 (stateful hash-based sigs)** | Guidance for stateful hash signatures (LMS/HSS, XMSS/XMSSMT) and their state-management hazards. | **Does not touch.** No detector flags LMS/XMSS, no Sieve category tests them. **Would require** (a) core detectors for LMS/HSS/XMSS library usage and (b) a Sieve stateful-signature battery (state-reuse/exhaustion checks are the core risk) to relate at all. Out of current scope. |
| **NIST SP 800-227 (KEM guidance, draft)** | Draft recommendations for using KEMs securely (encapsulation/decapsulation, key-derivation, FO transform). | **Touches** conceptually: Sieve's implicit-rejection (`AF-02`) category directly exercises the Fujisaki–Okamoto reject path that SP 800-227 cares about (no-error on bad ct, deterministic reject secret, differs from honest ss). **Helps align** as an implementation-hygiene pre-screen. To **claim** alignment, map each Sieve check to specific draft requirements and track the draft to final. |
| **NIST IR 8547 (transition to PQC standards)** | NIST's roadmap describing the move off RSA/ECC toward the FIPS 203/204/205 family, and discovery/inventory expectations. | **Helps align** with the *discovery & inventory* phase IR 8547 calls for: qscan/core produce a crypto inventory (`byAlgorithm`/`byCategory`/`bySeverity`), an HNDL count, and a 0–100 readiness score — exactly the "know where your quantum-vulnerable crypto is" step. It does **not** perform the migration; it informs it. |
| **NSA CNSA 2.0** | NSA's Commercial National Security Algorithm Suite 2.0 — PQC algorithm mandates and timelines for NSS (ML-KEM-1024, ML-DSA-87, LMS/XMSS, SHA-384/512, AES-256). | **Touches**: qscan flags the *classical* algorithms CNSA 2.0 retires (RSA, ECDH, ECDSA). **Helps align** by surfacing non-CNSA-2.0 asymmetric crypto for migration. **Gaps to claim alignment:** core has no "CNSA 2.0 level" policy mode (no detector for whether you reached ML-KEM-**1024** / ML-DSA-**87**, no LMS/XMSS detection per SP 800-208). To say "CNSA 2.0 readiness check" defensibly, **would require** a policy profile that asserts the CNSA-specified parameter levels and flags sub-CNSA PQC choices. |
| **BSI TR-02102** | German BSI's technical guideline on cryptographic mechanisms & key lengths (incl. PQC recommendations and hybrid guidance). | **Touches**: the classical algorithms qscan flags overlap TR-02102's deprecation guidance; core's hybrid recommendation (`X25519MLKEM768`) matches BSI's preference for hybrid KEX during transition. **Would require** a TR-02102 policy profile (its specific key-length and mechanism allow-lists) to claim "TR-02102-aligned" output. |
| **ANSSI PQC views** | French ANSSI's position favoring *hybrid* (classical + PQC) deployments and caution on pure-PQC during transition. | **Touches / supports**: the toolset's default remediation is explicitly **hybrid** (`X25519MLKEM768`), consistent with ANSSI's hybrid-first stance. This is alignment-by-default of recommendations, not a formal conformance claim. |
| **ETSI TC CYBER QSC** | ETSI's Quantum-Safe Cryptography working group — migration frameworks, quantum-safe protocol profiles, and inventory guidance. | **Helps align** with ETSI's migration-inventory guidance via qscan's crypto inventory and readiness scoring. No ETSI-specific report profile exists; relationship is at the methodology level. |
| **IETF hybrid drafts (TLS `X25519MLKEM768` group)** | IETF/TLS work standardizing hybrid key exchange named groups for TLS 1.3 (e.g. `X25519MLKEM768`). | **Touches directly**: `X25519MLKEM768` is core's **primary recommended remediation string** for ECDH/KEX findings (see `remediationFor`). The tool *recommends adopting* the hybrid group; it does not implement or negotiate TLS. To verify a deployment actually offers the group **would require** a TLS-handshake probe (out of scope; qscan is static/lexical). |

**Net for Section 1:** qscan/core **target** FIPS 203/204/205 + IETF hybrid as
*migration destinations* and **help with discovery** (IR 8547). Sieve **helps you
conformance-test** ML-KEM (FIPS 203) and ML-DSA (FIPS 204) implementations, and
**requires official NIST ACVP vectors** for any exact-value KAT claim. SLH-DSA,
SP 800-208 stateful sigs, and CNSA-2.0 parameter-level policy are **gaps**.

---

## 2. Output / interchange standards the tools emit (or could)

| Standard | What it is (one line) | How qproof-tools relates / supports / what'd be needed to claim alignment |
|---|---|---|
| **SARIF 2.1.0 (OASIS)** | Static Analysis Results Interchange Format — the OASIS standard JSON schema for static-analysis findings, consumed by GitHub code scanning and others. | **Emits today.** core's `toSarif()` produces SARIF 2.1.0 (`$schema`, `version`, `runs[0].tool.driver{name,informationUri,version,rules[]}`, `results[]` with `ruleId`/`level`/`message.text`/`physicalLocation`). qscan (`--format sarif`) and the Action both emit it; the Action uploads via `github/codeql-action/upload-sarif`. **Caveats to harden the claim:** (a) `docs/AUDIT.md` notes three different `informationUri`/repo URLs across core/qscan — reconcile to one; (b) CRLF files can be off-by-one in `startColumn` (precise SARIF column consumers affected). Validate output against the official OASIS SARIF JSON schema in CI to *claim* conformance. |
| **CWE (Common Weakness Enumeration)** | MITRE's catalog of software/hardware weakness types; SARIF results commonly carry CWE taxonomy references. | **Does not touch yet.** Findings are **not** tagged with CWE ids. Natural mappings exist (e.g. CWE-327 *Use of a Broken or Risky Cryptographic Algorithm*, CWE-326 *Inadequate Encryption Strength*, CWE-1240 *Use of a Risky Cryptographic Primitive*). **Recommended:** add a `cwe` field per rule and emit SARIF `taxonomies`/`relationships` referencing CWE. This is the single highest-leverage interchange improvement — it makes findings consumable by CWE-aware dashboards and audit frameworks. |
| **CycloneDX SBOM** | OWASP CycloneDX — a Software Bill of Materials format; recent versions support cryptographic assets (`cryptographic-asset` components) → effectively a CBOM. | **Strong fit, not yet emitted.** core already builds the substance of a crypto inventory (algorithms, categories, locations, dependency findings). **Would require** a CycloneDX exporter that maps each Finding to a `cryptographic-asset` component (algorithm family, primitive, location, HNDL flag). This is the most defensible path to a real **CBOM** (see below). |
| **SPDX SBOM** | Linux Foundation / ISO/IEC 5962 SBOM format; SPDX 3.0 adds security and (emerging) crypto profiles. | **Does not emit.** Same opportunity as CycloneDX. **Would require** an SPDX exporter; lower priority than CycloneDX for crypto assets since CycloneDX's crypto-asset model is more mature today. |
| **CBOM (Cryptographic Bill of Materials)** | An SBOM specialized to enumerate cryptographic assets (algorithms, keys, certificates, protocols) and their usage — the emerging primitive for PQC migration tracking. | **Best-fit future output for this toolset.** The inventory core already computes *is* a CBOM in all but format. **Would require** emitting it as standardized CBOM (via CycloneDX crypto-assets, or an SPDX crypto profile). Until then, qscan output **helps you build** a CBOM but is **not itself** a standardized CBOM. This is the flagship roadmap item (Section 6). |
| **NIST ACVP vector format** | The JSON test-vector format used by NIST's Automated Cryptographic Validation Protocol (CAVP/ACVTS) for ML-KEM (FIPS 203) and ML-DSA (FIPS 204). | **Consumes (does not emit).** Sieve's `src/vectors.ts` parses standard ACVP JSON (`algorithm`/`mode`/`testGroups[].tests[]`, hex byte fields) for `keyGen`, `encapDecap`, and `sigVer`, normalizing into `kem-keygen`/`kem-encap`/`kem-decap`/`dsa-verify` cases. It **never fabricates** values and records unrecognized files as non-fatal notes. **To claim ACVP-based conformance**, the operator must supply authentic NIST ACVP vectors; Sieve does not redistribute them. Sieve is **not** an ACVP *client/server* and does not talk to ACVTS. |

**Net for Section 2:** **SARIF 2.1.0 is emitted today** (the one true interchange
claim). **CWE tagging, CycloneDX/SPDX, and a standardized CBOM are not yet
emitted** but are natural, high-value additions. **ACVP format is consumed** by
Sieve, not produced.

---

## 3. Information-security management & evaluation

| Standard | What it is (one line) | How qproof-tools relates / supports / what'd be needed to claim alignment |
|---|---|---|
| **ISO/IEC 27001 + 27002, esp. control 8.24 "Use of cryptography"** | ISMS requirements (27001) and the control catalog (27002); A.8.24 requires a defined, enforced policy on cryptographic use, algorithms, and key management. | **Helps you produce evidence** for A.8.24. qscan's crypto inventory, readiness score, SARIF report, and CI gate are concrete artifacts an auditor accepts as evidence that the org *identifies* and *governs* cryptographic usage and is *managing the PQC transition*. **Important boundary:** the *tool is not the control.* The organization still owns the cryptography policy, key management, and risk treatment. To say "qscan supports our A.8.24 evidence" defensibly you need: a written crypto policy, qscan wired into CI with retained reports (audit trail), and a triage/remediation process. The tool **does not** by itself satisfy A.8.24. |
| **ISO/IEC 15408 (Common Criteria) + ISO/IEC 18045 (CEM)** | The IT-security evaluation framework (Protection Profiles, Security Targets, EALs) and its evaluation methodology. | **Relates only by analogy.** Sieve-style conformance testing resembles the *functional/assurance testing* an evaluator performs, and Sieve output could be **supporting evidence** within a developer's test documentation. It is **not** a CC evaluation, confers **no EAL**, and is not run by a licensed evaluation lab. To contribute to a real CC evaluation **would require** a Security Target, a recognized lab (ITSEF), and evaluator-driven testing; Sieve would be at most one developer-supplied test artifact. |
| **FIPS 140-3 / ISO/IEC 19790 (module validation)** | Security requirements for cryptographic modules; validated via CMVP using CAVP algorithm testing. | **Relate — do NOT claim.** Sieve is a *pre-screen / conformance battery*, useful to catch obvious ML-KEM/ML-DSA defects **before** a CAVP/CMVP submission, but it is **not** a CAVP test tool and a passing Sieve run is **not** a FIPS 140-3 result. No `qproof-tools` component is a "FIPS-validated module," and running qscan does not make a system FIPS-compliant. Any FIPS 140-3 claim **requires** CMVP validation of the actual module by an accredited lab — wholly outside this toolset. |
| **ISO/IEC 29147 (vuln disclosure) + ISO/IEC 30111 (vuln handling)** | How to *receive* (29147) and *process* (30111) security vulnerability reports — for the **project itself**, not the code it scans. | **Does not satisfy today.** The repo has a single `LICENSE` and no `SECURITY.md`, no disclosure policy, no advertised contact, and no `.github/` process files. **Would require** publishing a `SECURITY.md` with a reporting channel (security contact / private advisories), a triage SLA, and a coordinated-disclosure process to align. Given the MCP server's documented `scan_path` arbitrary-file-read risk in a hosted context (`docs/AUDIT.md` §2.3), a disclosure policy is especially warranted. |

**Net for Section 3:** qscan **helps generate A.8.24 evidence** inside an ISMS the
org still operates; Sieve **relates to CC/FIPS evaluation as a pre-screen** but
**certifies nothing**; the project itself currently **lacks** a 29147/30111
vulnerability-disclosure posture (a concrete, low-effort gap).

---

## 4. Regulation / mandates driving PQC migration

These create the *demand* for the toolset. qproof-tools **helps with the
technical discovery/migration steps** these mandates require; it does not by
itself make any entity "compliant."

| Mandate | What it is (one line) | How qproof-tools relates / supports / what'd be needed to claim alignment |
|---|---|---|
| **US OMB M-23-02 & NSM-10** | US federal direction (memo + National Security Memorandum) requiring agencies to inventory quantum-vulnerable crypto and plan PQC migration. | **Helps with the inventory mandate directly.** qscan/core produce exactly the *cryptographic inventory* M-23-02 requires for in-scope systems, plus a readiness score to prioritize. **Boundary:** federal inventories follow specific agency templates/reporting; qscan output **would require** mapping into the agency's required inventory format (and a CBOM export, Section 6) to be a turnkey submission. It informs, it does not file. |
| **EU DORA** | Digital Operational Resilience Act — ICT risk management for EU financial entities, incl. cryptographic and supply-chain resilience. | **Helps align** the cryptographic-risk-identification portion: qscan evidence supports DORA's ICT-risk-management and resilience-testing expectations for crypto. The broader DORA obligations (incident reporting, third-party oversight, resilience testing program) are organizational and out of scope. |
| **EU NIS2** | Network and Information Security Directive 2 — raises cybersecurity/risk-management baselines for essential & important entities. | **Helps align** with NIS2's risk-management requirement to assess cryptography and manage the PQC transition, via inventory + CI gating evidence. Not a NIS2 compliance attestation. |
| **eIDAS 2.0** | EU regulation for electronic identification & trust services (signatures, seals, the EU Digital Identity Wallet). | **Touches**: qscan flags classical signature crypto (RSA/ECDSA/EdDSA, JWT `RS*/PS*/ES*/EdDSA`) used in trust-service / identity stacks that eIDAS governs. **Would require** signature-policy awareness (qualified-signature algorithm allow-lists) to make any eIDAS-specific claim; today it is generic signature detection. |
| **GDPR (HNDL exposure of personal data)** | EU data-protection regulation; Art. 32 requires appropriate technical measures — relevant because *harvest-now-decrypt-later* threatens long-lived personal data. | **Helps surface the HNDL risk.** Every finding carries an `hndl: true/false` flag and core reports an HNDL count, directly highlighting where classical key-exchange/public-key encryption leaves personal data **recordable-now, decryptable-later** — material to an Art. 32 risk assessment. The tool identifies the exposure; the legal/DPIA judgment and remediation remain the controller's. |
| **PCI-DSS (cryptography requirements)** | Payment Card Industry Data Security Standard — strong-cryptography and key-management requirements (Req. 3/4 family). | **Helps with discovery** of weak/legacy crypto in scope (qscan also flags TLS ≤1.1, `rejectUnauthorized:false`, RC4/DES/3DES/MD5/NULL/EXPORT ciphers, embedded PEM keys/certs). **Boundary:** PCI requires a defined cryptographic architecture and key management; qscan is an input to that, not an assessor's verdict. |
| **HIPAA (Security Rule)** | US health-data rule requiring addressable encryption safeguards for ePHI. | **Touches** lightly: qscan surfaces where ePHI-handling systems rely on classical crypto and where HNDL exposes long-retention health data. Same boundary — evidence, not compliance. |

**Net for Section 4:** the toolset **helps satisfy the "inventory and plan"
technical step** these mandates impose (strongest fit: M-23-02/NSM-10 inventory
and GDPR/HNDL exposure). It produces **inputs to compliance**, never a compliance
attestation; turnkey alignment with most mandates **would require** mapping output
into mandate-specific report/inventory formats.

---

## 5. Software supply-chain / OSS assurance — for the project itself

This section assesses `qproof-tools` *as a published open-source project*. Current
state below is drawn from the repo (`package.json` × 6 = Apache-2.0 @ v0.1.0,
a single root `LICENSE`, **no `.github/` workflows**, no `SECURITY.md`).

| Framework | What it is (one line) | Current state in qproof-tools / what'd be needed to claim alignment |
|---|---|---|
| **SLSA** | Supply-chain Levels for Software Artifacts — graduated provenance/build-integrity levels for released artifacts. | **Not yet aligned.** No build provenance is generated. To reach **SLSA L1+** the project **would require** a scripted, version-controlled build with generated provenance; **L2/L3** need a hosted, hardened CI builder (e.g. GitHub Actions reusable workflow + signed provenance). Today: no CI present. |
| **OpenSSF Scorecard** | Automated checks scoring an OSS repo on security practices (branch protection, CI tests, pinned deps, code review, etc.). | **Not run.** **Would require** adding the Scorecard GitHub Action and acting on results. The project's **zero-runtime-dependency** posture helps several checks (`Pinned-Dependencies`, `Vulnerabilities` — minimal attack surface) for free; missing items are branch protection, CI, fuzzing, signed releases, and a security policy. |
| **OpenSSF Best Practices Badge (formerly CII)** | Self-certified badge for following OSS best practices (reporting process, tests, release notes, crypto hygiene). | **Not held.** Apache-2.0 + an existing `node:test` suite satisfy several criteria already. **Would require** a published vuln-reporting process (ties to ISO 29147/30111 above), documented release process, and completing the questionnaire to earn the *passing* badge. |
| **SPDX / REUSE (license compliance)** | REUSE.software best practice: every file carries an SPDX license identifier; machine-verifiable licensing. | **Partial.** Top-level `LICENSE` (Apache-2.0) is present and every package declares `"license": "Apache-2.0"`, but per-file `SPDX-License-Identifier` headers and a REUSE-compliant `LICENSES/` layout are **not** in place. **Would require** adding SPDX headers (or `.reuse/dep5`) and running `reuse lint` to claim REUSE compliance. |
| **SemVer** | Semantic Versioning — `MAJOR.MINOR.PATCH` with documented compatibility semantics. | **Followed in form.** All packages are `0.1.0`. Under SemVer's 0.x rule, **anything may change**; the API is explicitly pre-stable. To make compatibility *promises*, the project **would require** reaching `1.0.0` with a documented public API surface and a changelog. (`docs/AUDIT.md` already flags pre-1.0 API-honesty items — dead options, divergent baseline schemes.) |
| **npm provenance** | npm's signed build-provenance attestation (Sigstore) shown on the package page, proving which CI built a release. | **Not configured.** No `provenance` publish config and no CI to produce it. **Would require** publishing from a supported CI (GitHub Actions) with `npm publish --provenance` (or `publishConfig.provenance: true`) and OIDC. Pairs naturally with SLSA. |

**Net for Section 5:** strong **license clarity** (Apache-2.0 throughout) and an
excellent **minimal-dependency** security posture, but **no CI, no provenance, no
security policy, no SBOM/REUSE headers, and pre-1.0 SemVer**. These are the
project-hygiene items to address before making supply-chain assurance claims.

---

## Per-tool → standards matrix

Relationship key: **E** = Emits/produces today · **C** = Consumes today ·
**T** = Targets/recommends (touches) · **S** = Supports/helps-align (produces
evidence) · **R** = Relates (pre-screen/analogy, no claim) · **—** = not applicable.
Blank cells indicate no meaningful relationship.

### 5a. PQC algorithm & migration standards

| Standard | core | qscan | mcp | action | sieve |
|---|---|---|---|---|---|
| FIPS 203 (ML-KEM) | T | T | T | T | **C/S** (conformance test) |
| FIPS 204 (ML-DSA) | T | T | T | T | **C/S** (conformance test) |
| FIPS 205 (SLH-DSA) | T | T | T | T | — (gap) |
| SP 800-208 (stateful HBS) | — | — | — | — | — (gap) |
| SP 800-227 (KEM guidance, draft) | T | — | — | — | R (FO/implicit-reject probe) |
| NIST IR 8547 (PQC transition) | S (inventory) | S | S | S | — |
| NSA CNSA 2.0 | T | T | T (advice) | T | R (param-level gap) |
| BSI TR-02102 | T | T | — | — | — |
| ANSSI (hybrid-first) | T | T | T (advice) | T | — |
| ETSI TC CYBER QSC | S | S | — | S | — |
| IETF hybrid (`X25519MLKEM768`) | T (primary rec) | T | T | T | — |

### 5b. Output / interchange & assurance standards

| Standard | core | qscan | mcp | action | sieve |
|---|---|---|---|---|---|
| SARIF 2.1.0 (OASIS) | **E** | **E** | — (JSON/text only) | **E** | — |
| CWE tagging | — (gap) | — (gap) | — | — (gap) | — |
| CycloneDX / SPDX SBOM | — (gap) | — (gap) | — | — (gap) | — |
| CBOM (crypto BOM) | builds substance (gap to emit) | builds substance | — | — | — |
| NIST ACVP vector format | — | — | — | — | **C** |
| ISO 27001 / 27002 A.8.24 | S (evidence) | S (evidence) | S (advisory) | S (CI gate) | R (impl conformance) |
| ISO 15408/18045 (Common Criteria) | — | — | — | — | R (test evidence) |
| FIPS 140-3 / ISO 19790 | — | — | — | — | R (pre-screen only) |
| ISO 29147/30111 (project vuln disclosure) | — | — | — | — | — (gap, repo-wide) |

> **MCP note:** `@qproof/mcp` does **not** emit SARIF; its tools (`scan_path`,
> `inventory_crypto`, `explain_finding`, `suggest_hybrid`, `list_rules`) return
> MCP text/JSON content. It relates to standards as an **advisory surface** over
> core's knowledge (remediation table + detector catalog), not as a report emitter.

---

## 6. Roadmap to defensible alignment claims

Ordered by leverage. Each item converts a *"touches / could"* into a *"supports /
emits"* you can state without overclaiming. Effort estimates: **S** ≈ <½ day,
**M** ≈ 1–3 days, **L** ≈ 1 week+.

| # | Claim you want to make | What to implement | Tool(s) | Effort |
|---|---|---|---|---|
| 1 | **"qscan emits a CBOM."** | Add a CycloneDX exporter mapping each `Finding` to a `cryptographic-asset` component (algorithm family, primitive type, location, `hndl` flag, dependency provenance). Validate against the CycloneDX schema. | core, qscan, action | M |
| 2 | **"Findings are CWE-classified."** | Add a `cwe` field per detector rule (e.g. CWE-327/326/1240) and emit SARIF `taxonomies` + `relationships`. | core (SARIF), qscan, action | S |
| 3 | **"SARIF output is schema-valid."** | Reconcile the three divergent `informationUri`/repo URLs to one; fix CRLF off-by-one column; add a CI step validating output against the OASIS SARIF 2.1.0 JSON schema. | core, qscan | S |
| 4 | **"qscan supports our ISO 27001 A.8.24 evidence."** | Document the evidence chain (inventory → SARIF → CI gate → retained reports) and ship a sample crypto-policy mapping. Pair with CBOM (#1). The org still owns the policy. | docs + core/qscan | S |
| 5 | **"The project has a vulnerability-disclosure process (ISO 29147/30111)."** | Add `SECURITY.md` with a private reporting channel and triage SLA; enable private security advisories. Especially warranted given the hosted-MCP `scan_path` LFI risk (`docs/AUDIT.md` §2.3). | repo-wide | S |
| 6 | **"Releases carry signed provenance (SLSA / npm)."** | Add a GitHub Actions release workflow publishing with `npm publish --provenance` via OIDC; generate SLSA provenance. Enables Scorecard/Best-Practices gains too. | repo-wide | M |
| 7 | **"We follow OSS best practices (Scorecard / Best Practices Badge)."** | Add CI (build + the existing `node:test` suite), branch protection, Scorecard Action; complete the OpenSSF Best Practices questionnaire (unblocked by #5). | repo-wide | M |
| 8 | **"REUSE-compliant licensing."** | Add `SPDX-License-Identifier: Apache-2.0` headers (or `.reuse/dep5`); run `reuse lint` in CI. | repo-wide | S |
| 9 | **"Sieve covers SLH-DSA (FIPS 205) and CNSA-2.0 parameter levels."** | Add a SLH-DSA Sieve category + ACVP loader; add a CNSA-2.0 policy profile asserting ML-KEM-1024 / ML-DSA-87 and flagging sub-CNSA PQC choices. | sieve, core | L |
| 10 | **"Conformance results are reproducible & attributable."** | Have Sieve record the exact ACVP vector-file provenance (source URL, hash) in its report, so a passing `kat` run is traceable to authentic NIST vectors. Keep the no-fabrication stance. | sieve | S |

**Guardrails that must survive the roadmap (do not erode these honesty
properties):**

- Sieve must keep shipping **no** KAT vectors and **never fabricate** expected
  values — conformance claims stay tied to operator-supplied authentic NIST ACVP
  vectors.
- Nothing here turns Sieve into a CAVP/CMVP tool or yields a FIPS 140-3 result;
  module validation stays a lab/CMVP process.
- qscan stays a **lexical discovery** tool: a clean scan is *absence of detected
  candidates*, not proof of quantum-safety. Keep that framing in all reports.
- "Readiness" and "conformance testing" remain the ceiling of what is claimed; the
  toolset **certifies FIPS modules and grants accreditations to no one**.

---

*This document (`docs/COMPLIANCE.md`) was written as a READ-ONLY standards-and-compliance mapping; no source files in `qproof-tools` were modified.*
