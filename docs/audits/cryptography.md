# qproof-tools — Cryptographic-Correctness Audit (PQC Domain Review)

Read-only domain audit of the `qproof-tools` monorepo, scoped strictly to
**cryptographic correctness against the NIST PQC standards** (FIPS 203/204/205,
SP 800-56A/B/C, SP 800-208, NIST IR 8547) and adjacent transition guidance
(CNSA 2.0, BSI TR-02102). No source was modified. This complements — and does
not repeat — the prior general audit in `docs/AUDIT.md` (which covered
architecture, ReDoS, baselines, hosting, perf). Where that audit already noted
an item with cryptographic implications, it is cross-referenced, not re-derived.

Packages reviewed: `core` (detectors + remediation + dependency DB), `sieve`
(ML-KEM / ML-DSA conformance battery), `mcp` (advisory tools), with `qscan` /
`action` consuming `core` unchanged.

---

## 1. Summary verdict on domain correctness

**The cryptographic model is, in the large, correct and unusually disciplined.**
The two facts that matter most for a PQC-readiness tool are right:

1. **The HNDL-vs-forgery distinction is modeled correctly.** Confidentiality
   primitives (RSA-OAEP / KEM, ECDH, finite-field DH, X25519, ECIES) are marked
   `hndl: true` ("harvest now, decrypt later"); signature primitives (RSA-PSS /
   RS*/PS*, ECDSA, EdDSA, DSA) are marked `hndl: false` but still `high`
   severity because a quantum attacker forges them going forward rather than
   retroactively. This is the single most important conceptual axis and it is
   handled correctly across `source.ts`, `pem.ts`, and `dependencies.ts`.
2. **X25519 / Ed25519 are treated as classical-but-modern (`low`).** They are
   still flagged (correctly — Shor breaks them), but de-prioritized relative to
   RSA/ECDSA/DH. This matches real-world transition triage.

The Sieve parameter tables are **byte-exact against FIPS 203 Table 3 and FIPS
204 final Table 2** (verified below), the implicit-rejection category models the
correct FO property, the timing probe is correctly advisory and excluded from
the verdict, and the "ship no KAT, never fabricate vectors" stance is exactly
the right posture for a conformance harness.

**The defects are bounded and fall into three buckets:** (a) one genuine
*classification* bug — Node `'ec'` keygen is hard-classified as signature-only
and `hndl:false`, which under-reports ECDH harvest exposure; (b) a set of
**false negatives** (DH MODP groups, PGP/GPG, raw SSH `authorized_keys`,
DSA-PEM, TLS certificate signature algorithms, COSE/WebAuthn) that are scope
gaps rather than wrong answers; (c) Sieve **coverage gaps** (no SLH-DSA, no
SP 800-208 LMS/XMSS, ML-DSA shallower than ML-KEM, no deterministic-vs-hedged
signing check, no FIPS 203 encapsulation-key modulus-range check). None
produce a *cryptographically wrong* PASS verdict; the risk is silent
under-reporting (false negatives), which for a security scanner is the more
dangerous failure mode and is called out per-finding below.

Overall domain-correctness grade: **B+ / A-.** Correct where it commits;
honest where it abstains; the remaining work is breadth, plus the one `'ec'`
HNDL bug.

---

## 2. Findings

Severity here = **audit severity** (impact of the *tool* being wrong), not the
severity the tool assigns to findings.

| # | Sev | Location | Issue | Correct behavior |
|---|-----|----------|-------|------------------|
| C1 | **High** | `core/src/detectors/source.ts:54` | `generateKeyPair('ec', …)` is hard-mapped to `algorithm:"ECDSA", category:"signature", hndl:false`. But a Node `'ec'` key pair is used for **both ECDSA (sign) and ECDH (key agreement)**. ECDH usage is HNDL-exposed, so this **under-reports harvest-now exposure** (false `hndl:false`) and forces a signature-only remediation. The label literally says `"EC (ECDSA/ECDH)"`, acknowledging the ambiguity, yet commits to the non-HNDL branch. | An `'ec'` keygen with no usage context should either be `hndl:true` (conservative — an EC key *may* feed ECDH) or emit a dual/`unknown`-category finding noting both ECDSA and ECDH are possible. At minimum, do not assert `hndl:false` with `high` confidence for ambiguous EC keygen. |
| C2 | Low | `core/src/detectors/source.ts:58` | `x448` is mapped to `algorithm:"X25519"` (with label `"X448"`). X448 is a distinct curve (Ed448/X448 family, Goldilocks); the `AlgorithmFamily` enum has no `X448`. | Add `X448` to `AlgorithmFamily`, or use a neutral `unknown`/`X25519`-family note. Functionally both are `low`/HNDL-true key-agreement, so the verdict is right; only the algorithm label is wrong. |
| C3 | Low | `core/src/detectors/source.ts:60` | `ed448` is mapped to `algorithm:"EdDSA"` (correct family) but severity `low`, same as Ed25519. Fine, but note Ed448 targets a higher classical security level — irrelevant post-quantum (both fall to Shor), so `low` is defensible. | No change required; documented for completeness. |
| C4 | Med | `core/src/detectors/source.ts:55` | DSA keygen → `category:"signature"`, which is correct, but DSA is also **already classically deprecated** (FIPS 186-5 removed DSA signing). The message says "not quantum-safe" but omits that DSA is dead today. | Optionally raise context: DSA is deprecated independent of PQC. Severity `high` is fine. |
| C5 | Med | `core/src/dependencies.ts:181-194` | `dependencyFinding` derives **one** algorithm and remediation from `dep.algorithms[0]`. For multi-purpose libs this is lossy: `jsrsasign` (`[RSA,ECDSA,DSA]`) → RSA/KEM remediation though it is signature-heavy; `elliptic` (`[ECDSA,ECDH,EdDSA]`) → ECDSA signature remediation, hiding the **ECDH (HNDL)** half. The `hndl` flag *is* computed across all algorithms (line 189), so HNDL exposure is not lost — but the surfaced remediation can point the user at the wrong PQC primitive. | Emit remediation covering all families the package exposes (e.g. "KEM→ML-KEM-768 *and* sig→ML-DSA-65"), or pick the most-severe/most-HNDL algorithm rather than the array head. |
| C6 | Low | `core/src/dependencies.ts:189` | HNDL predicate is a hard-coded family list `RSA\|ECDH\|DH\|ECIES\|X25519`. It correctly excludes EdDSA/ECDSA/DSA (signatures). But note `RSA` is HNDL only for *encryption* RSA; an RSA-signatures-only library is marked `hndl:true` here. For `node-rsa`/`node-forge` (which do encryption) that is right; it would over-count HNDL for a hypothetical RSA-sign-only lib. | Acceptable conservative default (RSA libs almost always offer encryption). Document the assumption. |
| C7 | Med | `core/src/detectors/pem.ts:22-78` | PEM rules cover RSA / EC / OpenSSH / PKCS#8 / X.509 but **miss `-----BEGIN DSA PRIVATE KEY-----` and `-----BEGIN PGP PRIVATE KEY BLOCK-----` / `-----BEGIN PGP MESSAGE-----`**. A DSA PEM key or an embedded PGP/GPG secret key is undetected. | Add DSA-PEM and PGP-block rules (PGP keys are RSA/ECDSA/EdDSA/ElGamal — all classical; `critical` for private blocks). |
| C8 | Low | `core/src/detectors/pem.ts:68-77` | X.509 certificate finding is `low`, `hndl:false`, algorithm `unknown` — correct (a cert is a public artifact; the risk is its *signature* algorithm, a forgery vector, not HNDL). The message rightly says "almost certainly signed with classical RSA/ECDSA." | Correct as-is. Could parse the cert's signature OID to set the algorithm, but lexical scope makes that out of reach — acceptable. |
| C9 | Med | `core/src/detectors/source.ts:439` | TLS weak-cipher detector flags RC4/DES/3DES/MD5/NULL/EXPORT — these are **classical transport hygiene, not PQC**. Correctly `category:"tls"`, `hndl:false`. No false PQC claim. (ReDoS noted in `AUDIT.md`.) | Correct scoping; no PQC over-claim. |
| C10 | Low | `core/src/remediation.ts:13` | RSA recommendation string is `"ML-KEM-768 for encryption/KEM; ML-DSA-65 for signatures"` — correctly **disambiguated by usage**. This is the right answer and resolves the RSA dual-use problem at the remediation layer (even though the *finding* layer C1/C5 can mislabel). | Correct. The remediation table is the strongest part of `core`. |
| S1 | **Med** | `sieve` (whole package) | **No SLH-DSA (FIPS 205) support and no SP 800-208 LMS/XMSS support.** The harness drives only ML-KEM and ML-DSA. SLH-DSA is a standardized signature scheme an implementer may ship; it has its own conformance properties (sign/verify self-consistency, fixed sizes per parameter set, `simple` vs `robust`, `s`/`f` variants, randomized vs deterministic). | Add an `slh-dsa` family with its 12 parameter sets and a self-consistency category; note LMS/XMSS are stateful (SP 800-208) and need a different, state-aware harness. |
| S2 | Med | `sieve/src/categories/dsa.ts` | **ML-DSA depth < ML-KEM depth.** ML-KEM has 5 self-consistency categories (correctness, determinism, implicit-rejection, sizes, robustness); ML-DSA has one (`dsa.ts`) with only two negative length probes (`verify-pk-too-short`, `verify-sig-too-long`). No malformed/garbage/oversize verify-input probes, no empty-input probe, no tamper-public-key check. | Add an ML-DSA robustness category symmetric to ML-KEM's (empty / non-base64 / oversize pk·msg·sig), and a wrong-`pk` verify check. |
| S3 | Med | `sieve/src/categories/dsa.ts:4`, `determinism.ts` | **No deterministic-vs-hedged signing test.** FIPS 204 §3.4 defines both deterministic (rnd = 0) and hedged (rnd random) signing. `dsa.ts` comments "signing is randomized (hedged) by default" and never checks the deterministic path. Two conforming behaviors are conflated: a SUT that *only* supports hedged and one that supports both are indistinguishable. | Add an optional category: with a fixed message/key, hedged signing should (usually) produce **different** signatures across calls; if the SUT exposes a deterministic mode, repeated signs must be **identical**. Both still verify. This is the signature analog of the KEM determinism category. |
| S4 | Med | `sieve/src/categories/sizes.ts:60-92` | **No FIPS 203 encapsulation-key (`ek`) modulus-range check.** FIPS 203 §7.2 requires encapsulation to perform the "modulus check": the encapsulation key's `t̂` coefficients must be < q (3329), i.e. `ek` must round-trip through `ByteEncode₁₂`/`ByteDecode₁₂`. The sizes category checks only **length**, not coefficient range. A SUT that accepts a correctly-sized-but-out-of-range `ek` (the classic "ek not reduced mod q" malleability) passes today. | Add a negative probe: take a valid `ek`, set a 12-bit coefficient ≥ 3329 (still correct length), and require `encaps` to reject it. This is a named FIPS 203 input-validation requirement, not a self-consistency property — worth its own check. |
| S5 | Low | `sieve/src/categories/sizes.ts:116` | The negative probes send an **all-zeros valid-length `sk`** to `decaps` alongside a wrong-length `ct`. Because the wrong-length is on the *ciphertext*, the SUT must reject on `ct` length regardless of `sk` — so this is sound. (Prior `AUDIT.md` flagged a *different* zeros-sk concern; here the zeros-sk is just filler and harmless.) | Correct. The decaps-sk-too-short probe (line 132) is also sound: a short `sk` is a genuine length error. |
| S6 | Low | `sieve/src/categories/implicit-rejection.ts` | The four observable properties asserted (no error, correct length, deterministic, differs-from-honest) are **exactly** the right black-box surface for FO implicit rejection (KyberSlash / "reject secret must be keyed and silent"). No exact-value fabrication. This is the strongest single category. | Correct. One nuance: property (4) "differs from honest ss" can in principle collide with ~2⁻²⁵⁶ probability — negligible and correctly ignored. |
| S7 | Low | `sieve/src/vectors.ts:151-209` | ACVP loader is well-aligned to NIST ACVP JSON: ML-KEM `keyGen` (`d`/`z` → seed, `ek`/`dk`), `encapDecap` (`ek`/`c`/`k`, `m` as coins), ML-DSA `sigVer` (`pk`/`message`/`signature`/`testPassed`). It correctly **declines ML-DSA `sigGen`** as a KAT because hedged signing is nonce-dependent (line 200). Hex-validated, nothing invented. | Correct and honest. Minor: ACVP sometimes nests `tests` under `testGroups[].tests[]` with `tcId`; group-level `parameterSet` parsing matches the current ACVP-server schema. Verify against the exact `gen-vals` file shape when a curated set is added (see §4). |
| S8 | Low | `sieve/src/categories/timing.ts` | Timing probe is correctly **advisory-only, never fails the run** (`report` excludes it), with an explicit "cross-process timing is noisy, not proof; use dudect in-process" caveat. The 25% relative-median heuristic is arbitrary but honestly framed. | Correct posture. The caveat is exactly right and should be preserved verbatim. |
| S9 | Info | `sieve/src/categories/correctness.ts` | ML-KEM round-trip (`ss_encaps == ss_decaps` over N keys) is the correct fundamental KEM correctness property and needs no vectors. | Correct. |

---

## 3. False-positive analysis (precision)

**No cryptographic false positives were found.** The tool is conservative in the
right direction. Specifically, the following are *correctly NOT flagged*:

- **Password hashing / KDFs** — `bcrypt`, `scrypt`, `argon2`, `pbkdf2` are absent
  from the dependency DB and not matched by any source regex. Correct: these are
  symmetric/one-way and quantum-resistant (Grover only halves the bit-strength).
- **`bcrypto` is correctly flagged, and is *not* a `bcrypt` false positive.**
  `dependencies.ts:135` flags `bcrypto` (a real classical RSA/ECDSA/ECDH/EdDSA/DSA
  suite, `high`) — the name resembles the password-hashing `bcrypt`, but they are
  different packages and the DB matches the exact name `"bcrypto"`, so there is no
  bleed onto `bcrypt`. Good discipline.
- **Symmetric AEAD** — AES-GCM, ChaCha20-Poly1305 are not flagged (no regex,
  not in DB). Correct: symmetric crypto is out of PQC asymmetric scope.
- **`@noble/hashes`** — not in the DB; only `@noble/curves`, `@noble/secp256k1`,
  `@noble/ed25519` are. Correct: hashing is not asymmetric.
- **WebCrypto false-positive guard** — `source.ts:196` only flags an algorithm
  string (`RSA-OAEP`, `ECDH`, …) when it appears **within 400 chars of a
  `subtle.*` call**; a bare `const label = 'RSA-OAEP'` with no subtle call is
  ignored (asserted by `detectors.test.ts:114`). Good — this prevents flagging
  comments, docs, and unrelated strings.
- **PEM fast-reject** — `pem.ts:88` bails unless `-----BEGIN ` is present, so a
  file merely mentioning "certificate" is not flagged.

The one borderline case is **C6** (an RSA-signature-only library would be marked
`hndl:true`), but in practice RSA libraries offer encryption too, so the
conservative default is defensible — it is an over-count of HNDL, not a wrong
algorithm classification.

---

## 4. False-negative analysis (recall) — the real risk

For a scanner, missed crypto is the dangerous failure. The following are
**classical, quantum-vulnerable, and currently undetected**:

| Missed surface | Why it matters | Where it should live |
|---|---|---|
| **DH MODP groups** (`modp14`, `modp16`, `getDiffieHellman('modp14')`, IKE group numbers) | Finite-field DH key exchange — HNDL. `createDiffieHellman` is caught, but the named built-in MODP groups via `crypto.getDiffieHellman('modpN')` are not (`source.ts` has no `getDiffieHellman` rule). | new source rule |
| **PGP / GPG key blocks** | `-----BEGIN PGP PRIVATE KEY BLOCK-----`, `-----BEGIN PGP MESSAGE-----` — RSA/ECDSA/EdDSA/ElGamal, classical. Private blocks are `critical`. | `pem.ts` (C7) |
| **DSA PEM keys** | `-----BEGIN DSA PRIVATE KEY-----` — classical signature key, undetected. | `pem.ts` (C7) |
| **SSH `authorized_keys` / `known_hosts`** | Lines like `ssh-rsa AAAA…`, `ecdsa-sha2-nistp256 …`, `ssh-ed25519 …` in config files are classical SSH public keys; only the *OpenSSH private-key PEM* is caught. | new config rule |
| **TLS certificate signature algorithms** | `sha256WithRSAEncryption`, `ecdsa-with-SHA256` OIDs/strings in cert configs — the *forgery* surface of the PKI. | new config rule |
| **JOSE/COSE key-agreement & PQC tracking** | `ECDH-ES`, `ECDH-ES+A256KW` (HNDL key agreement) are **not** matched — `jwt-jose` only matches signature algs (`RS*/PS*/ES*/EdDSA`). COSE algorithm identifiers (`-7` ES256, `-8` EdDSA, `-25` ECDH-ES) are entirely unhandled. | extend `jwt-jose`; new COSE rule |
| **WebAuthn / FIDO2 attestation** | WebAuthn attestation/assertion uses COSE keys (ES256/EdDSA/RS256). Not detected as a distinct surface. | new rule (overlaps COSE) |
| **Raw secp256k1 wallet usage in source** | secp256k1 ECDSA is caught only via the `elliptic`/`secp256k1`/`@noble/secp256k1`/`ecpair` *dependencies* and `new EC('secp256k1')`. Direct `@noble/secp256k1`-style API calls (`secp.sign`, `getPublicKey`) in source are not matched by a source regex. The dependency DB catches the import, which is the main path, so this is partial coverage. | optional source rule |
| **`crypto.sign` / `crypto.verify` (one-shot)** | `source.ts` catches `createSign`/`createVerify` but **not** the one-shot `crypto.sign(algorithm, data, key)` / `crypto.verify(...)` APIs (Node ≥ 12). | extend `node-crypto-sign` |
| **`crypto.generateKeyPair` with options-object-only form** | The regex requires a quoted type as the first arg (`source.ts:45`); `generateKeyPair({ type: 'rsa' })`-style or variable-typed calls are missed. Lexical limitation, acceptable but worth noting. | — (inherent to lexical detection) |

**Correctly handled (not false negatives):** RSA (keygen/encrypt/PEM), ECDH
(`createECDH`, WebCrypto, `diffieHellman({})`), ECDSA (`createSign`, WebCrypto,
`elliptic`, ES* JWT), EdDSA (Ed25519/Ed448, `forge.ed25519`, `EdDSA` JWT), DH
(`createDiffieHellman`), DSA (keygen, `jsrsasign`), X25519/X448 (`low`), ECIES
(`eccrypto` dep). The **HNDL flag is set correctly** on every one of these
except the `'ec'` keygen ambiguity (C1).

---

## 5. Standards-alignment notes

- **FIPS 203 (ML-KEM).** Sizes (pk 800/1184/1568, sk 1632/2400/3168, ct
  768/1088/1568, ss 32) are **byte-exact** with Table 3 (`sizes.ts:71-117`,
  asserted in `sizes.test.ts:19`). Implicit rejection (FO transform) is modeled
  correctly (`implicit-rejection.ts`). **Gap:** no encapsulation-key
  modulus-range input check (S4), a named FIPS 203 §7.2 requirement.
- **FIPS 204 (ML-DSA).** Sizes (pk 1312/1952/2592, sk 2560/4032/4896, sig
  2420/3309/4627) are **byte-exact** with the **final** Table 2
  (`sizes.ts:96-116`). Note the sk values are the FIPS 204 *final* sizes — they
  differ from the earlier round-3 Dilithium and from some draft tables, so this
  is correctly current. Hedged-vs-deterministic signing (FIPS 204 §3.4) is
  acknowledged but untested (S3); `sigGen` correctly excluded from KAT (S7).
- **FIPS 205 (SLH-DSA).** Referenced in remediation text (`remediation.ts`,
  `mcp/tools.ts`) and offered as an alternative to ML-DSA — **correct guidance**
  ("stateless hash-based, good for long-lived roots", `tools.ts:363`). But
  **Sieve has no SLH-DSA conformance support** (S1) and `core` has no SLH-DSA
  parameter knowledge.
- **SP 800-208 (stateful hash signatures, LMS/XMSS).** **Not mentioned
  anywhere** in remediation, and Sieve cannot test them. For a complete PQC
  story, LMS/XMSS are NIST-approved (firmware/boot signing) but **stateful** —
  they warrant an explicit "use only with state management; see SP 800-208"
  caveat in remediation and are out of scope for the stateless Sieve harness.
- **SP 800-56A/B/C (classical key establishment).** The tool flags the
  *classical* DH/ECDH (56A) and RSA key transport (56B) that these supersede,
  and the hybrid `X25519MLKEM768` remediation aligns with the SP 800-56C
  key-derivation/combiner spirit (combine shared secrets). No misstatement.
- **X25519MLKEM768 hybrid.** The named hybrid in remediation
  (`remediation.ts:21,44,58`) is the IETF/TLS WG group **`X25519MLKEM768`**
  (codepoint 0x11EC) — the correct, current name (it superseded the earlier
  `x25519_kyber768`). Guidance to "wrap classical in the hybrid so confidentiality
  survives if one component breaks" is exactly the SP 800-56C combiner rationale.
  **Correct.**
- **NIST IR 8547 (PQC transition).** The tool's posture — inventory first, score
  readiness, prioritize HNDL over forgery, hybrids during transition — matches
  IR 8547's transition framing. Not cited by name in code; could be referenced.
- **CNSA 2.0 (NSA timelines).** CNSA 2.0 mandates ML-KEM-1024 and ML-DSA-87
  (Category 5) for national-security systems and sets 2030/2033 milestones.
  **The default remediation recommends ML-KEM-768 / ML-DSA-65 (Category 3).**
  This is correct for general commercial use and matches CNSA-2.0's *commercial*
  guidance, but a CNSA-2.0-regulated consumer needs the **-1024/-87** sets. The
  remediation does not surface this tier distinction.
- **BSI TR-02102.** BSI also endorses ML-KEM/ML-DSA and, notably, **FrodoKEM and
  Classic McEliece** as conservative alternatives, and recommends hybrids. The
  tool's ML-KEM-centric advice is BSI-compatible but does not mention the
  conservative alternates BSI prefers for high-assurance/long-term secrets.

---

## 6. What's required to improve

**New / improved detectors (`core`):**
1. **Fix C1 (the only real correctness bug):** make Node `'ec'` keygen either
   HNDL-conservative or dual-category; stop asserting `hndl:false` for ambiguous
   EC keygen.
2. Add the false-negative surfaces from §4 as detectors: `getDiffieHellman`
   MODP groups; PGP/GPG and DSA PEM blocks (C7); SSH `authorized_keys` public
   keys; TLS cert signature-algorithm OIDs; JOSE `ECDH-ES*` key agreement and a
   COSE/WebAuthn algorithm-identifier rule; one-shot `crypto.sign`/`crypto.verify`.
3. Make `dependencyFinding` (C5) emit multi-family remediation rather than
   `algorithms[0]` only.
4. Add `X448` to `AlgorithmFamily` (C2).

**Remediation nuance (`core/remediation.ts`, `mcp/tools.ts`):**
5. Add a **security-tier switch**: ML-KEM-768/ML-DSA-65 (Category 3, default,
   commercial) vs ML-KEM-1024/ML-DSA-87 (Category 5, CNSA 2.0 / long-lived).
6. Add an **SP 800-208 LMS/XMSS** note (stateful; firmware/boot signing only,
   with state-management warning).
7. Optionally cite **NIST IR 8547** and the **CNSA 2.0 2030/2033** timelines so
   the advice carries a deadline, and mention BSI's conservative alternates
   (FrodoKEM / Classic McEliece) for high-assurance contexts.

**Sieve ML-DSA / SLH-DSA coverage:**
8. **SLH-DSA (FIPS 205) family** (S1): 12 parameter sets, sign/verify
   self-consistency, fixed signature sizes per set, tamper checks — structurally
   identical to the `dsa` category, no vectors needed for self-consistency.
9. **ML-DSA robustness parity** (S2): empty / non-base64 / oversize probes for
   pk·msg·sig, plus a wrong-`pk` verify check.
10. **Deterministic-vs-hedged signing** (S3): repeated-sign distinctness for
    hedged mode; repeated-sign identity for deterministic mode; both verify.
11. **FIPS 203 ek modulus-range check** (S4): out-of-range-but-correct-length
    encapsulation key must be rejected by `encaps`.

**A curated ACVP vector pipeline (the highest-leverage Sieve addition):**
12. The loader (`vectors.ts`) is correct but Sieve ships *no* vectors by design.
    Provide a **documented, reproducible fetch** of the official NIST ACVP
    `gen-vals` JSON for ML-KEM (`keyGen`, `encapDecap`) and ML-DSA (`keyGen`,
    `sigVer`) — checked by hash, never committed — so users get exact-value KATs
    without the project fabricating bytes. This turns the (currently skipped)
    `kat` category from "honest abstention" into "honest verification" and is the
    only path to *exact-value* conformance. Wire seeded ML-KEM keygen (`d||z`)
    and deterministic encaps (`coins = m`) end-to-end; add SLH-DSA and ML-DSA
    `sigVer` ACVP shapes when S1/S2 land.

---

## 7. What's missing (algorithms & standards coverage)

**Algorithms not modeled at all:**
- **SLH-DSA / SPHINCS+ (FIPS 205)** — recommended in prose but no detector
  parameter knowledge and no Sieve harness.
- **LMS / XMSS / HSS (SP 800-208)** — stateful hash signatures; absent from
  remediation and untestable by the stateless harness.
- **FrodoKEM, Classic McEliece, HQC, BIKE** — conservative / round-4 KEMs (HQC
  was selected by NIST in 2025 as a code-based backup). Not in remediation as
  alternates; not in Sieve. (Reasonable to defer, but worth a roadmap note,
  especially HQC and BSI's preference for Classic McEliece.)
- **X448 / Ed448** — partially handled but mis-labeled (C2/C3).
- **ElGamal, GOST, SM2/SM9** — not handled (mostly out of typical JS scope;
  ElGamal appears inside PGP, which is itself a gap — C7).

**Standards referenced but not operationalized:**
- **CNSA 2.0 tiers** (Category 5 default for NSS) — guidance defaults to Category 3.
- **SP 800-208** — no mention.
- **NIST IR 8547 / FIPS 205 / 203 input-validation** — partly cited, partly
  (the §7.2 ek modulus check, S4) not enforced in Sieve.

**Standards correctly honored:** FIPS 203 & 204 sizes and core properties, the
HNDL/forgery split, X25519MLKEM768 naming, the SP 800-56C hybrid-combiner
rationale, and the "ship no fabricated vectors" honesty stance — these are
right and should be preserved exactly as written.

---

*This audit was performed read-only against the working tree of
`/Users/dandelionlabs/development/qproof-tools`; no source files were modified.*

The audit report has been written to `docs/audits/cryptography.md`.
