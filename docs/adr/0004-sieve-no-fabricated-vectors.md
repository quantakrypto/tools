# 0004 — Sieve ships no KAT vectors and never fabricates expected values

- **Status:** Accepted
- **Date:** 2025-06-09
- **Deciders:** qproof-tools maintainers
- **Supersedes / Superseded by:** —

## Context

`@qproof/sieve` is a **conformance battery**: it drives an external ML-KEM
(FIPS 203) / ML-DSA (FIPS 204) implementation (the SUT) over an NDJSON protocol
and reports deviations. It performs **no cryptography itself**. The integrity of
a `PASS` therefore depends entirely on the provenance of what it asserts against.

Two temptations would each be a correctness lie:
1. **Hard-coding "expected" Known-Answer-Test (KAT) bytes** (ciphertexts, shared
   secrets, signatures). These would be a maintenance hazard and, if ever mistyped
   or copied from an unauthoritative source, would silently certify wrong behaviour
   or reject correct behaviour.
2. **Fabricating an expected value to "fill a gap"** when a recognized vector field
   is missing — turning a SKIP into a fake PASS.

The [COMPLIANCE.md](../COMPLIANCE.md) honesty rules and the
[cryptography audit](../audits/cryptography.md) both treat this no-fabrication
stance as a load-bearing property of the toolset's credibility.

## Decision

Sieve will **ship no cryptographic test vectors** and will **never fabricate
expected cryptographic values**. Specifically:

- The only hard-coded cryptographic constants permitted are the **public,
  standardized parameter sizes** (e.g. ML-KEM-768 public key = 1184 bytes). These
  are not secrets and not KAT values.
- Exact-value (`kat`) checks run **only** against **official NIST ACVP vectors the
  operator supplies** via `--vectors <dir>`. Without them the `kat` category is
  **SKIPPED**, never invented — and a SKIP never causes a FAIL.
- All other categories (`correctness`, `determinism`, `implicit-rejection`,
  `sizes`, `robustness`, `dsa`) assert **self-consistency, structural, and
  negative properties** that need no external secret — e.g. `encaps`→`decaps`
  round-trips, ML-KEM implicit-rejection (AF-02), size/format (AF-05).
- For randomized operations, Sieve never asserts exact bytes: ML-DSA `sign` is
  hedged, so Sieve uses ACVP **sigVer** verdicts (not sigGen) and tests
  sign/verify self-consistency separately.
- Unrecognized files/algorithms/fields are recorded as **non-fatal notes** and
  skipped.

## Consequences

**Easier:** the harness ships clean (no redistributed NIST files, no license
entanglement, no stale-vector risk); a `PASS` is honest about what it covers; the
no-fabrication stance is a defensible compliance property.

**Harder (costs accepted):** exact-value conformance requires the operator to
**obtain and supply** authentic NIST ACVP vectors; out of the box Sieve cannot
make an exact-value KAT claim. We accept this — a SKIP that the operator can
resolve with authentic inputs is correct; a fabricated PASS would not be.

**Enforcement:** the loader (`src/vectors.ts`) only normalizes recognized ACVP
fields and emits notes for the rest; `vectors/` is tracked but ships only a
README + `.gitkeep`. To make a passing `kat` run *traceable* to the exact
authentic files used, Sieve should record vector **provenance** (source URL, hash,
version) in its report — designed in
[compliance/acvp-provenance.md](../compliance/acvp-provenance.md) and tracked as
[ROADMAP COMPLIANCE #10](../ROADMAP.md). That provenance record strengthens this
ADR; it does not relax it.

## Guardrails this ADR protects (do not erode)

- Sieve is **not** a CAVP/CMVP tool; a passing Sieve run is **not** a FIPS 140-3
  result. Module validation stays a lab/CMVP process.
- Adding a new family (e.g. SLH-DSA / FIPS 205, [ROADMAP P2-8](../ROADMAP.md))
  must follow the same rule: ship no vectors, load operator-supplied ACVP only.

## Alternatives considered

- **Bundle a small set of KAT vectors for convenience.** Rejected: maintenance
  hazard, possible licensing issues, and the exact correctness-lie risk this ADR
  exists to prevent.
- **Synthesize "plausible" expected values when a field is missing.** Rejected
  outright — it converts an honest SKIP into a fabricated PASS.
