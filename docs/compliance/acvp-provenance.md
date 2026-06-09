# Sieve — ACVP Vector Provenance Design

**Status: DESIGN ONLY.** This document designs how `@qproof/sieve` should record
the **provenance** of any official NIST ACVP test vectors an operator supplies, so
a passing `kat` (Known-Answer-Test) run is **traceable to authentic NIST inputs**.
It is the design for [ROADMAP COMPLIANCE #10 / P2-8](../ROADMAP.md); nothing here is
implemented.

It exists to strengthen — never relax —
[ADR-0004](../adr/0004-sieve-no-fabricated-vectors.md): Sieve ships no vectors and
never fabricates expected values. Provenance recording makes the *operator-supplied*
inputs attributable; it does not turn Sieve into a vector source.

## 1. Problem

Today, exact-value conformance runs **only** when the operator passes
`--vectors <dir>` of official NIST ACVP files
([`vectors/README.md`](../../packages/sieve/vectors/README.md)); otherwise the
`kat` category is SKIPPED. But the report does **not** record *which* files, from
*where*, at *what version*, drove a passing `kat` run. So a `PASS` is honest about
*what was asserted* but not *traceable to the authentic source* — a gap for anyone
who wants to reproduce or trust the result (the `Repudiation` row in the
[threat model](../THREAT-MODEL.md#45-qproofsieve-drives-an-untrusted-sut-with-full-harness-privileges)).

## 2. What to record (per vector file)

For every ACVP file Sieve loads and uses, capture a provenance record:

| Field | Meaning | How obtained |
|---|---|---|
| `path` | The local file path as given to `--vectors`. | from the loader |
| `sha256` | Hash of the **raw file bytes**, before parsing. | `node:crypto` over the file |
| `sizeBytes` | File size. | `fs.stat` |
| `algorithm` / `mode` | ACVP `algorithm` (`ML-KEM`/`ML-DSA`) and `mode` (`encapDecap`/`keyGen`/`sigVer`). | parsed from the JSON |
| `parameterSet` | e.g. `ML-KEM-768`; only files matching `--param` are used. | parsed |
| `acvpVersion` / `revision` | ACVP/vector-set version fields present in the file (`vsId`, `revision`, `algorithm` version), if any. | parsed, best-effort |
| `sourceUrl` | Authoritative origin (operator-declared; see §3). | operator input |
| `casesUsed` | Count of test cases actually consumed (recognized) vs. noted/skipped. | from the loader's normalization |

The hash is over the **bytes as supplied**, so the record proves *exactly* which
file content was used, independent of how Sieve parsed it.

## 3. Declaring the source URL

Sieve cannot *prove* a file came from NIST — it can only record what the operator
declares plus the content hash. Design:
- Accept an optional **`--vectors-manifest <file>`** (or sidecar `*.provenance.json`
  next to each vector) where the operator states the `sourceUrl` and, ideally, an
  upstream-published hash to compare against.
- If a manifest is absent, record `sourceUrl: "unknown (operator-supplied)"` and
  set a report flag `provenanceDeclared: false`. A `kat` PASS with
  `provenanceDeclared: false` is still a PASS, but the report **says so**, so a
  consumer can decide whether to trust it.
- Recommend (in docs) the authoritative sources already listed in the vectors
  README: the NIST `usnistgov/ACVP-Server` repo (`gen-val/json-files/`), ACVTS, and
  the CAVP program pages. Sieve does not fetch them — it records what it was given.

## 4. Where it lands in the report

Add a `provenance` block to the Sieve report (both JSON and the human render),
scoped to the `kat` category:

```jsonc
{
  "param": "ml-kem-768",
  "overall": "PASS",
  "categories": [ /* … */ {
    "name": "kat",
    "status": "pass",
    "provenance": {
      "provenanceDeclared": true,
      "vectorFiles": [
        {
          "path": "vectors/ML-KEM-encapDecap-FIPS203/internalProjection.json",
          "sha256": "…",
          "sizeBytes": 482113,
          "algorithm": "ML-KEM", "mode": "encapDecap",
          "parameterSet": "ML-KEM-768",
          "acvpVersion": "1.0", "revision": "FIPS203",
          "sourceUrl": "https://github.com/usnistgov/ACVP-Server/…",
          "casesUsed": 75
        }
      ]
    }
  } ]
}
```

When `--vectors` is absent and `kat` is SKIPPED, the `provenance` block is omitted
(there is nothing to attribute) — consistent with never inventing a value.

## 5. Interaction with the A.8.24 evidence report

When a Sieve report is bundled into the
[A.8.24 readiness evidence](iso27001-a8.24-evidence.md), this `provenance` block is
what makes a conformance claim *reproducible and attributable*: the signed report
then carries the exact vector hashes + declared sources behind any `kat` PASS.

## 6. Limits

- **Provenance ≠ authenticity proof.** A content hash + a declared URL show *what*
  was used and let a third party re-verify against the upstream; they do not
  cryptographically prove NIST authorship absent a NIST-published signature/hash to
  compare against. The design surfaces this via `provenanceDeclared`.
- **No vectors are shipped or fetched.** Sieve records provenance of operator-
  supplied files only ([ADR-0004](../adr/0004-sieve-no-fabricated-vectors.md)).
- **Still not CAVP/CMVP.** A traceable `kat` PASS is a stronger pre-screen result;
  it is not a FIPS 140-3 validation.
