# Official KAT / ACVP vectors

**Sieve ships no cryptographic test vectors.** This directory is where *you*
place official NIST vector files so the `kat` category can run exact-value
checks. Without `--vectors <dir>`, the `kat` category is **SKIPPED** — Sieve
will not invent expected values.

## Where to get them

Use the **NIST ACVP (Automated Cryptographic Validation Protocol) test
vectors**, which cover ML-KEM (FIPS 203) and ML-DSA (FIPS 204):

- **ACVP test vectors (recommended):**
  <https://github.com/usnistgov/ACVP-Server> — under
  `gen-val/json-files/`, e.g. `ML-KEM-encapDecap-FIPS203/`,
  `ML-KEM-keyGen-FIPS203/`, `ML-DSA-sigVer-FIPS204/`,
  `ML-DSA-keyGen-FIPS204/`. Each folder contains an
  `internalProjection.json` / `prompt.json` / `expectedResults.json` set.
- **ACVTS demo / production** servers publish the same format.
- The **CAVP** program pages link to the current vector packages:
  <https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program>.

Always verify you downloaded vectors from an authoritative NIST source. Do not
trust vectors of unknown provenance for conformance claims.

## How to use them

1. Download the relevant ACVP JSON files for your parameter set.
2. Drop the `*.json` files into a directory (this one, or any path).
3. Run Sieve with `--vectors`:

   ```bash
   sieve --impl "node ./my-impl.js" --param ml-kem-768 --vectors ./vectors
   ```

Only vectors whose `parameterSet` matches `--param` are used; the rest are
ignored (and noted).

## Expected file format

The loader (`src/vectors.ts`) parses the **standard NIST ACVP test-vector
JSON**. The relevant shape is:

```jsonc
{
  "algorithm": "ML-KEM",          // or "ML-DSA"
  "mode": "encapDecap",           // or "keyGen", "sigVer", ...
  "testGroups": [
    {
      "parameterSet": "ML-KEM-768",
      "function": "decapsulation", // for encapDecap groups
      "tests": [
        { "dk": "<hex>", "c": "<hex>", "k": "<hex>" }   // sk, ct, ss
      ]
    }
  ]
}
```

Bytes are **hex** strings in ACVP. The loader normalizes the fields it
recognizes into typed cases:

| ACVP `mode` / fields                | Sieve check        | What is asserted |
|-------------------------------------|--------------------|------------------|
| `keyGen` with `d`+`z` (or `seed`), `ek`, `dk` | `kem-keygen` | seeded keygen reproduces `pk`/`sk` (skipped if the SUT can't seed) |
| `encapDecap` (encapsulation), `ek`, `m`, `c`, `k` | `kem-encap` | with `coins=m`, deterministic encaps reproduces `ct`/`ss` (skipped if no coins support) |
| `encapDecap` (decapsulation), `dk`, `c`, `k` | `kem-decap` | `decaps(sk, ct)` equals expected `ss` |
| `sigVer`, `pk`, `message`, `signature`, `testPassed` | `dsa-verify` | `verify(pk, msg, sig)` equals `testPassed` |

> **Note on ML-DSA signing.** ML-DSA `sign` is randomized (hedged), so signature
> bytes are not reproducible without the exact private randomness. Sieve
> therefore uses ACVP **sigVer** vectors (verification verdicts) for ML-DSA KAT,
> not sigGen, and exercises sign/verify self-consistency separately in the `dsa`
> category.

Unrecognized files, algorithms, or fields are recorded as non-fatal notes and
skipped — Sieve never fabricates a value to fill a gap.

## `.gitkeep`

This directory is intentionally tracked (so `files` in `package.json` can ship
this README) but contains no vectors. Add your own; do not commit
redistributed NIST files unless their license permits it.
