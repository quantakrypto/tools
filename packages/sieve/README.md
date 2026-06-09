# @qproof/sieve

**Conformance battery for ML-KEM (FIPS 203) and ML-DSA (FIPS 204)
implementations.** Sieve drives *any* implementation through a small
stdin/stdout JSON protocol and reports where it deviates from the standard.

Zero runtime dependencies — Node built-ins only. Node ≥ 20, ESM.

## What Sieve is (and is not)

Sieve **tests other people's implementations**. It deliberately does **not**
implement ML-KEM/ML-DSA, and it **never fabricates** cryptographic
Known-Answer-Test values. Its power comes from two honest sources:

1. **Tests that need no external vectors** — self-consistency, structural, and
   negative/robustness checks that every conforming implementation must pass.
2. **A loader for official NIST ACVP / KAT vectors you supply** — exact-value
   checks whose expected bytes come from *your* downloaded NIST files, not from
   Sieve. See [`vectors/README.md`](./vectors/README.md).

The only hard-coded cryptographic constants in Sieve are the **public,
standardized parameter sizes** (e.g. ML-KEM-768 public key = 1184 bytes). Those
are not secrets and not KAT values.

## Install

Within the `qproof-tools` monorepo it builds with the workspace:

```bash
npm install
npm run build            # tsc -b across the workspace
```

The package exposes a `sieve` bin and a programmatic API.

## How it works

Sieve spawns your implementation (the **SUT**) as a child process and exchanges
newline-delimited JSON: one request per line in, one response per line out, all
byte fields base64. Full spec: [`PROTOCOL.md`](./PROTOCOL.md).

```
sieve  ──request (NDJSON)──▶  your SUT process
       ◀─response (NDJSON)──  (ML-KEM / ML-DSA)
```

## Quick start (against the mock)

`examples/mock-sut.ts` is a **non-cryptographic** reference SUT used only to
exercise the harness. It satisfies the protocol with deterministic, correctly
sized fake bytes — **it provides no security; never use it for anything real.**

```bash
# run the full ML-KEM-768 battery against the mock
node --import tsx src/cli.ts \
  --impl "node --import tsx examples/mock-sut.ts" \
  --param ml-kem-768 --iterations 32
```

After `npm run build` the bin runs directly:

```bash
sieve --impl "node ./my-impl.js" --param ml-kem-768 --iterations 64 --json
```

## Pointing Sieve at a REAL implementation

Write a thin **adapter** that speaks the protocol and calls a vetted library.
The adapter is the SUT; Sieve never bundles a crypto implementation.

Example sketch using a Node binding (e.g. a WASM/native ML-KEM library):

```js
// my-impl.js  — adapter only; the crypto comes from a vetted dependency.
import { createInterface } from "node:readline";
import { mlKem768 } from "some-vetted-pqc-lib";   // <- you choose & audit this

const b64 = (u8) => Buffer.from(u8).toString("base64");
const un  = (s)  => new Uint8Array(Buffer.from(s, "base64"));

createInterface({ input: process.stdin }).on("line", (line) => {
  if (!line.trim()) return;
  const r = JSON.parse(line);
  const out = (o) => process.stdout.write(JSON.stringify({ id: r.id, ok: true, ...o }) + "\n");
  const err = (code, message) => process.stdout.write(JSON.stringify({ id: r.id, ok: false, code, message }) + "\n");
  try {
    if (r.op === "keygen")  { const { publicKey, secretKey } = mlKem768.keygen(); return out({ pk: b64(publicKey), sk: b64(secretKey) }); }
    if (r.op === "encaps")  { const { cipherText, sharedSecret } = mlKem768.encapsulate(un(r.pk)); return out({ ct: b64(cipherText), ss: b64(sharedSecret) }); }
    if (r.op === "decaps")  { const ss = mlKem768.decapsulate(un(r.ct), un(r.sk)); return out({ ss: b64(ss) }); }
    return err("unsupported", `op ${r.op}`);
  } catch (e) { err("error", String(e?.message ?? e)); }
});
```

Then:

```bash
sieve --impl "node ./my-impl.js" --param ml-kem-768
```

For exact-value KAT, also pass `--vectors <dir>` with official NIST files.

## CLI

```
sieve --impl "<command...>" --param <set> [options]

  --impl  "<cmd...>"   command Sieve spawns and drives (quote the whole thing)
  --param <set>        ml-kem-512 | ml-kem-768 | ml-kem-1024 |
                       ml-dsa-44  | ml-dsa-65  | ml-dsa-87
  --iterations <N>     randomized iterations (default 32)
  --vectors <dir>      official NIST ACVP vector dir for KAT (else SKIPPED)
  --timing             include the advisory decaps-timing probe
  --only <a,b,...>     run only these categories
  --timeout-ms <N>     per-request timeout (default 10000)
  --json               machine-readable report

exit: 0 = PASS, 1 = FAIL, 2 = usage error
```

## Programmatic API

```ts
import { runSieve, formatHuman } from "@qproof/sieve";

const report = await runSieve({
  command: ["node", "./my-impl.js"],
  param: "ml-kem-768",
  iterations: 64,
  // vectorsDir: "./vectors/ml-kem-768",
});
console.log(formatHuman(report));
process.exit(report.overall === "PASS" ? 0 : 1);
```

## Category catalog

| Category             | Family  | Bug class | What it checks |
|----------------------|---------|-----------|----------------|
| `correctness`        | ML-KEM  | —         | keygen→encaps(pk)→decaps(sk,ct) ⇒ `ss_encaps === ss_decaps` over N iterations. |
| `determinism`        | ML-KEM  | —         | repeated `decaps(sk, ct)` returns identical `ss`. |
| `implicit-rejection` | ML-KEM  | **AF-02** | `decaps` of a corrupted ct returns a valid-length `ss` with **no error/crash**, is deterministic, and differs from the honest `ss`. No exact-value assertions. |
| `sizes`              | ML-KEM  | **AF-05** | emitted pk/sk/ct/ss lengths match the set; wrong-length pk/ct/sk are rejected with a defined error. |
| `robustness`         | ML-KEM  | AF-05     | empty / non-base64 / oversized inputs ⇒ defined error, never crash/silent-accept. |
| `dsa`                | ML-DSA  | AF-05     | sign→verify ⇒ true; tampered message/signature ⇒ false; pk/sk/sig sizes; wrong-length verify input rejected. |
| `kat`                | both    | —         | **SKIPPED** unless `--vectors <dir>` of official ACVP files is given; then checks decaps/seeded-keygen/seeded-encaps/sigVer against those exact expected values. Never fabricated. |
| `timing`             | ML-KEM  | (AF-02)   | **ADVISORY only.** Coarse decaps timing for valid vs. invalid ct. Reports a signal but never changes the verdict — cross-process timing is noisy and not proof of (non-)constant-time behavior. |

The overall verdict is **FAIL** if any non-advisory category fails, else
**PASS**. A `skip` (e.g. KAT with no vectors) never causes a failure.

## Honest stance on KAT vectors

Sieve ships **no** test vectors. Hard-coding "expected" ciphertext or
shared-secret bytes would be both a maintenance hazard and a correctness lie if
ever mistyped. Instead:

- Self-consistency and structural categories give strong coverage with no
  external data.
- For exact-value conformance, download the **official NIST ACVP vectors** and
  pass `--vectors`. The loader (`src/vectors.ts`) parses the standard ACVP JSON.

See [`vectors/README.md`](./vectors/README.md) for sources and the file format.

## Bug classes

- **AF-02** — implicit-rejection / Fujisaki–Okamoto reject-path mistakes
  (erroring on bad ct, constant/unkeyed reject secrets, non-determinism).
- **AF-05** — size/format confusion (accepting or emitting wrong-length
  artifacts, crashing on malformed input).

## License

Apache-2.0.
