# Sieve SUT Protocol (v1)

Sieve drives a **system-under-test (SUT)** — any ML-KEM (FIPS 203), ML-DSA
(FIPS 204), or SLH-DSA (FIPS 205) implementation you provide — by spawning it as
a child process and exchanging **newline-delimited JSON** (NDJSON) over
`stdin`/`stdout`.

- **One request per line** on the SUT's `stdin`.
- **One response per line** on the SUT's `stdout`.
- All byte fields are **base64** strings.
- `stderr` is for diagnostics only; Sieve captures it but does not parse it.
- The SUT should run as a **long-lived loop**: read a line, answer it, repeat,
  until `stdin` closes.

Sieve performs **no cryptography**. It only checks the structural and
self-consistency properties of the bytes your SUT returns, plus optional
exact-value checks against **official NIST vectors you supply** (see
`vectors/README.md`). Sieve never fabricates expected cryptographic values.

## Framing

Each message is a single line of UTF-8 JSON terminated by `\n`. Implementations
MUST NOT emit embedded newlines inside a JSON message and MUST flush each
response line promptly (Sieve uses a per-request timeout).

## Request fields

Every request has:

| field    | type   | notes                                            |
|----------|--------|--------------------------------------------------|
| `id`     | int    | correlation id; echo it back unchanged           |
| `family` | string | `"ml-kem"`, `"ml-dsa"`, or `"slh-dsa"`           |
| `param`  | string | e.g. `"ml-kem-768"`, `"ml-dsa-65"`, `"slh-dsa-sha2-128f"` |
| `op`     | string | `keygen` / `encaps` / `decaps` / `sign` / `verify` |

`encaps` / `decaps` apply to `ml-kem`; `sign` / `verify` apply to `ml-dsa` and
`slh-dsa`; `keygen` applies to all three.

### ML-KEM operations

```jsonc
// keygen — seed is OPTIONAL; when present, keygen MUST be deterministic.
{ "id": 1, "family": "ml-kem", "param": "ml-kem-768", "op": "keygen", "seed"?: "<b64>" }
// -> { "id": 1, "ok": true, "pk": "<b64>", "sk": "<b64>" }

// encaps — coins is OPTIONAL; when present, encaps MUST be deterministic.
{ "id": 2, "family": "ml-kem", "param": "ml-kem-768", "op": "encaps", "pk": "<b64>", "coins"?: "<b64>" }
// -> { "id": 2, "ok": true, "ct": "<b64>", "ss": "<b64>" }

// decaps — MUST be deterministic; MUST implicitly reject bad ct (see below).
{ "id": 3, "family": "ml-kem", "param": "ml-kem-768", "op": "decaps", "sk": "<b64>", "ct": "<b64>" }
// -> { "id": 3, "ok": true, "ss": "<b64>" }
```

### ML-DSA operations

```jsonc
{ "id": 4, "family": "ml-dsa", "param": "ml-dsa-65", "op": "keygen", "seed"?: "<b64>" }
// -> { "id": 4, "ok": true, "pk": "<b64>", "sk": "<b64>" }

{ "id": 5, "family": "ml-dsa", "param": "ml-dsa-65", "op": "sign", "sk": "<b64>", "msg": "<b64>" }
// -> { "id": 5, "ok": true, "sig": "<b64>" }   // signing MAY be randomized

{ "id": 6, "family": "ml-dsa", "param": "ml-dsa-65", "op": "verify", "pk": "<b64>", "msg": "<b64>", "sig": "<b64>" }
// -> { "id": 6, "ok": true, "valid": true }    // verdict, not an error
```

### SLH-DSA operations (FIPS 205)

SLH-DSA uses the **same** `keygen` / `sign` / `verify` shapes as ML-DSA; only
`family` and `param` differ. Parameter sets:
`slh-dsa-{sha2,shake}-{128,192,256}{s,f}` (12 sets). Like ML-DSA, signing MAY be
randomized (hedged) or deterministic — both conform; Sieve detects which but
never asserts exact signature bytes from self-consistency tests.

```jsonc
{ "id": 7, "family": "slh-dsa", "param": "slh-dsa-sha2-128f", "op": "keygen" }
// -> { "id": 7, "ok": true, "pk": "<b64>", "sk": "<b64>" }

{ "id": 8, "family": "slh-dsa", "param": "slh-dsa-sha2-128f", "op": "sign", "sk": "<b64>", "msg": "<b64>" }
// -> { "id": 8, "ok": true, "sig": "<b64>" }

{ "id": 9, "family": "slh-dsa", "param": "slh-dsa-sha2-128f", "op": "verify", "pk": "<b64>", "msg": "<b64>", "sig": "<b64>" }
// -> { "id": 9, "ok": true, "valid": true }
```

> **Out of scope:** SP 800-208 stateful hash signatures (LMS / XMSS / HSS) are
> not supported — their one-time-key state management cannot be modeled by a
> stateless request/response harness. See the README "Algorithm scope".

## Response shapes

A response is one of:

| `ok`    | extra fields        | meaning              |
|---------|---------------------|----------------------|
| `true`  | `pk`, `sk`          | keygen result        |
| `true`  | `ct`, `ss`          | encaps result        |
| `true`  | `ss`                | decaps result        |
| `true`  | `sig`               | sign result          |
| `true`  | `valid` (bool)      | verify verdict       |
| `false` | `code`, `message`   | defined error        |

Every response MUST include the matching `id` and a boolean `ok`.

### Errors

When the SUT cannot or will not honor a request — e.g. a wrong-length key, a
malformed input, or an unsupported parameter set — it MUST return a **defined
error**:

```json
{ "id": 7, "ok": false, "code": "invalid-length", "message": "pk must be 1184 bytes" }
```

It MUST NOT crash, hang, or silently return a normal-looking but bogus result.
Sieve's `sizes` and `robustness` categories treat a clean error as the
**correct** outcome for bad input, and treat a crash or silent acceptance as a
failure.

## Critical semantic: ML-KEM implicit rejection

`verify`-style failure signaling is **forbidden** for ML-KEM `decaps`. Per the
Fujisaki–Okamoto transform, when `decaps` receives a ciphertext that does not
re-encrypt to itself, it MUST:

1. **Return `ok: true` with an `ss`** — never an `error`, never a crash.
2. Return a shared secret of the **correct length**.
3. Be **deterministic** for the same `(sk, ct)`.
4. Return a value **derived from the secret key** (so it differs from the honest
   shared secret and is unpredictable to an attacker).

A wrong-length or otherwise malformed `ct` is different: that is a framing error
and SHOULD be rejected with a defined `error`. The distinction:

- **valid-length but cryptographically invalid `ct`** → implicit rejection
  (return a keyed pseudo-random `ss`).
- **wrong-length / unparseable `ct`** → defined `error`.

The `implicit-rejection` category (bug class **AF-02**) checks properties 1–4
without asserting the exact rejection value.

## Determinism expectations

- `decaps(sk, ct)` is a pure function — identical inputs give identical `ss`.
- `keygen` with a `seed` and `encaps` with `coins` must be reproducible; without
  them they may use fresh randomness.
- `sign` may be randomized (ML-DSA / SLH-DSA hedged mode) or deterministic; both
  conform. Sieve detects which (an **advisory** probe) but never asserts exact
  signature bytes from self-consistency tests.

## ML-KEM encapsulation-key validation (FIPS 203 §7.2)

`encaps` MUST perform the §7.2 **modulus check** on the encapsulation key `ek`:
the packed `t̂` coefficients must each be `< q` (3329), i.e. `ek` must round-trip
through `ByteEncode₁₂`/`ByteDecode₁₂`. A correctly-**sized** `ek` whose
coefficients are not reduced mod q MUST be rejected with a defined `error` — not
accepted. (A wrong-**length** `ek` is also rejected, as a framing error.) Sieve's
`sizes` category probes this with a same-length-but-out-of-range `ek`.

## Versioning

This is protocol version **1** (`PROTOCOL_VERSION`). Breaking wire changes bump
the number. A SUT may ignore the version; Sieve includes it in reports.

## Minimal SUT skeleton (Node)

```js
import { createInterface } from "node:readline";
const rl = createInterface({ input: process.stdin });
rl.on("line", (line) => {
  if (!line.trim()) return;
  const req = JSON.parse(line);
  try {
    const res = handle(req);              // your ML-KEM/ML-DSA calls
    process.stdout.write(JSON.stringify({ id: req.id, ok: true, ...res }) + "\n");
  } catch (e) {
    process.stdout.write(JSON.stringify({
      id: req.id, ok: false, code: e.code ?? "error", message: String(e.message ?? e),
    }) + "\n");
  }
});
```

A non-cryptographic reference implementation of this protocol (for exercising
the harness, **not** for security) is in `examples/mock-sut.ts`.
