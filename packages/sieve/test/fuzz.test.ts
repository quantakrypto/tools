/**
 * Deterministic fuzz targets for Sieve's hand-rolled parsers (ROADMAP P1-10):
 *   - `decodeResponse` on random/garbage NDJSON lines,
 *   - `fromB64` on random/garbage base64 strings.
 *
 * Contract: a malformed input must surface as a {@link ProtocolError} (a
 * defined, typed error), never an unhandled throw of another type and never a
 * crash. A well-formed input must round-trip into a typed {@link Response}.
 * Seeds are fixed (_fuzz.ts) so failures reproduce.
 */
import assert from "node:assert/strict";
import { test } from "node:test";

import { decodeResponse, fromB64, toB64, ProtocolError } from "../src/protocol.js";
import { FUZZ_ITERATIONS, makeRng } from "./_fuzz.js";
import type { Rng } from "./_fuzz.js";

/** Generate a candidate response line: sometimes valid, mostly garbage. */
function randomLine(rng: Rng): string {
  const kind = rng.int(0, 6);
  switch (kind) {
    case 0:
      return ""; // empty line
    case 1:
      return rng.string(rng.int(0, 80)); // raw garbage (may include control chars)
    case 2:
      return "{ " + rng.asciiString(rng.int(0, 40)); // truncated JSON
    case 3:
      // A JSON object missing/mistyping required fields.
      return JSON.stringify({
        id: rng.bool() ? rng.int(0, 100) : rng.asciiString(3),
        ok: rng.bool() ? rng.bool() : rng.asciiString(2),
        [rng.asciiString(3)]: rng.asciiString(5),
      });
    case 4:
      // A valid-looking error response.
      return JSON.stringify({
        id: rng.int(0, 100),
        ok: false,
        code: rng.asciiString(rng.int(0, 8)),
        message: rng.asciiString(rng.int(0, 20)),
      });
    case 5:
      // A valid-looking keygen success.
      return JSON.stringify({
        id: rng.int(0, 100),
        ok: true,
        pk: toB64(rng.bytes(rng.int(0, 16))),
        sk: toB64(rng.bytes(rng.int(0, 16))),
      });
    default:
      // A JSON primitive / array (not an object).
      return JSON.stringify(rng.bool() ? rng.int(-100, 100) : [1, 2, 3]);
  }
}

test("fuzz: decodeResponse never crashes — valid Response or ProtocolError", () => {
  const rng = makeRng(0x51e5e000);
  for (let i = 0; i < FUZZ_ITERATIONS; i++) {
    const line = randomLine(rng);
    try {
      const res = decodeResponse(line);
      // A returned value must be a structurally valid Response.
      assert.equal(typeof res.id, "number");
      assert.equal(typeof res.ok, "boolean");
      if (res.ok === false) {
        assert.equal(typeof res.code, "string");
        assert.equal(typeof res.message, "string");
      }
    } catch (err) {
      // The only acceptable throw is a typed ProtocolError.
      assert.ok(
        err instanceof ProtocolError,
        `decodeResponse threw a non-ProtocolError on iteration ${i}: ${String(err)}\nline: ${JSON.stringify(line)}`,
      );
    }
  }
});

/** Generate a candidate base64 string: sometimes valid, mostly garbage. */
function randomB64(rng: Rng): string {
  const kind = rng.int(0, 4);
  switch (kind) {
    case 0:
      return toB64(rng.bytes(rng.int(0, 32))); // canonical, valid
    case 1:
      return rng.string(rng.int(0, 60)); // arbitrary unicode garbage
    case 2: {
      // base64 alphabet but a deliberately wrong/odd length (invalid padding).
      const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
      let s = "";
      const n = rng.int(0, 20);
      for (let i = 0; i < n; i++) s += alphabet[rng.int(0, alphabet.length - 1)];
      return s + (rng.bool() ? "=" : ""); // sometimes add a stray pad
    }
    case 3:
      return rng.asciiString(rng.int(0, 40)); // printable ASCII, likely non-canonical
    default:
      return "===" + rng.asciiString(rng.int(0, 10)); // leading padding
  }
}

test("fuzz: fromB64 either decodes or throws ProtocolError (never crashes)", () => {
  const rng = makeRng(0x0b64f00d);
  for (let i = 0; i < FUZZ_ITERATIONS; i++) {
    const b64 = randomB64(rng);
    try {
      const bytes = fromB64(b64);
      assert.ok(bytes instanceof Uint8Array);
    } catch (err) {
      assert.ok(
        err instanceof ProtocolError,
        `fromB64 threw a non-ProtocolError on iteration ${i}: ${String(err)}\ninput: ${JSON.stringify(b64)}`,
      );
    }
  }
});

test("fuzz: valid round-trip — toB64∘bytes always decodes back equal", () => {
  const rng = makeRng(0xcafebabe);
  for (let i = 0; i < 1000; i++) {
    const bytes = rng.bytes(rng.int(0, 48));
    const decoded = fromB64(toB64(bytes));
    assert.deepEqual([...decoded], [...bytes]);
  }
});
