import { test } from "node:test";
import assert from "node:assert/strict";

import {
  decodeResponse,
  encodeRequest,
  ProtocolError,
  PROTOCOL_VERSION,
  toB64,
  fromB64,
} from "../src/protocol.js";

test("PROTOCOL_VERSION is 1", () => {
  assert.equal(PROTOCOL_VERSION, 1);
});

test("encodeRequest emits one NDJSON line", () => {
  const line = encodeRequest({ id: 5, family: "ml-kem", param: "ml-kem-768", op: "keygen" });
  assert.ok(line.endsWith("\n"));
  assert.equal(line.indexOf("\n"), line.length - 1);
  const parsed = JSON.parse(line);
  assert.equal(parsed.id, 5);
  assert.equal(parsed.op, "keygen");
});

test("decodeResponse parses keygen ok", () => {
  const r = decodeResponse('{"id":1,"ok":true,"pk":"AA==","sk":"AQ=="}');
  assert.equal(r.ok, true);
  assert.ok(r.ok && "pk" in r && r.pk === "AA==");
  assert.ok(r.ok && "sk" in r && r.sk === "AQ==");
});

test("decodeResponse parses encaps, decaps, sign, verify, error", () => {
  const enc = decodeResponse('{"id":1,"ok":true,"ct":"AA==","ss":"AQ=="}');
  assert.ok(enc.ok && "ct" in enc && "ss" in enc);

  const dec = decodeResponse('{"id":2,"ok":true,"ss":"AQ=="}');
  assert.ok(dec.ok && "ss" in dec && !("ct" in dec));

  const sig = decodeResponse('{"id":3,"ok":true,"sig":"AA=="}');
  assert.ok(sig.ok && "sig" in sig);

  const ver = decodeResponse('{"id":4,"ok":true,"valid":false}');
  assert.ok(ver.ok && "valid" in ver && ver.valid === false);

  const err = decodeResponse('{"id":5,"ok":false,"code":"bad","message":"nope"}');
  assert.equal(err.ok, false);
  assert.ok(!err.ok && err.code === "bad" && err.message === "nope");
});

test("decodeResponse rejects malformed lines", () => {
  assert.throws(() => decodeResponse(""), ProtocolError);
  assert.throws(() => decodeResponse("not json"), ProtocolError);
  assert.throws(() => decodeResponse("[1,2,3]"), ProtocolError);
  assert.throws(() => decodeResponse('{"ok":true}'), ProtocolError); // no id
  assert.throws(() => decodeResponse('{"id":1}'), ProtocolError); // no ok
  assert.throws(() => decodeResponse('{"id":1,"ok":false}'), ProtocolError); // error w/o code
  assert.throws(() => decodeResponse('{"id":1,"ok":true}'), ProtocolError); // no payload
});

test("base64 round-trips", () => {
  const bytes = new Uint8Array([0, 1, 2, 254, 255]);
  assert.deepEqual([...fromB64(toB64(bytes))], [...bytes]);
});

test("fromB64 rejects non-base64", () => {
  assert.throws(() => fromB64("!!!not base64!!!"), ProtocolError);
});
