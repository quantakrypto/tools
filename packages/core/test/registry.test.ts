/**
 * Tests for the DetectorRegistry plugin point and the default registry.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { DetectorRegistry, defaultRegistry, detectorScope, detectors } from "../src/index.js";
import type { Detector } from "../src/index.js";

const fakeDetector: Detector = {
  id: "fake-detector",
  description: "test",
  scope: "source",
  language: "js",
  appliesTo: () => true,
  detect: () => [],
};

test("defaultRegistry contains the built-in detectors", () => {
  const ids = new Set(defaultRegistry.all().map((d) => d.id));
  for (const id of [
    "node-crypto",
    "webcrypto",
    "crypto-libs",
    "jwt-jose",
    "tls-config",
    "pem-material",
  ]) {
    assert.ok(ids.has(id), `default registry has ${id}`);
  }
  // The exported `detectors` array stays in sync with the registry.
  assert.deepEqual(
    defaultRegistry.all().map((d) => d.id),
    detectors.map((d) => d.id),
  );
});

test("register / get / has / all preserve order and uniqueness", () => {
  const r = new DetectorRegistry();
  r.register(fakeDetector);
  assert.equal(r.get("fake-detector"), fakeDetector);
  assert.ok(r.has("fake-detector"));
  assert.deepEqual(
    r.all().map((d) => d.id),
    ["fake-detector"],
  );
  assert.throws(() => r.register(fakeDetector), /duplicate detector id/);
});

test("detectorScope defaults to source when undeclared", () => {
  const noScope: Detector = { id: "x", description: "", appliesTo: () => true, detect: () => [] };
  assert.equal(detectorScope(noScope), "source");
  assert.equal(detectorScope({ ...noScope, scope: "config" }), "config");
});

test("clone produces an independent registry seeded with the same detectors", () => {
  const clone = defaultRegistry.clone();
  clone.register(fakeDetector);
  assert.ok(clone.has("fake-detector"));
  assert.ok(!defaultRegistry.has("fake-detector"), "original unchanged");
});

test("config-scope detectors are declared, not prefix-inferred", () => {
  const byId = new Map(defaultRegistry.all().map((d) => [d.id, d]));
  assert.equal(detectorScope(byId.get("pem-material")!), "config");
  assert.equal(detectorScope(byId.get("tls-config")!), "config");
  assert.equal(detectorScope(byId.get("ssh-cert")!), "config");
  assert.equal(detectorScope(byId.get("node-crypto")!), "source");
});
