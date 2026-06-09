/**
 * Deterministic fuzz targets for core's hand-rolled parsers (ROADMAP P1-10):
 *   - `scanManifest` (dependency/manifest JSON parsing) on random JSON and
 *     malformed package.json / package-lock.json,
 *   - `toSarif` on randomly-generated findings.
 *
 * The contract under test is "no crash; either a valid typed result or a
 * defined error — never an unhandled throw of the wrong type". Seeds are fixed
 * (see _fuzz.ts) so any failure reproduces exactly.
 */
import assert from "node:assert/strict";
import { test } from "node:test";

import { scanManifest } from "../src/dependencies.js";
import { toSarif } from "../src/report.js";
import { buildInventory } from "../src/inventory.js";
import type {
  AlgorithmFamily,
  Confidence,
  Finding,
  FindingCategory,
  ScanResult,
  Severity,
} from "../src/types.js";
import { FUZZ_ITERATIONS, makeRng, randomJsonValue } from "./_fuzz.js";
import type { Rng } from "./_fuzz.js";

/* -------------------------------------------------------------------------- */
/* scanManifest                                                                */
/* -------------------------------------------------------------------------- */

const KNOWN_VULN = ["node-forge", "elliptic", "jsonwebtoken", "@noble/curves", "secp256k1"];

/** Build a (sometimes valid, sometimes broken) manifest string. */
function randomManifest(rng: Rng): string {
  const kind = rng.int(0, 5);
  switch (kind) {
    case 0:
      // Random JSON value serialized — exercises the "not an object" + key paths.
      return JSON.stringify(randomJsonValue(rng));
    case 1: {
      // A structurally-plausible package.json with random + known deps.
      const deps: Record<string, string> = {};
      const n = rng.int(0, 6);
      for (let i = 0; i < n; i++) {
        const name = rng.bool(0.4) ? rng.pick(KNOWN_VULN) : rng.asciiString(rng.int(1, 10));
        deps[name] = `^${rng.int(0, 9)}.${rng.int(0, 9)}.${rng.int(0, 9)}`;
      }
      return JSON.stringify({ name: rng.asciiString(5), dependencies: deps });
    }
    case 2: {
      // package-lock-ish packages map with node_modules/<name> keys.
      const packages: Record<string, unknown> = { "": { name: "root" } };
      const n = rng.int(0, 6);
      for (let i = 0; i < n; i++) {
        const name = rng.bool(0.4) ? rng.pick(KNOWN_VULN) : rng.asciiString(rng.int(1, 10));
        packages[`node_modules/${name}`] = { version: `${rng.int(0, 9)}.0.0` };
      }
      return JSON.stringify({ lockfileVersion: 3, packages });
    }
    case 3:
      // Truncated / malformed JSON — must be swallowed (returns []).
      return "{ " + rng.asciiString(rng.int(0, 30));
    case 4:
      // Random raw garbage bytes as a string.
      return rng.string(rng.int(0, 60));
    default:
      // Deeply nested random JSON object.
      return JSON.stringify(randomJsonValue(rng, 0));
  }
}

test("fuzz: scanManifest never throws and returns well-typed findings", () => {
  const rng = makeRng(0x5ca1ab1e);
  const fileNames = ["package.json", "package-lock.json", "nested/package.json"];
  for (let i = 0; i < FUZZ_ITERATIONS; i++) {
    const content = randomManifest(rng);
    const file = rng.pick(fileNames);
    let findings: Finding[];
    try {
      findings = scanManifest(file, content);
    } catch (err) {
      assert.fail(`scanManifest threw on iteration ${i}: ${String(err)}\ninput: ${content}`);
    }
    assert.ok(Array.isArray(findings), "findings must be an array");
    for (const f of findings) {
      assert.equal(typeof f.ruleId, "string");
      assert.equal(f.ruleId, "dep-vulnerable");
      assert.equal(f.category, "dependency");
      assert.equal(typeof f.message, "string");
      assert.equal(typeof f.location.file, "string");
      assert.equal(typeof f.location.line, "number");
      assert.ok(f.location.line >= 1);
      assert.equal(typeof f.hndl, "boolean");
    }
    // Deterministic ordering invariant: titles are sorted ascending.
    for (let k = 1; k < findings.length; k++) {
      assert.ok((findings[k - 1] as Finding).title <= (findings[k] as Finding).title);
    }
  }
});

/* -------------------------------------------------------------------------- */
/* toSarif                                                                     */
/* -------------------------------------------------------------------------- */

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
const CONFIDENCES: Confidence[] = ["high", "medium", "low"];
const CATEGORIES: FindingCategory[] = [
  "kem",
  "key-exchange",
  "signature",
  "tls",
  "certificate",
  "dependency",
  "hash",
  "rng",
];
const ALGORITHMS: AlgorithmFamily[] = [
  "RSA",
  "ECDH",
  "ECDSA",
  "EdDSA",
  "DH",
  "DSA",
  "X25519",
  "X448",
  "ECIES",
  "unknown",
];

/** Build a random-but-valid Finding (fields drawn from the locked enums). */
function randomFinding(rng: Rng): Finding {
  const f: Finding = {
    ruleId: rng.pick([
      "rsa-keygen",
      "ecdh-usage",
      "dep-vulnerable",
      rng.asciiString(rng.int(1, 8)),
    ]),
    title: rng.asciiString(rng.int(0, 20)),
    category: rng.pick(CATEGORIES),
    severity: rng.pick(SEVERITIES),
    confidence: rng.pick(CONFIDENCES),
    hndl: rng.bool(),
    message: rng.string(rng.int(0, 30)), // may contain control/non-ASCII chars
    location: {
      file: rng.asciiString(rng.int(0, 15)) + ".ts",
      line: rng.int(1, 5000),
    },
  };
  if (rng.bool()) f.algorithm = rng.pick(ALGORITHMS);
  if (rng.bool()) f.remediation = rng.asciiString(rng.int(0, 25));
  if (rng.bool(0.3)) f.cwe = `CWE-${rng.int(1, 999)}`;
  if (rng.bool()) f.location.column = rng.int(1, 200);
  if (rng.bool(0.3)) f.location.endLine = f.location.line + rng.int(0, 10);
  if (rng.bool()) f.location.snippet = rng.string(rng.int(0, 40));
  return f;
}

function resultOf(findings: Finding[]): ScanResult {
  return {
    root: ".",
    findings,
    filesScanned: findings.length,
    inventory: buildInventory(findings),
    startedAt: "2024-01-01T00:00:00.000Z",
    finishedAt: "2024-01-01T00:00:01.000Z",
    toolVersion: "0.1.0",
  };
}

test("fuzz: toSarif produces structurally valid SARIF for random findings", () => {
  const rng = makeRng(0x0ddba11);
  for (let i = 0; i < FUZZ_ITERATIONS; i++) {
    const findings: Finding[] = [];
    const n = rng.int(0, 8);
    for (let k = 0; k < n; k++) findings.push(randomFinding(rng));

    let sarif: ReturnType<typeof toSarif>;
    try {
      sarif = toSarif(resultOf(findings));
    } catch (err) {
      assert.fail(`toSarif threw on iteration ${i}: ${String(err)}`);
    }

    // Top-level shape.
    assert.equal(sarif.version, "2.1.0");
    assert.equal(typeof sarif.$schema, "string");
    assert.ok(Array.isArray(sarif.runs));
    assert.equal(sarif.runs.length, 1);

    const run = sarif.runs[0] as Record<string, unknown>;
    const tool = run.tool as { driver: { name: string; rules: unknown[] } };
    assert.equal(tool.driver.name, "qScan");
    assert.ok(Array.isArray(tool.driver.rules));

    const results = run.results as Array<Record<string, unknown>>;
    assert.ok(Array.isArray(results));
    assert.equal(results.length, findings.length);

    for (const r of results) {
      assert.equal(typeof r.ruleId, "string");
      assert.ok(["error", "warning", "note"].includes(r.level as string));
      const msg = r.message as { text: string };
      assert.equal(typeof msg.text, "string");
      const locs = r.locations as Array<{ physicalLocation: { artifactLocation: unknown } }>;
      assert.ok(Array.isArray(locs) && locs.length === 1);
      assert.ok(locs[0]?.physicalLocation);
    }

    // The whole thing must JSON-serialize (no circular refs / undefined holes).
    assert.doesNotThrow(() => JSON.stringify(sarif));
  }
});
