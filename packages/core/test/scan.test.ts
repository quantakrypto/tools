/**
 * End-to-end tests for the scan orchestrator: walking a temp tree, running
 * detectors + manifest scanning, honouring scope toggles and onFile progress.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import * as path from "node:path";

import { scan, VERSION } from "../src/index.js";

async function makeProject(): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), "qproof-scan-"));
  await mkdir(path.join(dir, "src"), { recursive: true });
  await writeFile(
    path.join(dir, "src", "crypto.ts"),
    [
      "import crypto from 'node:crypto';",
      "export const ecdh = crypto.createECDH('secp256k1');",
      "export function sign(p, k) { return jwt.sign(p, k, { algorithm: 'RS256' }); }",
    ].join("\n"),
  );
  await writeFile(
    path.join(dir, "id_rsa.pem"),
    "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----\n",
  );
  await writeFile(
    path.join(dir, "package.json"),
    JSON.stringify({ name: "demo", dependencies: { "node-forge": "^1", elliptic: "^6" } }, null, 2),
  );
  return dir;
}

test("scan finds source, config and dependency issues together", async () => {
  const dir = await makeProject();
  try {
    const seen: string[] = [];
    const result = await scan({ root: dir, onFile: (f) => seen.push(f) });

    assert.equal(result.toolVersion, VERSION);
    assert.ok(result.filesScanned >= 3);
    assert.ok(seen.length >= 3, "onFile called for each file");

    const rules = new Set(result.findings.map((f) => f.ruleId));
    assert.ok(rules.has("node-crypto-ecdh"), "source detector ran");
    assert.ok(rules.has("jwt-classical-alg"), "jwt detector ran");
    assert.ok(rules.has("pem-rsa-private-key"), "pem detector ran");
    assert.ok(rules.has("dep-vulnerable"), "manifest scanner ran");

    // Inventory is populated and HNDL is counted (ECDH + RSA key are HNDL).
    assert.ok(result.inventory.hndlCount >= 2);
    assert.ok(result.inventory.readinessScore < 100);

    // ISO timestamps and ordering.
    assert.ok(!Number.isNaN(Date.parse(result.startedAt)));
    assert.ok(!Number.isNaN(Date.parse(result.finishedAt)));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("dependencies:false skips manifest findings", async () => {
  const dir = await makeProject();
  try {
    const result = await scan({ root: dir, dependencies: false });
    assert.ok(!result.findings.some((f) => f.ruleId === "dep-vulnerable"));
    // source findings still present
    assert.ok(result.findings.some((f) => f.ruleId === "node-crypto-ecdh"));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("config:false skips PEM/TLS findings", async () => {
  const dir = await makeProject();
  try {
    const result = await scan({ root: dir, config: false });
    assert.ok(!result.findings.some((f) => f.ruleId.startsWith("pem-")));
    assert.ok(result.findings.some((f) => f.ruleId === "node-crypto-ecdh"));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("source:false skips inline crypto findings but keeps deps", async () => {
  const dir = await makeProject();
  try {
    const result = await scan({ root: dir, source: false });
    assert.ok(!result.findings.some((f) => f.ruleId === "node-crypto-ecdh"));
    assert.ok(result.findings.some((f) => f.ruleId === "dep-vulnerable"));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("scan supports a single-file root", async () => {
  const dir = await makeProject();
  try {
    const file = path.join(dir, "src", "crypto.ts");
    const result = await scan({ root: file });
    assert.equal(result.filesScanned, 1);
    assert.ok(result.findings.some((f) => f.ruleId === "node-crypto-ecdh"));
    assert.equal(result.findings[0].location.file, "crypto.ts");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
