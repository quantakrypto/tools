/**
 * Tests for the reporters: SARIF shape validity, JSON structure, the human
 * summary (with/without colour), and remediationFor coverage.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  toSarif,
  toJson,
  formatSummary,
  remediationFor,
  buildInventory,
  VERSION,
} from "../src/index.js";
import type { AlgorithmFamily, Finding, ScanResult } from "../src/index.js";

function sampleResult(): ScanResult {
  const findings: Finding[] = [
    {
      ruleId: "node-crypto-ecdh",
      title: "ECDH key exchange",
      category: "key-exchange",
      severity: "high",
      confidence: "high",
      algorithm: "ECDH",
      hndl: true,
      message: "ECDH is broken by Shor's algorithm.",
      remediation: "hybrid X25519MLKEM768 (ML-KEM-768)",
      location: { file: "src/a.ts", line: 12, column: 3, snippet: "crypto.createECDH('p256')" },
    },
    {
      ruleId: "pem-certificate",
      title: "X.509 certificate (PEM)",
      category: "certificate",
      severity: "low",
      confidence: "high",
      algorithm: "unknown",
      hndl: false,
      message: "Embedded X.509 certificate.",
      location: { file: "cert.pem", line: 1 },
    },
  ];
  return {
    root: ".",
    findings,
    filesScanned: 2,
    inventory: buildInventory(findings),
    startedAt: "2024-01-01T00:00:00.000Z",
    finishedAt: "2024-01-01T00:00:01.000Z",
    toolVersion: VERSION,
  };
}

test("toSarif produces a valid 2.1.0 log shape", () => {
  const log = toSarif(sampleResult());
  assert.ok(typeof log.$schema === "string" && log.$schema.length > 0);
  assert.equal(log.version, "2.1.0");
  assert.equal(log.runs.length, 1);

  const run = log.runs[0] as Record<string, any>;
  assert.equal(run.tool.driver.name, "qScan");
  assert.ok(typeof run.tool.driver.informationUri === "string");
  assert.equal(run.tool.driver.version, VERSION);
  assert.ok(Array.isArray(run.tool.driver.rules));
  // Two distinct ruleIds → two rules.
  assert.equal(run.tool.driver.rules.length, 2);

  assert.equal(run.results.length, 2);
  const first = run.results[0];
  assert.equal(first.ruleId, "node-crypto-ecdh");
  assert.equal(first.level, "error"); // high → error
  assert.ok(typeof first.message.text === "string");
  const region = first.locations[0].physicalLocation.region;
  assert.equal(first.locations[0].physicalLocation.artifactLocation.uri, "src/a.ts");
  assert.equal(region.startLine, 12);
  assert.equal(region.startColumn, 3);

  // low severity → note
  const cert = run.results.find((r: any) => r.ruleId === "pem-certificate");
  assert.equal(cert.level, "note");
});

test("toSarif level mapping covers error/warning/note", () => {
  const mk = (severity: Finding["severity"]): ScanResult => {
    const f: Finding = {
      ruleId: `r-${severity}`,
      title: "t",
      category: "signature",
      severity,
      confidence: "high",
      hndl: false,
      message: "m",
      location: { file: "a.ts", line: 1 },
    };
    return { ...sampleResult(), findings: [f], inventory: buildInventory([f]) };
  };
  const lvl = (r: ScanResult) => (toSarif(r).runs[0] as any).results[0].level;
  assert.equal(lvl(mk("critical")), "error");
  assert.equal(lvl(mk("high")), "error");
  assert.equal(lvl(mk("medium")), "warning");
  assert.equal(lvl(mk("low")), "note");
  assert.equal(lvl(mk("info")), "note");
});

test("toSarif maps CWE into rule properties, result taxa, and run taxonomies", () => {
  const f: Finding = {
    ruleId: "node-crypto-ecdh",
    title: "ECDH",
    category: "key-exchange",
    severity: "high",
    confidence: "high",
    algorithm: "ECDH",
    hndl: true,
    message: "m",
    cwe: "CWE-327",
    location: { file: "a.ts", line: 1 },
  };
  const log = toSarif({ ...sampleResult(), findings: [f], inventory: buildInventory([f]) });
  const run = log.runs[0] as Record<string, any>;

  // rules[].properties carries the CWE + security-severity.
  assert.equal(run.tool.driver.rules[0].properties.cwe, "CWE-327");
  assert.ok(run.tool.driver.rules[0].properties.tags.includes("CWE-327"));

  // results[].taxa references the CWE taxon.
  assert.equal(run.results[0].taxa[0].target.id, "CWE-327");
  assert.equal(run.results[0].properties.cwe, "CWE-327");

  // run.taxonomies declares the CWE taxonomy component.
  assert.ok(Array.isArray(run.taxonomies));
  assert.equal(run.taxonomies[0].name, "CWE");
  assert.equal(run.taxonomies[0].taxa[0].id, "CWE-327");
});

test("toSarif omits taxonomies when no finding has a CWE", () => {
  const f: Finding = {
    ruleId: "r",
    title: "t",
    category: "signature",
    severity: "low",
    confidence: "high",
    hndl: false,
    message: "m",
    location: { file: "a.ts", line: 1 },
  };
  const run = toSarif({ ...sampleResult(), findings: [f], inventory: buildInventory([f]) })
    .runs[0] as Record<string, any>;
  assert.equal(run.taxonomies, undefined);
});

test("toJson includes the cwe field", () => {
  const f: Finding = {
    ruleId: "r",
    title: "t",
    category: "signature",
    severity: "high",
    confidence: "high",
    hndl: false,
    message: "m",
    cwe: "CWE-327",
    location: { file: "a.ts", line: 1 },
  };
  const json = toJson({ ...sampleResult(), findings: [f], inventory: buildInventory([f]) });
  const findings = json.findings as Array<Record<string, unknown>>;
  assert.equal(findings[0].cwe, "CWE-327");
});

test("toJson returns a clean structured object", () => {
  const json = toJson(sampleResult());
  assert.equal(json.toolVersion, VERSION);
  assert.equal(json.filesScanned, 2);
  assert.ok(Array.isArray(json.findings));
  const inv = json.inventory as Record<string, unknown>;
  assert.ok(typeof inv.readinessScore === "number");
  // Round-trips through JSON without throwing.
  assert.doesNotThrow(() => JSON.parse(JSON.stringify(json)));
});

test("formatSummary is plain text by default and colours on request", () => {
  const plain = formatSummary(sampleResult());
  assert.ok(plain.includes("Readiness score"));
  assert.ok(plain.includes("ECDH key exchange"));
  assert.ok(!plain.includes("\x1b["), "no ANSI codes when color is off");

  const colored = formatSummary(sampleResult(), { color: true });
  assert.ok(colored.includes("\x1b["), "ANSI codes present when color is on");
});

test("formatSummary handles the clean (no findings) case", () => {
  const clean: ScanResult = { ...sampleResult(), findings: [], inventory: buildInventory([]) };
  const out = formatSummary(clean);
  assert.ok(out.includes("100/100"));
  assert.ok(/No classical asymmetric cryptography/.test(out));
});

test("redactSnippets drops every snippet from SARIF and JSON output", () => {
  const r = sampleResult(); // first finding carries a snippet.
  assert.ok(
    r.findings.some((f) => f.location.snippet),
    "fixture has at least one snippet to redact",
  );

  // SARIF: no region.snippet anywhere when redaction is on.
  const run = toSarif(r, { redactSnippets: true }).runs[0] as Record<string, any>;
  for (const res of run.results) {
    assert.equal(
      res.locations[0].physicalLocation.region.snippet,
      undefined,
      "SARIF snippet redacted",
    );
  }
  // …but present by default.
  const runDefault = toSarif(r).runs[0] as Record<string, any>;
  assert.ok(
    runDefault.results.some(
      (res: any) => res.locations[0].physicalLocation.region.snippet !== undefined,
    ),
    "snippet present without redaction",
  );

  // JSON: every finding's location.snippet is undefined when redaction is on.
  const json = toJson(r, { redactSnippets: true });
  for (const f of json.findings as Array<{ location: { snippet?: string } }>) {
    assert.equal(f.location.snippet, undefined, "JSON snippet redacted");
  }
  const jsonDefault = toJson(r);
  assert.ok(
    (jsonDefault.findings as Array<{ location: { snippet?: string } }>).some(
      (f) => f.location.snippet,
    ),
    "JSON snippet present without redaction",
  );
});

test("sensitive findings (key material) omit their snippet even with redaction off", () => {
  // A PEM private key + an SSH public key — the snippet IS the sensitive value.
  const pem: Finding = {
    ruleId: "pem-rsa-private-key",
    title: "RSA private key (PEM)",
    category: "certificate",
    severity: "critical",
    confidence: "high",
    algorithm: "RSA",
    hndl: true,
    sensitive: true,
    message: "Embedded RSA private key.",
    location: { file: "key.pem", line: 1, snippet: "-----BEGIN RSA PRIVATE KEY-----" },
  };
  const ssh: Finding = {
    ruleId: "ssh-public-key",
    title: "Classical SSH public key (ssh-rsa)",
    category: "certificate",
    severity: "low",
    confidence: "medium",
    algorithm: "RSA",
    hndl: false,
    sensitive: true,
    message: "SSH public key.",
    location: { file: "authorized_keys", line: 1, snippet: "ssh-rsa AAAAB3Nz... user@host" },
  };
  const r: ScanResult = {
    ...sampleResult(),
    findings: [pem, ssh],
    inventory: buildInventory([pem, ssh]),
  };

  // Redaction flag OFF — snippets must STILL be omitted for sensitive findings.
  const run = toSarif(r).runs[0] as Record<string, any>;
  for (const res of run.results) {
    assert.equal(
      res.locations[0].physicalLocation.region.snippet,
      undefined,
      "sensitive SARIF snippet always dropped",
    );
  }
  const json = toJson(r);
  for (const f of json.findings as Array<{ location: { snippet?: string } }>) {
    assert.equal(f.location.snippet, undefined, "sensitive JSON snippet always dropped");
  }
});

test("remediationFor covers every algorithm family", () => {
  const families: AlgorithmFamily[] = [
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
  for (const fam of families) {
    const r = remediationFor(fam);
    assert.ok(r, `remediation exists for ${fam}`);
    assert.equal(r.algorithm, fam);
    assert.ok(r.recommendation.length > 0);
    assert.ok(r.detail.length > 0);
  }
});
