/**
 * Shared test helpers: factories for findings / scan results, and a tiny
 * pattern-based fake scanner used by the end-to-end tests.
 *
 * These exist so each test file does not re-derive the (verbose) core types.
 */

import { readdir, readFile, stat } from "node:fs/promises";
import { join, relative, sep } from "node:path";

import type {
  CryptoInventory,
  Finding,
  ScanOptions,
  ScanResult,
  Severity,
} from "@qproof/core";

/** Build a Finding with sensible defaults; override any field. */
export function makeFinding(overrides: Partial<Finding> = {}): Finding {
  const base: Finding = {
    ruleId: "rsa-keygen",
    title: "RSA key generation",
    category: "kem",
    severity: "high",
    confidence: "high",
    algorithm: "RSA",
    hndl: true,
    message: "RSA is not quantum-safe.",
    remediation: "Use ML-KEM-768 (hybrid X25519MLKEM768).",
    location: { file: "src/a.ts", line: 1, snippet: "generateKeyPairSync('rsa')" },
    ...overrides,
  };
  if (overrides.location) base.location = { ...base.location, ...overrides.location };
  return base;
}

/** Aggregate findings into a minimal-but-valid inventory. */
export function makeInventory(findings: Finding[]): CryptoInventory {
  const bySeverity: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  let hndlCount = 0;
  const byAlgorithm: CryptoInventory["byAlgorithm"] = {};
  const byCategory: CryptoInventory["byCategory"] = {};
  for (const f of findings) {
    bySeverity[f.severity]++;
    if (f.hndl) hndlCount++;
    if (f.algorithm) byAlgorithm[f.algorithm] = (byAlgorithm[f.algorithm] ?? 0) + 1;
    byCategory[f.category] = (byCategory[f.category] ?? 0) + 1;
  }
  const readinessScore = findings.length === 0 ? 100 : Math.max(0, 100 - findings.length * 10);
  return { byAlgorithm, byCategory, bySeverity, hndlCount, readinessScore };
}

/** Wrap findings in a complete ScanResult. */
export function makeResult(findings: Finding[], root = "."): ScanResult {
  const now = new Date().toISOString();
  return {
    root,
    findings,
    filesScanned: 3,
    inventory: makeInventory(findings),
    startedAt: now,
    finishedAt: now,
    toolVersion: "0.1.0",
  };
}

/**
 * A self-contained fake scanner used by the end-to-end test.
 *
 * It really walks the given `root` (so the test exercises file traversal and
 * the full runQscan/baseline/report pipeline) and emits findings from a small
 * set of patterns that mirror what `@qproof/core` is contracted to detect.
 * This lets the e2e test pass against the *locked contract* even while core's
 * own `scan` is still a stub.
 */
export async function fakeScan(options: ScanOptions): Promise<ScanResult> {
  const startedAt = new Date().toISOString();
  const findings: Finding[] = [];
  let filesScanned = 0;

  const files = await walk(options.root, options.exclude ?? []);
  for (const abs of files) {
    const rel = relative(options.root, abs).split(sep).join("/");
    const content = await readFile(abs, "utf8");
    filesScanned++;

    // Dependency manifest scan.
    if (options.dependencies !== false && rel.endsWith("package.json")) {
      if (/"node-forge"/.test(content)) {
        findings.push(depFinding(rel, content, "node-forge"));
      }
    }

    // Source scan.
    if (options.source !== false && /\.(t|j)s$/.test(rel)) {
      eachLine(content, (line, n) => {
        if (/generateKeyPairSync\(\s*['"]rsa['"]/.test(line)) {
          findings.push(srcFinding(rel, n, line.trim(), "rsa-keygen", "RSA", "high"));
        }
        if (/createECDH\(|['"]ECDH['"]/.test(line)) {
          findings.push(srcFinding(rel, n, line.trim(), "ecdh-usage", "ECDH", "medium"));
        }
      });
    }
  }

  return {
    root: options.root,
    findings,
    filesScanned,
    inventory: makeInventory(findings),
    startedAt,
    finishedAt: new Date().toISOString(),
    toolVersion: "0.1.0",
  };
}

function srcFinding(
  file: string,
  line: number,
  snippet: string,
  ruleId: string,
  algorithm: Finding["algorithm"],
  severity: Severity,
): Finding {
  return makeFinding({
    ruleId,
    algorithm,
    severity,
    category: ruleId === "ecdh-usage" ? "key-exchange" : "kem",
    title: `${algorithm} usage`,
    message: `${algorithm} is not quantum-safe.`,
    location: { file, line, snippet },
  });
}

function depFinding(file: string, content: string, name: string): Finding {
  const line = lineOf(content, `"${name}"`);
  return makeFinding({
    ruleId: "dep-vulnerable",
    category: "dependency",
    severity: "high",
    algorithm: "RSA",
    title: `Vulnerable dependency: ${name}`,
    message: `Dependency "${name}" provides classical asymmetric crypto.`,
    location: { file, line, snippet: `"${name}"` },
  });
}

/** Recursively list files under `root`, skipping excludes + node_modules/.git. */
async function walk(root: string, exclude: string[]): Promise<string[]> {
  const out: string[] = [];
  const skip = new Set(["node_modules", ".git", "dist"]);
  async function recurse(dir: string): Promise<void> {
    const entries = await readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
      const abs = join(dir, entry.name);
      const rel = relative(root, abs).split(sep).join("/");
      if (skip.has(entry.name)) continue;
      if (exclude.some((p) => rel.includes(p))) continue;
      if (entry.isDirectory()) {
        await recurse(abs);
      } else if (entry.isFile()) {
        const s = await stat(abs);
        if (s.size <= 2 * 1024 * 1024) out.push(abs);
      }
    }
  }
  await recurse(root);
  return out.sort();
}

function eachLine(content: string, fn: (line: string, n: number) => void): void {
  const lines = content.split("\n");
  for (let i = 0; i < lines.length; i++) fn(lines[i] as string, i + 1);
}

function lineOf(content: string, needle: string): number {
  const lines = content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    if ((lines[i] as string).includes(needle)) return i + 1;
  }
  return 1;
}
