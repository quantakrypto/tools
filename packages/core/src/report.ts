/**
 * Reporters: turn a {@link ScanResult} into SARIF 2.1.0, a clean JSON object,
 * or a human-readable text summary. No third-party dependencies — ANSI colour
 * is emitted with raw escape codes and is off by default.
 */
import type { Finding, ScanResult, Severity } from "./types.js";
import { VERSION } from "./version.js";
import { SEVERITY_ORDER, sarifLevel } from "./severity.js";

/** Minimal SARIF 2.1.0 log shape (kept permissive on purpose). */
export interface SarifLog {
  $schema: string;
  version: "2.1.0";
  runs: unknown[];
}

/** Options shared by the structured reporters ({@link toSarif} / {@link toJson}). */
export interface ReportOptions {
  /**
   * Omit `location.snippet` from every finding in the output. Defaults to false
   * (snippets are included). Snippets of `sensitive` findings (e.g. PEM key
   * blocks, SSH public keys) are ALWAYS omitted regardless of this flag — the
   * snippet there IS the sensitive value.
   */
  redactSnippets?: boolean;
}

const SARIF_SCHEMA =
  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";

const INFORMATION_URI = "https://github.com/quantakrypto/pqc-tools";

/**
 * Resolve the snippet to emit for a finding, honouring redaction. Sensitive
 * findings (key material) never expose their snippet; otherwise the snippet is
 * dropped only when `redactSnippets` is set.
 */
function emittedSnippet(f: Finding, redactSnippets: boolean): string | undefined {
  if (redactSnippets || f.sensitive) return undefined;
  return f.location.snippet;
}

/** Map our severity to a SARIF rule-level default (used in rules[].defaultConfiguration). */
function sarifRank(severity: Severity): number {
  switch (severity) {
    case "critical":
      return 100;
    case "high":
      return 80;
    case "medium":
      return 50;
    case "low":
      return 20;
    default:
      return 5;
  }
}

/** Serialize a scan result as SARIF 2.1.0. */
export function toSarif(result: ScanResult, opts?: ReportOptions): SarifLog {
  const redactSnippets = opts?.redactSnippets ?? false;
  // Build the unique rule set (one rule per ruleId encountered) and collect the
  // set of CWE taxa referenced by any rule.
  const ruleIndex = new Map<string, number>();
  const rules: Array<Record<string, unknown>> = [];
  const cweTaxa = new Set<string>();
  for (const f of result.findings) {
    if (f.cwe) cweTaxa.add(f.cwe);
    if (ruleIndex.has(f.ruleId)) continue;
    ruleIndex.set(f.ruleId, rules.length);
    rules.push({
      id: f.ruleId,
      name: f.ruleId,
      shortDescription: { text: f.title },
      fullDescription: { text: f.message },
      defaultConfiguration: { level: sarifLevel(f.severity), rank: sarifRank(f.severity) },
      ...(f.remediation ? { help: { text: `Remediation: ${f.remediation}` } } : {}),
      properties: {
        category: f.category,
        ...(f.algorithm ? { algorithm: f.algorithm } : {}),
        hndl: f.hndl,
        ...(f.cwe ? { cwe: f.cwe, "security-severity": securitySeverity(f.severity) } : {}),
        ...(f.cwe ? { tags: ["security", f.cwe] } : {}),
      },
      ...(f.cwe
        ? {
            relationships: [
              { target: { id: f.cwe, toolComponent: { name: "CWE" } }, kinds: ["relevant"] },
            ],
          }
        : {}),
    });
  }

  const results = result.findings.map((f) => {
    const region: Record<string, number> = { startLine: f.location.line };
    if (typeof f.location.column === "number") region.startColumn = f.location.column;
    if (typeof f.location.endLine === "number") region.endLine = f.location.endLine;
    const snippet = emittedSnippet(f, redactSnippets);

    return {
      ruleId: f.ruleId,
      ruleIndex: ruleIndex.get(f.ruleId),
      level: sarifLevel(f.severity),
      message: { text: f.message },
      properties: {
        category: f.category,
        severity: f.severity,
        confidence: f.confidence,
        hndl: f.hndl,
        ...(f.algorithm ? { algorithm: f.algorithm } : {}),
        ...(f.remediation ? { remediation: f.remediation } : {}),
        ...(f.cwe ? { cwe: f.cwe } : {}),
      },
      ...(f.cwe
        ? {
            taxa: [
              {
                target: { id: f.cwe, toolComponent: { name: "CWE" } },
              },
            ],
          }
        : {}),
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: f.location.file },
            region: {
              ...region,
              ...(snippet ? { snippet: { text: snippet } } : {}),
            },
          },
        },
      ],
    };
  });

  // CWE taxonomy component (SARIF taxonomies), referenced by rules + results.
  const taxonomies =
    cweTaxa.size > 0
      ? [
          {
            name: "CWE",
            informationUri: "https://cwe.mitre.org/",
            organization: "MITRE",
            shortDescription: { text: "The MITRE Common Weakness Enumeration" },
            taxa: [...cweTaxa].sort().map((id) => ({
              id,
              helpUri: `https://cwe.mitre.org/data/definitions/${id.replace(/^CWE-/, "")}.html`,
            })),
          },
        ]
      : [];

  return {
    $schema: SARIF_SCHEMA,
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "qScan",
            informationUri: INFORMATION_URI,
            version: result.toolVersion || VERSION,
            rules,
          },
        },
        ...(taxonomies.length > 0 ? { taxonomies } : {}),
        results,
      },
    ],
  };
}

/** GitHub-code-scanning `security-severity` (0–10) derived from our severity. */
function securitySeverity(severity: Severity): string {
  switch (severity) {
    case "critical":
      return "9.5";
    case "high":
      return "8.0";
    case "medium":
      return "5.0";
    case "low":
      return "3.0";
    default:
      return "1.0";
  }
}

/** Serialize a scan result as a plain JSON-friendly object. */
export function toJson(result: ScanResult, opts?: ReportOptions): Record<string, unknown> {
  const redactSnippets = opts?.redactSnippets ?? false;
  return {
    toolVersion: result.toolVersion,
    root: result.root,
    startedAt: result.startedAt,
    finishedAt: result.finishedAt,
    filesScanned: result.filesScanned,
    inventory: {
      readinessScore: result.inventory.readinessScore,
      hndlCount: result.inventory.hndlCount,
      bySeverity: result.inventory.bySeverity,
      byCategory: result.inventory.byCategory,
      byAlgorithm: result.inventory.byAlgorithm,
    },
    findings: result.findings.map((f) => ({
      ruleId: f.ruleId,
      title: f.title,
      category: f.category,
      severity: f.severity,
      confidence: f.confidence,
      algorithm: f.algorithm,
      hndl: f.hndl,
      message: f.message,
      remediation: f.remediation,
      cwe: f.cwe,
      location: {
        file: f.location.file,
        line: f.location.line,
        column: f.location.column,
        endLine: f.location.endLine,
        snippet: emittedSnippet(f, redactSnippets),
      },
    })),
  };
}

/* -------------------------------------------------------------------------- */
/* Human-readable summary                                                      */
/* -------------------------------------------------------------------------- */

/** Raw ANSI codes (no chalk). Disabled when colour is off. */
const ANSI = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  magenta: "\x1b[35m",
  cyan: "\x1b[36m",
} as const;

function severityColor(sev: Severity): string {
  switch (sev) {
    case "critical":
      return ANSI.magenta;
    case "high":
      return ANSI.red;
    case "medium":
      return ANSI.yellow;
    case "low":
      return ANSI.blue;
    default:
      return ANSI.dim;
  }
}

function scoreColor(score: number): string {
  if (score >= 80) return ANSI.green;
  if (score >= 50) return ANSI.yellow;
  return ANSI.red;
}

/**
 * Render a human-readable summary of a scan result. Colour is off by default;
 * pass `{ color: true }` to emit ANSI escape codes.
 */
export function formatSummary(result: ScanResult, options?: { color?: boolean }): string {
  const color = options?.color ?? false;
  const c = (code: string, text: string): string => (color ? `${code}${text}${ANSI.reset}` : text);

  const lines: string[] = [];
  const inv = result.inventory;

  lines.push(c(ANSI.bold, "qScan — post-quantum readiness report"));
  lines.push(c(ANSI.dim, `tool v${result.toolVersion} · root: ${result.root}`));
  lines.push("");

  // Readiness score banner.
  lines.push(
    `Readiness score: ${c(`${ANSI.bold}${scoreColor(inv.readinessScore)}`, `${inv.readinessScore}/100`)}`,
  );
  lines.push(
    `Files scanned:   ${result.filesScanned}   Findings: ${result.findings.length}   HNDL-exposed: ${c(
      inv.hndlCount > 0 ? ANSI.red : ANSI.green,
      String(inv.hndlCount),
    )}`,
  );
  lines.push("");

  // Severity breakdown.
  const sevParts = SEVERITY_ORDER.filter((s) => inv.bySeverity[s] > 0).map((s) =>
    c(severityColor(s), `${s}: ${inv.bySeverity[s]}`),
  );
  lines.push(`By severity:  ${sevParts.length ? sevParts.join("   ") : c(ANSI.green, "none")}`);

  // Algorithm breakdown.
  const algoParts = Object.entries(inv.byAlgorithm)
    .sort((a, b) => b[1] - a[1])
    .map(([k, v]) => `${k}: ${v}`);
  if (algoParts.length) lines.push(`By algorithm: ${algoParts.join("   ")}`);
  lines.push("");

  if (result.findings.length === 0) {
    lines.push(c(ANSI.green, "No classical asymmetric cryptography detected. ✓"));
    return lines.join("\n");
  }

  // Top findings, grouped by severity (most severe first), capped for readability.
  const sorted = [...result.findings].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
  );
  const MAX_SHOWN = 25;
  lines.push(
    c(ANSI.bold, `Top findings (${Math.min(MAX_SHOWN, sorted.length)} of ${sorted.length}):`),
  );

  for (const f of sorted.slice(0, MAX_SHOWN)) {
    const loc = `${f.location.file}:${f.location.line}${
      f.location.column ? `:${f.location.column}` : ""
    }`;
    const tag = c(severityColor(f.severity), `[${f.severity}]`);
    const hndl = f.hndl ? c(ANSI.red, " (HNDL)") : "";
    lines.push(`  ${tag} ${f.title}${hndl}`);
    lines.push(c(ANSI.dim, `      ${loc} — ${f.message}`));
    if (f.remediation) lines.push(c(ANSI.cyan, `      → ${f.remediation}`));
  }

  if (sorted.length > MAX_SHOWN) {
    lines.push(c(ANSI.dim, `  …and ${sorted.length - MAX_SHOWN} more.`));
  }

  lines.push("");
  if (inv.hndlCount > 0) {
    lines.push(
      c(
        ANSI.yellow,
        `Note: ${inv.hndlCount} finding(s) are exposed to "harvest now, decrypt later" — ` +
          "encrypted traffic captured today can be decrypted once a quantum computer exists. " +
          "Prioritise migrating key exchange / encryption to hybrid PQC (X25519MLKEM768).",
      ),
    );
  }

  return lines.join("\n");
}
