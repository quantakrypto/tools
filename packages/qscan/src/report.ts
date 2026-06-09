/**
 * qScan report rendering.
 *
 * Produces the three output formats the CLI supports:
 *  - `human`  — a tasteful plain-text banner (counts, top findings, readiness
 *               score, and a one-line next step). Optional raw ANSI color.
 *  - `json`   — the structured scan result via core's `toJson`.
 *  - `sarif`  — SARIF 2.1.0 via core's `toSarif`.
 *
 * Only `human` lives here; `json`/`sarif` delegate to `@qproof/core` so the
 * serialized shape stays consistent across every tool in the monorepo.
 */

import { toJson, toSarif } from "@qproof/core";
import type { Finding, ScanResult, Severity } from "@qproof/core";
import { SEVERITY_ORDER, severityRank } from "./args.js";

/** Minimal ANSI palette. Empty strings when color is disabled. */
interface Palette {
  reset: string;
  bold: string;
  dim: string;
  red: string;
  yellow: string;
  green: string;
  cyan: string;
}

const PLAIN: Palette = { reset: "", bold: "", dim: "", red: "", yellow: "", green: "", cyan: "" };
const COLOR: Palette = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  red: "\x1b[31m",
  yellow: "\x1b[33m",
  green: "\x1b[32m",
  cyan: "\x1b[36m",
};

/**
 * Render the JSON report (pretty-printed, no trailing newline).
 *
 * Delegates to core's `toJson` for a monorepo-consistent shape. If the running
 * core build has not implemented the serializer yet, falls back to emitting the
 * `ScanResult` directly (which is already JSON-friendly) so reports never break.
 */
export function renderJson(result: ScanResult): string {
  return JSON.stringify(serialize(() => toJson(result), result), null, 2);
}

/**
 * Render the SARIF 2.1.0 report (pretty-printed, no trailing newline).
 *
 * Delegates to core's `toSarif`, with a minimal SARIF 2.1.0 fallback so the
 * format always produces valid, ingestible output.
 */
export function renderSarif(result: ScanResult): string {
  return JSON.stringify(serialize(() => toSarif(result), fallbackSarif(result)), null, 2);
}

/**
 * Call a core serializer, falling back when it is an unimplemented stub.
 * Only the documented "not implemented" stub error is swallowed; real errors
 * (e.g. a bug in a future core) propagate. The two branches may have different
 * shapes — both are ultimately handed to `JSON.stringify`.
 */
function serialize<T, F>(fn: () => T, fallback: F): T | F {
  try {
    return fn();
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (message.includes("not implemented")) return fallback;
    throw err;
  }
}

/** A minimal, valid SARIF 2.1.0 log used when core's `toSarif` is unavailable. */
function fallbackSarif(result: ScanResult): Record<string, unknown> {
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "qscan",
            informationUri: "https://github.com/qproof/qproof-tools",
            version: result.toolVersion,
            rules: [],
          },
        },
        results: result.findings.map((f) => ({
          ruleId: f.ruleId,
          level: sarifLevel(f.severity),
          message: { text: f.message },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: f.location.file },
                region: {
                  startLine: f.location.line,
                  ...(f.location.column ? { startColumn: f.location.column } : {}),
                },
              },
            },
          ],
        })),
      },
    ],
  };
}

/** Map a qScan severity to a SARIF level. */
function sarifLevel(severity: Severity): "error" | "warning" | "note" {
  switch (severity) {
    case "critical":
    case "high":
      return "error";
    case "medium":
      return "warning";
    default:
      return "note";
  }
}

/**
 * Render the human-readable banner.
 *
 * @param result The scan result.
 * @param opts.color Emit raw ANSI escapes (default: false / plain text).
 * @param opts.topN How many findings to list (default: 5).
 */
export function renderHuman(
  result: ScanResult,
  opts: { color?: boolean; topN?: number } = {},
): string {
  const c = opts.color ? COLOR : PLAIN;
  const topN = opts.topN ?? 5;
  const { findings, inventory, filesScanned } = result;
  const lines: string[] = [];

  lines.push(`${c.bold}qScan — quantum-vulnerable cryptography report${c.reset}`);
  lines.push(`${c.dim}root: ${result.root}  •  files scanned: ${filesScanned}  •  qscan v${result.toolVersion}${c.reset}`);
  lines.push("");

  if (findings.length === 0) {
    lines.push(`${c.green}No quantum-vulnerable cryptography detected.${c.reset}`);
    lines.push(`${c.bold}Readiness score: ${readiness(inventory.readinessScore, c)}/100${c.reset}`);
    lines.push("");
    lines.push(`${c.dim}Next step:${c.reset} keep scanning in CI to catch regressions.`);
    return lines.join("\n");
  }

  // Severity counts, most-severe first.
  const counts = SEVERITY_ORDER.map((sev) => {
    const n = inventory.bySeverity[sev] ?? 0;
    return n > 0 ? `${severityColor(sev, c)}${n} ${sev}${c.reset}` : null;
  }).filter((s): s is string => s !== null);

  lines.push(`${c.bold}${findings.length} finding${findings.length === 1 ? "" : "s"}${c.reset}  (${counts.join(", ")})`);
  if (inventory.hndlCount > 0) {
    lines.push(
      `${c.yellow}${inventory.hndlCount}${c.reset} exposed to harvest-now-decrypt-later (HNDL).`,
    );
  }
  lines.push(`${c.bold}Readiness score: ${readiness(inventory.readinessScore, c)}/100${c.reset}`);
  lines.push("");

  // Top findings, sorted by severity then file/line for determinism.
  const top = [...findings].sort(compareFindings).slice(0, topN);
  lines.push(`${c.bold}Top findings${c.reset}`);
  for (const f of top) {
    const loc = `${f.location.file}:${f.location.line}`;
    lines.push(`  ${severityColor(f.severity, c)}${f.severity.padEnd(8)}${c.reset} ${c.cyan}${f.ruleId}${c.reset}  ${loc}`);
    lines.push(`           ${f.message}`);
    if (f.remediation) {
      lines.push(`           ${c.dim}→ ${f.remediation}${c.reset}`);
    }
  }
  if (findings.length > top.length) {
    lines.push(`  ${c.dim}…and ${findings.length - top.length} more${c.reset}`);
  }
  lines.push("");
  lines.push(`${c.dim}Next step:${c.reset} ${nextStep(findings)}`);

  return lines.join("\n");
}

/** Suggest a single concrete next action based on the worst finding. */
function nextStep(findings: Finding[]): string {
  const worst = [...findings].sort(compareFindings)[0];
  if (!worst) return "review the findings above.";
  if (worst.remediation) {
    return `migrate ${worst.location.file} — ${worst.remediation}`;
  }
  return `triage ${worst.ruleId} in ${worst.location.file}:${worst.location.line}.`;
}

/** Deterministic ordering: most severe first, then file, then line. */
function compareFindings(a: Finding, b: Finding): number {
  const bySev = severityRank(a.severity) - severityRank(b.severity);
  if (bySev !== 0) return bySev;
  const byFile = a.location.file.localeCompare(b.location.file);
  if (byFile !== 0) return byFile;
  return a.location.line - b.location.line;
}

/** Color the readiness score green/yellow/red by band. */
function readiness(score: number, c: Palette): string {
  const color = score >= 80 ? c.green : score >= 50 ? c.yellow : c.red;
  return `${color}${score}${c.reset}`;
}

/** Map a severity to its palette color. */
function severityColor(severity: Severity, c: Palette): string {
  switch (severity) {
    case "critical":
    case "high":
      return c.red;
    case "medium":
      return c.yellow;
    default:
      return c.dim;
  }
}
