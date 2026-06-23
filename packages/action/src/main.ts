/**
 * quantakrypto Action entrypoint.
 *
 * Runs qScan over the repository, writes a SARIF (or JSON) report for GitHub
 * code scanning, annotates each finding inline, sets action outputs, optionally
 * comments a summary on the pull request, and fails the build when new
 * quantum-vulnerable cryptography lands.
 *
 * The scan, report rendering, and baseline live in `@quantakrypto/qscan` /
 * `@quantakrypto/core` so the Action and the CLI share one code path and one baseline
 * format — this module only adds the GitHub-runner glue (inputs, outputs,
 * annotations, PR comment, exit policy). The decision logic is factored into
 * small, pure functions so it can be tested without a real Actions environment.
 */

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

import { applyBaseline, fingerprintFinding, loadBaseline } from "@quantakrypto/core";
import type { Baseline, Finding, ScanResult, Severity } from "@quantakrypto/core";
import { renderReport, runQscan } from "@quantakrypto/qscan";

import {
  error as annotateError,
  getBooleanInput,
  getInput,
  info,
  setFailed,
  setOutput,
  warning,
} from "./io.js";
import { mdCell } from "./escape.js";

/** Severity ordering, most → least severe. Lower index = more severe. */
const SEVERITY_ORDER: readonly Severity[] = ["critical", "high", "medium", "low", "info"];

/** Default report file when the `output` input is omitted. */
const DEFAULT_OUTPUT = "quantakrypto.sarif.json";

/** Normalised, validated inputs for a run. */
export interface ActionInputs {
  path: string;
  severityThreshold: Severity;
  failOnFindings: boolean;
  format: "sarif" | "json";
  output: string;
  baseline?: string;
  commentPr: boolean;
  githubToken?: string;
}

/** Parse + validate the action's inputs from the environment. Pure given `env`. */
export function readInputs(env: NodeJS.ProcessEnv = process.env): ActionInputs {
  const severityThreshold = (getInput("severity-threshold", env) || "high") as Severity;
  if (!SEVERITY_ORDER.includes(severityThreshold)) {
    throw new TypeError(
      `Invalid severity-threshold "${severityThreshold}"; expected one of ${SEVERITY_ORDER.join(", ")}`,
    );
  }
  const format = (getInput("format", env) || "sarif") as "sarif" | "json";
  if (format !== "sarif" && format !== "json") {
    throw new TypeError(`Invalid format "${format}"; expected "sarif" or "json"`);
  }
  const baseline = getInput("baseline", env);
  const githubToken = getInput("github-token", env);
  return {
    path: getInput("path", env) || ".",
    severityThreshold,
    failOnFindings: getBooleanInput("fail-on-findings", true, env),
    format,
    output: getInput("output", env) || DEFAULT_OUTPUT,
    baseline: baseline || undefined,
    commentPr: getBooleanInput("comment-pr", false, env),
    githubToken: githubToken || undefined,
  };
}

/** True when `severity` is at least as severe as `threshold`. */
export function meetsThreshold(severity: Severity, threshold: Severity): boolean {
  return SEVERITY_ORDER.indexOf(severity) <= SEVERITY_ORDER.indexOf(threshold);
}

/**
 * A stable identity for a finding, used to match it against a baseline.
 *
 * Re-exported from `@quantakrypto/core` so the Action and the CLI share one
 * fingerprint (line-insensitive sha256 of `ruleId | file | normalizedSnippet`)
 * and therefore one baseline format. Kept under this name for the Action's
 * public surface.
 */
export { fingerprintFinding as fingerprint };

/** Decide whether the run should fail the build. Pure. */
export function shouldFail(blockingCount: number, failOnFindings: boolean): boolean {
  return failOnFindings && blockingCount > 0;
}

/** Map our internal severity onto a SARIF/GitHub annotation level. */
function annotationLevel(severity: Severity): "error" | "warning" | "notice" {
  if (severity === "critical" || severity === "high") return "error";
  if (severity === "medium" || severity === "low") return "warning";
  return "notice";
}

/**
 * Emit one inline annotation per finding (errors for blocking severities).
 *
 * The finding-derived `message` and `file` are attacker-controlled (a scanned
 * fork PR names the files and can craft the message text). They are escaped for
 * the workflow-command wire format inside `io.ts` (`escapeData` for the message;
 * `escapeProperty`, which additionally encodes `,` and `:`, for `file`), so a
 * hostile finding cannot break out of the `::error file=…,line=…::message`
 * command.
 */
export function annotateFindings(findings: Finding[], threshold: Severity): void {
  for (const f of findings) {
    const level = meetsThreshold(f.severity, threshold) ? "error" : annotationLevel(f.severity);
    const message = f.remediation ? `${f.message} → ${f.remediation}` : f.message;
    const props = {
      title: `quantakrypto: ${f.title}`,
      file: f.location.file,
      line: f.location.line,
      col: f.location.column,
      endLine: f.location.endLine,
    };
    if (level === "error") annotateError(message, props);
    else warning(message, props);
  }
}

/** Build a Markdown summary suitable for a PR comment. Pure. */
export function buildSummary(
  result: ScanResult,
  newFindings: Finding[],
  threshold: Severity,
): string {
  const score = result.inventory.readinessScore;
  const blocking = newFindings.filter((f) => meetsThreshold(f.severity, threshold));
  const lines: string[] = [];
  lines.push("## quantakrypto — Quantum Readiness Scan");
  lines.push("");
  lines.push(`**Readiness score:** ${score}/100`);
  lines.push(
    `**New findings:** ${newFindings.length} (${blocking.length} at or above \`${threshold}\`)`,
  );
  lines.push("");
  if (blocking.length === 0) {
    lines.push("No new quantum-vulnerable cryptography at or above the threshold. ✅");
    return lines.join("\n");
  }
  lines.push("| Severity | Rule | File | Message |");
  lines.push("| --- | --- | --- | --- |");
  for (const f of blocking.slice(0, 50)) {
    // Every cell carries finding-derived (attacker-controlled) text. Escape each
    // one so a crafted filename/message cannot break the table or inject HTML.
    const loc = mdCell(`${f.location.file}:${f.location.line}`);
    const rule = mdCell(f.ruleId);
    const msg = mdCell(f.message);
    lines.push(`| ${f.severity} | \`${rule}\` | ${loc} | ${msg} |`);
  }
  if (blocking.length > 50) lines.push(`| … | | | _${blocking.length - 50} more_ |`);
  lines.push("");
  lines.push("<sub>Reported by [quantakrypto](https://quantakrypto.com/tools).</sub>");
  return lines.join("\n");
}

/** Minimal GitHub PR context derived from the runner environment. */
export interface PullRequestContext {
  owner: string;
  repo: string;
  prNumber: number;
  apiUrl: string;
}

/**
 * Derive PR context from the `GITHUB_*` env + event payload, or return
 * undefined when not running on a pull request. Never throws.
 */
export async function readPullRequestContext(
  env: NodeJS.ProcessEnv = process.env,
): Promise<PullRequestContext | undefined> {
  try {
    const repository = env["GITHUB_REPOSITORY"];
    const eventPath = env["GITHUB_EVENT_PATH"];
    if (!repository || !eventPath) return undefined;
    const [owner, repo] = repository.split("/");
    if (!owner || !repo) return undefined;
    const payload = JSON.parse(await readFile(eventPath, "utf8")) as {
      pull_request?: { number?: number };
      number?: number;
    };
    const prNumber = payload.pull_request?.number ?? payload.number;
    if (typeof prNumber !== "number") return undefined;
    const apiUrl = env["GITHUB_API_URL"] || "https://api.github.com";
    return { owner, repo, prNumber, apiUrl };
  } catch {
    return undefined;
  }
}

/**
 * POST a summary comment to a pull request via the REST API. Best-effort: any
 * failure is logged as a warning and swallowed so commenting never breaks CI.
 */
export async function commentOnPullRequest(
  ctx: PullRequestContext,
  token: string,
  body: string,
): Promise<boolean> {
  try {
    const url = `${ctx.apiUrl}/repos/${ctx.owner}/${ctx.repo}/issues/${ctx.prNumber}/comments`;
    const res = await fetch(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "Content-Type": "application/json",
        "User-Agent": "quantakrypto-action",
      },
      body: JSON.stringify({ body }),
    });
    if (!res.ok) {
      warning(`Could not comment on PR #${ctx.prNumber}: ${res.status} ${res.statusText}`);
      return false;
    }
    return true;
  } catch (err) {
    warning(`Could not comment on PR: ${(err as Error).message}`);
    return false;
  }
}

/** Resolve a possibly-relative path against the GitHub workspace (or cwd). */
function resolveInWorkspace(p: string, env: NodeJS.ProcessEnv): string {
  if (isAbsolute(p)) return p;
  const workspace = env["GITHUB_WORKSPACE"] || process.cwd();
  return join(workspace, p);
}

/**
 * Load the shared `@quantakrypto/core` baseline (the `{ version, fingerprints }`
 * format written by `qscan --write-baseline`) into the set of accepted
 * fingerprints. `loadBaseline` is tolerant of a missing/unparseable file, so
 * an absent baseline degrades to "suppress nothing".
 */
async function loadBaselineSet(baselinePath: string, env: NodeJS.ProcessEnv): Promise<Baseline> {
  const abs = resolveInWorkspace(baselinePath, env);
  return loadBaseline(abs);
}

/** The full action run, parameterised on `env` for testability. */
export async function run(env: NodeJS.ProcessEnv = process.env): Promise<void> {
  const inputs = readInputs(env);

  const scanRoot = resolveInWorkspace(inputs.path, env);
  info(`quantakrypto: scanning ${scanRoot} (threshold: ${inputs.severityThreshold})`);

  // One code path with the CLI: qScan runs the scan and renders the report.
  // We deliberately do NOT hand the baseline to runQscan — the report (SARIF
  // for code scanning) must carry the FULL, pre-baseline result; we apply the
  // baseline ourselves below to derive the NEW findings that gate the build.
  const { result } = await runQscan({
    path: scanRoot,
    format: inputs.format,
    severityThreshold: inputs.severityThreshold,
  });

  // Apply the shared baseline so only NEW quantum-vulnerable crypto can fail.
  const baseline = inputs.baseline
    ? await loadBaselineSet(inputs.baseline, env)
    : { version: 1, fingerprints: [] as string[] };
  const { newFindings } = applyBaseline(result.findings, baseline);

  // Write the report (SARIF for code scanning, or JSON) to the output path.
  const outputPath = resolveInWorkspace(inputs.output, env);
  await mkdir(dirname(outputPath), { recursive: true });
  await writeFile(outputPath, renderReport(result, inputs.format), "utf8");
  info(`quantakrypto: wrote ${inputs.format} report to ${inputs.output}`);

  // Annotate findings inline in the diff.
  annotateFindings(newFindings, inputs.severityThreshold);

  // The findings that gate the build.
  const blocking = newFindings.filter((f) => meetsThreshold(f.severity, inputs.severityThreshold));

  // Outputs.
  setOutput("findings-count", String(blocking.length), env);
  setOutput("readiness-score", String(result.inventory.readinessScore), env);
  setOutput("sarif-file", inputs.output, env);

  // Optional PR comment (best-effort, never fatal).
  if (inputs.commentPr && inputs.githubToken) {
    const ctx = await readPullRequestContext(env);
    if (ctx) {
      const body = buildSummary(result, newFindings, inputs.severityThreshold);
      await commentOnPullRequest(ctx, inputs.githubToken, body);
    } else {
      info("quantakrypto: comment-pr enabled but no pull-request context found; skipping comment.");
    }
  }

  info(
    `quantakrypto: ${newFindings.length} new finding(s), ${blocking.length} at/above "${inputs.severityThreshold}"; readiness ${result.inventory.readinessScore}/100.`,
  );

  if (shouldFail(blocking.length, inputs.failOnFindings)) {
    setFailed(
      `quantakrypto: ${blocking.length} quantum-vulnerable finding(s) at or above "${inputs.severityThreshold}".`,
    );
    process.exit(1);
  }
}

// Run when invoked as the action's entrypoint, not when imported by tests.
// Compare this module's URL against the script Node was launched with so the
// guard holds regardless of the emitted filename (tsc's `main.js` or the
// bundled `index.js` that `action.yml` points at).
const invokedDirectly =
  process.argv[1] !== undefined && import.meta.url === pathToFileURL(resolve(process.argv[1])).href;
if (invokedDirectly) {
  run().catch((err: unknown) => {
    setFailed(`quantakrypto: ${(err as Error).message}`);
    process.exit(1);
  });
}
