/**
 * Zero-dependency replacements for the handful of `@actions/core` helpers this
 * action needs. Everything here speaks the GitHub Actions runner protocol
 * directly (environment variables + workflow commands on stdout) so the action
 * carries no runtime dependencies and still behaves sanely when run locally
 * (outside a runner) for tests and ad-hoc use.
 *
 * Workflow command reference:
 * https://docs.github.com/actions/using-workflows/workflow-commands-for-github-actions
 */

import { appendFileSync } from "node:fs";
import { EOL } from "node:os";

/** Convert an input name to its runner env var, e.g. "severity-threshold" → "INPUT_SEVERITY_THRESHOLD". */
function inputEnvName(name: string): string {
  return `INPUT_${name.replace(/ /g, "_").replace(/-/g, "_").toUpperCase()}`;
}

/**
 * Read an action input. The runner exposes `with:` values as `INPUT_*` env
 * vars. Returns the trimmed value, or `""` when unset (matching `@actions/core`).
 */
export function getInput(name: string, env: NodeJS.ProcessEnv = process.env): string {
  const raw = env[inputEnvName(name)];
  return raw === undefined ? "" : raw.trim();
}

/**
 * Read a boolean input following the YAML 1.2 spec the runner uses:
 * "true"/"True"/"TRUE" → true, "false"/"False"/"FALSE" → false. An empty or
 * missing value falls back to `defaultValue`. Anything else throws.
 */
export function getBooleanInput(
  name: string,
  defaultValue = false,
  env: NodeJS.ProcessEnv = process.env,
): boolean {
  const value = getInput(name, env);
  if (value === "") return defaultValue;
  if (["true", "True", "TRUE"].includes(value)) return true;
  if (["false", "False", "FALSE"].includes(value)) return false;
  throw new TypeError(
    `Input "${name}" does not meet YAML 1.2 "Core Schema" specification: got "${value}"`,
  );
}

/**
 * Escape a value for the `key=value` portion of a workflow command's data.
 * (Data after `::` only needs `%`, `\r`, `\n` escaped.)
 */
function escapeData(value: string): string {
  return value.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
}

/** Escape a value used inside a command's property list (e.g. `file=...`). */
function escapeProperty(value: string): string {
  return value
    .replace(/%/g, "%25")
    .replace(/\r/g, "%0D")
    .replace(/\n/g, "%0A")
    .replace(/:/g, "%3A")
    .replace(/,/g, "%2C");
}

/** Properties accepted by the annotation workflow commands. */
export interface AnnotationProperties {
  title?: string;
  file?: string;
  /** 1-based start line. */
  line?: number;
  /** 1-based start column. */
  col?: number;
  /** 1-based end line. */
  endLine?: number;
  /** 1-based end column. */
  endColumn?: number;
}

/**
 * Format a single workflow command string. Exposed (and pure) so the exact
 * wire format can be unit-tested without spying on stdout.
 *
 * @example formatCommand("error", "boom", { file: "a.ts", line: 12 })
 *   // "::error file=a.ts,line=12::boom"
 */
export function formatCommand(
  command: string,
  message: string,
  properties: AnnotationProperties = {},
): string {
  const entries: Array<[string, string | number | undefined]> = [
    ["title", properties.title],
    ["file", properties.file],
    ["line", properties.line],
    ["col", properties.col],
    ["endLine", properties.endLine],
    ["endColumn", properties.endColumn],
  ];
  const props = entries
    .filter(([, v]) => v !== undefined && v !== "")
    .map(([k, v]) => `${k}=${escapeProperty(String(v))}`)
    .join(",");
  const head = props ? `::${command} ${props}::` : `::${command}::`;
  return `${head}${escapeData(message)}`;
}

/** Print a workflow command on stdout (where the runner parses it). */
function issueCommand(command: string, message: string, properties?: AnnotationProperties): void {
  process.stdout.write(formatCommand(command, message, properties) + EOL);
}

/** Log an informational line. */
export function info(message: string): void {
  process.stdout.write(message + EOL);
}

/** Emit a `warning` annotation (or plain log line locally). */
export function warning(message: string, properties?: AnnotationProperties): void {
  issueCommand("warning", message, properties);
}

/** Emit an `error` annotation (or plain log line locally). */
export function error(message: string, properties?: AnnotationProperties): void {
  issueCommand("error", message, properties);
}

/** Emit a `notice` annotation. */
export function notice(message: string, properties?: AnnotationProperties): void {
  issueCommand("notice", message, properties);
}

/**
 * Set an action output. On a runner this appends `name<<EOF\nvalue\nEOF` to the
 * file named by `$GITHUB_OUTPUT`. With no such file (local/test runs) it falls
 * back to a deprecated-but-harmless stdout command so callers still see it.
 */
export function setOutput(
  name: string,
  value: string,
  env: NodeJS.ProcessEnv = process.env,
): void {
  const filePath = env["GITHUB_OUTPUT"];
  if (filePath) {
    // Heredoc form is required for values that may contain newlines.
    const delimiter = `ghadelimiter_${name}`;
    appendFileSync(filePath, `${name}<<${delimiter}${EOL}${value}${EOL}${delimiter}${EOL}`, {
      encoding: "utf8",
    });
    return;
  }
  process.stdout.write(formatCommand("set-output", value, { title: name }) + EOL);
}

/**
 * Mark the action as failed: emit an `error` annotation and set the process
 * exit code to 1. (Does not call `process.exit`; the caller decides when.)
 */
export function setFailed(message: string): void {
  error(message);
  process.exitCode = 1;
}
