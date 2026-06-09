/**
 * Shared helpers for the regex-based source detectors: turning a string offset
 * into a 1-based line/column, extracting a trimmed single-line snippet, and a
 * small factory for building Finding objects with consistent remediation text.
 */
import type {
  AlgorithmFamily,
  Confidence,
  Finding,
  FindingCategory,
  Severity,
} from "./types.js";
import { remediationText } from "./remediation.js";

/** A 1-based line/column position derived from a character offset. */
export interface LineCol {
  line: number;
  column: number;
}

/**
 * Convert a 0-based character offset within `content` into a 1-based
 * line/column. Newlines are LF; CR is treated as an ordinary character, so on
 * CRLF files the column includes the trailing CR offset harmlessly.
 */
export function offsetToLineCol(content: string, offset: number): LineCol {
  let line = 1;
  let lastNewline = -1;
  for (let i = 0; i < offset && i < content.length; i++) {
    if (content.charCodeAt(i) === 10 /* \n */) {
      line++;
      lastNewline = i;
    }
  }
  return { line, column: offset - lastNewline };
}

/** Extract the (trimmed) single source line containing `offset`. */
export function lineAt(content: string, offset: number): string {
  let start = offset;
  while (start > 0 && content.charCodeAt(start - 1) !== 10) start--;
  let end = offset;
  while (end < content.length && content.charCodeAt(end) !== 10) end++;
  return content.slice(start, end).replace(/\r$/, "").trim();
}

/** Inputs for {@link makeFinding}. */
export interface FindingSpec {
  ruleId: string;
  title: string;
  category: FindingCategory;
  severity: Severity;
  confidence: Confidence;
  algorithm?: AlgorithmFamily;
  hndl: boolean;
  message: string;
  /** Override the auto-derived remediation text. */
  remediation?: string;
  /** The matched source text and its start offset within `content`. */
  file: string;
  content: string;
  index: number;
  /** Length of the match, used to compute endLine for multi-line matches. */
  matchLength?: number;
}

/**
 * Build a {@link Finding} with location info derived from a match offset. When
 * no explicit remediation is given but an algorithm is, the canonical
 * remediation text for that family is used.
 */
export function makeFinding(spec: FindingSpec): Finding {
  const { line, column } = offsetToLineCol(spec.content, spec.index);
  const snippet = lineAt(spec.content, spec.index);

  const remediation =
    spec.remediation ?? (spec.algorithm ? remediationText(spec.algorithm) : undefined);

  const location: Finding["location"] = {
    file: spec.file,
    line,
    column,
    snippet: snippet.length > 200 ? `${snippet.slice(0, 197)}...` : snippet,
  };

  if (spec.matchLength && spec.matchLength > 0) {
    const matched = spec.content.slice(spec.index, spec.index + spec.matchLength);
    const extraLines = (matched.match(/\n/g) ?? []).length;
    if (extraLines > 0) location.endLine = line + extraLines;
  }

  const finding: Finding = {
    ruleId: spec.ruleId,
    title: spec.title,
    category: spec.category,
    severity: spec.severity,
    confidence: spec.confidence,
    hndl: spec.hndl,
    message: spec.message,
    location,
  };
  if (spec.algorithm) finding.algorithm = spec.algorithm;
  if (remediation) finding.remediation = remediation;
  return finding;
}

/** True if `filePath` has one of the given (lower-case, dotted) extensions. */
export function hasExtension(filePath: string, exts: readonly string[]): boolean {
  const lower = filePath.toLowerCase();
  return exts.some((e) => lower.endsWith(e));
}

/** JavaScript / TypeScript source extensions handled by the source detectors. */
export const JS_TS_EXTENSIONS: readonly string[] = [
  ".js",
  ".jsx",
  ".ts",
  ".tsx",
  ".mjs",
  ".cjs",
];

/**
 * Run a global regex over `content`, invoking `onMatch` for each hit. Resets
 * lastIndex and guards against zero-width matches (which would loop forever).
 */
export function eachMatch(
  re: RegExp,
  content: string,
  onMatch: (match: RegExpExecArray) => void,
): void {
  const g = re.global ? re : new RegExp(re.source, `${re.flags}g`);
  g.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = g.exec(content)) !== null) {
    onMatch(m);
    if (m.index === g.lastIndex) g.lastIndex++; // avoid infinite loop on empty match
  }
}
