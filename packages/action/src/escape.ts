/**
 * Output-escaping helpers for finding-derived, attacker-controlled text.
 *
 * A finding's `file`, `message`, and `ruleId` originate from the *scanned*
 * repository — in a fork pull request an attacker controls all of them (they
 * name the files and can craft message text). Two sinks render this text into a
 * security-sensitive context the Action emits with a write-scoped token:
 *
 *   1. the PR-comment Markdown table — handled here by {@link mdCell}, and
 *   2. the `::error file=…,line=…::message` workflow command — handled by the
 *      `escapeData`/`escapeProperty` helpers in `io.ts`.
 *
 * `mdCell` neutralises every way a single table cell can break out of, or
 * inject into, the surrounding GitHub-flavoured Markdown comment.
 */

/**
 * Escape a string for safe inclusion in a single GitHub-flavoured-Markdown
 * table cell.
 *
 * Defends against:
 *  - **Table breakout** — `|` ends a cell early; escaped to `\|`.
 *  - **Row/structure breakout** — CR/LF would start a new table row or end the
 *    table entirely; collapsed to a single space.
 *  - **Code-span breakout / spoofing** — a backtick can open or close an inline
 *    code span and swallow following cells; escaped to `` \` ``.
 *  - **Raw-HTML injection** — GitHub renders inline HTML in comments, so `<`,
 *    `>`, and `&` are entity-encoded (this also disarms `<img>`/`<script>`-style
 *    payloads and HTML entities).
 *  - **Backslash games** — a trailing/odd backslash could escape our own
 *    escaping; backslashes are doubled first so subsequent escapes are literal.
 *
 * The output is plain text that renders verbatim inside one cell and cannot
 * alter the table's shape or the comment's structure. Length is clipped so a
 * pathological filename cannot bloat the comment.
 */
export function mdCell(value: string): string {
  const clipped = value.length > 512 ? `${value.slice(0, 512)}…` : value;
  return (
    clipped
      // Order matters: double backslashes first so the escapes we add below are
      // themselves literal and can't be "un-escaped" by an attacker backslash.
      .replace(/\\/g, "\\\\")
      // HTML — entity-encode before anything else that could form a tag.
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      // Markdown table / code-span metacharacters.
      .replace(/\|/g, "\\|")
      .replace(/`/g, "\\`")
      // Newlines would break the row; flatten any CR/LF run to one space.
      .replace(/[\r\n]+/g, " ")
  );
}
