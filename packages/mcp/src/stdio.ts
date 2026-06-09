#!/usr/bin/env node
/**
 * qproof-mcp — stdio transport.
 *
 * MCP's stdio transport is newline-delimited JSON: exactly one JSON-RPC 2.0
 * message per line on stdin, one per line on stdout. (This is NOT HTTP-style
 * Content-Length framing.) This module reads stdin line-by-line with
 * {@link node:readline}, hands each parsed message to {@link McpServer.handle},
 * and writes any response back as a single line on stdout. Diagnostics go to
 * stderr so they never corrupt the protocol stream.
 *
 * Run as the `qproof-mcp` bin, or `node dist/stdio.js`.
 */

import { createInterface } from "node:readline";
import process from "node:process";
import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { createQproofServer } from "./index.js";
import { ErrorCode, makeFailure } from "./protocol.js";
import type { McpServer } from "./server.js";

/** Serialize a value as one newline-terminated JSON line to stdout. */
function writeLine(value: unknown): void {
  process.stdout.write(JSON.stringify(value) + "\n");
}

/**
 * Attach a line-delimited JSON-RPC loop to the given streams. Exposed (rather
 * than only run on import) so it can be reused or tested with custom streams.
 */
export function runStdioServer(
  server: McpServer,
  input: NodeJS.ReadableStream = process.stdin,
  output: NodeJS.WritableStream = process.stdout,
): void {
  const rl = createInterface({ input, crlfDelay: Infinity });

  rl.on("line", (raw: string) => {
    const line = raw.trim();
    if (line.length === 0) return; // tolerate blank lines / keepalives

    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch {
      // Parse error: we have no id, so reply with a null-id error per JSON-RPC.
      output.write(JSON.stringify(makeFailure(null, ErrorCode.ParseError, "parse error")) + "\n");
      return;
    }

    // Process asynchronously; responses are written as they resolve. Ordering
    // within a single client is preserved because handlers here are fast and
    // the event loop drains line events in order.
    void server
      .handle(parsed)
      .then((response) => {
        if (response !== null) output.write(JSON.stringify(response) + "\n");
      })
      .catch((err: unknown) => {
        // Defensive: handle() already catches, but never let a rejection escape.
        const messageText = err instanceof Error ? err.message : String(err);
        process.stderr.write(`qproof-mcp internal error: ${messageText}\n`);
      });
  });

  rl.on("close", () => {
    process.exitCode = 0;
  });
}

/** Entry point when executed directly (the bin / `node dist/stdio.js`). */
function main(): void {
  const server = createQproofServer();
  process.stderr.write(`qproof MCP server (stdio) ready\n`);
  runStdioServer(server);
}

/**
 * True when this module is the program's entry point. Resolves symlinks so the
 * check also holds when launched via the `qproof-mcp` bin shim in node_modules/.bin.
 */
function isMainModule(): boolean {
  const argv1 = process.argv[1];
  if (!argv1) return false;
  const thisPath = fileURLToPath(import.meta.url);
  try {
    return realpathSync(argv1) === realpathSync(thisPath);
  } catch {
    return argv1 === thisPath;
  }
}

// Only auto-run when invoked as a script, not when imported by tests.
if (isMainModule()) {
  main();
}

export { writeLine };
