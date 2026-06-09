/**
 * The SUT runner: spawns a user-provided implementation as a child process and
 * exchanges newline-delimited JSON requests/responses over stdin/stdout.
 *
 * Responsibilities:
 *   - spawn the command, wire up a readline interface on its stdout,
 *   - correlate responses to requests by `id`,
 *   - enforce a per-request timeout,
 *   - surface SUT crashes / stderr,
 *   - tear the process down cleanly.
 *
 * Uses only node:child_process and node:readline. No cryptography here.
 */

import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createInterface, type Interface } from "node:readline";

import {
  decodeResponse,
  encodeRequest,
  ProtocolError,
  type Request,
  type RequestInput,
  type Response,
} from "./protocol.js";

/** Options for constructing a {@link Runner}. */
export interface RunnerOptions {
  /** Argv of the SUT, e.g. ["node", "./my-impl.js"]. First item is the bin. */
  command: readonly string[];
  /** Per-request timeout in milliseconds. */
  timeoutMs?: number;
  /** Working directory for the child process. */
  cwd?: string;
  /** Extra environment variables, merged over the current process env. */
  env?: Record<string, string>;
  /** Optional sink for the SUT's stderr lines (for diagnostics). */
  onStderr?: (line: string) => void;
}

/** Thrown when a request exceeds its timeout. */
export class TimeoutError extends Error {
  constructor(public readonly request: Request, public readonly timeoutMs: number) {
    super(`SUT did not respond to id=${request.id} (${request.op}) within ${timeoutMs}ms`);
    this.name = "TimeoutError";
  }
}

/** Thrown when the SUT process dies before/while a request is in flight. */
export class SutCrashError extends Error {
  constructor(message: string, public readonly stderr: string) {
    super(message);
    this.name = "SutCrashError";
  }
}

interface Pending {
  resolve: (r: Response) => void;
  reject: (e: Error) => void;
  timer: NodeJS.Timeout;
}

const DEFAULT_TIMEOUT_MS = 10_000;

/**
 * A long-lived handle to a spawned SUT. Construct once per test run, issue many
 * requests, then `close()`. Requests are matched to responses by `id`, so the
 * SUT MAY answer out of order, though in practice it answers serially.
 */
export class Runner {
  private readonly child: ChildProcessWithoutNullStreams;
  private readonly rl: Interface;
  private readonly pending = new Map<number, Pending>();
  private readonly timeoutMs: number;
  private nextId = 1;
  private stderrBuf = "";
  private closed = false;
  private fatal: Error | undefined;

  constructor(opts: RunnerOptions) {
    if (opts.command.length === 0) {
      throw new Error("Runner: command must have at least one element");
    }
    this.timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;

    const [bin, ...args] = opts.command;
    this.child = spawn(bin as string, args, {
      cwd: opts.cwd,
      env: { ...process.env, ...opts.env },
      stdio: ["pipe", "pipe", "pipe"],
    }) as ChildProcessWithoutNullStreams;

    this.child.on("error", (err) => {
      this.failAll(new SutCrashError(`failed to spawn SUT: ${err.message}`, this.stderrBuf));
    });

    this.child.on("exit", (code, signal) => {
      if (this.closed) return;
      const why =
        signal !== null
          ? `SUT exited via signal ${signal}`
          : `SUT exited with code ${code}`;
      this.failAll(new SutCrashError(why, this.stderrBuf));
    });

    this.child.stderr.setEncoding("utf8");
    this.child.stderr.on("data", (chunk: string) => {
      this.stderrBuf += chunk;
      if (this.stderrBuf.length > 1 << 16) {
        this.stderrBuf = this.stderrBuf.slice(-(1 << 16));
      }
      if (opts.onStderr) {
        for (const line of chunk.split("\n")) {
          if (line.length > 0) opts.onStderr(line);
        }
      }
    });

    this.rl = createInterface({ input: this.child.stdout });
    this.rl.on("line", (line) => this.onLine(line));
  }

  /** Stderr captured from the SUT so far (most recent 64 KiB). */
  get stderr(): string {
    return this.stderrBuf;
  }

  private onLine(line: string): void {
    if (line.trim().length === 0) return;
    let resp: Response;
    try {
      resp = decodeResponse(line);
    } catch (err) {
      // A protocol violation on a line we can't correlate is fatal; if we can
      // extract an id, fail just that request, else fail everything.
      const pe = err as ProtocolError;
      this.failAll(pe);
      return;
    }
    const entry = this.pending.get(resp.id);
    if (entry === undefined) {
      // Unsolicited / duplicate id — record but do not crash the run.
      return;
    }
    clearTimeout(entry.timer);
    this.pending.delete(resp.id);
    entry.resolve(resp);
  }

  private failAll(err: Error): void {
    if (this.fatal === undefined) this.fatal = err;
    for (const [, p] of this.pending) {
      clearTimeout(p.timer);
      p.reject(err);
    }
    this.pending.clear();
  }

  /**
   * Send one request and await its response. The `id` field is assigned by the
   * runner; any `id` on the passed object is overwritten.
   */
  send(req: RequestInput): Promise<Response> {
    if (this.closed) {
      return Promise.reject(new Error("Runner is closed"));
    }
    if (this.fatal !== undefined) {
      return Promise.reject(this.fatal);
    }
    const id = this.nextId++;
    const full = { ...req, id } as Request;

    return new Promise<Response>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new TimeoutError(full, this.timeoutMs));
      }, this.timeoutMs);
      // Do not keep the event loop alive solely for this timer.
      if (typeof timer.unref === "function") timer.unref();

      this.pending.set(id, { resolve, reject, timer });

      this.child.stdin.write(encodeRequest(full), (err) => {
        if (err) {
          clearTimeout(timer);
          this.pending.delete(id);
          reject(new SutCrashError(`write to SUT failed: ${err.message}`, this.stderrBuf));
        }
      });
    });
  }

  /**
   * Gracefully shut the SUT down: end stdin, wait briefly for a clean exit,
   * then SIGTERM, then SIGKILL. Idempotent.
   */
  async close(graceMs = 500): Promise<void> {
    if (this.closed) return;
    this.closed = true;

    this.rl.close();
    try {
      this.child.stdin.end();
    } catch {
      /* already closed */
    }

    const exited = new Promise<void>((resolve) => {
      if (this.child.exitCode !== null || this.child.signalCode !== null) {
        resolve();
        return;
      }
      this.child.once("exit", () => resolve());
    });

    const timed = await Promise.race([
      exited.then(() => true),
      delay(graceMs).then(() => false),
    ]);

    if (!timed && this.child.exitCode === null) {
      this.child.kill("SIGTERM");
      const killed = await Promise.race([
        exited.then(() => true),
        delay(graceMs).then(() => false),
      ]);
      if (!killed && this.child.exitCode === null) {
        this.child.kill("SIGKILL");
      }
    }
  }
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => {
    const t = setTimeout(resolve, ms);
    if (typeof t.unref === "function") t.unref();
  });
}
