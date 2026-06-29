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
  /**
   * Extra environment variables for the SUT. These are layered ON TOP of the
   * scrubbed base env (see below) — they are the ONLY way to pass arbitrary
   * variables to a SUT unless {@link RunnerOptions.inheritEnv} is set.
   */
  env?: Record<string, string>;
  /**
   * Inherit the FULL parent environment (`process.env`) instead of the scrubbed
   * minimal env. **Default `false`.** The SUT is user-supplied code that Sieve
   * drives; inheriting the parent env hands it every secret in the harness's
   * environment (CI tokens, cloud creds, signing keys). Only enable this for
   * trusted, local implementations you control. See docs/audits/security.md Q-17
   * (CWE-526 / CWE-200).
   */
  inheritEnv?: boolean;
  /**
   * Additional environment variable NAMES to copy from `process.env` into the
   * scrubbed base env (allow-list extension). Has no effect when
   * {@link RunnerOptions.inheritEnv} is `true`. Values are read from the parent
   * env at spawn time; names absent from `process.env` are skipped.
   */
  envAllowlist?: readonly string[];
  /** Optional sink for the SUT's stderr lines (for diagnostics). */
  onStderr?: (line: string) => void;
}

/**
 * Minimal environment variables a child process generally needs to locate its
 * interpreter, resolve its home directory, and produce sane text output. This
 * is the default base env handed to the SUT — secrets in the parent env
 * (tokens, credentials) are NOT forwarded. Extend via
 * {@link RunnerOptions.envAllowlist} or pass explicit {@link RunnerOptions.env}.
 */
export const DEFAULT_ENV_ALLOWLIST: readonly string[] = [
  "PATH",
  "HOME",
  "LANG",
  "LC_ALL",
  "LC_CTYPE",
  "TMPDIR",
  "TMP",
  "TEMP",
  // Windows process-spawn essentials (harmless / empty on POSIX).
  "SystemRoot",
  "SystemDrive",
  "windir",
  "PATHEXT",
  "COMSPEC",
];

/**
 * Build the environment handed to the spawned SUT.
 *
 * By default this is a SCRUBBED, minimal env: only the names in
 * {@link DEFAULT_ENV_ALLOWLIST} (plus any in `opts.envAllowlist`) are copied
 * from the parent `process.env`, then `opts.env` is layered on top. This keeps
 * harness secrets out of untrusted SUT code (security.md Q-17). When
 * `opts.inheritEnv` is set, the full parent env is used instead (legacy /
 * trusted-local behavior).
 *
 * Exported for testing; the returned object never aliases `process.env`.
 */
export function buildSutEnv(
  opts: Pick<RunnerOptions, "env" | "inheritEnv" | "envAllowlist">,
  parentEnv: NodeJS.ProcessEnv = process.env,
): Record<string, string> {
  const out: Record<string, string> = {};
  if (opts.inheritEnv === true) {
    for (const [k, v] of Object.entries(parentEnv)) {
      if (typeof v === "string") out[k] = v;
    }
  } else {
    const names = new Set<string>([...DEFAULT_ENV_ALLOWLIST, ...(opts.envAllowlist ?? [])]);
    for (const name of names) {
      const v = parentEnv[name];
      if (typeof v === "string") out[name] = v;
    }
  }
  // Explicit extra env always wins, even over an inherited value.
  if (opts.env) {
    for (const [k, v] of Object.entries(opts.env)) out[k] = v;
  }
  return out;
}

/** Thrown when a request exceeds its timeout. */
export class TimeoutError extends Error {
  constructor(
    public readonly request: Request,
    public readonly timeoutMs: number,
  ) {
    super(`SUT did not respond to id=${request.id} (${request.op}) within ${timeoutMs}ms`);
    this.name = "TimeoutError";
  }
}

/** Thrown when the SUT process dies before/while a request is in flight. */
export class SutCrashError extends Error {
  constructor(
    message: string,
    public readonly stderr: string,
  ) {
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

/** Cap on retained stderr (and sidelined-stdout notes): most recent 64 KiB. */
const STDERR_CAP = 1 << 16;

/**
 * Largest stdout line we will buffer/decode (64 KiB). A protocol response is
 * tiny; a longer line is a misbehaving or non-protocol SUT, so we sideline it
 * rather than buffer it without bound. Mirrors the stderr cap.
 */
const MAX_STDOUT_LINE = 1 << 16;

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
  private readonly onStderr?: (line: string) => void;

  constructor(opts: RunnerOptions) {
    this.onStderr = opts.onStderr;
    if (opts.command.length === 0) {
      throw new Error("Runner: command must have at least one element");
    }
    this.timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;

    const [bin, ...args] = opts.command;
    this.child = spawn(bin as string, args, {
      cwd: opts.cwd,
      // Scrubbed, minimal env by default — see buildSutEnv / security.md Q-17.
      env: buildSutEnv(opts),
      stdio: ["pipe", "pipe", "pipe"],
    }) as ChildProcessWithoutNullStreams;

    this.child.on("error", (err) => {
      this.failAll(new SutCrashError(`failed to spawn SUT: ${err.message}`, this.stderrBuf));
    });

    this.child.on("exit", (code, signal) => {
      if (this.closed) return;
      const why =
        signal !== null ? `SUT exited via signal ${signal}` : `SUT exited with code ${code}`;
      this.failAll(new SutCrashError(why, this.stderrBuf));
    });

    this.child.stderr.setEncoding("utf8");
    this.child.stderr.on("data", (chunk: string) => {
      this.stderrBuf += chunk;
      if (this.stderrBuf.length > STDERR_CAP) {
        this.stderrBuf = this.stderrBuf.slice(-STDERR_CAP);
      }
      if (this.onStderr) {
        for (const line of chunk.split("\n")) {
          if (line.length > 0) this.onStderr(line);
        }
      }
    });

    this.child.stdout.setEncoding("utf8");
    // crlfDelay groups CRLF; the byte cap is enforced per-line in onLine.
    this.rl = createInterface({ input: this.child.stdout, crlfDelay: Infinity });
    this.rl.on("line", (line) => this.onLine(line));
  }

  /** Stderr captured from the SUT so far (most recent 64 KiB). */
  get stderr(): string {
    return this.stderrBuf;
  }

  private onLine(line: string): void {
    if (line.trim().length === 0) return;
    // Cap the line we attempt to decode, mirroring the stderr cap. A SUT that
    // streams an unbounded line (or never emits a newline) must not let us
    // buffer it without limit before we sideline it as noise.
    if (line.length > MAX_STDOUT_LINE) {
      this.sidelineStdout(`SUT stdout line exceeded ${MAX_STDOUT_LINE} bytes; ignored`);
      return;
    }
    let resp: Response;
    try {
      resp = decodeResponse(line);
    } catch (err) {
      // An undecodable stdout line is NOT fatal: a SUT may legitimately print a
      // banner, log line, or progress note to stdout. We sideline it (surface it
      // via stderr/log) and keep going. Only a process `exit`/`error` poisons the
      // runner via failAll — a stray line must not abort an otherwise-valid run.
      const pe = err as ProtocolError;
      this.sidelineStdout(`ignored non-protocol stdout line: ${pe.message}`);
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

  /**
   * Record a stdout line we could not use (non-protocol banner, oversize line,
   * etc.). It is surfaced through the stderr buffer and the `onStderr` sink for
   * diagnostics, but never fails any request — see the `onLine` rationale.
   */
  private sidelineStdout(detail: string): void {
    const note = `[sieve] ${detail}`;
    this.stderrBuf += note + "\n";
    if (this.stderrBuf.length > STDERR_CAP) {
      this.stderrBuf = this.stderrBuf.slice(-STDERR_CAP);
    }
    if (this.onStderr) this.onStderr(note);
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
   * Issue many INDEPENDENT requests with bounded concurrency (pipelining).
   *
   * The protocol is id-correlated (each response carries the request's `id`),
   * so multiple requests may be in flight against the SUT at once. This writes
   * up to `maxInFlight` requests before awaiting any response, refilling as each
   * completes, and returns results in the SAME ORDER as `reqs` (independent of
   * the order the SUT answers).
   *
   * CORRECTNESS CONSTRAINT: every request in `reqs` MUST be independent of the
   * others — no request may depend on another's response, and the SUT must not
   * carry cross-request state that ordering would expose. Dependent or
   * order-sensitive sequences (e.g. keygen→encaps→decaps for a single key, or
   * the timing category's isolated measurements) MUST use serial `send()`
   * instead. See docs/audits/performance.md §7.1.
   *
   * Setting `maxInFlight <= 1` degrades to strictly serial behavior.
   */
  async sendMany(reqs: readonly RequestInput[], maxInFlight = 16): Promise<Response[]> {
    const limit = Math.max(1, Math.floor(maxInFlight));
    const results: Response[] = new Array(reqs.length);
    let next = 0;
    let firstError: Error | undefined;

    const worker = async (): Promise<void> => {
      while (firstError === undefined) {
        const i = next++;
        if (i >= reqs.length) return;
        try {
          results[i] = await this.send(reqs[i] as RequestInput);
        } catch (err) {
          // Capture the first failure and stop launching new work; in-flight
          // siblings settle on their own (their results are discarded).
          if (firstError === undefined) firstError = err as Error;
          return;
        }
      }
    };

    const workers: Promise<void>[] = [];
    for (let w = 0; w < Math.min(limit, reqs.length); w++) {
      workers.push(worker());
    }
    await Promise.all(workers);
    if (firstError !== undefined) throw firstError;
    return results;
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

    const timed = await Promise.race([exited.then(() => true), delay(graceMs).then(() => false)]);

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
