#!/usr/bin/env node
/**
 * `sieve` command-line interface.
 *
 * Usage:
 *   sieve --impl "<command...>" --param ml-kem-768 [--iterations N]
 *         [--vectors <dir>] [--timing] [--only a,b] [--timeout-ms N] [--json]
 *
 * Exit codes: 0 on overall PASS, 1 on overall FAIL, 2 on a usage error.
 *
 * Zero runtime dependencies — argument parsing is hand-rolled below.
 */

import { runSieve } from "./index.js";
import { formatHuman, formatJson } from "./report.js";
import { isParamSet, PARAM_SETS, type ParamSet } from "./sizes.js";

interface CliOptions {
  impl: string[];
  param: ParamSet;
  iterations: number;
  vectorsDir?: string;
  timing: boolean;
  only?: string[];
  timeoutMs?: number;
  pipelineDepth?: number;
  inheritEnv: boolean;
  json: boolean;
}

const USAGE = `sieve — conformance battery for ML-KEM / ML-DSA implementations

USAGE:
  sieve --impl "<command...>" --param <set> [options]

REQUIRED:
  --impl  "<cmd...>"   Command Sieve spawns and drives over stdin/stdout JSON.
                       Quote the whole command, e.g. --impl "node ./impl.js".
  --param <set>        Parameter set. One of:
                       ${PARAM_SETS.join(", ")}

OPTIONS:
  --iterations <N>     Randomized iterations for applicable categories (default 32).
  --vectors <dir>      Directory of OFFICIAL NIST ACVP vector files for the KAT
                       category. Sieve ships none and never fabricates them; see
                       vectors/README.md. Without this, KAT is SKIPPED.
  --timing             Include the advisory (non-verdict) decaps timing probe.
  --only <a,b,...>     Run only these categories (comma-separated).
  --timeout-ms <N>     Per-request timeout in ms (default 10000).
  --pipeline-depth <N> Max concurrent in-flight requests for independent-iteration
                       categories (default 16). Use 1 for strictly serial.
  --inherit-env        Pass the FULL parent environment to the SUT. DANGEROUS:
                       the SUT is untrusted code; by default Sieve scrubs the env
                       to a minimal allow-list. Only for trusted local impls.
  --json               Emit the report as JSON instead of human-readable text.
  -h, --help           Show this help.

EXIT: 0 = PASS, 1 = FAIL, 2 = usage error.`;

class UsageError extends Error {}

function parseArgs(argv: readonly string[]): CliOptions {
  let impl: string[] | undefined;
  let param: ParamSet | undefined;
  let iterations = 32;
  let vectorsDir: string | undefined;
  let timing = false;
  let only: string[] | undefined;
  let timeoutMs: number | undefined;
  let pipelineDepth: number | undefined;
  let inheritEnv = false;
  let json = false;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i] as string;
    const eq = arg.indexOf("=");
    const flag = eq >= 0 ? arg.slice(0, eq) : arg;
    const inlineVal = eq >= 0 ? arg.slice(eq + 1) : undefined;
    const next = (): string => {
      if (inlineVal !== undefined) return inlineVal;
      const v = argv[++i];
      if (v === undefined) throw new UsageError(`flag ${flag} requires a value`);
      return v;
    };

    switch (flag) {
      case "--impl": {
        const raw = next().trim();
        impl = raw.split(/\s+/).filter((s) => s.length > 0);
        if (impl.length === 0) throw new UsageError("--impl command is empty");
        break;
      }
      case "--param": {
        const p = next();
        if (!isParamSet(p)) {
          throw new UsageError(`unknown --param "${p}"; expected one of ${PARAM_SETS.join(", ")}`);
        }
        param = p;
        break;
      }
      case "--iterations": {
        const n = Number(next());
        if (!Number.isInteger(n) || n < 1) throw new UsageError("--iterations must be a positive integer");
        iterations = n;
        break;
      }
      case "--vectors":
        vectorsDir = next();
        break;
      case "--timing":
        timing = true;
        break;
      case "--only":
        only = next().split(",").map((s) => s.trim()).filter((s) => s.length > 0);
        break;
      case "--timeout-ms": {
        const n = Number(next());
        if (!Number.isInteger(n) || n < 1) throw new UsageError("--timeout-ms must be a positive integer");
        timeoutMs = n;
        break;
      }
      case "--pipeline-depth": {
        const n = Number(next());
        if (!Number.isInteger(n) || n < 1) throw new UsageError("--pipeline-depth must be a positive integer");
        pipelineDepth = n;
        break;
      }
      case "--inherit-env":
        inheritEnv = true;
        break;
      case "--json":
        json = true;
        break;
      case "-h":
      case "--help":
        process.stdout.write(USAGE + "\n");
        process.exit(0);
        break;
      default:
        throw new UsageError(`unknown flag: ${flag}`);
    }
  }

  if (!impl) throw new UsageError("missing required --impl");
  if (!param) throw new UsageError("missing required --param");

  return {
    impl,
    param,
    iterations,
    ...(vectorsDir ? { vectorsDir } : {}),
    timing,
    ...(only ? { only } : {}),
    ...(timeoutMs !== undefined ? { timeoutMs } : {}),
    ...(pipelineDepth !== undefined ? { pipelineDepth } : {}),
    inheritEnv,
    json,
  };
}

async function main(): Promise<number> {
  let opts: CliOptions;
  try {
    opts = parseArgs(process.argv.slice(2));
  } catch (err) {
    if (err instanceof UsageError) {
      process.stderr.write(`error: ${err.message}\n\n${USAGE}\n`);
      return 2;
    }
    throw err;
  }

  const report = await runSieve({
    command: opts.impl,
    param: opts.param,
    iterations: opts.iterations,
    ...(opts.vectorsDir ? { vectorsDir: opts.vectorsDir } : {}),
    timing: opts.timing,
    ...(opts.only ? { only: opts.only } : {}),
    ...(opts.timeoutMs !== undefined ? { timeoutMs: opts.timeoutMs } : {}),
    ...(opts.pipelineDepth !== undefined ? { pipelineDepth: opts.pipelineDepth } : {}),
    ...(opts.inheritEnv ? { inheritEnv: true } : {}),
  });

  process.stdout.write((opts.json ? formatJson(report) : formatHuman(report)) + "\n");
  return report.overall === "PASS" ? 0 : 1;
}

main().then(
  (code) => process.exit(code),
  (err) => {
    process.stderr.write(`sieve: fatal: ${(err as Error).stack ?? String(err)}\n`);
    process.exit(2);
  },
);
