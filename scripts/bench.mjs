#!/usr/bin/env node
// scripts/bench.mjs — zero-dependency benchmark harness (P2-4).
//
// Generates a synthetic source tree of N JS/TS files seeded with sample
// (quantum-vulnerable) crypto, then times the serial `scan()` against the
// worker-pool `scanParallel()` from the BUILT @qproof/core and prints a small
// table: files, ms, files/s, speedup.
//
// Requires a build first: `npm run build` (it imports from dist via the
// @qproof/core workspace package). Run via `npm run bench`.
//
// Flags (all optional):
//   --files=<N>        number of synthetic files to generate (default 1000)
//   --runs=<N>         timed repetitions per mode, best is reported (default 3)
//   --concurrency=<N>  worker count for scanParallel (default: os parallelism)
//   --keep             do not delete the generated tree (for inspection)
//
// Zero runtime deps: only Node built-ins + @qproof/core (a workspace package).

import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir, availableParallelism } from "node:os";
import { join } from "node:path";
import { performance } from "node:perf_hooks";

import { scan, scanParallel } from "@qproof/core";

function parseArgs(argv) {
  const opts = { files: 1000, runs: 3, concurrency: undefined, keep: false };
  for (const arg of argv) {
    const m = /^--([^=]+)(?:=(.*))?$/.exec(arg);
    if (!m) continue;
    const [, key, val] = m;
    switch (key) {
      case "files":
        opts.files = Math.max(1, Number.parseInt(val, 10) || opts.files);
        break;
      case "runs":
        opts.runs = Math.max(1, Number.parseInt(val, 10) || opts.runs);
        break;
      case "concurrency":
        opts.concurrency = Math.max(1, Number.parseInt(val, 10) || 1);
        break;
      case "keep":
        opts.keep = true;
        break;
      default:
        break;
    }
  }
  return opts;
}

// A handful of representative snippets, each containing crypto the detectors
// flag (RSA/EC keygen, ECDH, classical TLS, a vulnerable dependency import).
// Index by file number so the corpus is varied but deterministic.
const SNIPPETS = [
  `import crypto from "node:crypto";
export function makeRsa() {
  return crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
}
`,
  `import crypto from "node:crypto";
export function makeEc() {
  return crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
}
`,
  `import crypto from "node:crypto";
export function ecdh() {
  const a = crypto.createECDH("prime256v1");
  a.generateKeys();
  return a.getPublicKey();
}
`,
  `// classic TLS config
export const tlsOptions = {
  ciphers: "ECDHE-RSA-AES128-GCM-SHA256",
  minVersion: "TLSv1.2",
};
`,
  `import forge from "node-forge";
export function rsaForge() {
  return forge.pki.rsa.generateKeyPair({ bits: 2048 });
}
`,
  // A benign file with no crypto, to keep the corpus realistic.
  `export function add(a: number, b: number): number {
  return a + b;
}
`,
];

async function generateTree(root, fileCount) {
  // Spread files across a few directories so the walker does real work.
  const dirs = ["src", "src/lib", "src/util", "src/net", "src/crypto"];
  for (const d of dirs) {
    await mkdir(join(root, d), { recursive: true });
  }
  let totalBytes = 0;
  const writes = [];
  for (let i = 0; i < fileCount; i++) {
    const dir = dirs[i % dirs.length];
    const ext = i % 2 === 0 ? "ts" : "js";
    const body = SNIPPETS[i % SNIPPETS.length];
    // Pad each file a little so combined size comfortably crosses the
    // serial/parallel byte floor and the chunker has something to split.
    const filler = `// file ${i}\n`.repeat(20);
    const content = `${filler}${body}`;
    totalBytes += Buffer.byteLength(content);
    writes.push(writeFile(join(root, dir, `mod_${i}.${ext}`), content));
  }
  await Promise.all(writes);
  return totalBytes;
}

async function timeBest(label, fn, runs) {
  let best = Infinity;
  let lastResult;
  for (let i = 0; i < runs; i++) {
    const t0 = performance.now();
    lastResult = await fn();
    const dt = performance.now() - t0;
    if (dt < best) best = dt;
  }
  return { label, ms: best, result: lastResult };
}

function fmtMs(ms) {
  return ms.toFixed(1).padStart(9);
}

function fmtRate(filesPerSec) {
  return Math.round(filesPerSec).toLocaleString("en-US").padStart(11);
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  const concurrency = opts.concurrency ?? availableParallelism();

  const root = await mkdtemp(join(tmpdir(), "qproof-bench-"));
  let exitCode = 0;
  try {
    process.stdout.write(`qproof bench — generating ${opts.files} files in ${root} ...\n`);
    const totalBytes = await generateTree(root, opts.files);
    process.stdout.write(
      `generated ${(totalBytes / 1024 / 1024).toFixed(2)} MiB across the tree; ` +
        `concurrency=${concurrency}, runs=${opts.runs} (best reported)\n\n`,
    );

    // Warm-up: one untimed scan so JIT/fs caches don't skew the first timing.
    await scan({ root });

    const serial = await timeBest("scan (serial)", () => scan({ root }), opts.runs);
    const parallel = await timeBest(
      "scanParallel",
      () =>
        scanParallel({
          root,
          concurrency,
          // Force the parallel path regardless of corpus size so the harness
          // measures the worker pool, not the small-repo serial fallback.
          parallelFileThreshold: 1,
          parallelThresholdBytes: 0,
        }),
      opts.runs,
    );

    // Sanity: both paths must agree on what they found, or the comparison is
    // meaningless. Report a warning rather than failing the bench.
    const sFindings = serial.result.findings.length;
    const pFindings = parallel.result.findings.length;
    const sFiles = serial.result.filesScanned;

    const rows = [serial, parallel].map((r) => ({
      mode: r.label,
      files: r.result.filesScanned,
      ms: r.ms,
      rate: (r.result.filesScanned / r.ms) * 1000,
    }));

    const speedup = serial.ms / parallel.ms;

    // Print the table.
    const head =
      "mode".padEnd(16) + "files".padStart(8) + "ms".padStart(11) + "files/s".padStart(13);
    process.stdout.write(head + "\n");
    process.stdout.write("-".repeat(head.length) + "\n");
    for (const row of rows) {
      process.stdout.write(
        row.mode.padEnd(16) +
          String(row.files).padStart(8) +
          fmtMs(row.ms) +
          "  " +
          fmtRate(row.rate) +
          "\n",
      );
    }
    process.stdout.write("\n");
    process.stdout.write(
      `speedup (serial / parallel): ${speedup.toFixed(2)}x` +
        (speedup < 1 ? "  (parallel slower — overhead dominates this corpus)" : "") +
        "\n",
    );

    if (sFindings !== pFindings) {
      process.stderr.write(
        `WARNING: finding counts differ (serial=${sFindings}, parallel=${pFindings}); ` +
          `results may not be comparable.\n`,
      );
      exitCode = 1;
    } else {
      process.stdout.write(
        `(both paths scanned ${sFiles} files and agreed on ${sFindings} findings)\n`,
      );
    }
  } finally {
    if (opts.keep) {
      process.stdout.write(`\nkept generated tree at ${root}\n`);
    } else {
      await rm(root, { recursive: true, force: true });
    }
  }
  process.exit(exitCode);
}

main().catch((err) => {
  process.stderr.write(`bench failed: ${err?.stack ?? err}\n`);
  process.exit(1);
});
