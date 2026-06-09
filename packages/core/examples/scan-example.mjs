// Example: scan a directory and print a human report + an HNDL summary.
//
//   node examples/scan-example.mjs [path]
//
// Defaults to scanning the current working directory. Run after `npm run build`
// so the compiled package is importable from dist/.
import { scan, formatSummary, toSarif, remediationFor } from "../dist/index.js";

const root = process.argv[2] ?? ".";

const result = await scan({
  root,
  onFile: (file) => process.stderr.write(`  scanning ${file}\n`),
});

// 1) Human-readable report (colour on when stdout is a TTY).
console.log(formatSummary(result, { color: process.stdout.isTTY }));

// 2) Highlight the harvest-now-decrypt-later findings specifically.
const hndl = result.findings.filter((f) => f.hndl);
if (hndl.length > 0) {
  console.log(`\n${hndl.length} HNDL-exposed finding(s):`);
  for (const f of hndl) {
    const rec = f.algorithm ? remediationFor(f.algorithm)?.recommendation : f.remediation;
    console.log(`  ${f.location.file}:${f.location.line}  ${f.title}  →  ${rec ?? "review"}`);
  }
}

// 3) SARIF for CI tooling (e.g. GitHub code scanning).
//    Uncomment to emit SARIF to a file:
// import { writeFile } from "node:fs/promises";
// await writeFile("qproof.sarif", JSON.stringify(toSarif(result), null, 2));
void toSarif;

process.exitCode = result.inventory.readinessScore < 100 ? 1 : 0;
