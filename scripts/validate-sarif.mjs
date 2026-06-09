#!/usr/bin/env node
// scripts/validate-sarif.mjs — SARIF 2.1.0 STRUCTURAL validator (P2-6).
//
// Asserts the required SARIF 2.1.0 structure that downstream consumers (GitHub
// code scanning, etc.) depend on, and exits non-zero with a clear message on
// the first violation.
//
// HONEST SCOPE: this is a *structural* check, not full JSON-Schema validation.
// It verifies presence and basic types of the load-bearing fields — $schema,
// version === "2.1.0", runs[], each run's tool.driver.name + rules, and each
// result's ruleId / level / message.text / locations[].physicalLocation. It
// does NOT validate against the official sarif-schema-2.1.0.json (that would
// need a JSON-Schema engine, and we keep this repo zero-dependency).
//
// Usage:
//   node scripts/validate-sarif.mjs <path-to.sarif.json>   # validate a file
//   node scripts/validate-sarif.mjs                         # scan ./packages,
//                                                           # produce + validate
//
// Zero runtime deps: Node built-ins + @qproof/core (a workspace package, only
// used in the "produce a SARIF" mode). Requires `npm run build` first for that
// mode.

import { readFile } from "node:fs/promises";
import process from "node:process";

const VALID_LEVELS = new Set(["error", "warning", "note", "none"]);

/** A structural violation, collected with a JSON-path-ish location. */
class SarifViolations {
  constructor() {
    this.errors = [];
  }
  add(path, message) {
    this.errors.push(`${path}: ${message}`);
  }
  get ok() {
    return this.errors.length === 0;
  }
}

function isObject(v) {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * Validate the SARIF document structure. Returns a {@link SarifViolations}.
 * Collects ALL violations (does not stop at the first) so the report is useful.
 */
export function validateSarif(doc) {
  const v = new SarifViolations();

  if (!isObject(doc)) {
    v.add("$", "top-level value must be a JSON object");
    return v;
  }
  if (typeof doc.$schema !== "string" || doc.$schema.length === 0) {
    v.add("$.$schema", 'missing or empty "$schema" string');
  }
  if (doc.version !== "2.1.0") {
    v.add("$.version", `expected "2.1.0", got ${JSON.stringify(doc.version)}`);
  }
  if (!Array.isArray(doc.runs)) {
    v.add("$.runs", "missing or non-array runs[]");
    return v; // nothing more to check without runs.
  }
  if (doc.runs.length === 0) {
    v.add("$.runs", "runs[] is empty (expected at least one run)");
  }

  doc.runs.forEach((run, ri) => {
    const rp = `$.runs[${ri}]`;
    if (!isObject(run)) {
      v.add(rp, "run must be an object");
      return;
    }
    // tool.driver.name + rules.
    const driver = isObject(run.tool) ? run.tool.driver : undefined;
    if (!isObject(driver)) {
      v.add(`${rp}.tool.driver`, "missing tool.driver object");
    } else {
      if (typeof driver.name !== "string" || driver.name.length === 0) {
        v.add(`${rp}.tool.driver.name`, "missing or empty driver name");
      }
      if (!Array.isArray(driver.rules)) {
        v.add(`${rp}.tool.driver.rules`, "missing or non-array rules[]");
      } else {
        driver.rules.forEach((rule, idx) => {
          if (!isObject(rule) || typeof rule.id !== "string" || rule.id.length === 0) {
            v.add(`${rp}.tool.driver.rules[${idx}].id`, "rule missing a non-empty string id");
          }
        });
      }
    }

    // results[] (may be absent for a clean scan; if present, validate each).
    if (run.results !== undefined) {
      if (!Array.isArray(run.results)) {
        v.add(`${rp}.results`, "results must be an array when present");
      } else {
        run.results.forEach((res, si) => validateResult(res, `${rp}.results[${si}]`, v));
      }
    }
  });

  return v;
}

/** Validate a single SARIF result object. */
function validateResult(res, path, v) {
  if (!isObject(res)) {
    v.add(path, "result must be an object");
    return;
  }
  if (typeof res.ruleId !== "string" || res.ruleId.length === 0) {
    v.add(`${path}.ruleId`, "missing or empty ruleId");
  }
  if (typeof res.level !== "string" || !VALID_LEVELS.has(res.level)) {
    v.add(
      `${path}.level`,
      `level must be one of ${[...VALID_LEVELS].join("|")}, got ${JSON.stringify(res.level)}`,
    );
  }
  if (!isObject(res.message) || typeof res.message.text !== "string") {
    v.add(`${path}.message.text`, "missing message.text string");
  }
  if (!Array.isArray(res.locations) || res.locations.length === 0) {
    v.add(`${path}.locations`, "missing or empty locations[]");
  } else {
    res.locations.forEach((loc, li) => {
      if (!isObject(loc) || !isObject(loc.physicalLocation)) {
        v.add(`${path}.locations[${li}].physicalLocation`, "missing physicalLocation object");
        return;
      }
      const art = loc.physicalLocation.artifactLocation;
      if (!isObject(art) || typeof art.uri !== "string") {
        v.add(
          `${path}.locations[${li}].physicalLocation.artifactLocation.uri`,
          "missing artifactLocation.uri string",
        );
      }
    });
  }
}

/** Load + validate a SARIF file path. Returns the violations bundle. */
async function validateFile(file) {
  let text;
  try {
    text = await readFile(file, "utf8");
  } catch (err) {
    const v = new SarifViolations();
    v.add(file, `cannot read file: ${err.message}`);
    return v;
  }
  let doc;
  try {
    doc = JSON.parse(text);
  } catch (err) {
    const v = new SarifViolations();
    v.add(file, `invalid JSON: ${err.message}`);
    return v;
  }
  return validateSarif(doc);
}

/** Produce a SARIF doc by scanning ./packages with the BUILT @qproof/core. */
async function produceSarif() {
  const { scan, toSarif } = await import("@qproof/core");
  const result = await scan({ root: "packages" });
  return toSarif(result);
}

async function main(argv) {
  const file = argv[0];
  let violations;
  let label;

  if (file) {
    label = file;
    violations = await validateFile(file);
  } else {
    label = "(scan of ./packages)";
    try {
      const doc = await produceSarif();
      violations = validateSarif(doc);
    } catch (err) {
      process.stderr.write(
        `validate-sarif: failed to produce SARIF (did you run \`npm run build\`?): ${err.message}\n`,
      );
      return 2;
    }
  }

  if (violations.ok) {
    process.stdout.write(`validate-sarif: OK — ${label} is structurally valid SARIF 2.1.0.\n`);
    return 0;
  }

  process.stderr.write(`validate-sarif: ${violations.errors.length} violation(s) in ${label}:\n`);
  for (const e of violations.errors) process.stderr.write(`  - ${e}\n`);
  return 1;
}

main(process.argv.slice(2))
  .then((code) => process.exit(code))
  .catch((err) => {
    process.stderr.write(`validate-sarif: fatal: ${err?.stack ?? err}\n`);
    process.exit(2);
  });
