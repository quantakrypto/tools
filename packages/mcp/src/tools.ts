/**
 * quantakrypto MCP tools, backed by {@link @quantakrypto/core}.
 *
 * Every tool returns an MCP {@link ToolResult} ({ content, isError? }). Because
 * `@quantakrypto/core` is still partly stubbed (several functions throw "not
 * implemented"), each handler runs core calls through {@link safe} so a missing
 * implementation surfaces as a readable `isError` tool result instead of a
 * protocol-level crash. When core lands, the tools work unchanged.
 */

import process from "node:process";

import {
  VERSION,
  AbortError,
  BudgetExceededError,
  buildInventory,
  detectors,
  remediationFor,
  scan,
  toCbom,
} from "@quantakrypto/core";
import type {
  AlgorithmFamily,
  CryptoInventory,
  Remediation,
  ScanOptions,
  ScanResult,
  Severity,
} from "@quantakrypto/core";

import { errorResult, textResult } from "./protocol.js";
import type { JsonSchema, ToolContext, ToolDefinition, ToolResult } from "./protocol.js";
import { resolveRule } from "./rules.js";
import { resolveFsConfig, resolveScanPath } from "./fsconfig.js";

/** Severity order for stable, human-friendly summaries. */
const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

/** All classical algorithm families we can advise on, used for validation/help. */
const ALGORITHM_FAMILIES: AlgorithmFamily[] = [
  "RSA",
  "ECDH",
  "ECDSA",
  "EdDSA",
  "DH",
  "DSA",
  "X25519",
  "ECIES",
  "unknown",
];

/**
 * Map a core failure to a caller-safe message. Cancellation and budget overflows
 * are intentional, expected outcomes — their messages are author-controlled and
 * carry no host detail, so they pass through. Every other error may embed a
 * server path (an `ENOENT … '/etc/shadow'`, a stack), so it is logged locally
 * and replaced with a generic string; the remote caller never sees internals.
 */
function describeError(label: string, err: unknown): string {
  if (err instanceof AbortError) return `${label} was aborted (request timed out).`;
  if (err instanceof BudgetExceededError) {
    // Author-written, no host detail: "maxFiles budget exceeded (limit: …)".
    return `${label} failed: ${err.message}`;
  }
  const detail = err instanceof Error ? (err.stack ?? err.message) : String(err);
  process.stderr.write(`quantakrypto MCP: ${label} failed: ${detail}\n`);
  return `${label} failed: an internal error occurred.`;
}

/**
 * Run a possibly-throwing core call, mapping any failure to an error tool
 * result. Returns either the value or a {@link ToolResult} sentinel. Error
 * messages are sanitized via {@link describeError} so server paths never leak.
 */
async function safe<T>(
  label: string,
  fn: () => T | Promise<T>,
): Promise<{ ok: true; value: T } | { ok: false; result: ToolResult }> {
  try {
    return { ok: true, value: await fn() };
  } catch (err) {
    return { ok: false, result: errorResult(describeError(label, err)) };
  }
}

/**
 * Resolve the FS-tool policy (root allow-list + work budgets) once per call from
 * the live environment, then validate the caller's path against it and assemble
 * the {@link ScanOptions} for a confined, bounded, cancellable scan.
 *
 * Returns an `errorResult` when the path escapes the allow-list (a `..`
 * traversal or an out-of-root absolute path), so the FS tools can `return` it
 * directly. The `signal` from the transport's request deadline (when present) is
 * threaded in so a timed-out request actually aborts the underlying scan.
 */
function buildScanOptions(
  requested: string,
  context?: ToolContext,
): { ok: true; options: ScanOptions } | { ok: false; result: ToolResult } {
  const config = resolveFsConfig(process.env);
  const decision = resolveScanPath(config, requested);
  if (!decision.ok) {
    return { ok: false, result: errorResult(`scan rejected: ${decision.reason}`) };
  }
  return {
    ok: true,
    options: {
      root: decision.path,
      signal: context?.signal,
      maxFiles: config.maxFiles,
      maxBytes: config.maxBytes,
    },
  };
}

/** Map a free-text algorithm string onto a known {@link AlgorithmFamily}. */
function normalizeAlgorithm(input: string): AlgorithmFamily {
  const cleaned = input
    .trim()
    .toUpperCase()
    .replace(/[\s_-]+/g, "");
  for (const fam of ALGORITHM_FAMILIES) {
    if (fam.toUpperCase() === cleaned) return fam;
  }
  // Common aliases / families folded into the canonical set.
  if (cleaned.startsWith("RSA")) return "RSA";
  if (cleaned.includes("ECDSA")) return "ECDSA";
  if (cleaned.includes("ED25519") || cleaned.includes("EDDSA")) return "EdDSA";
  if (cleaned.includes("X25519") || cleaned.includes("CURVE25519")) return "X25519";
  if (cleaned.includes("ECDH")) return "ECDH";
  if (cleaned.includes("ECIES")) return "ECIES";
  if (cleaned === "DH" || cleaned.includes("DIFFIEHELLMAN")) return "DH";
  if (cleaned === "DSA") return "DSA";
  return "unknown";
}

/** Render a scan result as a compact human-readable summary. */
function summarizeScan(result: ScanResult): string {
  const inv = result.inventory;
  const lines: string[] = [];
  lines.push(`quantakrypto scan of ${result.root}`);
  lines.push(`Files scanned: ${result.filesScanned}`);
  lines.push(`Findings: ${result.findings.length}`);
  lines.push(`Readiness score: ${inv.readinessScore}/100`);
  lines.push(`Harvest-now-decrypt-later exposure: ${inv.hndlCount} finding(s)`);

  const sev = SEVERITY_ORDER.filter((s) => (inv.bySeverity[s] ?? 0) > 0)
    .map((s) => `${s}: ${inv.bySeverity[s]}`)
    .join(", ");
  if (sev) lines.push(`By severity: ${sev}`);

  const algos = Object.entries(inv.byAlgorithm)
    .filter(([, n]) => (n ?? 0) > 0)
    .map(([a, n]) => `${a}: ${n}`)
    .join(", ");
  if (algos) lines.push(`By algorithm: ${algos}`);

  if (result.findings.length > 0) {
    lines.push("");
    lines.push("Top findings:");
    const top = [...result.findings]
      .sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity))
      .slice(0, 20);
    for (const f of top) {
      const loc = `${f.location.file}:${f.location.line}`;
      lines.push(`- [${f.severity}] ${f.ruleId} (${loc}) — ${f.message}`);
    }
    if (result.findings.length > top.length) {
      lines.push(`… and ${result.findings.length - top.length} more.`);
    }
  }
  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Tool definitions
// ---------------------------------------------------------------------------

const scanPathTool: ToolDefinition = {
  name: "scan_path",
  description:
    "Scan a file or directory for classical (quantum-vulnerable) asymmetric " +
    "cryptography using quantakrypto. Returns a readiness summary and findings.",
  inputSchema: {
    type: "object",
    properties: {
      path: {
        type: "string",
        description: "Absolute or relative path to a file or directory to scan.",
      },
      format: {
        type: "string",
        enum: ["summary", "json"],
        description:
          "Output format: 'summary' (default) for readable text, 'json' for the raw ScanResult.",
      },
    },
    required: ["path"],
    additionalProperties: false,
  },
  async handler(args, context): Promise<ToolResult> {
    const path = args.path;
    if (typeof path !== "string" || path.length === 0) {
      return errorResult("scan_path requires a non-empty 'path' string.");
    }
    const format = args.format === "json" ? "json" : "summary";
    const opts = buildScanOptions(path, context);
    if (!opts.ok) return opts.result;
    const scanned = await safe("scan", () => scan(opts.options));
    if (!scanned.ok) return scanned.result;
    const result = scanned.value;
    if (format === "json") {
      return textResult(JSON.stringify(result, null, 2));
    }
    return textResult(summarizeScan(result));
  },
};

const inventoryCryptoTool: ToolDefinition = {
  name: "inventory_crypto",
  description:
    "Produce a post-quantum readiness inventory for a path: a 0-100 readiness " +
    "score plus counts of cryptographic findings by algorithm, category, and severity.",
  inputSchema: {
    type: "object",
    properties: {
      path: {
        type: "string",
        description: "Absolute or relative path to a file or directory to inventory.",
      },
    },
    required: ["path"],
    additionalProperties: false,
  },
  async handler(args, context): Promise<ToolResult> {
    const path = args.path;
    if (typeof path !== "string" || path.length === 0) {
      return errorResult("inventory_crypto requires a non-empty 'path' string.");
    }
    const opts = buildScanOptions(path, context);
    if (!opts.ok) return opts.result;
    const scanned = await safe("scan", () => scan(opts.options));
    if (!scanned.ok) return scanned.result;
    const result = scanned.value;

    // Prefer a freshly built inventory from findings; fall back to the scan's own.
    const built = await safe<CryptoInventory>("buildInventory", () =>
      buildInventory(result.findings),
    );
    const inventory = built.ok ? built.value : result.inventory;

    const lines: string[] = [];
    lines.push(`Post-quantum readiness for ${result.root}`);
    lines.push(`Readiness score: ${inventory.readinessScore}/100`);
    lines.push(`HNDL exposure: ${inventory.hndlCount}`);
    lines.push("");
    lines.push("By algorithm:");
    for (const [algo, n] of Object.entries(inventory.byAlgorithm)) {
      if ((n ?? 0) > 0) lines.push(`  ${algo}: ${n}`);
    }
    lines.push("By category:");
    for (const [cat, n] of Object.entries(inventory.byCategory)) {
      if ((n ?? 0) > 0) lines.push(`  ${cat}: ${n}`);
    }
    lines.push("By severity:");
    for (const sev of SEVERITY_ORDER) {
      const n = inventory.bySeverity[sev] ?? 0;
      if (n > 0) lines.push(`  ${sev}: ${n}`);
    }
    return {
      content: [
        { type: "text", text: lines.join("\n") },
        { type: "text", text: JSON.stringify(inventory, null, 2) },
      ],
    };
  },
};

const explainFindingTool: ToolDefinition = {
  name: "explain_finding",
  description:
    "Explain a quantakrypto finding and its post-quantum remediation. Provide a " +
    "ruleId (e.g. 'forge-rsa-keygen', 'elliptic-ec', 'node-rsa', 'pem-ec-private-key') " +
    "and/or an algorithm (e.g. 'RSA', 'ECDSA'). The ruleId is resolved against the " +
    "core detector set, so library and config rules explain correctly.",
  inputSchema: {
    type: "object",
    properties: {
      ruleId: {
        type: "string",
        description: "The finding's rule id, matching a detector id prefix.",
      },
      algorithm: {
        type: "string",
        description: "The classical algorithm family involved (e.g. RSA, ECDH, ECDSA).",
      },
    },
    additionalProperties: false,
  },
  async handler(args): Promise<ToolResult> {
    const ruleId = typeof args.ruleId === "string" ? args.ruleId.trim() : "";
    const algoInput = typeof args.algorithm === "string" ? args.algorithm.trim() : "";
    if (!ruleId && !algoInput) {
      return errorResult("explain_finding requires at least one of 'ruleId' or 'algorithm'.");
    }

    const lines: string[] = [];

    // Resolve the rule against core's actual detector set/registry (P0-5),
    // not by a fragile id-prefix match. Library rules (forge-*, elliptic-ec,
    // node-rsa, …) resolve to their `crypto-libs` detector and carry their
    // algorithm, so they now explain correctly.
    let resolvedAlgorithm: AlgorithmFamily | undefined;
    if (ruleId) {
      const resolved = resolveRule(ruleId);
      resolvedAlgorithm = resolved.algorithm;
      lines.push(`Rule: ${ruleId}`);
      if (resolved.detector) {
        lines.push(`Detector: ${resolved.detector.id} — ${resolved.detector.description}`);
      } else if (resolved.via === "unresolved") {
        lines.push(
          "No matching detector found in the catalog (rule may be unknown to this core version).",
        );
      }
    }

    // Prefer an explicit algorithm; otherwise use the one the rule resolved to.
    const algorithm: AlgorithmFamily | undefined = algoInput
      ? normalizeAlgorithm(algoInput)
      : resolvedAlgorithm && resolvedAlgorithm !== "unknown"
        ? resolvedAlgorithm
        : undefined;

    if (algorithm) {
      if (lines.length) lines.push("");
      lines.push(`Algorithm: ${algorithm}`);
      const rem = await safe<Remediation | undefined>("remediationFor", () =>
        remediationFor(algorithm),
      );
      if (rem.ok && rem.value) {
        lines.push(
          `Why it matters: ${algorithm} relies on hardness assumptions (integer factorization / discrete log) that Shor's algorithm breaks on a cryptographically-relevant quantum computer.`,
        );
        lines.push(`Recommendation: ${rem.value.recommendation}`);
        lines.push(`Detail: ${rem.value.detail}`);
      } else if (rem.ok) {
        lines.push("No specific remediation is registered for this algorithm.");
      } else {
        return rem.result;
      }
    }

    return textResult(lines.join("\n"));
  },
};

const suggestHybridTool: ToolDefinition = {
  name: "suggest_hybrid",
  description:
    "Recommend a post-quantum / hybrid migration. Provide an 'algorithm' " +
    "(e.g. RSA, ECDH, ECDSA) or free-text 'context' describing the usage.",
  inputSchema: {
    type: "object",
    properties: {
      algorithm: {
        type: "string",
        description: "Classical algorithm family to migrate away from.",
      },
      context: {
        type: "string",
        description:
          "Free-text description of the cryptographic usage (used when no algorithm is given).",
      },
    },
    additionalProperties: false,
  },
  async handler(args): Promise<ToolResult> {
    const algoInput = typeof args.algorithm === "string" ? args.algorithm.trim() : "";
    const context = typeof args.context === "string" ? args.context.trim() : "";
    if (!algoInput && !context) {
      return errorResult("suggest_hybrid requires either 'algorithm' or 'context'.");
    }

    const algorithm = normalizeAlgorithm(algoInput || context);
    const lines: string[] = [];
    lines.push(`Migration guidance for: ${algoInput || context}`);
    lines.push(`Detected family: ${algorithm}`);

    const rem = await safe<Remediation | undefined>("remediationFor", () =>
      remediationFor(algorithm),
    );
    if (rem.ok && rem.value) {
      lines.push(`Recommended replacement: ${rem.value.recommendation}`);
      lines.push(`Rationale: ${rem.value.detail}`);
    } else {
      // Static fallback table so the tool stays useful even with a stubbed core.
      lines.push(...staticHybridAdvice(algorithm));
    }

    lines.push("");
    lines.push(
      "Hybrid migrations combine a classical primitive with a NIST PQC algorithm " +
        "so security holds if either survives. Roll out hybrids first, then drop the " +
        "classical half once the PQC side is proven in your environment.",
    );
    return textResult(lines.join("\n"));
  },
};

/** Built-in PQC guidance used when core's remediation table is unavailable. */
function staticHybridAdvice(algorithm: AlgorithmFamily): string[] {
  switch (algorithm) {
    case "RSA":
    case "ECIES":
      return [
        "Recommended replacement: ML-KEM-768 for key establishment (hybrid X25519MLKEM768).",
        "For signatures use ML-DSA-65 (Dilithium) or SLH-DSA (SPHINCS+) where statelessness matters.",
      ];
    case "ECDH":
    case "DH":
    case "X25519":
      return [
        "Recommended replacement: hybrid X25519MLKEM768 key exchange (ML-KEM-768 + X25519).",
        "Supported in modern TLS 1.3 stacks; prefer the hybrid named group over bare ML-KEM.",
      ];
    case "ECDSA":
    case "EdDSA":
    case "DSA":
      return [
        "Recommended replacement: ML-DSA-65 (Dilithium) for general signatures.",
        "Use SLH-DSA (SPHINCS+) for long-lived roots or where a stateless hash-based scheme is preferred.",
      ];
    default:
      return [
        "Recommended replacement: adopt NIST PQC — ML-KEM for key establishment, ML-DSA for signatures.",
        "Deploy as hybrids (classical + PQC) during transition.",
      ];
  }
}

const listRulesTool: ToolDefinition = {
  name: "list_rules",
  description: "List the quantakrypto detector catalog: every detector id and what it looks for.",
  inputSchema: {
    type: "object",
    properties: {},
    additionalProperties: false,
  },
  async handler(): Promise<ToolResult> {
    const detectorList = await safe("detectors", () => detectors);
    if (!detectorList.ok) return detectorList.result;
    const catalog = detectorList.value.map((d) => ({ id: d.id, description: d.description }));
    if (catalog.length === 0) {
      return textResult(
        "No detectors are registered in @quantakrypto/core yet (the catalog is empty).",
      );
    }
    const human = catalog.map((d) => `- ${d.id}: ${d.description}`).join("\n");
    return {
      content: [
        {
          type: "text",
          text: `quantakrypto detector catalog (${catalog.length} rules):\n${human}`,
        },
        { type: "text", text: JSON.stringify(catalog, null, 2) },
      ],
    };
  },
};

const generateCbomTool: ToolDefinition = {
  name: "generate_cbom",
  description:
    "Scan a path and emit a CycloneDX 1.6 Cryptographic Bill of Materials (CBOM) " +
    "of the classical cryptographic assets found, for compliance / supply-chain " +
    "tooling. Reads the filesystem, so it is gated like scan_path over HTTP.",
  inputSchema: {
    type: "object",
    properties: {
      path: {
        type: "string",
        description: "Absolute or relative path to a file or directory to inventory.",
      },
    },
    required: ["path"],
    additionalProperties: false,
  },
  async handler(args, context): Promise<ToolResult> {
    const path = args.path;
    if (typeof path !== "string" || path.length === 0) {
      return errorResult("generate_cbom requires a non-empty 'path' string.");
    }
    const opts = buildScanOptions(path, context);
    if (!opts.ok) return opts.result;
    const scanned = await safe("scan", () => scan(opts.options));
    if (!scanned.ok) return scanned.result;
    const cbom = await safe("toCbom", () => toCbom(scanned.value));
    if (!cbom.ok) return cbom.result;
    return textResult(JSON.stringify(cbom.value, null, 2));
  },
};

/**
 * Tools that read arbitrary filesystem paths. Disabled by default on the HTTP
 * transport (see {@link ./http.ts}) because a hosted endpoint must not be an
 * arbitrary-file-read oracle (security audit Q-01). The stdio transport, which
 * trusts the local user, always exposes them.
 */
export const FS_TOOL_NAMES: readonly string[] = ["scan_path", "inventory_crypto", "generate_cbom"];

/** All quantakrypto MCP tools, in a stable order. */
export const quantakryptoTools: ToolDefinition[] = [
  scanPathTool,
  inventoryCryptoTool,
  explainFindingTool,
  suggestHybridTool,
  listRulesTool,
  generateCbomTool,
];

/** The core version these tools are built against (re-exported for diagnostics). */
export const CORE_VERSION = VERSION;

/** Exposed for tests and advanced callers. */
export const __test = {
  normalizeAlgorithm,
  summarizeScan,
  staticHybridAdvice,
  buildScanOptions,
  describeError,
};

/** Keep the schema type imported and referenced (documentation aid). */
export type ToolInputSchema = JsonSchema;
