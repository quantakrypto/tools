/**
 * CBOM (Cryptographic Bill of Materials) export — CycloneDX 1.6 with
 * `cryptographic-asset` components. Turns a {@link ScanResult} into a
 * machine-readable inventory of the classical cryptographic assets discovered,
 * for compliance / supply-chain tooling.
 *
 * Reference: CycloneDX 1.6 cryptography properties
 * (https://cyclonedx.org/capabilities/cbom/). We emit one
 * `cryptographic-asset` component per distinct (algorithm, primitive) pair
 * observed, with occurrence evidence pointing back at the findings.
 */
import { createHash } from "node:crypto";

import type {
  AlgorithmFamily,
  Finding,
  FindingCategory,
  ScanResult,
} from "./types.js";
import { VERSION } from "./version.js";

/** A CycloneDX 1.6 cryptographic bill of materials (kept permissive). */
export interface CycloneDxBom {
  bomFormat: "CycloneDX";
  specVersion: "1.6";
  serialNumber: string;
  version: number;
  metadata: Record<string, unknown>;
  components: CbomComponent[];
}

/** A single CycloneDX `cryptographic-asset` component. */
export interface CbomComponent {
  type: "cryptographic-asset";
  "bom-ref": string;
  name: string;
  cryptoProperties: Record<string, unknown>;
  evidence?: Record<string, unknown>;
}

/** CycloneDX cryptographic primitive for a finding category. */
function primitiveFor(category: FindingCategory): string {
  switch (category) {
    case "kem":
      return "kem";
    case "key-exchange":
      return "key-agree";
    case "signature":
      return "signature";
    case "certificate":
      return "pki";
    case "tls":
      return "other";
    default:
      return "other";
  }
}

/** True when the algorithm family is broken by Shor's algorithm (quantum). */
function isQuantumVulnerable(algorithm: AlgorithmFamily): boolean {
  return algorithm !== "unknown";
}

/** Deterministic bom-ref for a (algorithm, primitive) asset key. */
function bomRef(key: string): string {
  return `crypto:${createHash("sha256").update(key, "utf8").digest("hex").slice(0, 16)}`;
}

/**
 * Build a CycloneDX 1.6 CBOM from a scan result. One component per distinct
 * (algorithm + primitive) pair, with occurrence evidence (file:line) per
 * finding. Output is deterministic (components and occurrences are sorted).
 */
export function toCbom(result: ScanResult): CycloneDxBom {
  // Group findings by (algorithm | primitive).
  const groups = new Map<
    string,
    { algorithm: AlgorithmFamily; primitive: string; findings: Finding[] }
  >();

  for (const f of result.findings) {
    const algorithm: AlgorithmFamily = f.algorithm ?? "unknown";
    const primitive = primitiveFor(f.category);
    const key = `${algorithm}|${primitive}`;
    let g = groups.get(key);
    if (!g) {
      g = { algorithm, primitive, findings: [] };
      groups.set(key, g);
    }
    g.findings.push(f);
  }

  const components: CbomComponent[] = [...groups.entries()]
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
    .map(([key, g]) => {
      const occurrences = g.findings
        .map((f) => ({
          location: `${f.location.file}:${f.location.line}`,
          ...(f.cwe ? { additionalContext: f.cwe } : {}),
        }))
        .sort((a, b) => (a.location < b.location ? -1 : a.location > b.location ? 1 : 0));

      const anyHndl = g.findings.some((f) => f.hndl);

      return {
        type: "cryptographic-asset" as const,
        "bom-ref": bomRef(key),
        name: `${g.algorithm} (${g.primitive})`,
        cryptoProperties: {
          assetType: "algorithm",
          algorithmProperties: {
            primitive: g.primitive,
            parameterSetIdentifier: g.algorithm,
            executionEnvironment: "software-plain-ram",
            classicalSecurityLevel: 0,
            nistQuantumSecurityLevel: 0,
            cryptoFunctions:
              g.primitive === "signature"
                ? ["sign", "verify"]
                : g.primitive === "kem"
                  ? ["encapsulate", "decapsulate"]
                  : g.primitive === "key-agree"
                    ? ["keygen"]
                    : ["other"],
          },
          quantumVulnerable: isQuantumVulnerable(g.algorithm),
          harvestNowDecryptLater: anyHndl,
        },
        evidence: { occurrences },
      };
    });

  const serial = `urn:uuid:${stableUuid(result)}`;

  return {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    serialNumber: serial,
    version: 1,
    metadata: {
      timestamp: result.finishedAt,
      tools: {
        components: [
          {
            type: "application",
            name: "qScan",
            version: result.toolVersion || VERSION,
          },
        ],
      },
      component: {
        type: "application",
        "bom-ref": "root",
        name: result.root,
      },
    },
    components,
  };
}

/**
 * Derive a stable UUID-shaped serial from the scan result so re-exporting the
 * same result yields the same serial number (deterministic output).
 */
function stableUuid(result: ScanResult): string {
  const h = createHash("sha256")
    .update(`${result.root}|${result.toolVersion}|${result.findings.length}`, "utf8")
    .digest("hex");
  // Shape as a v4-ish UUID (variant/version nibbles forced).
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-8${h.slice(17, 20)}-${h.slice(20, 32)}`;
}
