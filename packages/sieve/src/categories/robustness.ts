/**
 * Robustness category (ML-KEM).
 *
 * Feed deliberately malformed inputs and require a *defined error* response —
 * never a crash, hang, or silent success:
 *   - empty pk/ct/sk,
 *   - non-base64 garbage in a byte field,
 *   - an oversized blob (e.g. 1 MiB) where a key/ct is expected.
 *
 * This overlaps with the size category but targets structural malformation
 * rather than off-by-N lengths. Together they map to the AF-05 family.
 */

import {
  type Category,
  type CategoryResult,
  type Check,
  fail,
  pass,
  rollUp,
} from "./types.js";
import { requireKem } from "./helpers.js";
import type { Response } from "../protocol.js";

const OVERSIZE = 1 << 20; // 1 MiB

export const robustness: Category = async (ctx): Promise<CategoryResult> => {
  const checks: Check[] = [];

  if (ctx.sizes.family !== "ml-kem") {
    return {
      category: "robustness",
      status: "skip",
      checks: [],
      summary: "robustness probes currently target ML-KEM",
    };
  }

  const km = requireKem(ctx.sizes);
  const param = km.id;
  const oversizeB64 = Buffer.alloc(OVERSIZE).toString("base64");

  const probes: Array<{ name: string; run: () => Promise<Response> }> = [
    {
      name: "encaps-empty-pk",
      run: () => ctx.runner.send({ family: "ml-kem", param, op: "encaps", pk: "" }),
    },
    {
      name: "encaps-garbage-pk",
      run: () =>
        ctx.runner.send({ family: "ml-kem", param, op: "encaps", pk: "!!!not base64!!!" }),
    },
    {
      name: "encaps-oversize-pk",
      run: () => ctx.runner.send({ family: "ml-kem", param, op: "encaps", pk: oversizeB64 }),
    },
    {
      name: "decaps-empty-ct",
      run: () =>
        ctx.runner.send({
          family: "ml-kem",
          param,
          op: "decaps",
          sk: Buffer.alloc(km.secretKey).toString("base64"),
          ct: "",
        }),
    },
    {
      name: "decaps-empty-sk",
      run: () =>
        ctx.runner.send({
          family: "ml-kem",
          param,
          op: "decaps",
          sk: "",
          ct: Buffer.alloc(km.ciphertext).toString("base64"),
        }),
    },
    {
      name: "decaps-oversize-ct",
      run: () =>
        ctx.runner.send({
          family: "ml-kem",
          param,
          op: "decaps",
          sk: Buffer.alloc(km.secretKey).toString("base64"),
          ct: oversizeB64,
        }),
    },
  ];

  for (const probe of probes) {
    try {
      const resp = await probe.run();
      if (resp.ok === false) {
        checks.push(pass(probe.name, `defined error: ${resp.code} (${resp.message})`));
      } else {
        checks.push(
          fail(probe.name, "SUT returned a success result for malformed input instead of an error"),
        );
      }
    } catch (err) {
      checks.push(
        fail(
          probe.name,
          `SUT crashed/hung on malformed input: ${(err as Error).message}`,
        ),
      );
    }
  }

  const status = rollUp(checks);
  const failed = checks.filter((c) => c.status === "fail").length;
  return {
    category: "robustness",
    status,
    checks,
    summary:
      status === "pass"
        ? `${probes.length} malformed-input probes all rejected cleanly`
        : `${failed}/${probes.length} malformed-input probes mishandled`,
  };
};
