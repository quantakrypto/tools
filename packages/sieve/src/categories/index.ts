/**
 * Category registry. Each entry is selected by family so the runner only
 * executes categories relevant to the parameter set under test.
 */

import type { Category } from "./types.js";
import type { Family } from "../sizes.js";

import { correctness } from "./correctness.js";
import { determinism } from "./determinism.js";
import { implicitRejection } from "./implicit-rejection.js";
import { sizes } from "./sizes.js";
import { robustness } from "./robustness.js";
import { dsa } from "./dsa.js";
import { slhDsa } from "./slh-dsa.js";
import { kat } from "./kat.js";
import { timing } from "./timing.js";

export * from "./types.js";

/** A named, family-scoped category. */
export interface RegisteredCategory {
  name: string;
  family: Family | "any";
  /** Whether the category runs by default (timing is opt-in). */
  defaultOn: boolean;
  run: Category;
}

/** The full catalog, in execution order. */
export const CATEGORIES: readonly RegisteredCategory[] = [
  { name: "correctness", family: "ml-kem", defaultOn: true, run: correctness },
  { name: "determinism", family: "ml-kem", defaultOn: true, run: determinism },
  { name: "implicit-rejection", family: "ml-kem", defaultOn: true, run: implicitRejection },
  { name: "sizes", family: "ml-kem", defaultOn: true, run: sizes },
  { name: "robustness", family: "ml-kem", defaultOn: true, run: robustness },
  { name: "dsa", family: "ml-dsa", defaultOn: true, run: dsa },
  { name: "slh-dsa", family: "slh-dsa", defaultOn: true, run: slhDsa },
  { name: "kat", family: "any", defaultOn: true, run: kat },
  { name: "timing", family: "ml-kem", defaultOn: false, run: timing },
];

/** Categories applicable to a family (plus family-agnostic ones). */
export function categoriesFor(family: Family, includeTiming: boolean): RegisteredCategory[] {
  return CATEGORIES.filter(
    (c) =>
      (c.family === family || c.family === "any") &&
      (c.defaultOn || (c.name === "timing" && includeTiming)),
  );
}

export { correctness, determinism, implicitRejection, sizes, robustness, dsa, slhDsa, kat, timing };
