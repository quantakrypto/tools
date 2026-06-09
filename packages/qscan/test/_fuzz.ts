/**
 * Tiny DETERMINISTIC fuzzing helpers for qScan (no third-party deps, no
 * Math.random). Fixed-seed `mulberry32` PRNG so every run is reproducible.
 */

/** A reproducible 32-bit PRNG. Returns a function yielding floats in [0, 1). */
export function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return function next(): number {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** A small bundle of typed random generators over one PRNG stream. */
export interface Rng {
  next(): number;
  int(min: number, max: number): number;
  pick<T>(arr: readonly T[]): T;
  bool(p?: number): boolean;
  asciiString(len: number): string;
}

/** Build an {@link Rng} seeded from `seed`. */
export function makeRng(seed: number): Rng {
  const next = mulberry32(seed);
  const int = (min: number, max: number): number => min + Math.floor(next() * (max - min + 1));
  return {
    next,
    int,
    pick<T>(arr: readonly T[]): T {
      return arr[int(0, arr.length - 1)] as T;
    },
    bool(p = 0.5): boolean {
      return next() < p;
    },
    asciiString(len: number): string {
      let s = "";
      for (let i = 0; i < len; i++) s += String.fromCharCode(int(32, 126));
      return s;
    },
  };
}

/** Common iteration count for a fast-but-meaningful fuzz pass. */
export const FUZZ_ITERATIONS = 3000;
