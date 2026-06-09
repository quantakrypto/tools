/**
 * Tiny DETERMINISTIC fuzzing helpers for Sieve (no third-party deps, no
 * Math.random). Mirrors core/test/_fuzz.ts but kept local since Sieve does not
 * depend on @qproof/core. The PRNG is a fixed-seed `mulberry32` so every run is
 * reproducible.
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
  bytes(len: number): Uint8Array;
  string(len: number): string;
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
    bytes(len: number): Uint8Array {
      const b = new Uint8Array(len);
      for (let i = 0; i < len; i++) b[i] = int(0, 255);
      return b;
    },
    string(len: number): string {
      let s = "";
      for (let i = 0; i < len; i++) s += String.fromCharCode(int(0, 0xffff));
      return s;
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
