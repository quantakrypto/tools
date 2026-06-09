/**
 * Tiny DETERMINISTIC fuzzing helpers (no third-party deps, no Math.random).
 *
 * The PRNG is a 32-bit `mulberry32` seeded from a fixed constant per target, so
 * every run produces the same sequence of inputs — a failure is reproducible
 * and a green run is meaningful. These helpers generate random bytes, strings,
 * and small JSON-ish values to feed the hand-rolled parsers.
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
  /** Float in [0, 1). */
  next(): number;
  /** Integer in [min, max] inclusive. */
  int(min: number, max: number): number;
  /** Pick a random element from a non-empty array. */
  pick<T>(arr: readonly T[]): T;
  /** `true` with the given probability (default 0.5). */
  bool(p?: number): boolean;
  /** Random bytes of the given length. */
  bytes(len: number): Uint8Array;
  /** Random (possibly non-ASCII, possibly garbage) string of the given length. */
  string(len: number): string;
  /** Random ASCII-ish printable string. */
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

/**
 * Generate a random JSON value (deterministically). Depth-bounded so it always
 * terminates. Includes objects, arrays, strings, numbers, booleans, and null —
 * enough to stress a JSON-consuming parser with structurally-valid-but-weird
 * shapes.
 */
export function randomJsonValue(rng: Rng, depth = 0): unknown {
  if (depth > 4 || rng.bool(0.3)) {
    const kind = rng.int(0, 4);
    switch (kind) {
      case 0:
        return rng.asciiString(rng.int(0, 12));
      case 1:
        return rng.int(-1000, 1000);
      case 2:
        return rng.bool();
      case 3:
        return null;
      default:
        return rng.next() * 1000;
    }
  }
  if (rng.bool()) {
    const n = rng.int(0, 5);
    const arr: unknown[] = [];
    for (let i = 0; i < n; i++) arr.push(randomJsonValue(rng, depth + 1));
    return arr;
  }
  const n = rng.int(0, 5);
  const obj: Record<string, unknown> = {};
  for (let i = 0; i < n; i++) obj[rng.asciiString(rng.int(1, 8))] = randomJsonValue(rng, depth + 1);
  return obj;
}

/** Common iteration count for a fast-but-meaningful fuzz pass. */
export const FUZZ_ITERATIONS = 3000;
