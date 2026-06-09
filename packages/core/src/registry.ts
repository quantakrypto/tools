/**
 * Detector registry — the plugin point for source/config detectors.
 *
 * Instead of `scan()` closing over a hardcoded array and inferring scope from
 * ruleId prefixes, detectors are registered with a declared `scope` and
 * `language` (see {@link Detector}). `scan()` consults a registry (the
 * {@link defaultRegistry} by default, or an explicit `detectors` override) and
 * honours the source/config toggles by each detector's declared scope.
 *
 * To add a language or detector, see the "Adding a detector / language" section
 * of the package README.
 */
import type { Detector, DetectorScope } from "./types.js";
import { sourceDetectors } from "./detectors/source.js";
import { pemDetector } from "./detectors/pem.js";

/** Normalised scope of a detector (defaults to "source" when undeclared). */
export function detectorScope(d: Detector): DetectorScope {
  return d.scope ?? "source";
}

/**
 * An ordered, id-indexed collection of detectors. Registration order is
 * preserved by {@link all} for deterministic scan output. Ids must be unique.
 */
export class DetectorRegistry {
  private readonly byId = new Map<string, Detector>();
  private readonly order: string[] = [];

  /** Construct a registry, optionally seeded with an initial detector set. */
  constructor(initial: readonly Detector[] = []) {
    for (const d of initial) this.register(d);
  }

  /** Register a detector. Throws on a duplicate id. Returns `this` for chaining. */
  register(d: Detector): this {
    if (this.byId.has(d.id)) {
      throw new Error(`duplicate detector id: ${d.id}`);
    }
    this.byId.set(d.id, d);
    this.order.push(d.id);
    return this;
  }

  /** Look up a detector by its id (exact, not prefix). */
  get(id: string): Detector | undefined {
    return this.byId.get(id);
  }

  /** True if a detector with this id is registered. */
  has(id: string): boolean {
    return this.byId.has(id);
  }

  /** All registered detectors, in registration order. */
  all(): Detector[] {
    return this.order.map((id) => this.byId.get(id)!);
  }

  /** A shallow copy of this registry (useful to extend the defaults). */
  clone(): DetectorRegistry {
    return new DetectorRegistry(this.all());
  }
}

/**
 * The default registry, preloaded with the built-in detectors in run order:
 * the JS/TS source + config detectors, then the language-agnostic PEM detector.
 * The manifest (dependency) scanner is handled separately by `scan()`.
 */
export const defaultRegistry = new DetectorRegistry([...sourceDetectors, pemDetector]);
