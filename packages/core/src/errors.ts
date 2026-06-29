/**
 * Error types thrown by {@link scan} when cooperative cancellation or a work
 * budget kicks in. Kept in their own module so every consumer (qScan, the MCP
 * server, the Action) can `instanceof`-check them without importing the scanner.
 */

/**
 * Thrown when a scan is aborted via `ScanOptions.signal`. `name` is `"AbortError"`
 * to match the Web platform convention (`AbortController` / `DOMException`), so
 * callers that already special-case `err.name === "AbortError"` keep working.
 */
export class AbortError extends Error {
  override readonly name = "AbortError";
  constructor(message = "The scan was aborted.") {
    super(message);
  }
}

/** Thrown when a scan exceeds its `maxFiles` / `maxBytes` work budget mid-walk. */
export class BudgetExceededError extends Error {
  override readonly name = "BudgetExceededError";
  constructor(message: string) {
    super(message);
  }
}
