/**
 * FS-confinement + work-budget policy tests (P0 — FS path confinement).
 *
 * The root allow-list, `..`-traversal rejection, and budget clamping are pure
 * functions of an env snapshot, tested directly. The end-to-end enforcement
 * (an out-of-root path rejected by the scan_path tool) is covered in
 * tools.test.ts.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import * as path from "node:path";

import {
  resolveFsConfig,
  resolveScanPath,
  DEFAULT_MAX_FILES,
  DEFAULT_MAX_BYTES,
  MAX_MAX_FILES,
  MAX_MAX_BYTES,
} from "../src/fsconfig.js";

/* ----------------------------- config defaults ---------------------------- */

test("resolveFsConfig defaults the root to cwd and uses default budgets", () => {
  const cfg = resolveFsConfig({}, "/srv/app");
  assert.deepEqual(cfg.roots, ["/srv/app"]);
  assert.equal(cfg.maxFiles, DEFAULT_MAX_FILES);
  assert.equal(cfg.maxBytes, DEFAULT_MAX_BYTES);
});

test("resolveFsConfig reads a :-separated root allow-list", () => {
  const cfg = resolveFsConfig(
    { QUANTAKRYPTO_MCP_ROOT: ["/srv/a", "/srv/b"].join(path.delimiter) },
    "/srv/app",
  );
  assert.deepEqual(cfg.roots, ["/srv/a", "/srv/b"]);
});

test("resolveFsConfig resolves relative roots against cwd and dedupes", () => {
  const cfg = resolveFsConfig(
    { QUANTAKRYPTO_MCP_ROOT: ["sub", "sub", "/srv/app/sub"].join(path.delimiter) },
    "/srv/app",
  );
  assert.deepEqual(cfg.roots, ["/srv/app/sub"]);
});

/* ------------------------------ budget clamps ----------------------------- */

test("resolveFsConfig honours env budgets but clamps them to the hard cap", () => {
  const ok = resolveFsConfig({
    QUANTAKRYPTO_MCP_MAX_FILES: "10",
    QUANTAKRYPTO_MCP_MAX_BYTES: "2048",
  });
  assert.equal(ok.maxFiles, 10);
  assert.equal(ok.maxBytes, 2048);

  const huge = resolveFsConfig({
    QUANTAKRYPTO_MCP_MAX_FILES: String(MAX_MAX_FILES * 1000),
    QUANTAKRYPTO_MCP_MAX_BYTES: String(MAX_MAX_BYTES * 1000),
  });
  assert.equal(huge.maxFiles, MAX_MAX_FILES, "maxFiles is capped");
  assert.equal(huge.maxBytes, MAX_MAX_BYTES, "maxBytes is capped");
});

test("resolveFsConfig falls back on invalid budget values", () => {
  const cfg = resolveFsConfig({
    QUANTAKRYPTO_MCP_MAX_FILES: "not-a-number",
    QUANTAKRYPTO_MCP_MAX_BYTES: "-5",
  });
  assert.equal(cfg.maxFiles, DEFAULT_MAX_FILES);
  assert.equal(cfg.maxBytes, DEFAULT_MAX_BYTES);
});

/* ----------------------------- path resolution ---------------------------- */

test("resolveScanPath accepts a path inside the root", () => {
  const cfg = resolveFsConfig({}, "/srv/app");
  const inside = resolveScanPath(cfg, "/srv/app/src");
  assert.equal(inside.ok, true);
  assert.equal(inside.ok && inside.path, "/srv/app/src");

  const self = resolveScanPath(cfg, "/srv/app");
  assert.equal(self.ok, true);
});

test("resolveScanPath resolves a relative path against the primary root", () => {
  const cfg = resolveFsConfig({}, "/srv/app");
  const rel = resolveScanPath(cfg, "src/crypto");
  assert.equal(rel.ok, true);
  assert.equal(rel.ok && rel.path, "/srv/app/src/crypto");
});

test("resolveScanPath rejects an out-of-root absolute path", () => {
  const cfg = resolveFsConfig({}, "/srv/app");
  const escape = resolveScanPath(cfg, "/etc/passwd");
  assert.equal(escape.ok, false);
  assert.match(escape.ok ? "" : escape.reason, /outside the configured scan root|allow-list/i);
});

test("resolveScanPath rejects a `..` traversal that escapes the root", () => {
  const cfg = resolveFsConfig({}, "/srv/app");
  const escape = resolveScanPath(cfg, "../../etc/passwd");
  assert.equal(escape.ok, false);
  // A relative `..` traversal must resolve outside /srv/app and be refused.
  const climb = resolveScanPath(cfg, "/srv/app/../secret");
  assert.equal(climb.ok, false);
});

test("resolveScanPath honours multiple roots", () => {
  const cfg = resolveFsConfig(
    { QUANTAKRYPTO_MCP_ROOT: ["/srv/a", "/srv/b"].join(path.delimiter) },
    "/srv/app",
  );
  assert.equal(resolveScanPath(cfg, "/srv/a/x").ok, true);
  assert.equal(resolveScanPath(cfg, "/srv/b/y").ok, true);
  assert.equal(resolveScanPath(cfg, "/srv/c/z").ok, false);
});

test("resolveScanPath rejects an empty path", () => {
  const cfg = resolveFsConfig({}, "/srv/app");
  assert.equal(resolveScanPath(cfg, "   ").ok, false);
});
