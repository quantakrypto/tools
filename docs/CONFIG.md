# `qproof.config.json` — Configuration Spec

**Status: SPECIFICATION ONLY.** This document describes an *optional* project
configuration file that `qScan` and `@qproof/core` would consume. It is a design
spec for [ROADMAP P2-9](ROADMAP.md); **nothing here is implemented**, and it does
not change current behavior. The goal is to capture the schema, precedence, and
semantics so the implementation is a faithful build, not a fresh design.

## 1. Motivation

Today qScan is configured entirely by CLI flags ([qscan README](../packages/qscan/README.md)),
and `ScanOptions` carries a few options that are not yet wired
([ROADMAP P1-2](ROADMAP.md): `include` is unwireable, `maxFileSize`/`noDefaultIgnores`
are dropped by `runQscan`). A committed config file lets a project encode its scan
policy once — include/exclude globs, size limits, the severity gate, which
detector families/languages to run, and a baseline path — so CI, the editor (MCP),
and local runs agree without repeating long flag lists.

## 2. Discovery

- File name: **`qproof.config.json`**, discovered by walking up from the scan
  `root` (then the CWD) to the first match, stopping at a `.git` boundary or
  filesystem root.
- A `--config <path>` flag (proposed) overrides discovery and names the file
  explicitly. `--no-config` disables discovery entirely.
- Exactly **one** config file applies per run; configs do **not** merge across
  directories (no cascading), to keep precedence simple and auditable.

## 3. Precedence

Effective options are resolved with a strict, documented order. **Flags beat
config; config beats defaults.** There is no environment-variable layer in this
spec.

```
CLI flags  >  qproof.config.json  >  built-in defaults
(highest)                                      (lowest)
```

Resolution is **per-key**, not all-or-nothing: a flag overrides only the key it
sets, leaving other keys to come from config or defaults. List-valued keys
(`include`, `exclude`) follow the rule in §4.2 (flags *append* by default, with an
explicit replace form) — chosen so a config baseline of excludes is additive with
ad-hoc CLI excludes, which is the common case.

## 4. Schema

A single JSON object. All keys optional. Unknown keys are a **warning, not an
error** (forward compatibility), except a malformed *value* for a known key, which
is a usage error (exit 2). JSON only (no comments) so it parses with `JSON.parse`
under [ADR-0001](adr/0001-zero-runtime-dependencies.md)'s zero-dep rule.

```jsonc
{
  "$schema": "https://qproof.com/schema/qproof.config.v1.json",
  "version": 1,

  // ── file selection ──────────────────────────────────────────────
  "include": ["src/**", "packages/*/src/**"],   // patterns to scan (see §4.2)
  "exclude": ["**/vendor/**", "legacy/**"],      // patterns to skip (added to defaults)
  "noDefaultIgnores": false,                     // disable node_modules/.git/dist/… ignores
  "maxFileSize": 2097152,                         // bytes; default 2 MiB

  // ── what to scan ────────────────────────────────────────────────
  "detectors": {                                  // toggle detector families
    "node-crypto": true,
    "webcrypto": true,
    "crypto-libs": true,
    "jwt-jose": true,
    "tls-config": true,
    "pem-material": true,
    "dependencies": true
  },
  "languages": ["js", "ts"],                       // forward-looking; see §4.3

  // ── policy ──────────────────────────────────────────────────────
  "severityThreshold": "high",                     // gate: critical|high|medium|low|info
  "baseline": ".qproof/baseline.json"              // path to a baseline file
}
```

### 4.1 Field reference

| Key | Type | Default | Maps to | Notes |
|---|---|---|---|---|
| `version` | int | `1` | — | Config schema version. Unknown future versions are a warning + best-effort. |
| `include` | string[] | (all scannable) | `ScanOptions.include` | Substring/prefix/glob patterns (§4.2). Empty/omitted = scan everything not excluded. |
| `exclude` | string[] | `[]` | `ScanOptions.exclude` | **Added to** the built-in default ignores unless `noDefaultIgnores`. |
| `noDefaultIgnores` | bool | `false` | `ScanOptions.noDefaultIgnores` | Disables `node_modules`/`.git`/`dist`/… defaults. |
| `maxFileSize` | int (bytes) | `2097152` | `ScanOptions.maxFileSize` | Files larger are skipped; the [perf](audits/performance.md)/[security](audits/security.md) 2 MiB cap rationale applies. |
| `detectors.<family>` | bool | `true` | maps to `source`/`config`/`dependencies` scan toggles + per-family selection | Family names mirror `@qproof/core`'s detector families and the `--no-source`/`--no-deps`/`--no-config` flags. Turning a family off is equivalent to its `--no-*` flag. |
| `languages` | string[] | (all built-in) | (forward-looking) | See §4.3 — has no effect until the detector-registry/plugin work ([ROADMAP P1-4](ROADMAP.md)) lands. |
| `severityThreshold` | enum | `high` | `runQscan({severityThreshold})` | Drives the exit code. CLI `--severity-threshold` overrides. |
| `baseline` | string (path) | none | `runQscan({baseline})` | Relative to the config file's directory. CLI `--baseline` overrides. |

### 4.2 Pattern and list semantics

- Patterns reuse qScan's existing matcher (substring / path-prefix, extended to
  globs if/when the implementation adds them); this spec does not mandate a new
  glob engine.
- **`exclude`** from config is **unioned** with built-in default ignores (unless
  `noDefaultIgnores: true`) and with any CLI `--ignore` flags (CLI appends).
- **`include`** from config sets the base inclusion set; CLI include flags (if
  added) append. An explicit replace form (`"include!"` / a `--include-only`
  flag) is reserved for a future revision and out of scope here.
- Exclude always wins over include when both match a path.

### 4.3 `languages` (forward-looking)

`languages` is specified now so the file format is stable, but it is **inert**
until [ROADMAP P1-4](ROADMAP.md) makes detectors a real plugin point with a
declared `language`/`scope` per detector. Until then, detector selection is via
`detectors.<family>`. When the registry lands, `languages` filters the active
detector set by declared language (e.g. `["python","go"]`).

## 5. Interaction with baselines and CI

- `baseline` in the config is equivalent to passing `--baseline`; `--write-baseline`
  remains CLI-only (it is an action, not config state).
- In CI, committing `qproof.config.json` lets the [Action](../packages/action/README.md)
  and a local `qscan` run share one policy. The Action would read the same file
  (its `path`/`severity-threshold`/`baseline` inputs still take precedence as
  "flags" in the §3 order).
- The MCP server, when scanning a workspace, would honor a discovered config so an
  agent's view matches CI's.

## 6. Validation

- Parse with `JSON.parse`; on syntax error, exit 2 with the file path and offset.
- Validate value *types* against this schema; an out-of-range enum or wrong type
  for a **known** key is a usage error (exit 2). Unknown **keys** warn and are
  ignored.
- The implementation should treat the parsed object as **untrusted input** in the
  same spirit as scanned manifests ([THREAT-MODEL](THREAT-MODEL.md) Q-09): no deep
  merge of parsed config into prototypes; membership-test keys only.

## 7. Out of scope (this spec)

- An env-var configuration layer.
- Cascading/merged configs across directories.
- A JSON Schema file artifact (the `$schema` URL above is a placeholder for when
  one is published).
- Per-rule severity overrides and CWE mapping config (would pair with
  [ROADMAP P2-6](ROADMAP.md) CWE tagging).
