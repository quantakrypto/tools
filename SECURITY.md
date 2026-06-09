# Security Policy

`qproof-tools` is security tooling, so we hold the project to a high bar and
welcome reports. This policy follows the spirit of ISO/IEC 29147 (vulnerability
disclosure) and ISO/IEC 30111 (vulnerability handling).

## Supported versions

The project is pre-1.0. Only the latest `main` is supported while the API
stabilises. Versioned support windows will be defined at the 1.0 release.

## Reporting a vulnerability

**Please do not open public issues for security problems.**

- Email **security@qproof.com** (or the maintainers listed in `package.json`).
- Preferably use GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
  ("Report a vulnerability" on the Security tab).
- Include: affected package, version/commit, a reproduction, impact, and any
  suggested fix.

We aim to acknowledge within **3 business days** and to provide a remediation
plan within **10 business days**. We will credit reporters who wish to be named.

## Scope & threat model

These are developer tools that read source code and (for Sieve) drive an
external implementation. The most security-relevant surfaces — documented in
[`docs/audits/security.md`](docs/audits/security.md) — are:

- **`@qproof/mcp` HTTP transport (`packages/mcp/src/http.ts`).** The hosted
  transport is a **scaffold**. Do **not** expose it publicly without adding
  authentication, per-tool timeouts, and a sandbox: the `scan_path` /
  `inventory_crypto` tools read the filesystem and would otherwise be an
  unauthenticated arbitrary-read service. The local **stdio** transport
  (`npx @qproof/mcp`) runs on the developer's own machine and is the supported
  path today.
- **`@qproof/sieve` runner (`packages/sieve/src/runner.ts`).** It spawns a
  user-provided implementation. Only point it at code you trust; treat the SUT
  as you would any executable.
- **`@qproof/qscan` / `@qproof/core`.** Scanning untrusted repositories is
  generally safe (no code execution, symlinks are not followed), but see the
  ReDoS notes in the security audit before scanning adversarial inputs at scale.

## Hardening status

Known issues and their remediations are tracked in
[`docs/ROADMAP.md`](docs/ROADMAP.md) (the **P0 — security & correctness** block).
This file will be updated as those land.
