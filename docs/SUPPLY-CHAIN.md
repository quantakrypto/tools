# Supply-Chain Assurance

How `qproof-tools` targets the three pillars of OSS supply-chain assurance —
**OpenSSF Scorecard**, **SLSA / npm provenance**, and **SPDX/REUSE licensing** —
and where the project stands against each today. This operationalises
[ROADMAP P2-7](ROADMAP.md) and the supply-chain section of [COMPLIANCE.md](COMPLIANCE.md §5).

The project's strongest asset here is the [zero-runtime-dependency](adr/0001-zero-runtime-dependencies.md)
posture: no transitive CVEs, no lifecycle scripts, a tiny dev-tool surface. That
buys several assurance checks for free; the gaps are process, not dependencies.

## 1. Targets vs. current status

| Pillar | Target | Status | Gap to target |
|---|---|---|---|
| **OpenSSF Scorecard** | A published score with a badge; act on findings each run. | Workflow added ([`scorecard.yml`](../.github/workflows/scorecard.yml)), weekly + on push to `main`, SARIF to code scanning, results published. | Turn on **branch protection** + required reviews (the checks Scorecard most penalizes), then track the score. Zero deps already wins `Pinned-Dependencies`/`Vulnerabilities`. |
| **SLSA provenance** | SLSA build-provenance on every released artifact (L2+: hosted, hardened CI builder). | Not generated yet. | Publish from the gated [release workflow](../.github/workflows/release.yml) so npm provenance (Sigstore) is produced; that attestation is the provenance record. |
| **npm provenance** | Each `@qproof/*` package page shows a signed provenance attestation. | Configured but **deferred** — release workflow is gated behind `workflow_dispatch` + `NPM_TOKEN` (ROADMAP §5). | Add `NPM_TOKEN`, commit the Action `dist/`, run the release workflow with `confirm: publish`. |
| **SPDX / REUSE** | `reuse lint` passes; licensing is machine-verifiable. | [`REUSE.toml`](../REUSE.toml) bulk declaration + [`LICENSES/Apache-2.0.txt`](../LICENSES/Apache-2.0.txt) added. | Run `reuse lint` in CI to keep it clean as files are added. |

## 2. OpenSSF Scorecard

The [`scorecard.yml`](../.github/workflows/scorecard.yml) workflow runs the
`ossf/scorecard-action`, uploads SARIF to the Security tab, and publishes the
score (OIDC `id-token: write`) so a badge can be displayed.

- **Free wins from zero deps:** `Pinned-Dependencies` (no third-party runtime
  deps; pin dev deps via `npm ci` + lockfile), `Vulnerabilities` (minimal surface),
  no dangerous lifecycle scripts.
- **Already in place:** CI (`Token-Permissions` are scoped read-by-default),
  `SECURITY.md`, `License`, issue/PR templates, a maintained changelog.
- **To raise the score:** enable **branch protection** + required code review on
  `main`; the [fuzz targets](THREAT-MODEL.md) and the release/provenance work below
  feed `Fuzzing` and `Signed-Releases`.

## 3. SLSA + npm provenance

The plan is the standard GitHub-Actions-native path:

1. Build + test in the [release workflow](../.github/workflows/release.yml)
   (`npm ci`, `npm run build`, `npm test`).
2. Publish with **`npm publish --provenance --access public`** using the OIDC
   `id-token: write` token. npm generates a Sigstore-backed provenance attestation
   linking the artifact to the exact CI workflow + commit, shown on the package
   page. This is also a SLSA-aligned provenance statement.
3. Tag the release (e.g. `v0.1.0`) and record it in the [CHANGELOG](../CHANGELOG.md)
   per [VERSIONING.md](VERSIONING.md).

**Why it is deferred (ROADMAP §5):** publishing waits until the technology is
finalized. Two preconditions gate it, both encoded in the workflow:
- The `NPM_TOKEN` secret must be configured; the workflow errors out otherwise.
- The **Action's `dist/` must be committed/bundled first** — a `node20` action
  runs `packages/action/dist/main.js` directly, so the action cannot be consumed as
  `uses: …/packages/action@v1` (nor sensibly published) until the built JS is
  committed and guarded by a "dist is fresh" CI gate. The action publish line is
  left commented for exactly this reason.

## 4. SPDX / REUSE licensing

The project is uniformly **Apache-2.0**, copyright **"qproof / Dandelion Labs JSC"**.
Rather than stamp a per-file `SPDX-License-Identifier` header into every source
file, we use a **bulk declaration**:

- [`REUSE.toml`](../REUSE.toml) declares `**` as `Apache-2.0` with the project
  copyright, plus carve-outs for generated/data files. This is the REUSE-spec
  machine-readable equivalent of per-file headers — `reuse lint` passes without
  modifying any source (consistent with the read-only-on-source constraint).
- [`LICENSES/Apache-2.0.txt`](../LICENSES/Apache-2.0.txt) holds the canonical
  Apache-2.0 text REUSE expects in the `LICENSES/` directory; the root
  [`LICENSE`](../LICENSE) remains the human-facing copy.
- **NIST ACVP vectors are explicitly excluded** — Sieve ships none
  ([ADR-0004](adr/0004-sieve-no-fabricated-vectors.md)); any operator-supplied
  vectors are uncommitted and out of REUSE scope (track provenance per
  [compliance/acvp-provenance.md](compliance/acvp-provenance.md)).

**To verify:** `reuse lint` (and wire it into CI alongside the build/test).

## 5. Ongoing posture (recurring gates)

Beyond the one-time setup, fold these into CI cadence (ROADMAP §6):
- **Scorecard weekly** (this workflow) — track drift, act on regressions.
- **Lockfile integrity** — always `npm ci`; never run arbitrary lifecycle scripts.
- **`reuse lint`** on every push to keep licensing clean as files land.
- **Reproducible builds** for published artifacts (verify provenance round-trips).
- **No new runtime dependency** without an ADR ([ADR-0001](adr/0001-zero-runtime-dependencies.md)).
