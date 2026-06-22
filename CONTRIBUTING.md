# Contributing to quantakrypto-tools

Thanks for helping make post-quantum readiness tooling better. This is an
Apache-2.0 project by [quantakrypto](https://quantakrypto.com); the methodology is open and
contributions are welcome.

## Principles (please read first)

1. **Zero runtime dependencies.** Every published package must run on Node
   built-ins alone. Dev-only tooling (TypeScript, `tsx`) is fine; a new runtime
   dependency needs a strong justification and a maintainer's sign-off.
2. **Simple, reusable, documented.** Prefer small pure functions, clear names,
   and a doc comment that says *why*. Shared logic belongs in `@quantakrypto/core`.
3. **Honesty over coverage.** Especially in `@quantakrypto/sieve`: never fabricate
   cryptographic test vectors. If we can't verify it correctly, we skip and say so.

## Getting started

Requires Node ≥ 20.

```bash
git clone git@github.com:quantakrypto/tools.git
cd quantakrypto-tools
npm install        # links the workspaces
npm run build      # tsc --build (project references)
npm test           # node:test across all packages
```

Source lives in `packages/*/src`; tests are `node:test` files in
`packages/*/test/*.test.ts` (run on `.ts` via `tsx`).

### Enable git hooks

A zero-dependency pre-commit hook lives in `.githooks/`. It runs the same gates
as CI (`build` → `lint` → `format:check` → `test`) so problems surface before
you push. Opt in once per clone:

```bash
git config core.hooksPath .githooks
```

On a fresh checkout the hook file may need the executable bit
(`chmod +x .githooks/pre-commit`). For a large, test-heavy commit you can gate
on only build + lint + format:check with `QUANTAKRYPTO_PRECOMMIT_FAST=1 git commit`,
or skip the hook entirely for a WIP checkpoint with `git commit --no-verify`.

## Conventions

- **TypeScript strict**, ESM, `module: NodeNext` — **relative imports must end
  in `.js`** (e.g. `import { scan } from "./scan.js"`), and use `import type` for
  type-only imports.
- The `@quantakrypto/core` public surface (`packages/core/src/index.ts` +
  `types.ts`) is a contract shared by every tool — coordinate changes to it.
- Add or update tests for any behaviour change. Add an example when you add a
  user-facing feature.
- Keep commit messages imperative and scoped (e.g. `core: add SSH-key detector`).

## Pull requests

1. Branch from `main`.
2. Ensure `npm run build` and `npm test` pass locally (CI runs them on Node 20 & 22).
3. Update the relevant package `README.md` and, if it changes a documented
   behaviour, `CHANGELOG.md`.
4. Describe what changed and why; link any related item in
   [`docs/ROADMAP.md`](docs/ROADMAP.md).

## Where to start

The prioritised work is in [`docs/ROADMAP.md`](docs/ROADMAP.md), distilled from
the discipline audits under [`docs/audits/`](docs/audits/). Good first issues are
the P1 detector additions (new languages / algorithms) and test-coverage gaps.

## Security

Do not file security issues publicly — see [`SECURITY.md`](SECURITY.md).
