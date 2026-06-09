# qproof-tools

Open-source post-quantum readiness tooling by [qproof](https://qproof.com/tools).
Free to use, instrumented for nothing — find quantum-vulnerable cryptography,
wire post-quantum readiness into your editor and your CI, and conformance-test
post-quantum implementations.

> **Design goals:** simple, clean, reusable code; **zero runtime dependencies**
> (Node built-ins only); everything documented, tested, and example-driven.

## Packages

| Package | What it is | Install |
|---|---|---|
| [`@qproof/core`](packages/core) | Shared library — crypto detectors, vulnerable-dependency DB, inventory + SARIF reporting | `npm i @qproof/core` |
| [`@qproof/qscan`](packages/qscan) | **qScan** — CLI that finds quantum-vulnerable crypto in any codebase | `npx @qproof/qscan ./` |
| [`@qproof/mcp`](packages/mcp) | **qproof MCP** — post-quantum readiness for AI coding agents (local + hostable) | `claude mcp add qproof npx @qproof/mcp` |
| [`@qproof/action`](packages/action) | **qproof Action** — fail CI when new quantum-vulnerable crypto lands | `uses: dandelionlabs-io/qproof-tools/packages/action@v1` |
| [`@qproof/sieve`](packages/sieve) | **Sieve** — conformance battery for ML-KEM / ML-DSA implementations | `npx @qproof/sieve` |

`qScan`, `qproof MCP`, and `qproof Action` all share `@qproof/core`. `Sieve` is
standalone (it tests *other* implementations, it doesn't implement crypto).

## Workspace layout

```
qproof-tools/
├── packages/
│   ├── core/     @qproof/core    — shared engine (the contract lives in src/types.ts + src/index.ts)
│   ├── qscan/    @qproof/qscan   — CLI
│   ├── mcp/      @qproof/mcp     — MCP server (stdio now, HTTP scaffold for hosting)
│   ├── action/   @qproof/action — GitHub Action
│   └── sieve/    @qproof/sieve  — conformance battery + JSON protocol
├── docs/         architecture, hosted-MCP design, improvement roadmap
└── examples/     end-to-end examples
```

## Development

Requires Node ≥ 20.

```bash
npm install        # links the workspaces
npm run build      # tsc --build (project references)
npm test           # node:test across all packages
```

The toolchain is intentionally tiny: TypeScript + `tsx` (to run `node:test` on
`.ts`) are the only dev dependencies; there are **no runtime dependencies**.

## License

[Apache-2.0](LICENSE). The methodology is open; the audits, certificates, and
deliverables are where the [qproof](https://qproof.com) practice lives.
