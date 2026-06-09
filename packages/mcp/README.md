# @qproof/mcp

A **Model Context Protocol (MCP) server** that gives AI coding agents post-quantum
readiness superpowers. It scans code for classical (quantum-vulnerable) asymmetric
cryptography and recommends NIST post-quantum / hybrid migrations, all backed by
[`@qproof/core`](../core).

- **Zero runtime dependencies.** The MCP / JSON-RPC 2.0 protocol is implemented
  from scratch on Node built-ins (`node:readline`, `node:http`, `node:process`).
  The only dependency is `@qproof/core`.
- **Two transports.** A `stdio` transport (the `qproof-mcp` bin) for local agents
  like Claude, and a hostable `http` transport for running qproof as a remote
  service (see [HOSTING.md](./HOSTING.md)).
- **Transport-agnostic core.** All protocol logic lives in a pure, unit-tested
  `McpServer` class; transports only do I/O.

## Install / register with an MCP client

The published package exposes a `qproof-mcp` binary that speaks MCP over stdio:

```bash
# Claude Code / Claude Desktop
claude mcp add qproof npx @qproof/mcp
```

Equivalently, in an MCP client config:

```json
{
  "mcpServers": {
    "qproof": {
      "command": "npx",
      "args": ["@qproof/mcp"]
    }
  }
}
```

The bin is `qproof-mcp` (→ `dist/stdio.js`). You can also run it directly:

```bash
node dist/stdio.js
```

## Protocol

MCP **stdio transport** is newline-delimited JSON: exactly one JSON-RPC 2.0
message per line on stdin/stdout (this is *not* HTTP-style `Content-Length`
framing). Supported methods:

| Method | Notes |
| --- | --- |
| `initialize` | Replies with `protocolVersion`, `capabilities.tools.listChanged = false`, and `serverInfo { name: "qproof", version }`. |
| `notifications/initialized` | Notification; no response. |
| `ping` | Replies `{}`. |
| `tools/list` | Lists all tools with JSON-Schema `inputSchema`. |
| `tools/call` | Runs a tool, returns `{ content: [...], isError? }`. |

Unknown methods return JSON-RPC error `-32601`; bad params return `-32602`;
unparseable input returns `-32700`; non-request objects return `-32600`.

## Tools

Each tool returns MCP content: `{ content: [{ type: "text", text }], isError? }`.

### `scan_path`

Scan a file or directory for quantum-vulnerable cryptography.

```json
{
  "type": "object",
  "properties": {
    "path":   { "type": "string", "description": "Path to scan." },
    "format": { "type": "string", "enum": ["summary", "json"] }
  },
  "required": ["path"]
}
```

Returns a readiness summary (or the raw `ScanResult` JSON when `format: "json"`).

### `inventory_crypto`

Produce a 0–100 readiness score plus counts by algorithm, category, and severity.

```json
{
  "type": "object",
  "properties": { "path": { "type": "string" } },
  "required": ["path"]
}
```

### `explain_finding`

Explain a finding and its remediation. Provide a `ruleId`, an `algorithm`, or both.

```json
{
  "type": "object",
  "properties": {
    "ruleId":    { "type": "string" },
    "algorithm": { "type": "string", "description": "RSA, ECDH, ECDSA, …" }
  }
}
```

### `suggest_hybrid`

Recommend a PQC / hybrid migration from an `algorithm` or free-text `context`.

```json
{
  "type": "object",
  "properties": {
    "algorithm": { "type": "string" },
    "context":   { "type": "string" }
  }
}
```

### `list_rules`

List the qproof detector catalog (ids + descriptions). No input.

```json
{ "type": "object", "properties": {} }
```

### `generate_cbom`

Scan a path and emit a **CycloneDX 1.6 Cryptographic Bill of Materials (CBOM)**
of the classical cryptographic assets found, for compliance / supply-chain
tooling. Reads the filesystem, so it is gated like `scan_path` over HTTP.

```json
{
  "type": "object",
  "properties": { "path": { "type": "string" } },
  "required": ["path"]
}
```

## Hosted HTTP server (safe-by-default)

The same `McpServer` can be served over HTTP (a Streamable-HTTP-style JSON-RPC
endpoint) for remote deployments. The stdio transport trusts the local user and
is fully featured; the **HTTP transport is hardened**, because a hosted endpoint
is reachable by untrusted peers:

- **Binds to `127.0.0.1` by default** (not `0.0.0.0`). Override via
  `QPROOF_MCP_HOST`. Binding to a non-loopback host **without a token is refused
  at startup** (it would be an open, unauthenticated tool relay).
- **Bearer-token auth.** Set `QPROOF_MCP_TOKEN` and every `/mcp` request must
  send `Authorization: Bearer <token>`, else `401`. With no token set, only the
  loopback bind is allowed.
- **Filesystem tools are disabled by default.** `scan_path`, `inventory_crypto`
  and `generate_cbom` read arbitrary server paths, so over HTTP they are exposed
  only when `QPROOF_MCP_ALLOW_FS=1`. The knowledge tools (`explain_finding`,
  `suggest_hybrid`, `list_rules`) are always available. `tools/list` and
  `tools/call` both reflect the gating.
- **Limits.** A 1 MiB request-body cap (always), a per-request tool timeout
  (`QPROOF_MCP_TIMEOUT_MS`, default 30000 → `504` on timeout) and a response-size
  cap (`QPROOF_MCP_MAX_RESPONSE_BYTES`, default 4 MiB).

| Env var | Default | Purpose |
| --- | --- | --- |
| `QPROOF_MCP_HOST` (or `HOST`) | `127.0.0.1` | Bind interface. Non-loopback requires a token. |
| `PORT` | `3000` | Listen port. |
| `QPROOF_MCP_TOKEN` | _(unset)_ | When set, requires `Authorization: Bearer <token>`. |
| `QPROOF_MCP_ALLOW_FS` | _(off)_ | `1`/`true` exposes the filesystem tools over HTTP. |
| `QPROOF_MCP_TIMEOUT_MS` | `30000` | Per-request tool-execution deadline. |
| `QPROOF_MCP_MAX_RESPONSE_BYTES` | `4194304` | Response-body size cap. |

```bash
# Local, knowledge tools only (default safe posture)
node dist/http.js

# Local with the filesystem tools enabled
QPROOF_MCP_ALLOW_FS=1 node dist/http.js

# Reachable from the network: a token is mandatory
QPROOF_MCP_HOST=0.0.0.0 QPROOF_MCP_TOKEN="$(openssl rand -hex 32)" node dist/http.js
```

Endpoints:

- `POST /mcp` — one JSON-RPC 2.0 message; the JSON-RPC response is the
  `application/json` body. Notifications get `202` with no body. An
  `mcp-session-id` header is echoed or minted on each request.
- `GET /health` — liveness probe returning `{ "status": "ok" }` (no auth).

```bash
curl -s localhost:3000/health
curl -s localhost:3000/mcp \
  -H 'content-type: application/json' \
  -H 'authorization: Bearer YOUR_TOKEN' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

See [HOSTING.md](./HOSTING.md) for the full production design (auth, multi-tenant
sessions, rate limiting, scaling). A sample request/response transcript lives in
[`examples/transcript.jsonl`](./examples/transcript.jsonl).

## Programmatic use

```ts
import { createQproofServer } from "@qproof/mcp";

const server = createQproofServer();
const res = await server.handle({ jsonrpc: "2.0", id: 1, method: "tools/list" });
```

## Development

```bash
npm run build   # tsc -b
npm test        # node --import tsx --test test/*.test.ts
```

Tests drive `McpServer.handle` directly (and the stdio loop via in-memory
streams) — no process spawning.

## License

Apache-2.0
