# Hosting quantakrypto MCP as a remote service

This document describes how to run `@quantakrypto/mcp` as a hosted, multi-tenant
service rather than a per-user local stdio process. The shipped `src/http.ts` is
the minimal, working core of this design; everything below is the path from that
scaffold to production.

## 0. Safe-by-default posture (what `src/http.ts` enforces today)

The stdio transport trusts the local user and is fully featured. The HTTP
transport is **hardened by default** (P0-1 / security-audit Q-01–Q-03) because a
hosted endpoint is reachable by untrusted peers. Out of the box `node dist/http.js`:

- **Binds to `127.0.0.1`**, not `0.0.0.0`. Override with `QUANTAKRYPTO_MCP_HOST`.
  Binding to a **non-loopback host without a token is refused at startup** — an
  unauthenticated, network-reachable tool server would be an open relay into the
  arbitrary-file-read tools.
- **Requires Bearer auth when `QUANTAKRYPTO_MCP_TOKEN` is set.** Every `/mcp` request
  must carry `Authorization: Bearer <token>`; auth is checked *before* the body
  is read or dispatched. Missing/invalid token → `401` with `WWW-Authenticate: Bearer`.
  `GET /health` is unauthenticated.
- **Gates the filesystem tools off by default.** `scan_path`, `inventory_crypto`
  and `generate_cbom` take a client-supplied path straight into `core.scan` and
  would otherwise be an arbitrary-directory reader (`/etc`, `/root/.ssh`, …) with
  matched-line snippets echoed back. Over HTTP they are registered **only when
  `QUANTAKRYPTO_MCP_ALLOW_FS=1`**, so both `tools/list` and `tools/call` reflect the
  gate. The knowledge tools (`explain_finding`, `suggest_hybrid`, `list_rules`)
  are pure and always exposed. The gating is a pure function (`gateHttpTools`),
  unit-tested in `test/http.test.ts`.
- **Confines the filesystem tools to a root allow-list.** When the FS tools are
  enabled, every scanned path must resolve inside `QUANTAKRYPTO_MCP_ROOT`
  (`:`-separated; defaults to the process CWD). `..` traversal and out-of-root
  absolute paths are rejected (`resolveScanPath` in `src/fsconfig.ts`), so the
  endpoint cannot be turned into an `/etc/passwd` read oracle.
- **Validates the request `Origin`.** `POST /mcp` rejects a browser request whose
  `Origin` host is not loopback (or in `QUANTAKRYPTO_MCP_ALLOW_ORIGIN`) with `403`,
  blocking DNS-rebinding / localhost-CSRF against the default no-token config.
  Requests with no `Origin` (CLI / native MCP clients) are unaffected.
- **Bounds each request.** A 1 MiB request-body cap (`413` only on the cap; a
  transport read error is `400`), a per-request tool timeout that **aborts the
  in-flight scan** (`QUANTAKRYPTO_MCP_TIMEOUT_MS`, default 30 s → `504`; no
  background work leaks past the response), a response-size cap
  (`QUANTAKRYPTO_MCP_MAX_RESPONSE_BYTES`, default 4 MiB → `500`), and per-scan work
  budgets (`QUANTAKRYPTO_MCP_MAX_FILES` / `QUANTAKRYPTO_MCP_MAX_BYTES`, each capped).
- **Sanitizes error messages.** Internal failures (an `ENOENT` carrying a server
  path, a stack trace) are logged to stderr and replaced with a generic message
  in the wire response, so a remote caller never learns server internals.

| Env var | Default | Purpose |
| --- | --- | --- |
| `QUANTAKRYPTO_MCP_HOST` (or `HOST`) | `127.0.0.1` | Bind interface. Non-loopback **requires** a token. |
| `PORT` | `3000` | Listen port. |
| `QUANTAKRYPTO_MCP_TOKEN` | _(unset)_ | When set, requires `Authorization: Bearer <token>`. |
| `QUANTAKRYPTO_MCP_ALLOW_FS` | _(off)_ | `1`/`true` exposes the filesystem tools over HTTP. |
| `QUANTAKRYPTO_MCP_ROOT` | _(cwd)_ | `:`-separated allow-list of directories the FS tools may scan. |
| `QUANTAKRYPTO_MCP_ALLOW_ORIGIN` | _(loopback)_ | Comma-separated extra `Origin` hosts allowed on `/mcp`. |
| `QUANTAKRYPTO_MCP_TIMEOUT_MS` | `30000` | Per-request deadline; aborts the in-flight scan on timeout. |
| `QUANTAKRYPTO_MCP_MAX_RESPONSE_BYTES` | `4194304` | Response-body size cap. |
| `QUANTAKRYPTO_MCP_MAX_FILES` | `25000` (cap `250000`) | Max files a single scan may read. |
| `QUANTAKRYPTO_MCP_MAX_BYTES` | `268435456` (cap 2 GiB) | Max cumulative bytes a single scan may read. |

**Design choice — refuse vs. warn on a wide-open bind.** Binding to a
non-loopback host with `QUANTAKRYPTO_MCP_TOKEN` unset is **refused** (startup fails)
rather than merely warned, because the failure mode is severe and silent (an
internet-reachable arbitrary-tool endpoint). A non-loopback bind *with* a token
is allowed but emits a hard `WARNING` to stderr. Even then, the recommendation
remains to terminate TLS and validate keys at a gateway (§3) and to leave the
filesystem tools off unless the path surface is sandboxed (§3.1 of the security
audit). The sections below describe the remaining production hardening.

## 1. Transport choice

MCP defines two transports:

- **stdio** — newline-delimited JSON over a child process's stdin/stdout. Ideal
  for *local* agents (Claude Desktop/Code spawns the bin). Not hostable: one
  process per client, no network surface.
- **Streamable HTTP** — JSON-RPC over HTTP. A client `POST`s a JSON-RPC message
  to a single endpoint (`/mcp`) and either gets a JSON response back, or upgrades
  to an SSE (`text/event-stream`) stream for server-initiated messages.

**For hosting, use Streamable HTTP.** Our `http.ts` implements the JSON
request/response half (sufficient for stateless tool calls). To fully conform,
add:

- **SSE responses**: when a client sends `Accept: text/event-stream`, reply with
  an event stream so the server can push notifications/progress. quantakrypto's tools
  are currently synchronous request/response, so this is optional until we add
  long-running scans with progress events.
- **`GET /mcp`**: opens a standalone SSE stream for server→client messages.

```
            ┌────────────┐   POST /mcp (JSON-RPC)   ┌──────────────────┐
  MCP       │            │ ───────────────────────► │  HTTP transport  │
  client ◄──┤  client    │                          │  (src/http.ts)   │
            │            │ ◄─── 200 JSON / SSE ───── │                  │
            └────────────┘                          └────────┬─────────┘
                                                             │ handle()
                                                    ┌────────▼─────────┐
                                                    │   McpServer      │
                                                    │ (src/server.ts)  │
                                                    └────────┬─────────┘
                                                             │ tools
                                                    ┌────────▼─────────┐
                                                    │   @quantakrypto/core   │
                                                    └──────────────────┘
```

## 2. Multi-tenant sessions

The MCP Streamable HTTP transport uses an **`Mcp-Session-Id`** header. Our
scaffold echoes a provided id or mints one with `randomUUID()`, but keeps **no
state** (every request is independent). For production:

1. On `initialize`, mint a session id, create a `Session` record, and return the
   id in the `Mcp-Session-Id` response header.
2. Require that header on every subsequent request; reject unknown/expired
   sessions with `404` (so clients re-`initialize`).
3. Store per-session state in a shared store (Redis / Postgres), **not** process
   memory, so any instance behind a load balancer can serve any session:
   - tenant/identity, negotiated protocol version, capabilities;
   - rate-limit counters, usage metering;
   - any in-flight long-running scan handles.
4. Expire idle sessions (TTL) and support explicit teardown
   (`DELETE /mcp` with the session header).

Keep the `McpServer` instance **stateless and shared** across sessions — it
already is (the only mutable field is an informational `initialized` flag, which
should move into the session record once sessions exist).

## 3. Authentication & API keys

stdio trusts the local user; a hosted endpoint must not.

- **API keys / bearer tokens.** Require `Authorization: Bearer <token>` on
  `/mcp`. Validate before `readBody`/dispatch. Map the key → tenant for metering
  and quotas. This is the natural place to gate access in `handleMcpPost`.
- **OAuth 2.1.** The MCP spec defines an OAuth flow for HTTP transports
  (Protected Resource Metadata + Authorization Server). For first-party clients,
  scoped API keys are simpler; add OAuth when third-party clients must connect on
  a user's behalf.
- **mTLS / network policy.** For internal/enterprise deployments, terminate mTLS
  at the gateway and keep `/mcp` private.
- Never log request bodies that may contain source code; treat scanned content
  as sensitive.

## 4. Rate limiting & quotas

- **Per-key token bucket** at the edge (gateway) and a backstop in-process limit.
  Scans are CPU- and I/O-bound, so limit by *concurrent scans* per tenant, not
  just request rate.
- **Body size cap** — already enforced (`MAX_BODY_BYTES`, 1 MiB). Make it
  configurable and tenant-tiered.
- **Per-call timeouts** for tool execution; return an `isError` tool result on
  timeout rather than hanging the connection.
- **Cost metering** keyed by session/tenant for billing and abuse detection.

## 5. Scaling

- **Stateless app tier.** With sessions in a shared store, run N replicas behind
  an L7 load balancer; no sticky sessions needed for request/response. *Sticky
  routing is required only for long-lived SSE streams* — pin those to the
  instance that owns the stream, or use a pub/sub fan-out (Redis) so any instance
  can deliver server→client events.
- **Horizontal autoscale** on CPU (scans are CPU-heavy). Consider offloading
  large scans to a worker queue and returning progress over SSE.
- **Caching.** Cache `tools/list`, `list_rules`, and remediation lookups (static
  per core version). Optionally cache scan results keyed by a content hash.
- **Health & readiness.** `GET /health` exists; add a readiness probe that checks
  the session store and a liveness probe that excludes it.
- **Observability.** Structured logs (never bodies), per-method latency/error
  metrics, and tracing across HTTP → `McpServer.handle` → core.

## 6. What runs server-side vs. in core

| Concern | Where |
| --- | --- |
| HTTP framing, sessions, auth, rate limiting, metering | **HTTP transport / gateway** (`src/http.ts` + infra) |
| JSON-RPC 2.0 dispatch, MCP methods, error mapping | **`McpServer`** (`src/server.ts`) — pure, reused by every transport |
| Tool schemas, argument validation, result shaping | **Tools** (`src/tools.ts`) |
| Crypto detection, inventory, remediation knowledge | **`@quantakrypto/core`** — the single source of truth; transports never reimplement detection logic |

The guiding principle: **transports do I/O and policy; `McpServer` does protocol;
`@quantakrypto/core` does cryptographic analysis.** Hosting adds an HTTP/edge layer
around the exact same `McpServer` used over stdio, so behaviour is identical
whether quantakrypto runs locally or as a service.

## 7. Minimal deployment example

```bash
# Container entrypoint. A non-loopback bind REQUIRES a token (else startup is
# refused). Leave QUANTAKRYPTO_MCP_ALLOW_FS unset to keep the filesystem tools off.
PORT=8080 \
QUANTAKRYPTO_MCP_HOST=0.0.0.0 \
QUANTAKRYPTO_MCP_TOKEN="$(cat /run/secrets/quantakrypto_mcp_token)" \
node dist/http.js
```

Put it behind a gateway that terminates TLS, validates API keys, applies rate
limits, and forwards to `/mcp`. Run ≥2 replicas with a shared session store and a
health check on `/health`. The built-in Bearer check is a backstop; the gateway
should remain the primary auth boundary. Enable `QUANTAKRYPTO_MCP_ALLOW_FS=1` only when
the scanned path surface is sandboxed (e.g. a read-only, dedicated mount).
