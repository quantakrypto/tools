# Hosting qproof MCP as a remote service

This document describes how to run `@qproof/mcp` as a hosted, multi-tenant
service rather than a per-user local stdio process. The shipped `src/http.ts` is
the minimal, working core of this design; everything below is the path from that
scaffold to production.

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
  an event stream so the server can push notifications/progress. qproof's tools
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
                                                    │   @qproof/core   │
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
| Crypto detection, inventory, remediation knowledge | **`@qproof/core`** — the single source of truth; transports never reimplement detection logic |

The guiding principle: **transports do I/O and policy; `McpServer` does protocol;
`@qproof/core` does cryptographic analysis.** Hosting adds an HTTP/edge layer
around the exact same `McpServer` used over stdio, so behaviour is identical
whether qproof runs locally or as a service.

## 7. Minimal deployment example

```bash
# Container entrypoint
PORT=8080 HOST=0.0.0.0 node dist/http.js
```

Put it behind a gateway that terminates TLS, validates API keys, applies rate
limits, and forwards to `/mcp`. Run ≥2 replicas with a shared session store and a
health check on `/health`.
