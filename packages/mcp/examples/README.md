# Examples

## `transcript.jsonl`

A sample MCP session against the qproof server, one JSON object per line. Each
line has a `direction` (`client→server` / `server→client`), an optional `note`,
and the JSON-RPC `message` actually exchanged.

It walks through a full lifecycle:

1. `initialize` handshake (and its response advertising `serverInfo` + capabilities)
2. the `notifications/initialized` notification (no response is returned)
3. a `ping` keepalive
4. `tools/list` (the complete tool catalog with input schemas)
5. two `tools/call` invocations (`suggest_hybrid`, `explain_finding`)
6. an error case: an unknown method returning JSON-RPC error `-32601`

The `direction`/`note` wrappers are illustrative metadata; on the wire only the
`message` payloads are sent (newline-delimited over stdio, or as the `POST /mcp`
body over HTTP).

The `explain_finding` / detector text shown reflects a populated `@qproof/core`;
with the current stub the catalog may be empty, but the protocol shapes are
identical.

### Replaying over HTTP

```bash
PORT=3000 node ../dist/http.js &

curl -s localhost:3000/mcp -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/list"}' | jq

curl -s localhost:3000/mcp -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"suggest_hybrid","arguments":{"algorithm":"RSA"}}}' | jq
```
