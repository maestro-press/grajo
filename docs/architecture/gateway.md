# Gateway

The gateway (`servers/gateway/`) is an Express server that makes Crow's MCP servers accessible over HTTP with OAuth 2.1 authentication.

## Modular Route Structure

The gateway entry point (`servers/gateway/index.js`, ~600 lines) is an **ordered security narrative**: the funnel/network-boundary middleware and the auth chain are wired inline, in a deliberate order that *is* the security model. Everything else is mounted from modules under `servers/gateway/boot/`:

| Boot module | Purpose |
|---|---|
| `boot/public-endpoints.js` | Public-safe endpoints (`/health`, `.well-known`, robots, manifest) |
| `boot/mcp-mounts.js` | All MCP server mounts (per-server endpoints + the router) |
| `boot/feature-mounts.js` | Feature routes: backup admin, storage, blog, window manager, media |
| `boot/admin-api.js` | Dashboard admin API routes |
| `boot/peer-public-api.js` | Peer/federation public API surface |
| `boot/late-mounts.js` | Routes that must mount after the main stacks |
| `boot/post-listen.js` | Post-listen startup tasks + console summary |

Core MCP transport logic is in `routes/mcp.js`, which exports the `mountMcpServer()` helper. Other route modules handle specific concerns:

| Module | Purpose |
|---|---|
| `routes/mcp.js` | `mountMcpServer()` — mounts Streamable HTTP + SSE transports for any MCP server |
| `routes/storage-http.js` | File upload (multipart) and download (presigned redirect) HTTP routes |
| `routes/owner-media.js` | `GET /dashboard/media/:key(*)` — the owner's media read behind the dashboard session (proxied bytes; the MCP bearer route `/storage/file/` is not reachable from an `<img>`) |
| `routes/blog-public.js` | Public blog pages, tag pages, RSS and Atom feeds (no auth) |
| `dashboard/` | Crow's Nest UI panels and auth system |
| `session-manager.js` | Consolidated session storage for all MCP servers (replaces per-server Maps) |

## Transports

### mountMcpServer() Helper

All MCP servers are mounted via the `mountMcpServer(router, prefix, createServer, sessionManager, authMiddleware, peerGate)` function from `routes/mcp.js`. It registers both Streamable HTTP and SSE endpoints for a given server factory, using the consolidated `SessionManager` for session tracking. The optional `peerGate` is a default-deny exposure check applied to authenticated **peer instances** (federation): a remote instance can only reach servers the operator has explicitly exposed to it. Local operators (dashboard session, OAuth, or the local MCP token) bypass the peer gate.

### Streamable HTTP (Primary)

Modern MCP transport used by most clients.

| Endpoint | Server |
|---|---|
| `POST\|GET\|DELETE /memory/mcp` | crow-memory |
| `POST\|GET\|DELETE /projects/mcp` | crow-projects |
| `POST\|GET\|DELETE /research/mcp` | crow-projects (legacy alias) |
| `POST\|GET\|DELETE /sharing/mcp` | crow-sharing |
| `POST\|GET\|DELETE /storage/mcp` | crow-storage (conditional, requires MinIO) |
| `POST\|GET\|DELETE /blog-mcp/mcp` | crow-blog |
| `POST\|GET\|DELETE /tools/mcp` | External tool proxy |
| `POST\|GET\|DELETE /mcp` | crow-memory (compatibility alias) |

Sessions are managed via the `mcp-session-id` header. New sessions are created on `initialize` requests. Each transport gets an in-memory `EventStore` for resumability.

### SSE (Legacy)

Legacy transport for ChatGPT and older clients.

| Endpoint | Purpose |
|---|---|
| `GET /memory/sse` | Open SSE stream + create session |
| `POST /memory/messages` | Send messages to session |
| `GET /projects/sse` | Open SSE stream |
| `POST /projects/messages` | Send messages |
| `GET /research/sse` | Open SSE stream (legacy alias) |
| `POST /research/messages` | Send messages (legacy alias) |
| `GET /sharing/sse` | Open SSE stream |
| `POST /sharing/messages` | Send messages |
| `GET /storage/sse` | Open SSE stream (conditional) |
| `POST /storage/messages` | Send messages (conditional) |
| `GET /blog-mcp/sse` | Open SSE stream |
| `POST /blog-mcp/messages` | Send messages |
| `GET /tools/sse` | Open SSE stream |
| `POST /tools/messages` | Send messages |

Sessions are identified by `sessionId` query parameter on message endpoints.

## OAuth 2.1

The gateway implements OAuth 2.1 with Dynamic Client Registration:

| Route | Purpose |
|---|---|
| `GET /.well-known/oauth-authorization-server` | OAuth metadata discovery |
| `GET /.well-known/oauth-protected-resource` | Protected resource metadata |
| `POST /register` | Dynamic client registration |
| `GET /authorize` | Authorization endpoint |
| `POST /token` | Token endpoint |
| `POST /introspect` | Token introspection |

OAuth is backed by SQLite tables (`oauth_clients`, `oauth_tokens`) for persistence across restarts.

Run without auth for local development only:
```bash
node servers/gateway/index.js --no-auth
```

> **Safety guard:** The gateway refuses to start with `--no-auth` if `CROW_GATEWAY_URL` contains a public domain (e.g., `.ts.net`, `.onrender.com`, `.fly.dev`). This prevents accidental exposure of unauthenticated MCP endpoints via Tailscale Funnel or cloud hosting.

## Integration Proxy

The proxy system (`proxy.js` + `services/legacy-sources.js`) aggregates external MCP servers into the `/tools/mcp` endpoint:

1. On startup, reads the service bundles (registry manifests with a `connect` block) and checks which of their fields are set in environment variables
2. For each configured service, spawns the MCP server as a child process (installed add-ons in `mcp-addons.json` follow; a service add-on starts only when its fields are set)
3. Connects via stdio transport and discovers available tools
4. Prefixes tool names with the integration ID (e.g., `github_create_issue`)
5. Exposes all tools through a single MCP endpoint

### Adding a New Integration

Add `bundles/my-service/manifest.json` with a `connect` block, then run `npm run build-registry`:

```json
{
  "id": "my-service",
  "name": "My Service",
  "description": "What it does",
  "type": "mcp-server",
  "server": { "command": "npx", "args": ["-y", "mcp-server-my-service"], "envKeys": ["MY_SERVICE_API_KEY"] },
  "connect": {
    "method": "token",
    "group": "paste",
    "fields": [{ "name": "MY_SERVICE_API_KEY", "kind": "secret", "label_key": "services.field.MY_SERVICE_API_KEY" }],
    "steps": ["services.steps.my-service.1"]
  }
}
```

See [Building Integrations](../developers/integrations.md) for the full manifest.

## Setup Page

`GET /setup` serves a mobile-friendly HTML page showing:

- Connected integrations (green) with tool counts
- Available integrations (gray) with setup links
- MCP endpoint URLs for all supported transports
- Quick setup instructions for each AI platform

No authentication required — doesn't expose secrets.

## Security Considerations

- **Never use `--no-auth` in production** — it disables all authentication. The gateway refuses `--no-auth` when `NODE_ENV=production` or when `CROW_GATEWAY_URL` contains a public domain
- **Always deploy behind HTTPS** — Render and Railway provide this automatically. If self-hosting, use a reverse proxy (nginx, Caddy) with TLS, or Tailscale Funnel
- The **`/setup` page** shows only a password form (no secrets). Until a password exists, it and the first-run login require a one-time setup token, generated in `<CROW_HOME>/setup-token` (mode 0600) or taken from `CROW_SETUP_TOKEN` when set; a request from the machine itself (loopback, no forwarding headers) is exempt, unless `CROW_SETUP_TOKEN` is set — that token is required from every source
- **`/api/health`** is protected by dashboard session auth — it exposes system metrics (RAM, disk, CPU). The public **`/health`** endpoint returns only server status (no system info)
- **OAuth tokens** are stored in the SQLite database and persist across restarts
- **Rate limiting** is built in — 200 requests per 15 minutes (general) and 20 requests per 15 minutes (auth endpoints: `/authorize`, `/token`, `/register`). For high-traffic deployments, add additional rate limiting via your reverse proxy or hosting provider. Limits key on the client address, and `X-Forwarded-For` is trusted only from Tailscale Serve/Funnel (verified by socket owner) and from proxies listed in `CROW_TRUSTED_PROXIES` (see [Dashboard › Network Security](./dashboard.md#network-security))
- **SSE connections are capped** — at most `CROW_SSE_MAX` (default 200) concurrent open streams across all eight SSE endpoints. Over the cap, the gateway responds `503` with `Retry-After: 5` and releases all per-stream resources
- A **local MCP token** (generated from the dashboard's Connect panel) authenticates local AI clients without the OAuth flow — verified server-side, hashed at rest, revocable from the same panel. See the [Cross-Platform Guide](../guide/cross-platform.md)
- The **board token** (`<CROW_HOME>/board-token`) is meant for bots, whose calls carry signed actor headers. A call on the board token without those headers is treated as an unattributed bot, and it fails closed: it sees at most the shared trackers, and project cards answer "not found". Interactive tools and your own MCP clients should use the full local MCP token instead, not the board token. (The `/board/mcp` mount accepts both tokens, except that the full local token is refused on a contained bot's relayed socket; the actor is resolved by `resolveActor` in `servers/gateway/board-mcp.js`. Generate the full token from the Connect panel, see the [Cross-Platform Guide](../guide/cross-platform.md).)
- **Content Security Policy** restricts resource loading — allows Google Fonts (dashboard), same-origin scripts, and podcast media sources
- The **`/crow.md` endpoint** is protected by OAuth when auth is enabled, since it exposes behavioral context

For the full public/private access model, see the [Security Guide](https://github.com/maestro-press/grajo/blob/main/SECURITY.md#whats-public-by-default).

## Router Mode

The `/router/mcp` endpoint exposes **one consolidated category tool per server** instead of the full raw tool surface (126+ tools across all servers). This is a major context-window reduction and the recommended way to connect an AI client.

On a full install the router registers 8 tools: 6 category tools (`crow_memory`, `crow_projects`, `crow_blog`, `crow_sharing`, `crow_storage`, `crow_media`) plus `crow_tools` (external integrations + remote instances) and `crow_discover` (schema lookup). Storage and media categories appear only when their backing service or bundle is available. Each category tool dispatches to the underlying server via an in-process MCP Client. The `crow_discover` tool returns full schemas on demand, so clients can inspect available actions without loading all tool definitions upfront. The `crow_research` name is accepted as a backward-compatible alias for `crow_projects`.

Router mode is backward compatible — existing per-server endpoints (`/memory/mcp`, `/research/mcp`, etc.) remain unchanged and continue to work as before. The router is an additional endpoint, not a replacement.

To disable router mode, set the environment variable `CROW_DISABLE_ROUTER=1`.

For the full reference, see [Context Management](/architecture/context-management).

## Chat API

The gateway includes a built-in AI Chat system (`/api/chat/*`) that turns Crow into an AI client. This powers the BYOAI Chat feature in the Crow's Nest. All chat routes are protected by dashboard session auth (cookie-based).

### Routes

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/api/chat/conversations` | Create a new conversation |
| `GET` | `/api/chat/conversations` | List conversations (paginated) |
| `GET` | `/api/chat/conversations/:id` | Get conversation with all messages |
| `DELETE` | `/api/chat/conversations/:id` | Delete conversation (cascades to messages) |
| `POST` | `/api/chat/conversations/:id/messages` | Send message, receive SSE stream |
| `POST` | `/api/chat/conversations/:id/cancel` | Cancel in-progress generation |
| `GET` | `/api/chat/providers` | List available providers and current config |
| `POST` | `/api/chat/providers/test` | Test provider connection |

### Provider Adapter Pattern

The AI provider layer (`ai/provider.js`) uses a registry of lazy-loaded adapters:

| Provider | Adapter | API Format |
|---|---|---|
| `openai` | `ai/adapters/openai.js` | OpenAI Chat Completions (also OpenRouter, vLLM, LM Studio) |
| `anthropic` | `ai/adapters/anthropic.js` | Anthropic Messages API |
| `google` | `ai/adapters/google.js` | Google Gemini REST API |
| `ollama` | `ai/adapters/ollama.js` | Ollama native `/api/chat` |

Each adapter implements a `chatStream(messages, tools, options)` method that returns an async iterator yielding events: `content_delta` (text chunks), `tool_call` (function calls), and `done` (usage stats). Provider config is hot-reloaded from `.env` with a 5-second cache.

### Tool Executor Pattern

When the AI responds with tool calls, the tool executor (`ai/tool-executor.js`) dispatches them to Crow's MCP servers:

1. The executor maintains a pool of lazy in-process MCP Clients, one per server category
2. Each client connects to its server factory via `InMemoryTransport` (same pattern as the tool router)
3. Tool calls are resolved by category — `crow_memory` routes to the memory server, `crow_projects` to the project server, etc.
4. The AI sees the router-style category tools (the executor dispatches the memory, projects, blog, sharing, storage, and media categories), plus `crow_tools`, `crow_discover` for schema lookup, and explicit orchestration tools
5. Results are truncated to 2000 characters to prevent context overflow
6. Up to 10 tool call rounds per message turn (the AI can call tools, get results, and call more tools)

```
User Message
  → AI Provider API (streaming)
    → content_delta events → SSE to browser
    → tool_call events → Tool Executor
      → InMemoryTransport → MCP Server → Database
      → result → back to AI for next round
  → done event → SSE to browser
```

Tool results and assistant messages are persisted to `chat_messages` with token counts. Conversations track total tokens for usage monitoring.

### Rate Limiting

Chat messages are rate-limited to 10 messages per minute per session (separate from the gateway's general rate limiter). Active generations can be cancelled via the cancel endpoint or by the client disconnecting.

## Graceful Shutdown

On `SIGTERM`/`SIGINT` the gateway runs a staged drain instead of exiting immediately: it stops the scheduler (so no new background ticks fire during teardown), stops accepting new connections, gives in-flight requests up to `CROW_SHUTDOWN_DRAIN_MS` (default 3000 ms) to finish, severs remaining sockets (long-lived SSE streams reconnect after restart), shuts down MCP sessions and proxy children, and finally checkpoints the SQLite WAL best-effort before exiting. This minimizes mid-operation kills during deploys and restarts. A monitor polling `/health` may see refusals for up to the drain window — that's the expected restart behavior.

## Health Check

`GET /health` returns JSON status:

```json
{
  "status": "ok",
  "servers": ["crow-memory", "crow-projects", "crow-sharing", "crow-storage", "crow-blog"],
  "externalServers": [{"id": "github", "name": "GitHub", "tools": 15}]
}
```

System resource metrics (RAM, disk, CPU) are available at `GET /api/health`, protected by dashboard session auth.

## Federation

The gateway can proxy tool calls to remote Crow instances via HTTP. When an instance is registered in the `crow_instances` table with a `gateway_url`, the proxy layer connects using the MCP SDK's `StreamableHTTPClientTransport` and makes remote tools available through the `crow_tools` router action with an `instance_id` parameter. See [Multi-Instance Architecture](./instances) for sync, conflict resolution, and security details.

## Convergence: how a gateway gets current with its checkout

Several gateways can share one `~/crow` checkout while keeping separate data
dirs (on the dev host: `crow-gateway`, `crow-mpa-gateway`, `crow-r4-gateway`).
That makes updating two different jobs with different scopes:

| Operation | Scope | Lock | Who runs it |
|---|---|---|---|
| pull the tree | the checkout | checkout-scoped, one winner | whichever instance wins |
| converge the instance | one data dir | none | **every** instance, always |

`checkForUpdates()` does the tree half only if it holds the lock, then **always**
runs the instance half. **A lock loss is normal, not an error** — another
co-hosted gateway is pulling the shared tree, which is correct. The loser skips
the pull it does not need and still migrates its own stores and restarts.

Convergence triggers on `bootSha !== HEAD`, never on whether this process
pulled: `runLockedUpdate` returns `updated: false` on several branches *after*
the tree has already moved.

**A process honors its own refusal.** The branches that deliberately withhold a
restart (init-db failure, both migration-guard loss paths) return
`converge: false`, and `checkForUpdates` then skips the instance half. Without
that, convergence would restart into a sha whose `init-db` just failed and the
boot guard would `process.exit(1)`. On units configured `RestartSec=5` against a
10 s `StartLimitInterval`, `StartLimitBurst` never trips — so the result is an
**unbounded** crash loop, not a stopped unit, with each iteration re-running
`init-db` against a live store.

Convergence **owns the restart** — scheduled only after migrations run and the
boot cookie is written. An unsupervised instance migrates, logs that a manual
restart is needed, and writes no cookie.

### Migration registry

`scripts/migrations/NNNN-slug.mjs`, each exporting `id` and
`run({ dbPath, tasksDbPath, log })`. Bodies must be idempotent and shape-checked
(`PRAGMA` presence, additive `ALTER`) — a restored backup can lose the
bookkeeping row while keeping the change.

Return `{ deferred: true }` when **any** target table is absent. Bundle-owned
stores are created by their bundle, which starts *after* the gateway boots;
recording a deferral as applied would let the table be created later without the
new columns and never retry.

A deferral may carry a short stable `reason` (`"tasks_items absent"`). It is
remembered in `schema_migrations_deferred` (also created lazily by the runner,
never in `init-db.js`) so a wait that repeats on every boot is logged once: the
first deferral — and any change of reason — is loud, a repeat with the same
reason only refreshes `last_checked_at`. A migration that applies deletes its
deferral row in the same transaction as its `schema_migrations` record, and a
missing row (a restored DB) just costs one extra log line. The row never syncs
(instance-sync replicates only `SYNCED_TABLES`).

The registry runs **twice per boot**: once before serving (covers `crow.db`) and
again after the addons settle (covers bundle-owned stores). Bookkeeping lives in
`schema_migrations`, created lazily by the runner — deliberately **not** in
`init-db.js`, which would bump `SCHEMA_GENERATION` and re-run its `DROP TABLE`
statements on every live instance DB.

### Health gate

A **regression** check, not an absolute one: it compares the post-restart addon
snapshot against the pre-restart baseline carried in the boot cookie. "All addons
connected" would quarantine a good sha on any host that already had a broken
addon. Only `entry.isAddon` entries count — `connectedServers` also holds remote
federation peers, whose status flips to `offline` when a crow on another machine
reboots.

The gate waits on an addons-settled signal rather than a clock (addons connect
sequentially, 60 s timeout each) with a 10-minute timeout that yields
**unknown / fail open**. An indeterminate gate never quarantines.

### Quarantine, not rollback

On regression the sha is written to `.crow-convergence-quarantine.json` at both
repo and data level, an alert fires, and the instance keeps running degraded.
Peers read the repo-level marker and refuse that sha, so **the first instance to
converge is the canary by construction**.

The tree is never rolled back: `git reset --hard` on a shared checkout would drag
co-hosted peers backward for one instance's failure. Markers hard-expire after
**24 h**, so no failure mode needs manual file deletion to recover. To clear one
early, delete both files.

### Kill switch

`CROW_DISABLE_CONVERGE=1` short-circuits the instance half entirely. The tree
half still runs, so the checkout keeps updating — the instance just stops
migrating and restarting itself.

## Keychain envelopes: a saved password is bound to its row

Every value in `crow_keychain` is sealed with `servers/sharing/secret-box.js` under the keychain's own key (`<CROW_HOME>/secrets/keychain.key`). Since the AAD era it is sealed in the **v2** form (`enc:v2:`): AES-256-GCM with associated data — `rowAad()` in `servers/gateway/keychain/store.js` over the row's `kind`, `bundle_id`, `env_key`, `connection_uuid` (label, username, url and status are deliberately not bound, because they change legitimately). `openSecret` (v1, no associated data) still opens Shared Storage settings, but a keychain v2 blob opens only in the row it belongs to, so a blob copied into another add-on's row — the way a bot with `crow.db` write access used to make Crow hand it the Mail password at its next spawn — fails its tag check and the row counts as unreadable.

The pre-listen boot pass `servers/gateway/boot/keychain-aad.js` (also wired into the satellite agent, whose `satellite.db` carries its own `crow_keychain`) runs right after the provider-key seal pass: it takes a verified `crow.db` copy under `secrets/backups/keychain-aad/`, snapshots the blob digests of every `enc:v1:` row into `secrets/keychain-aad-rollback-<ts>.json`, refuses (alarms, leaves in the old form) any candidate whose 12-byte GCM nonce another row also carries — a copy, whichever base64 spelling it was re-written in, and the source row is refused with it — or whose body is not canonical base64, or that is bound to something no local row names (an add-on that is not installed, a connection uuid that is neither a project connection nor a Mail account — an ADVISORY check, since every table it reads is bot-writable and it must never refuse an owner's row when it cannot know), reseals the rest to v2 in one transaction and proves each one by re-opening it, then records the **era** — `secrets/keychain-aad-state.json` (0600, read hardened and synchronously by the add-on spawn reader, from the secrets DIR the reader's key path names — also the fd-anchored `/proc/self/fd/<n>` the pibot host uses) plus the local-scope `keychain_aad_era` DB mirror (which the boot pass trusts only together with a v2 row that actually opens: a mirror a bot plants before the first boot is alarmed and ignored, so it can never freeze every saved password in the refused form, and boot re-writes the state file whenever that evidence proves the era). From then on an `enc:v1:` keychain row is refused like an unreadable row, audited as `keychain_legacy_form` and reported once a day as a `security` bell: nothing this release writes is v1 any more, so such a row is a value something else put there — and any `enc:v2:` row is itself evidence a conversion ran, so the refusal fails closed whatever a bot deletes from crow.db. A crash between the conversion and the marker converts only the rows the newest snapshot names (never a row written after it), where crash evidence is a v2 row that actually opens under this key; before the era, v1 rows open exactly as before. The conversion also moves each converted row's Export fingerprint to its new blob, so the off-site upload gate and the "not exported yet" reminder do not regress.

Two operator tools, both printing counts only: `scripts/ops/keychain-aad-dryrun.mjs --db <label>=<path> … --key-from <home> --home <scratch>` copies each database and the keychain key into a scratch home, runs the real converter twice (the second boot must change nothing) and re-opens every row through the store's own open path, printing `PASS` or `STOP` per label (the scratch home — key copies and converted databases — is always cleared at exit); `scripts/ops/keychain-aad-downgrade.mjs --yes` is the rollback for a code revert — it refuses while the gateway looks running unless `--force-while-running`, takes the same verified copy, reseals every v2 row back to v1 and removes the era marker and mirror.

**Deploy note — restart the GATEWAY FIRST, then the pibot hosts.** A pibot host (`pibot-gateways@*`) is a separate process that reads the keychain key and the add-ons' rows (`scripts/pi-bots/mcp_writer.mjs` → `servers/shared/addon-secrets.js` → `servers/gateway/keychain/store.js`) to hydrate a spawn, and its code is the code on disk: a host STARTED before the gateway converts runs the new reader against an unconverted keychain, and a new-code reader REFUSES an `enc:v1:` row (nothing this release writes is v1), so every bot spawn on that host answers `ROWS_MISSING` until the gateway's boot pass has converted the rows. Restart `crow-gateway` first, let its boot pass convert and record the era, and only then restart every `pibot-gateways@*` unit — the host then reads v2 rows and an era that is already in place. (An old-code host still cannot open a v2 row, so it must not be left running across the conversion either: once the era exists, an old host hands its bots `ROWS_MISSING` or leaves the era unenforced against a v1 blob it still opens.) Re-run the deploy on any host that was down while the gateway converted.
