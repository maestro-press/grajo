/**
 * MOVED — this module now lives at bundles/phone/panel/authority.js.
 *
 * Why: everything under a bundle's server/ tree is BOT-REACHABLE (a bot MCP
 * child loads it), and these checks read the gateway's owner rule
 * (servers/gateway/dashboard/local-session.js -> servers/gateway/token-store.js,
 * whose verifiers are minted under servers/shared/token-mac.js's host-only HMAC
 * key) plus the gateway's 2FA module. Only panel/ code — which runs inside the
 * gateway — may do that. Nothing under server/ ever imported this module: only
 * panel/routes.js did, and it now resolves it from panel/ through the bundle's
 * app root.
 *
 * THIS STUB MUST STAY. Do not delete it as "a leftover": a bundle refresh copies
 * the repo's server/ tree into ~/.crow/bundles/<id>/server/ ADDITIVELY — the top-level
 * directories go through copyBundleRefreshItem with its default prune:false (only a
 * manifest-declared refresh root is pruned), so a file the repo no longer ships is never
 * removed from an installed copy. Deleting this stub would leave the OLD,
 * session-checking authority.js in place for every install made before the move, at the
 * same manifest version — exactly the file this stub replaced. A zero-export stub is the
 * only way to make the refresh overwrite it.
 * tests/bundle-server-no-gateway-auth.test.js enforces the rule.
 */
export {};