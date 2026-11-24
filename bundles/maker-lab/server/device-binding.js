/**
 * MOVED — this module now lives at bundles/maker-lab/panel/device-binding.js.
 *
 * Why: everything under a bundle's server/ tree is BOT-REACHABLE (a bot MCP
 * child loads it), and `hasAdminSession` reads the dashboard's session rule
 * (servers/gateway/dashboard/auth.js -> servers/gateway/token-store.js, the
 * store whose verifiers are minted under servers/shared/token-mac.js's
 * host-only HMAC key). Only panel/ code — which runs inside the gateway — may
 * do that. Nothing under server/ ever imported this module: only
 * panel/routes.js and panel/maker-lab.js did, and both now resolve it from
 * panel/ through the bundle's app root.
 *
 * THIS STUB MUST STAY. Do not delete it as "a leftover": a bundle refresh copies
 * the repo's server/ tree into ~/.crow/bundles/<id>/server/ ADDITIVELY — the top-level
 * directories go through copyBundleRefreshItem with its default prune:false (only a
 * manifest-declared refresh root is pruned), so a file the repo no longer ships is never
 * removed from an installed copy. Deleting this stub would leave the OLD, auth-importing
 * device-binding.js in place for every install that was made before the move, at the same
 * manifest version — exactly the file this stub replaced. A zero-export stub is the only
 * way to make the refresh overwrite it.
 * tests/bundle-server-no-gateway-auth.test.js enforces the rule.
 */
export {};