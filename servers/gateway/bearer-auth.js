/**
 * The gateway's OAuth bearer middleware — and the ONE place that refuses it on an
 * egress-relayed socket.
 *
 * Every surface that falls back to OAuth reaches this one instance:
 * `servers/gateway/index.js` builds it once and hands it to every
 * `mountMcpServer` mount (`routes/mcp.js`'s `skipAuthForInstance`), to
 * `/crow.md`, to the dashboard router's owner-token routes, and to the storage /
 * push / settings-scope / extension-proxy routers. So the relay check lives
 * here, not in any mount: a mount added later inherits it without knowing about
 * it.
 *
 * WHY a relayed socket never authenticates here. A contained bot has `crow.db`
 * bound read-write, so it can write its own `oauth_tokens` row and then present
 * it as an OAuth access token. Every mount OAuth admits calls the caller the
 * owner (`routes/mcp.js` `callerFor` → `owner-remote` → the board, phone and
 * artifacts tool guards resolve the owner actor), which is precisely the hole
 * `localTokenAuthMiddleware` closes for the operator's full local token on a
 * relayed socket (`servers/gateway/local-token.js`). The same refusal must
 * therefore cover OAuth: only the path-scoped token families (board, phone,
 * artifacts, secrets, sharing-bot, reports, mail-draft, report-pickup, peer-relay, the `llm`
 * doors) — each with its own signed actor signature — admit a relayed caller.
 *
 * WHAT the refusal looks like: exactly what a relayed socket already gets today
 * when it presents the full local token. `localTokenAuthMiddleware` declines to
 * authenticate it, the request reaches this middleware, and its verifier rejects
 * the unknown token — `401` with the SDK's `WWW-Authenticate: Bearer
 * error="invalid_token", …` header and `{error: "invalid_token",
 * error_description: "Invalid token"}` body. That body is built by the SDK's own
 * `requireBearerAuth` here too, from an always-invalid verifier, so the two
 * cannot drift and no new refusal text is invented. Non-relayed callers are
 * untouched: they get the real verifier and the real middleware.
 *
 * The dashboard's session cookie has the matching guards of its own
 * (`dashboardAuth` / `sessionFromRequest` in `dashboard/auth.js`), because a
 * session is not a bearer token.
 */

import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import { InvalidTokenError } from "@modelcontextprotocol/sdk/server/auth/errors.js";
import { isRelayedSocket } from "../shared/bot-doors.js";

/**
 * Build the gateway's bearer auth middleware.
 *
 * @param {object} opts
 * @param {{ verifyAccessToken: (token: string) => Promise<object> }} opts.verifier
 *   the OAuth provider's token verifier (the gateway passes CrowOAuthProvider's)
 * @param {string[]} [opts.requiredScopes]
 * @param {string} [opts.resourceMetadataUrl] advertised on the 401
 * @returns {(req: object, res: object, next: Function) => void} Express middleware
 */
export function createBearerAuthMiddleware({ verifier, requiredScopes = [], resourceMetadataUrl }) {
  const oauth = requireBearerAuth({ verifier, requiredScopes, resourceMetadataUrl });

  // The refusal a relayed socket gets. Built from the SAME options with a
  // verifier that never accepts anything, so its answer is byte-for-byte the one
  // an unknown token gets ("Invalid token" is the message
  // CrowOAuthProvider.verifyAccessToken throws for a row that is not there).
  const relayedRefusal = requireBearerAuth({
    verifier: {
      verifyAccessToken: async () => { throw new InvalidTokenError("Invalid token"); },
    },
    requiredScopes,
    resourceMetadataUrl,
  });

  return function bearerAuth(req, res, next) {
    if (isRelayedSocket(req.socket)) return relayedRefusal(req, res, next);
    return oauth(req, res, next);
  };
}