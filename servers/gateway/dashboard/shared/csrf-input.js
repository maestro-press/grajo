/**
 * The CSRF token's RENDER helpers — the two pure functions that draw a token into HTML.
 *
 * They live apart from csrf.js (the middleware + the session-bound HMAC) because the
 * middleware reads the session (`sessionTokenFromRequest` from auth.js), and auth.js goes
 * through servers/gateway/token-store.js, whose verifiers are minted under
 * servers/shared/token-mac.js's host-only HMAC key. Anything that only RENDERS a form —
 * the Fix-it registry in servers/gateway/fix-it/index.js, which is reachable from
 * bot-reachable code (servers/research/server.js -> servers/shared/project-lifecycle.js ->
 * servers/gateway/proxy.js) — must not pull that key into a bot's module graph for a
 * hidden input. csrf.js re-exports both, so every existing importer is unchanged.
 */
import { escapeHtml } from "./components.js";

/**
 * Emit a hidden input carrying the CSRF token. For classic `<form>` submits
 * that don't go through Turbo's auto-header-attach path.
 */
export function csrfInput(req) {
  const token = req && req.csrfToken ? String(req.csrfToken) : "";
  return `<input type="hidden" name="_csrf" value="${escapeHtml(token)}">`;
}

/** The bytes for the `<meta name="crow-csrf">` tag a page renders (layout.js). */
export function csrfMetaTag(token) {
  return `<meta name="crow-csrf" content="${escapeHtml(typeof token === "string" ? token : "")}">`;
}