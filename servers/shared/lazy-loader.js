/**
 * The lazy-loader rule, in one place: a provider kind that loads its model on the first request, so
 * anything that sends to it is an on-demand model starter.
 *
 * Two callers read it: the gateway's model router (`routes/llm-router.js`, which re-exports
 * `isLazyLoader` for its own callers and refuses such an endpoint for a background completion) and the
 * reports approvals path (`reports/approvals.js`), which refuses one when it resolves the model a
 * report's role names, so a report is never sealed over an endpoint its completion would not send to.
 *
 * Pure: no DB, no fs, no network.
 */

/** Provider kinds that load a model on the first request (a lazy loader is a model starter). */
export const LAZY_LOADER_RE = /ollama|llama[-_ ]?swap|lemonade|lm[-_ ]?studio|localai/i;

/** Ollama's well-known port, for a row whose kind was never recorded. */
export const LAZY_LOADER_PORT_RE = /:11434(\/|$)/;

/**
 * Does this resolved upstream (`{baseUrl, providerType}`) load its model lazily?
 * @param {{baseUrl?: string, providerType?: string|null}|null} up
 * @returns {boolean}
 */
export function isLazyLoader(up) {
  return !!up && (LAZY_LOADER_RE.test(String(up.providerType || "")) || LAZY_LOADER_PORT_RE.test(String(up.baseUrl || "")));
}