/**
 * The model check a report pickup's locked turn runs, and nothing else (defence in depth).
 *
 * A pickup's prompt is written by people OUTSIDE Crow — a recipient's comment, quoted as untrusted data —
 * so the turn must run on a model that is provably on this box or the local network. `pickupCheckModel`
 * builds the one `checkModel(resolved)` a pickup launcher hands the bridge: it reads the model the bridge
 * actually resolved (after role resolution and before any spawn) and answers `{ok: true}` only for a key
 * that is non-empty, is not a `role:` ref, and is not a cloud key by the codebase's one locality notion.
 *
 * THE SECOND LOCK: the bridge already enforces the kind's local-only floor for a `report-pickup` turn
 * (`modelFloor: "local-only"` in scripts/pi-bots/mcp_writer.mjs's locked-turn table, refused with a
 * `lockedTurn` code before a model is warmed). This check is the launcher's own copy of that rule, run on
 * the resolved key in the same place Crow Mail's drafting gate runs, so a pickup refuses even if a bridge
 * build or a seam were to let a cloud model through.
 *
 * The rule is EXACTLY `allowDraftModelKey`'s local half (servers/gateway/mail/drafts/turn.js): a pickup
 * has no owner switch to turn a cloud model on and no account-level opt-out to honour, so anything not
 * proven local — a role ref, a provider with no row, a public or unresolvable host — is refused with one
 * code. Nothing here imports from the mail tree: the mail rule belongs to mail, and this is reports'.
 *
 * A missing `providers` array fails closed: with no rows nothing can be proven local, so the returned
 * check refuses every key rather than waving one through.
 */
import { isCloudKey, isRoleRef } from "../../shared/model-roles.js";

/** The one code a refused pickup model carries. */
export const MODEL_NOT_LOCAL = "model_not_local";

/**
 * Build the pickup turn's `checkModel`.
 *
 * @param {{providers?: object[]}} [options] the provider rows as the locality predicate reads them
 *   (`id`, `baseUrl`, `host`, ...), loaded by the launcher from this instance
 * @returns {(resolved: {key?: string|null}|null|undefined) => {ok: true}|{ok: false, code: string}}
 */
export function pickupCheckModel({ providers } = {}) {
  const rows = Array.isArray(providers) ? providers : null;
  return (resolved) => {
    if (!rows) return { ok: false, code: MODEL_NOT_LOCAL };
    const key = typeof resolved?.key === "string" ? resolved.key.trim() : "";
    if (!key || isRoleRef(key)) return { ok: false, code: MODEL_NOT_LOCAL };
    if (isCloudKey(key, { providers: rows }) !== false) return { ok: false, code: MODEL_NOT_LOCAL };
    return { ok: true };
  };
}