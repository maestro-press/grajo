/**
 * Fix-it detector: data backends whose approval predates keyed approvals.
 *
 * An `mcp_server` data backend is a command the gateway runs, and the owner's
 * approval is stored in the same crow.db row it approves. Older versions stored
 * a plain SHA-256 there — a value anyone who can write crow.db can recompute —
 * so those rows prove nothing. The gateway stops every one of them and the
 * owner approves them again on the Projects page (which writes the keyed form).
 * This card says how many are waiting, once, so the owners of older installs do
 * not lose a backend's tools without being told why.
 *
 * No event fires for a database row, so this is a BOOT check: fix-it/index.js's
 * runBootChecks() calls `check()` once per gateway start, and the card resolves
 * itself once nothing is left to re-approve.
 */
import { cardContext, cardRemedyLabel, cardText } from "../card-copy.js";
import { isLegacyApproval } from "../../../shared/data-backend-approval.js";

export const SOURCE = "data-backend-reapproval";
export const DEDUP_KEY = "data-backend:legacy-approval";
/** The link remedy whose target lives in code (fix-it/index.js LINK_REMEDIES). */
export const REMEDY_ACTION_ID = "open-projects-page";

const CARD_CODE = "data-backend-reapproval";

/** The card's title, from the ONE copy table (fix-it/card-copy.js). */
export const TITLE = cardText(CARD_CODE, { n: 0 }, "en").title;

/** The card's body, with the number of backends waiting. */
export function bodyText(count) {
  const n = Number(count) || 0;
  return cardText(CARD_CODE, { n }, "en").why;
}

/** How many mcp_server rows carry the old bare-hash approval. */
export async function countLegacyApprovals(db) {
  if (!db || typeof db.execute !== "function") return 0;
  const { rows } = await db.execute({
    sql: "SELECT approved_ref_sha256 FROM data_backends WHERE backend_type = 'mcp_server' AND approved_ref_sha256 IS NOT NULL",
    args: [],
  });
  return (rows || []).filter((r) => isLegacyApproval(r)).length;
}

export default {
  source: SOURCE,
  // A database row emits no event: runBootChecks() calls check() at gateway start.
  events: [],
  async onEvent() {},
  /**
   * Upsert one card while any legacy approval is left, RESOLVE it once there
   * are none. Never throws into boot (runBootChecks isolates a detector).
   */
  async check(store, opts = {}) {
    const count = await countLegacyApprovals(opts.db || store?.db);
    if (count === 0) {
      try { await store.resolveByKey(SOURCE, DEDUP_KEY); } catch { /* no row yet, or no store */ }
      return null;
    }
    // The stored English is built from the same keys the renderer uses, and the
    // count travels as a VALUE, so a Spanish dashboard renders it too.
    const text = cardText(CARD_CODE, { n: count }, "en");
    await store.upsertItem({
      source: SOURCE,
      dedupKey: DEDUP_KEY,
      title: text.title,
      why: text.why,
      severity: "warn",
      // A link, not a POST: the owner approves on the Projects page, where the
      // command is shown in full. The destination is held in code (LINK_REMEDIES,
      // fix-it/index.js) — only the actionId is stored, so a crow.db writer
      // cannot point this card at another host. handleFixItAction refuses a
      // non-instant entry, so this actionId can never be executed as one.
      remedies: [{
        actionId: REMEDY_ACTION_ID,
        kind: "link",
        label: cardRemedyLabel(CARD_CODE, REMEDY_ACTION_ID, "en"),
      }],
      context: cardContext(CARD_CODE, { n: count }, { legacyApprovals: count }),
    });
    return { count };
  },
};