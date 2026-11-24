/**
 * Fix-it remedy: take messaging away from one bot — remove every `crow-sharing` entry from its
 * definition's `tools.crow_mcp` list and nothing else.
 *
 * This is the card's "Remove messaging from this bot" answer (fix-it/detectors/sharing-bot-acl.js).
 * It is the same edit the Bot Builder's Abilities tab makes when the operator sets the Sharing source
 * to Off, done without the operator's having to find the checkbox: a definition whose remaining keys
 * are byte-identical is written back with just those entries filtered out, so no other tool, model,
 * prompt or policy moves.
 *
 * THREE RAILS, all of them the ones the rest of Bot Builder already uses:
 *
 *  - THE ID IS RE-CHECKED. It arrives in the remedy's own `args` (a crow.db column, so anything that
 *    can write crow.db controls it) and again on the item's `context`; both must be a bot id this
 *    instance could have (<BOT_ID_RE>), and the row must exist. An id that fails changes nothing.
 *  - COMPARE-AND-SWAP ON THE STORED TEXT. The UPDATE's WHERE matches the exact `definition` string
 *    this remedy read (`definition IS ?`), the same CAS the Studio and Artifacts def editors use. A
 *    concurrent save (another tab, a peer, an approved skill) makes the write match zero rows, and
 *    the card stays up rather than clobbering the newer definition.
 *  - OWNER ONLY. A bot's tools decide what it can reach, and the dashboard's fix-it route is the
 *    owner's; this re-proves the owner's own local password session (the same gate
 *    remove-retired-bundle.js uses) so a peer SSO session or a session-less call changes nothing.
 */
import { t as i18nT } from "../../dashboard/shared/i18n.js";
import { BOT_ID_RE } from "../../../../scripts/pi-bots/bot-workspace-env.mjs";
// The gateway's owner rule, STATIC: a remedy runs only inside the gateway process. The
// bot-reachable chain that used to reach this file is cut at its source (the research server
// checks ownership through servers/shared/project-ownership.js). See
// tests/bot-seed-import-guard.test.js.
import { isLocalPasswordSessionOn } from "../../dashboard/local-session.js";
import { OWNER_ONLY_FLASH, OWNER_ONLY_MESSAGE } from "./restore-bundle-compose.js";

export const ACTION_ID = "bot-sharing-remove";

/**
 * Does this `crow_mcp` entry name the Sharing server, in any spelling the catalog accepts? The bare
 * server (`crow-sharing`), a tool key (`crow-sharing/crow_send_message`) and pi's own registered
 * spelling (`crow-sharing__crow_send_message`) all fold to the server name in the catalog
 * (scripts/pi-bots/crow-server-catalog.mjs), so the detector and this filter must see all three.
 */
export function namesSharingServer(entry) {
  if (typeof entry !== "string") return false;
  const value = entry.trim();
  return value === "crow-sharing"
    || value.startsWith("crow-sharing/")
    || value.startsWith("crow-sharing__");
}

/** The `crow_mcp` entries of a definition that name `crow-sharing` (empty when it does not). */
export function sharingSelections(def) {
  const list = def && def.tools && Array.isArray(def.tools.crow_mcp) ? def.tools.crow_mcp : [];
  return list.filter(namesSharingServer);
}

/** The one i18n key the button's label comes from (en/es). */
export const LABEL_KEY = "botbuilder.sharing.fixitUndo";

/** The button's label in the dashboard's language. */
export function label(lang) {
  return i18nT(LABEL_KEY, lang === "es" ? "es" : "en");
}

// Test-only: replace the owner rule (the real one needs a password session in crow.db).
let _ownerCheckForTest = null;
export function _setOwnerCheckForTest(fn) { _ownerCheckForTest = fn || null; }

async function isOwner(db, req) {
  if (_ownerCheckForTest) return (await _ownerCheckForTest(db, req)) === true;
  return (await isLocalPasswordSessionOn(db, req)) === true;
}

/**
 * The definition with every `crow-sharing` selection removed, or null when it has none.
 * Exported so the detector's rule and this remedy's filter cannot drift.
 */
export function withoutSharingSelections(def) {
  if (!def || typeof def !== "object") return null;
  const tools = def.tools && typeof def.tools === "object" ? def.tools : null;
  const list = tools && Array.isArray(tools.crow_mcp) ? tools.crow_mcp : null;
  if (!list) return null;
  const next = list.filter((entry) => !namesSharingServer(entry));
  if (next.length === list.length) return null;
  return { ...def, tools: { ...tools, crow_mcp: next } };
}

export default async function removeBotSharing(args = {}, { item, db, req } = {}) {
  const fromArgs = typeof args?.bot === "string" ? args.bot : "";
  const fromCard = typeof item?.context?.bot === "string" ? item.context.bot : "";
  const botId = fromArgs || fromCard;
  if (!botId || !BOT_ID_RE.test(botId)) return { resolved: false, flash: "fixit_error" };

  let owner = false;
  try { owner = await isOwner(db, req); } catch { owner = false; }
  if (!owner) return { resolved: false, flash: OWNER_ONLY_FLASH, message: OWNER_ONLY_MESSAGE };

  const { rows } = await db.execute({
    sql: "SELECT definition FROM pi_bot_defs WHERE bot_id = ?",
    args: [botId],
  });
  const row = rows?.[0];
  if (!row) return { resolved: false, flash: "fixit_error" };
  let def = null;
  try { def = JSON.parse(row.definition || "{}"); } catch { def = null; }
  const next = withoutSharingSelections(def);
  // No selection left to remove: the card's condition is already gone, so the item is answered.
  if (!next) return { resolved: true };

  const written = await db.execute({
    sql: "UPDATE pi_bot_defs SET definition = ?, updated_at = datetime('now') WHERE bot_id = ? AND definition IS ?",
    args: [JSON.stringify(next), botId, row.definition ?? null],
  });
  if (!written.rowsAffected) {
    // Somebody saved this definition between the read and the write: the newer text wins, and the
    // boot check will re-decide the card from it.
    return { resolved: false, flash: "fixit_error" };
  }
  return { resolved: true };
}