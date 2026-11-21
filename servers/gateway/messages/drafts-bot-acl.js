/**
 * The bot half of a draft's send re-check: is the bot that DRAFTED this message still allowed to write
 * to the people it is addressed to?
 *
 * A bot's message is always a draft, and the owner's own send is what publishes it. That makes the
 * allow-list (`<CROW_HOME>/secrets/sharing-bot-acl.json`, servers/gateway/sharing-bot/acl.js) a check
 * that has to be re-run at the ONE moment the words leave the box, not only when the bot wrote them: a
 * draft can sit in the owner's queue for hours, and a permission can be revoked (the bot's entry
 * deleted, a contact dropped from it), a contact re-keyed, or a room's pinned member set moved while it
 * waits. The draft's seal proves the audience has not been rewritten under the owner; this check proves
 * the BOT is still the one the operator allowed to reach that audience.
 *
 * Read fresh every time, never cached: the point of a revoked permission is that it takes effect on the
 * next send, and the file is a few hundred bytes.
 *
 * The codes are the door's own vocabulary, so a card can say the same thing the bot's tool result says:
 *
 *   - `not_allowed`    — the bot has no entry any more, or the recipient (contact or group) is no
 *                        longer in it. A row with no bot id at all lands here too: nobody granted it.
 *   - `pubkey_changed` — the contact is listed, but the allow-list pins a different secp256k1 key
 *                        than the one this draft sealed. The pinned key IS the permission.
 *   - `group_changed`  — the room's pinned member set (crow ids and keys) is not the draft's audience.
 *   - `acl_unreadable` — the allow-list file exists and cannot be read or parsed. A damaged file
 *                        narrows a bot to nothing; it is never read as "no restrictions".
 *
 * Nothing here writes, and nothing here decides a sentence: the route owns the answer, and its text is
 * fixed per code.
 */
import { readBotAcl } from "../sharing-bot/acl.js";
import { sameMemberSet } from "../sharing-bot/contacts.js";
import { resolveCrowHome } from "../../shared/crow-home.js";

/** Every code this check can answer. */
export const BOT_ACL_REFUSALS = Object.freeze(["not_allowed", "pubkey_changed", "group_changed", "acl_unreadable"]);

const text = (value) => (value == null ? "" : String(value).trim());

/**
 * The bot's allow-list entry as this send sees it.
 *
 * @param {{botId?: string|null}} draft
 * @param {string} [crowHome] this instance's home (default: the resolved CROW_HOME)
 * @returns {{ok: true, entry: object} | {ok: false, code: "not_allowed"|"acl_unreadable"}}
 */
export function readDraftBotAcl(draft, crowHome = resolveCrowHome()) {
  const read = readBotAcl(crowHome, draft?.botId == null ? "" : String(draft.botId));
  if (read.ok) return { ok: true, entry: read.entry };
  // `bad_bot_id` (a row that names no bot) is indistinguishable from "this bot was never allowed
  // anything", and the answer a person needs is the same: this draft's reporter may not reach them.
  return { ok: false, code: read.reason === "unreadable" ? "acl_unreadable" : "not_allowed" };
}

/**
 * Is this bot's draft still covered by `entry`? Null when it is, a code when it is not.
 *
 * For a 1:1 draft every sealed recipient must be an allow-listed contact with the SAME pinned key. For
 * a room draft the group must still be listed and its pinned member set must equal the draft's
 * audience (crow ids AND keys, order-independent) — the same comparison the door's own group send
 * makes, so the owner's send and the bot's draft can never disagree about who the room is.
 *
 * @param {{origin?: string, conversationKind?: string, conversationId?: number,
 *   recipients?: Array<{crowId: string, pubkey: string}>}} draft
 * @param {object|null} entry the bot's normalized allow-list entry
 * @returns {null | "not_allowed" | "pubkey_changed" | "group_changed"}
 */
export function botAudienceRefusal(draft, entry) {
  if (!draft || draft.origin !== "bot") return null;
  if (!entry || typeof entry !== "object") return "not_allowed";
  const recipients = Array.isArray(draft.recipients) ? draft.recipients : [];
  if (!recipients.length) return "not_allowed";

  if (draft.conversationKind === "room") {
    const groups = Array.isArray(entry.groups) ? entry.groups : [];
    const group = groups.find((candidate) => Number(candidate?.id) === Number(draft.conversationId));
    if (!group) return "not_allowed";
    return sameMemberSet(group.members, recipients) ? null : "group_changed";
  }

  const contacts = Array.isArray(entry.contacts) ? entry.contacts : [];
  for (const recipient of recipients) {
    const allowed = contacts.find((candidate) => text(candidate?.crow_id) === text(recipient?.crowId));
    if (!allowed) return "not_allowed";
    if (text(allowed.secp256k1_pubkey) !== text(recipient?.pubkey)) return "pubkey_changed";
  }
  return null;
}

export default readDraftBotAcl;