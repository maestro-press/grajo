/**
 * What the OWNER's side of a bot's draft tells the bot and the bell: the fixed outcome line queued for
 * the bot's chat, and the one notification a NEW bot draft rings.
 *
 * Three rules, and they are the whole point of this module:
 *
 *  - FIXED LINES, NEVER MESSAGE TEXT. The bot learns what happened to its draft from a sentence this
 *    file owns, filled with the RECIPIENT's display name and nothing else: "Your message to <name> was
 *    sent / edited and sent / was not sent". No line ever carries the draft's words back to the bot
 *    (they may be the operator's own edits) and no line carries an address or a key.
 *  - THE SAME TAKEN-ONCE QUEUE. The line is queued with `addStagedNote` (servers/gateway/staged/
 *    send-service.js) — the queue a Perch turn claims with `claimStagedNotes` and each line leaves
 *    once. A draft whose `chat_thread_id` is null (an owner's, or a bot turn that arrived over
 *    Gmail/Discord/a job) queues nothing: there is no Perch chat here to tell, exactly like a bridge
 *    staged send's note.
 *  - "EDITED" IS DECIDED BY HASH, NOT BY A FLAG. The draft's audit trail keeps a body hash per write
 *    and never the text; the newest row written by the bot (`actor = 'bot'`) is the last text the bot
 *    itself wrote. The send route hands the EXACT text it is sending, and this module compares its
 *    hash with that row's: different means the operator changed the words the bot proposed.
 *
 * The bell is rung by the DOOR (servers/gateway/sharing-bot/messages.js), on a new draft only — a
 * revise is the same conversation and the same card, and ringing twice for it would be noise. It
 * carries the bot's name, the recipient's name and a link to the card; no message text.
 *
 * Every name used here is FLATTENED first: control characters fold to a space, the Unicode FORMAT and
 * BIDI characters fold to nothing, whitespace collapses and the result is capped. A bot's display name
 * and a contact's display name are both values somebody typed, and this module's sentences end up in
 * a chat and in a bell.
 */
import { createHash } from "node:crypto";
import { addStagedNote } from "../staged/send-service.js";
import { createNotification } from "../../shared/notifications.js";
import { fill, t } from "../dashboard/shared/i18n.js";

/** The most of a name any sentence here may carry. */
export const NOTE_NAME_MAX = 80;

/** One name, flattened into one plain line (see the header). */
export function flattenName(raw) {
  const folded = String(raw ?? "")
    .replace(/[\u0000-\u001f\u007f-\u009f]+/g, " ")
    .replace(/[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]+/g, "");
  return folded.replace(/\s+/g, " ").trim().slice(0, NOTE_NAME_MAX);
}

/** The i18n key of each outcome line. */
const NOTE_KEYS = Object.freeze({
  sent: "messages.draft.botNoteSent",
  edited: "messages.draft.botNoteEdited",
  discarded: "messages.draft.botNoteDiscarded",
});

/** The fixed line for one outcome and recipient name, or null when there is no name to fill. */
export function botOutcomeLine(outcome, recipientName, lang = "en") {
  const key = NOTE_KEYS[outcome];
  const name = flattenName(recipientName);
  if (!key || !name) return null;
  return fill(t(key, lang), { name });
}

/** The bell's title for a new bot draft, or null when there is no recipient name to name. */
export function botDraftBellTitle(botName, recipientName, lang = "en") {
  const name = flattenName(recipientName);
  if (!name) return null;
  // A bot whose name flattens away is still a bot: the sentence says "a bot", never an empty slot.
  const bot = flattenName(botName) || "a bot";
  return fill(t("messages.draft.bellTitle", lang), { bot, name });
}

/**
 * Where the bell points: the Perch thread the draft was written in (`?msgdraft=<id>#<session>`), else
 * the Messages panel's own draft (`?draft=<id>`). Only ids this store minted reach the link — a draft
 * id is `msgd-<32 hex>`; anything else answers the Messages panel with no query at all.
 */
export function botDraftBellUrl(draft) {
  const id = typeof draft?.id === "string" ? draft.id : "";
  if (!/^msgd-[0-9a-f]{32}$/.test(id)) return "/dashboard/messages";
  const thread = typeof draft?.chatThreadId === "string" ? draft.chatThreadId : "";
  if (thread) return `/dashboard/perch?msgdraft=${id}#${encodeURIComponent(thread)}`;
  return `/dashboard/messages?draft=${id}`;
}

/**
 * Ring the bell for a NEW bot draft. Never throws: the draft is already written, and a notification
 * that cannot be stored must not turn the bot's successful tool call into an error.
 *
 * @param {object} db
 * @param {{draft: object, botName: string, recipientName: string}} input
 * @param {{notify?: Function, lang?: string}} [deps] `notify` is the createNotification seam (a test
 *   stub); production uses servers/shared/notifications.js.
 * @returns {Promise<{title: string, action_url: string} | null>}
 */
export async function notifyBotDraft(db, { draft, botName, recipientName } = {}, deps = {}) {
  const title = botDraftBellTitle(botName, recipientName, deps.lang || "en");
  if (!title) return null;
  const actionUrl = botDraftBellUrl(draft);
  const notify = typeof deps.notify === "function" ? deps.notify : createNotification;
  try {
    await notify(db, { source: "messages", type: "system", title, action_url: actionUrl });
  } catch {
    // The draft is written; the bell is best-effort by contract.
  }
  return { title, action_url: actionUrl };
}

/** The body's hash: the same sha256 the draft store keeps in `message_draft_audit.body_hash`. */
function hashOf(body) {
  return createHash("sha256").update(String(body ?? ""), "utf8").digest("hex");
}

/**
 * Did the owner change the words the bot last wrote? The newest audit row written by the bot is the
 * bot's own last text; a hash that differs means the operator edited it before sending. Answers false
 * when the trail has no bot row at all (nothing to compare: the words are then the posted ones).
 */
export async function sentTextWasEdited(db, draft, postedBody) {
  if (!draft || draft.origin !== "bot") return false;
  try {
    const { rows } = await db.execute({
      sql: `SELECT body_hash FROM message_draft_audit
             WHERE draft_id = ? AND actor = 'bot'
             ORDER BY at DESC, id DESC LIMIT 1`,
      args: [String(draft.id)],
    });
    const last = rows?.[0]?.body_hash;
    if (!last) return false;
    return String(last) !== hashOf(postedBody);
  } catch {
    return false;
  }
}

/** The recipient's display name for a draft's conversation, or null when the row is gone. */
export async function conversationDisplayName(db, draft) {
  if (!draft) return null;
  try {
    if (draft.conversationKind === "contact") {
      const { rows } = await db.execute({
        sql: "SELECT display_name, crow_id FROM contacts WHERE id = ?",
        args: [Number(draft.conversationId)],
      });
      const row = rows?.[0];
      if (!row) return null;
      return flattenName(row.display_name) || flattenName(row.crow_id) || null;
    }
    if (draft.conversationKind === "room") {
      const { rows } = await db.execute({
        sql: "SELECT name FROM contact_groups WHERE id = ?",
        args: [Number(draft.conversationId)],
      });
      const row = rows?.[0];
      return row ? flattenName(row.name) || null : null;
    }
  } catch {
    // A missing table or a failed read leaves no name: the note is skipped, never guessed.
  }
  return null;
}

/**
 * Queue the fixed outcome line for the bot whose draft the owner just acted on.
 *
 * `outcome` is `"sent"`, `"edited"` or `"discarded"`. `label` is the recipient name the caller already
 * resolved (the send route has it from `resolveConversation`); `sentBody` is the exact text being sent,
 * which only a send passes (an edit is decided by hash against the bot's last write). Answers the line
 * it queued, or null when nothing was queued (an owner's draft, no chat thread, no name).
 *
 * @param {object} db
 * @param {object} draft the store's row
 * @param {"sent"|"edited"|"discarded"} outcome
 * @param {{label?: string|null, sentBody?: string|null}} [opts]
 * @returns {Promise<string|null>}
 */
export async function queueBotOutcomeNote(db, draft, outcome, opts = {}) {
  if (!draft || draft.origin !== "bot") return null;
  const thread = draft.chatThreadId == null ? "" : String(draft.chatThreadId);
  if (!thread) return null;
  let kind = outcome;
  if (kind === "sent") {
    kind = opts.sentBody != null && await sentTextWasEdited(db, draft, opts.sentBody) ? "edited" : "sent";
  }
  if (!NOTE_KEYS[kind]) return null;
  const label = opts.label != null ? opts.label : await conversationDisplayName(db, draft);
  const line = botOutcomeLine(kind, label);
  if (!line) return null;
  addStagedNote(thread, line);
  return line;
}

export default queueBotOutcomeNote;