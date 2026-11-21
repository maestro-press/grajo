/**
 * The bot door's drafting rules: what a bot's `crow_send_message` / `crow_send_group_message` may do,
 * in one place, with no MCP and no HTTP around it so every rule is testable on its own.
 *
 * THE ONE RULE THAT MATTERS: a bot's message is ALWAYS a draft. Both send tools land a row in
 * `message_drafts` (servers/gateway/messages/drafts-store.js) with `origin = "bot"`, the bot's id and
 * the bot's display name (snapshotted under the seal), and return the draft's id. Nothing here
 * imports, calls or knows how to reach a transport: the owner reads the draft in Crow Messages and
 * their own send is the only thing that publishes it. In v1 that holds for every bot, whatever its
 * `external_send` says — there is no auto-send path to misconfigure.
 *
 * Before a draft is written, five things are checked, in this order, and each refusal is a code the
 * door audits and the bot's tool result names:
 *
 *   1. THE TEXT: non-empty, and at most MAX_MESSAGE_CHARS. (The sharing server's own message tools
 *      cap a message at 10,000 characters too; a bot cannot smuggle a longer body into the store
 *      through this door.)
 *   2. THE TARGET, INSIDE THE ALLOW-LIST: a contact or group is resolved only among the entries the
 *      allow-list holds (contacts.js). A name that matches nobody on the list is `not_allowed` — the
 *      door never resolves a label against the whole contact book.
 *   3. THE PERSON IS STILL THE PERSON: the live contact row must be unblocked, accepted, and still
 *      hold the secp256k1 key the allow-list pinned (`blocked`, `pubkey_changed`); a group's live
 *      member set must equal the pinned one (`group_changed`); a plain organizational group (no room
 *      thread) is `group_not_a_room`, because there is no conversation to draft into.
 *   4. THE CONVERSATION IS FREE: at most one open draft exists per conversation (the store's unique
 *      index). An owner's open draft is `owner_draft_open` — the bot must never overwrite words the
 *      owner is typing. Another bot's open draft is `draft_open`. The bot's OWN open draft is revised
 *      (`revised`), unless the owner has edited it (an `edit` audit row with actor `owner`), in which
 *      case it is frozen: `owner_edited`.
 *   5. THE RATE CAP: at most `rate.per_hour` drafts per bot per hour, counted from the door's own
 *      audit trail (audit.js countDraftsSince) — so the cap survives a gateway restart and the owner
 *      can see exactly what it counted. THE RESIDUAL, stated plainly: `bot_sharing_audit` is a table in
 *      crow.db, which a contained bot has read-write (the documented Phase-1 residual), so a bot that
 *      writes that table directly CAN delete its own `drafted`/`revised` rows and make the count read
 *      low. The cap is therefore a brake on what a bot's own turns do, not a wall against a bot
 *      editing the instance's database. Two things it does still hold: the cap's INPUT cannot be
 *      raised — `rate.per_hour` comes from the allow-list FILE in `secrets/`, which every bot's sandbox
 *      masks — and the scrubbing is not silent, because the trail is what the operator reads.
 *
 * The draft is written with a COMPARE-AND-SET version: 0 for a fresh conversation (`create only` — a
 * draft that appeared between the check and the write is a `draft_changed` refusal, never an
 * overwrite) and the open draft's own version when revising. A lost race is reported, not papered
 * over: the bot retries on its next turn.
 *
 * Every function answers a plain result — `{ok: true, …}` or `{ok: false, code}` — and never throws
 * for a caller's mistake. The door turns the result into one MCP text block and one audit row.
 */
import { createDraft, getOpenDraft } from "../messages/drafts-store.js";
import { listAllowedTargets, resolveAllowedContact, resolveAllowedGroup } from "./contacts.js";
import { DEFAULT_RATE_PER_HOUR } from "./acl.js";

/** The most text one bot message may carry, matching the sharing tools' own cap. */
export const MAX_MESSAGE_CHARS = 10_000;

/** The refusal codes these rules can answer. The door writes `refused:<code>` for each. */
export const DRAFT_REFUSALS = Object.freeze([
  "no_allowlist", "acl_unreadable", "empty_message", "too_long",
  "not_allowed", "contact_gone", "blocked", "pubkey_changed",
  "group_gone", "group_not_a_room", "group_changed",
  "owner_draft_open", "draft_open", "owner_edited", "draft_changed", "rate_limited",
  "draft_failed",
]);

const text = (value) => (value == null ? "" : String(value));

/**
 * The display name a bot is shown by in a draft ("Draft by Hank"), snapshotted at draft time. The
 * definition's own name, else the id (an identifier, not a secret, and a blank chip would be worse).
 */
export async function botDisplayName(db, botId) {
  try {
    const { rows } = await db.execute({
      sql: "SELECT display_name FROM pi_bot_defs WHERE bot_id = ?",
      args: [String(botId)],
    });
    const name = text(rows?.[0]?.display_name).trim();
    return name || String(botId);
  } catch {
    return String(botId);
  }
}

/** Has the owner edited this draft? (`edit` with actor `owner` in the draft's own audit trail.) */
async function ownerEdited(db, draftId) {
  const { rows } = await db.execute({
    sql: `SELECT 1 AS hit FROM message_draft_audit
           WHERE draft_id = ? AND action = 'edit' AND actor = 'owner' LIMIT 1`,
    args: [draftId],
  });
  return Boolean(rows && rows.length);
}

/**
 * The draft-two-ways write every message tool shares: revise this bot's own open draft when there is
 * one, else create. Both go through the store's compare-and-set, and every refusal is a code.
 */
async function writeDraft(db, { conversationKind, conversationId, recipients, body, origin, botId, botName, opts }) {
  const open = await getOpenDraft(db, conversationKind, conversationId);
  if (open) {
    if (open.origin !== "bot") return { ok: false, code: "owner_draft_open" };
    if (String(open.botId ?? "") !== String(botId)) return { ok: false, code: "draft_open" };
    if (await ownerEdited(db, open.id)) return { ok: false, code: "owner_edited" };
    const revised = await createDraft(db, {
      conversationKind, conversationId, body, recipients, origin, botId, botName,
      expectVersion: open.version,
    }, opts);
    if (!revised.ok) return { ok: false, code: "draft_changed" };
    return { ok: true, outcome: "revised", draftId: revised.draft.id };
  }
  const created = await createDraft(db, {
    conversationKind, conversationId, body, recipients, origin, botId, botName, expectVersion: 0,
  }, opts);
  if (!created.ok) return { ok: false, code: "draft_changed" };
  return { ok: true, outcome: "drafted", draftId: created.draft.id };
}

/**
 * `crow_send_message`: draft a peer message to one allow-listed contact.
 *
 * @param {object} db
 * @param {{botId: string, botName: string, entry?: object|null, aclFailure?: string|null,
 *   contact: string, message: string, now: number, loadSeed?: Function, emit?: Function}} input
 *   `aclFailure` is "unreadable" when the allow-list file could not be read (never treated as "no
 *   restriction"); a missing entry is reported as `no_allowlist`.
 * @returns {Promise<{ok: true, outcome: "drafted"|"revised", draftId: string, target: string,
 *   label: string} | {ok: false, code: string, target?: string}>}
 */
export async function draftPeerMessage(db, input = {}) {
  const message = text(input.message);
  const target = text(input.contact).trim();
  if (!message.trim()) return { ok: false, code: "empty_message", target };
  if (message.length > MAX_MESSAGE_CHARS) return { ok: false, code: "too_long", target };
  if (input.aclFailure === "unreadable") return { ok: false, code: "acl_unreadable", target };
  if (!input.entry) return { ok: false, code: "no_allowlist", target };

  const resolved = await resolveAllowedContact(db, input.entry.contacts, input.contact);
  if (!resolved.ok) {
    const code = resolved.code;
    // A label that matches nothing on the list is `not_allowed`; a listed contact whose row moved on
    // keeps its own code so the owner can tell a deletion from a typo.
    return { ok: false, code, target };
  }
  const contact = resolved.contact;
  const used = Number(input.usedThisHour) || 0;
  if (used >= Number(input.entry.rate?.per_hour ?? DEFAULT_RATE_PER_HOUR)) {
    return { ok: false, code: "rate_limited", target: contact.crowId };
  }
  const written = await writeDraft(db, {
    conversationKind: "contact",
    conversationId: contact.contactId,
    recipients: [contact],
    body: message,
    origin: "bot",
    botId: input.botId,
    botName: input.botName,
    opts: { now: input.now, ...(typeof input.loadSeed === "function" ? { loadSeed: input.loadSeed } : {}),
      ...(typeof input.emit === "function" ? { emit: input.emit } : {}) },
  });
  if (!written.ok) return { ...written, target: contact.crowId };
  return { ok: true, outcome: written.outcome, draftId: written.draftId, target: contact.crowId, label: contact.name };
}

/**
 * `crow_send_group_message`: draft a room message to one allow-listed group.
 *
 * A room (a `contact_groups` row with a `room_uid`) is the only group with a conversation thread and
 * an owner send path today, so a plain organizational group is refused (`group_not_a_room`) rather
 * than landing a draft the owner has no way to send. The audience is the live member set, and it must
 * equal the set the operator allowed (crow ids AND keys).
 *
 * @param {object} db
 * @param {{botId: string, botName: string, entry?: object|null, aclFailure?: string|null,
 *   group: string|number, message: string, now: number, loadSeed?: Function, emit?: Function}} input
 * @returns {Promise<{ok: true, outcome: "drafted"|"revised", draftId: string, target: string,
 *   label: string} | {ok: false, code: string, target?: string}>}
 */
export async function draftGroupMessage(db, input = {}) {
  const message = text(input.message);
  const target = text(input.group).trim();
  if (!message.trim()) return { ok: false, code: "empty_message", target };
  if (message.length > MAX_MESSAGE_CHARS) return { ok: false, code: "too_long", target };
  if (input.aclFailure === "unreadable") return { ok: false, code: "acl_unreadable", target };
  if (!input.entry) return { ok: false, code: "no_allowlist", target };

  const resolved = await resolveAllowedGroup(db, input.entry.groups, input.group);
  if (!resolved.ok) return { ok: false, code: resolved.code, target };
  const group = resolved.group;
  const used = Number(input.usedThisHour) || 0;
  if (used >= Number(input.entry.rate?.per_hour ?? DEFAULT_RATE_PER_HOUR)) {
    return { ok: false, code: "rate_limited", target: String(group.id) };
  }
  const written = await writeDraft(db, {
    conversationKind: "room",
    conversationId: group.id,
    recipients: group.members,
    body: message,
    origin: "bot",
    botId: input.botId,
    botName: input.botName,
    opts: { now: input.now, ...(typeof input.loadSeed === "function" ? { loadSeed: input.loadSeed } : {}),
      ...(typeof input.emit === "function" ? { emit: input.emit } : {}) },
  });
  if (!written.ok) return { ...written, target: String(group.id) };
  return { ok: true, outcome: written.outcome, draftId: written.draftId, target: String(group.id), label: group.name };
}

/** `crow_list_contacts`: the allow-list, names and ids only. */
export async function listContacts(db, entry) {
  const targets = await listAllowedTargets(db, entry);
  return { contacts: targets.contacts, groups: targets.groups };
}