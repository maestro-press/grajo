/**
 * `crow_bot_inbox`: the messages a bot may READ — and the narrowest reading surface in the product.
 *
 * A bot that may draft messages to an allow-listed contact may also read what that contact sent, and
 * nothing else. Concretely, four rules, in the query and in the loop after it:
 *
 *   1. RECEIVED ONLY. `messages.direction = 'received'` (and `room_messages.direction` the same): the
 *      bot never sees the owner's own outgoing words, and it never sees a message it drafted.
 *   2. ALLOW-LISTED SENDERS ONLY. A `messages` row is considered only when its contact is one the
 *      allow-list names for THIS bot; a `room_messages` row only in an allow-listed room, and only
 *      when its sender is one of that room's PINNED members. A row with NO sender contact
 *      (`sender_contact_id IS NULL`) is a host-relayed message from somebody who is not a member of
 *      this room — the host's own words are `direction = 'sent'` and never appear here — so it is not
 *      this bot's to read either, and the query below filters it out with the rest of the strangers.
 *   3. THE PINNED KEY STILL MATCHES. A sender whose `secp256k1_pubkey` has changed since the operator
 *      allowed them is not the person who was allowed: their rows are dropped from the answer (and a
 *      blocked contact's with them). The same rule the send tools apply, in the reading direction.
 *   4. SINCE A CURSOR, READ-ONLY, AND NOTHING STEPPED OVER. The cursor is opaque
 *      (`p<message id>.r<room message id>`, plus `.d<epoch ms>.i<draft id>` once this bot has drafts)
 *      and each mark advances only over rows this call actually RETURNED. Both marks are the head of a
 *      page, never a high-water guess: the peer rows are read by id, and every allow-listed room's
 *      rows share the ONE `r` mark, so the room rows are consumed in id order across rooms — a row in
 *      a second room can therefore never be behind a mark another room's row advanced. `is_read` is
 *      NEVER touched: a bot reading a message is not the owner reading it, and the unread badge is
 *      the owner's. There is no UPDATE in this module at all.
 *
 * DRAFT UPDATES ride on the same cursor: `draft_updates: [{draft_id, state}]` names the drafts THIS
 * bot wrote (`message_drafts.origin = 'bot'` and `bot_id` = the caller) whose row moved since the
 * previous call — a state change (the owner sent or discarded it), and a revision of its body by the
 * bot itself, which reports the same state again because `updated_at` is the mark. Only ids and a
 * state word — never a line of the draft's body, which is the bot's own text sitting in the owner's
 * queue and not something a tool result needs to echo back.
 *
 * The draft mark is COMPOUND — `(updated_at, id)`, folded into the cursor as `.d<ms>.i<draft id>` —
 * because a plain `updated_at` mark loses rows: every write inside the same millisecond ties, and a
 * page cut at `LIMIT` would then leave the rest of that millisecond behind a mark that already passed
 * it. The id breaks the tie, and the query continues at `(updated_at, id) > (mark, mark id)`. A cursor
 * minted before draft updates existed (`p1.r2`) or before the id half (`p1.r2.d<ms>`) still parses,
 * with a mark of 0 / an empty id — an old cursor simply reports the bot's drafts once and then
 * advances.
 *
 * The text of one message is capped at MAX_INBOX_TEXT_CHARS before it reaches a tool result, and the
 * whole page at MAX_INBOX_LIMIT items — a bot's context is not the place to stream a mailbox. Every
 * item is marked `untrusted: true`: a message body is a stranger's words, never an instruction.
 *
 * The ids, the draft ids and the resulting cursor are what the door audits (`refs_json`); the text
 * never is.
 */

/** The most items one call may return. */
export const MAX_INBOX_LIMIT = 50;
/** The default page size. */
export const DEFAULT_INBOX_LIMIT = 20;
/** The most text one message contributes to an answer. */
export const MAX_INBOX_TEXT_CHARS = 4000;

// `p<message id>.r<room message id>` is the original shape; `.d<epoch ms>` is the draft-update mark
// added with the bot sharing door, and `.i<draft id>` the tie-break that makes that mark compound.
// Both draft parts are optional, so a cursor issued before either existed still parses (its mark is 0
// and its id empty, which reports the bot's drafts once and then advances).
const CURSOR_RE = /^p([0-9]{1,12})\.r([0-9]{1,12})(?:\.d([0-9]{1,15}))?(?:\.i([0-9a-zA-Z-]{1,64}))?$/;

const text = (value) => (value == null ? "" : String(value).trim());

/** An epoch-ms time from SQLite's `datetime('now')` text (UTC), or null for a row that has none. */
export function epochOf(createdAt) {
  if (createdAt == null) return null;
  if (typeof createdAt === "number" && Number.isFinite(createdAt)) return Math.floor(createdAt);
  const raw = String(createdAt).trim();
  if (!raw) return null;
  // "YYYY-MM-DD HH:MM:SS" is UTC in every insert this schema makes.
  const iso = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(raw) ? `${raw.replace(" ", "T")}Z` : raw;
  const parsed = Date.parse(iso);
  return Number.isFinite(parsed) ? parsed : null;
}

/**
 * The cursor as its high-water marks (message id, room message id, the draft's `(updated_at, id)`), or
 * null for anything this module did not mint. A cursor without the `.d` part is the original two-mark
 * shape (draft mark 0); one without the `.i` part predates the compound mark (empty draft id).
 */
export function parseInboxCursor(cursor) {
  if (cursor == null || cursor === "") return { messageId: 0, roomMessageId: 0, draftUpdatedAt: 0, draftId: "" };
  if (typeof cursor !== "string") return null;
  const match = CURSOR_RE.exec(cursor.trim());
  if (!match) return null;
  return {
    messageId: Number(match[1]),
    roomMessageId: Number(match[2]),
    draftUpdatedAt: match[3] ? Number(match[3]) : 0,
    draftId: match[4] ? String(match[4]) : "",
  };
}

/**
 * The opaque cursor for the high-water marks. The draft parts are written only when this bot has
 * drafts (a mark above 0), so a bot with none keeps the exact two-mark shape it always had; the id
 * half rides along only once a row at that exact millisecond has been reported.
 */
export function formatInboxCursor(messageId, roomMessageId, draftUpdatedAt = 0, draftId = "") {
  const base = `p${Math.max(0, Number(messageId) || 0)}.r${Math.max(0, Number(roomMessageId) || 0)}`;
  const draftMark = Math.max(0, Math.floor(Number(draftUpdatedAt) || 0));
  if (draftMark <= 0) return base;
  const id = typeof draftId === "string" ? draftId.trim().replace(/[^0-9a-zA-Z-]/g, "") : "";
  return id ? `${base}.d${draftMark}.i${id.slice(0, 64)}` : `${base}.d${draftMark}`;
}

/** The `?`-list and args for an id set, or null when the set is empty (so no query is made). */
function idList(ids) {
  const list = [...new Set((ids || []).map((id) => Number(id)).filter((id) => Number.isInteger(id) && id > 0))];
  return list.length ? list : null;
}

/**
 * Read one page of the bot's inbox.
 *
 * @param {object} db
 * @param {{entry?: object|null, aclFailure?: string|null, botId?: string|null, cursor?: string|null,
 *   limit?: number}} input
 * @returns {Promise<{ok: true, items: object[], cursor: string, ids: string[],
 *   draftUpdates: Array<{draft_id: string, state: string}>, draftIds: string[]}
 *   | {ok: false, code: "acl_unreadable"|"no_allowlist"|"bad_cursor"}>}
 */
export async function readBotInbox(db, input = {}) {
  if (input.aclFailure === "unreadable") return { ok: false, code: "acl_unreadable" };
  if (!input.entry) return { ok: false, code: "no_allowlist" };
  const from = parseInboxCursor(input.cursor);
  if (!from) return { ok: false, code: "bad_cursor" };
  const limit = Number.isInteger(input.limit) && input.limit > 0
    ? Math.min(input.limit, MAX_INBOX_LIMIT)
    : DEFAULT_INBOX_LIMIT;

  const allowedContacts = Array.isArray(input.entry.contacts) ? input.entry.contacts : [];
  const allowedGroups = Array.isArray(input.entry.groups) ? input.entry.groups : [];

  // The allow-listed contacts that are still the same person: unblocked, accepted, same pinned key.
  // Only these can be senders. A contact whose row is gone contributes nothing either.
  const contactIds = [];
  const pinnedByContactId = new Map();
  if (allowedContacts.length) {
    const crowIds = [...new Set(allowedContacts.map((contact) => text(contact.crow_id)).filter(Boolean))];
    if (crowIds.length) {
      const placeholders = crowIds.map(() => "?").join(", ");
      const { rows } = await db.execute({
        sql: `SELECT id, crow_id, display_name, secp256k1_pubkey, is_blocked, request_status
                FROM contacts WHERE crow_id IN (${placeholders})`,
        args: crowIds,
      });
      const byCrowId = new Map((rows || []).map((row) => [text(row.crow_id), row]));
      for (const contact of allowedContacts) {
        const row = byCrowId.get(text(contact.crow_id));
        if (!row) continue;
        if (Number(row.is_blocked ?? 0) === 1) continue;
        const status = text(row.request_status);
        if (status && status !== "accepted") continue;
        if (text(row.secp256k1_pubkey) !== text(contact.secp256k1_pubkey)) continue;
        contactIds.push(Number(row.id));
        pinnedByContactId.set(Number(row.id), {
          crowId: text(row.crow_id),
          name: text(row.display_name) || text(row.crow_id),
        });
      }
    }
  }

  const peerItems = [];

  const contactList = idList(contactIds);
  if (contactList) {
    const placeholders = contactList.map(() => "?").join(", ");
    const { rows } = await db.execute({
      sql: `SELECT id, contact_id, content, created_at FROM messages
             WHERE direction = 'received' AND id > ? AND contact_id IN (${placeholders})
             ORDER BY id ASC LIMIT ?`,
      args: [from.messageId, ...contactList, limit],
    });
    for (const row of rows || []) {
      const sender = pinnedByContactId.get(Number(row.contact_id));
      if (!sender) continue; // never a row from somebody this bot may not read
      peerItems.push({
        id: Number(row.id),
        item: {
          id: `p${Number(row.id)}`,
          from: { name: sender.name, crow_id: sender.crowId },
          conversation: { kind: "contact", crow_id: sender.crowId, name: sender.name },
          text: text(row.content).slice(0, MAX_INBOX_TEXT_CHARS),
          received_at: epochOf(row.created_at),
          untrusted: true,
        },
      });
    }
  }
  // The peer stream in id order: the mark is `p<id>`, and a page may only consume a prefix of it.
  peerItems.sort((a, b) => a.id - b.id);

  // Rooms: a received row in an allow-listed room, from one of that room's PINNED members (the same
  // member set the send tools require), whose key still matches — and decided IN SQL, not after the
  // page was cut. Filtering in JS after `LIMIT` is what used to starve the page: a run of rows from
  // people who are not pinned filled the window and was then thrown away, so a pinned sender's later
  // row could be reached only after the whole run had been re-read. A row with NO sender contact is a
  // host-relayed message from an author who is not a member here (the host's own words are
  // `direction = 'sent'`), so `IN (...)` is also what excludes it (rule 2 in the header).
  const roomItems = [];
  for (const group of allowedGroups) {
    const groupId = Number(group.id);
    if (!Number.isInteger(groupId) || groupId <= 0) continue;
    const pinned = Array.isArray(group.members) ? group.members : [];
    const pinnedByCrowId = new Map(pinned.map((member) => [text(member.crow_id), text(member.secp256k1_pubkey)]));
    if (!pinnedByCrowId.size) continue;
    const placeholders = [...pinnedByCrowId.keys()].map(() => "?").join(", ");
    const { rows: memberRows } = await db.execute({
      sql: `SELECT c.id, c.crow_id, c.display_name, c.secp256k1_pubkey, c.is_blocked
              FROM contact_group_members gm JOIN contacts c ON c.id = gm.contact_id
             WHERE gm.group_id = ? AND c.crow_id IN (${placeholders})`,
      args: [groupId, ...pinnedByCrowId.keys()],
    });
    const senderMeta = new Map();
    for (const row of memberRows || []) {
      const pinnedKey = pinnedByCrowId.get(text(row.crow_id));
      if (!pinnedKey || text(row.secp256k1_pubkey) !== pinnedKey) continue;
      if (Number(row.is_blocked ?? 0) === 1) continue;
      senderMeta.set(Number(row.id), {
        crowId: text(row.crow_id),
        name: text(row.display_name) || text(row.crow_id),
      });
    }
    const senderIds = [...senderMeta.keys()];
    if (!senderIds.length) continue;
    const { rows: groupRow } = await db.execute({
      sql: "SELECT name FROM contact_groups WHERE id = ?",
      args: [groupId],
    });
    const roomName = text(groupRow?.[0]?.name) || `Room ${groupId}`;
    const senders = senderIds.map(() => "?").join(", ");
    const { rows } = await db.execute({
      sql: `SELECT id, content, created_at, sender_contact_id FROM room_messages
             WHERE group_id = ? AND direction = 'received' AND sender_contact_id IN (${senders})
               AND id > ?
             ORDER BY id ASC LIMIT ?`,
      args: [groupId, ...senderIds, from.roomMessageId, limit],
    });
    for (const row of rows || []) {
      const senderId = row.sender_contact_id == null ? null : Number(row.sender_contact_id);
      const sender = senderId == null ? null : senderMeta.get(senderId);
      if (!sender) continue; // the SQL already refuses this; belt and braces on a re-keyed row
      roomItems.push({
        id: Number(row.id),
        item: {
          id: `r${Number(row.id)}`,
          from: { name: sender.name, crow_id: sender.crowId },
          conversation: { kind: "room", group_id: groupId, name: roomName },
          text: text(row.content).slice(0, MAX_INBOX_TEXT_CHARS),
          received_at: epochOf(row.created_at),
          untrusted: true,
        },
      });
    }
  }
  // EVERY allow-listed room shares the one `r<id>` mark, so room rows are paged by ID ACROSS rooms:
  // sorted here once and consumed in that order below. That is what keeps a row in a second room from
  // being left behind a mark that another room's row advanced (the ids of `room_messages` are per
  // table, not per room).
  roomItems.sort((a, b) => a.id - b.id);

  // The bot's OWN drafts whose row moved since the cursor's draft mark. Every write to a draft bumps
  // `updated_at` (the store's own rule), and the mark is COMPOUND — `(updated_at, id)` — so a page that
  // stopped inside one millisecond continues at the next id instead of skipping the rest of that
  // millisecond. The id half is what makes it exact: ids are random hex, so ordering the pair is the
  // only deterministic way to cut a page of rows that share a timestamp. The order is
  // (updated_at, id) so the row that had to be left out is the next call's first one.
  const draftUpdates = [];
  let draftUpdatedAt = from.draftUpdatedAt;
  let draftId = from.draftId;
  const botId = typeof input.botId === "string" ? input.botId.trim() : "";
  if (botId) {
    const { rows } = await db.execute({
      sql: `SELECT id, state, updated_at FROM message_drafts
             WHERE origin = 'bot' AND bot_id = ?
               AND (updated_at > ? OR (updated_at = ? AND id > ?))
             ORDER BY updated_at ASC, id ASC LIMIT ?`,
      args: [botId, draftUpdatedAt, draftUpdatedAt, draftId, limit],
    });
    for (const row of rows || []) {
      draftUpdates.push({ draft_id: String(row.id), state: String(row.state) });
    }
    // The page is ordered, so the LAST row returned is the highest pair this call saw — the mark a
    // continuation starts after. Reporting anything else would either look at rows twice or skip them.
    const last = rows && rows.length ? rows[rows.length - 1] : null;
    if (last) {
      draftUpdatedAt = Math.max(draftUpdatedAt, Math.floor(Number(last.updated_at) || 0));
      draftId = String(last.id);
    }
  }

  // ONE PAGE, oldest-first, taken as a PREFIX OF EACH STREAM. Peer rows are consumed in id order and
  // room rows in id order (both read with `id >` their own mark); the page takes whichever stream's
  // head came earlier in time. Taking prefixes — never a time-sorted re-shuffle of the whole set — is
  // what makes each cursor exact: every row a mark passes was returned, so a row dropped from a full
  // page can never hide the rows behind it.
  const page = [];
  let pi = 0;
  let ri = 0;
  while (page.length < limit && (pi < peerItems.length || ri < roomItems.length)) {
    const peer = pi < peerItems.length ? peerItems[pi] : null;
    const room = ri < roomItems.length ? roomItems[ri] : null;
    if (room && (!peer || (room.item.received_at ?? 0) <= (peer.item.received_at ?? 0))) {
      page.push(room.item);
      ri += 1;
    } else {
      page.push(peer.item);
      pi += 1;
    }
  }
  let messageId = from.messageId;
  let roomMessageId = from.roomMessageId;
  for (const item of page) {
    const n = Number(item.id.slice(1));
    if (item.id.startsWith("p")) messageId = Math.max(messageId, n);
    else roomMessageId = Math.max(roomMessageId, n);
  }
  return {
    ok: true,
    items: page,
    cursor: formatInboxCursor(messageId, roomMessageId, draftUpdatedAt, draftId),
    ids: page.map((item) => item.id),
    draftUpdates,
    draftIds: draftUpdates.map((update) => update.draft_id),
  };
}