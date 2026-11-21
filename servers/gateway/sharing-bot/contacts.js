/**
 * Who a bot's allow-list actually names, resolved against the live conversation tables — and the two
 * comparisons that decide whether "the person the operator allowed" is still the person a message
 * would reach.
 *
 * The allow-list (servers/gateway/sharing-bot/acl.js) pins a crow id AND a secp256k1 key per contact,
 * and a member set (crow id + key, each) per group. This module turns those entries into the live
 * rows the draft store seals:
 *
 *   - a CONTACT is one `contacts` row, found by the crow id the entry pinned. The row must still be
 *     unblocked and accepted (`is_blocked = 0`, `request_status` NULL or 'accepted') — the same
 *     conditions the sharing tools' own lookup applies — and its `secp256k1_pubkey` must still equal
 *     the pinned one. A re-keyed contact is a different person to send to: `pubkey_changed`.
 *   - a GROUP is one `contact_groups` row that IS a room (`room_uid` NOT NULL) and the rows
 *     `listRoomMembers` returns — the same list the room panel draws and the room send fans out to,
 *     so a draft's audience can never be a second, drifting idea of who is in the room. The live set
 *     must equal the pinned set by crow id AND key, or the group changed under the permission:
 *     `group_changed`.
 *
 * A label may be a crow id, a numeric group id, or a NAME. Names are matched only among entries the
 * allow-list already contains, case-insensitively — a name can therefore never widen a bot's reach,
 * and two bots naming the same person resolve to the same row. The crow id wins over a name so a
 * contact called another contact's crow id cannot hijack the lookup.
 *
 * Nothing here writes, and nothing here decides a refusal's wording: the codes are the door's
 * vocabulary (`not_allowed`, `contact_gone`, `blocked`, `pubkey_changed`, `group_changed`,
 * `group_not_a_room`), and the door turns them into one fixed sentence each.
 */
import { getRoom, listRoomMembers } from "../dashboard/panels/messages/rooms-store.js";
import { groupEntryId } from "./acl.js";

/** The most text one contact-group label may be (a name, or a numeric id as text). */
const LABEL_MAX = 200;

const text = (value) => (value == null ? "" : String(value).trim());

/** A contacts row as a draft recipient: the seeded audience entry plus the name a person reads. */
function recipientOf(row) {
  return {
    contactId: Number(row.id),
    crowId: text(row.crow_id),
    pubkey: text(row.secp256k1_pubkey),
    name: text(row.display_name) || text(row.crow_id),
    blocked: Number(row.is_blocked ?? 0) === 1,
  };
}

/** The live contacts rows for a set of crow ids, keyed by crow id. */
async function contactsByCrowId(db, crowIds) {
  const ids = [...new Set((crowIds || []).map(text).filter(Boolean))];
  const out = new Map();
  if (!ids.length) return out;
  const placeholders = ids.map(() => "?").join(", ");
  const { rows } = await db.execute({
    sql: `SELECT id, crow_id, display_name, secp256k1_pubkey, is_blocked, request_status
            FROM contacts WHERE crow_id IN (${placeholders})`,
    args: ids,
  });
  for (const row of rows || []) out.set(text(row.crow_id), row);
  return out;
}

/**
 * The contact an allow-list entry names, resolved to a live row.
 *
 * @param {object} db
 * @param {Array<{crow_id: string, secp256k1_pubkey: string}>} allowed the bot's allow-listed contacts
 * @param {string} label a crow id or a name (only names of allowed contacts are considered)
 * @returns {Promise<{ok: true, contact: object}
 *   | {ok: false, code: "not_allowed"|"contact_gone"|"blocked"|"pubkey_changed"}>}
 */
export async function resolveAllowedContact(db, allowed, label) {
  const wanted = text(label);
  if (!wanted || wanted.length > LABEL_MAX) return { ok: false, code: "not_allowed" };
  const rows = await contactsByCrowId(db, (allowed || []).map((entry) => entry.crow_id));

  // The exact crow id wins; then a name among the allowed entries only.
  let entry = (allowed || []).find((candidate) => text(candidate.crow_id) === wanted) || null;
  let row = entry ? rows.get(text(entry.crow_id)) || null : null;
  if (!entry) {
    const lower = wanted.toLowerCase();
    for (const candidate of allowed || []) {
      const live = rows.get(text(candidate.crow_id));
      if (!live) continue;
      if ((text(live.display_name) || text(live.crow_id)).toLowerCase() === lower) {
        entry = candidate;
        row = live;
        break;
      }
    }
  }
  if (!entry) return { ok: false, code: "not_allowed" };
  if (!row) return { ok: false, code: "contact_gone" };
  if (Number(row.is_blocked ?? 0) === 1) return { ok: false, code: "blocked" };
  const status = text(row.request_status);
  if (status && status !== "accepted") return { ok: false, code: "not_allowed" };
  if (text(row.secp256k1_pubkey) !== text(entry.secp256k1_pubkey)) {
    return { ok: false, code: "pubkey_changed" };
  }
  return { ok: true, contact: recipientOf(row) };
}

/** The message recipients for a group's pinned member set, resolved to live rows, or why not. */
async function membersForGroup(db, groupId, pinned) {
  const members = await listRoomMembers(db, groupId);
  const live = members.map(recipientOf);
  if (!sameMemberSet(pinned, live)) return { ok: false, code: "group_changed" };
  return { ok: true, members: live };
}

/** The same people with the same keys on both sides (order-independent). */
export function sameMemberSet(pinned, live) {
  const key = (member) => JSON.stringify([text(member?.crow_id ?? member?.crowId), text(member?.secp256k1_pubkey ?? member?.pubkey)]);
  const norm = (list) => [...new Set((Array.isArray(list) ? list : []).map(key))].sort();
  const a = norm(pinned);
  const b = norm(live);
  if (a.length === 0 || a.length !== b.length) return false;
  return a.every((value, at) => value === b[at]);
}

/**
 * The group an allow-list entry names, resolved to a live room and its live member rows.
 *
 * @param {object} db
 * @param {Array<{id: number, members: Array<{crow_id: string, secp256k1_pubkey: string}>}>} allowed
 * @param {string|number} label a group id or a name (only names of allowed groups are considered)
 * @returns {Promise<{ok: true, group: {id: number, name: string, members: object[]}}
 *   | {ok: false, code: "not_allowed"|"group_gone"|"group_not_a_room"|"group_changed"}>}
 */
export async function resolveAllowedGroup(db, allowed, label) {
  const wanted = text(label);
  if (!wanted || wanted.length > LABEL_MAX) return { ok: false, code: "not_allowed" };
  const numeric = /^[0-9]{1,12}$/.test(wanted) ? Number(wanted) : null;

  // Group names are read for the allowed ids only: a name never widens the allow-list. The id is read
  // through the ACL's own accessor (the entry stores `{ id, members }`), like every other reader.
  const ids = [...new Set((allowed || []).map(groupEntryId).filter((id) => id != null))];
  const rooms = new Map();
  for (const id of ids) {
    const room = await getRoom(db, id);
    if (room) rooms.set(id, room);
  }

  let entry = null;
  let room = null;
  if (numeric !== null) {
    entry = (allowed || []).find((candidate) => groupEntryId(candidate) === numeric) || null;
    room = entry ? rooms.get(numeric) || null : null;
  }
  if (!entry) {
    const lower = wanted.toLowerCase();
    for (const candidate of allowed || []) {
      const live = rooms.get(groupEntryId(candidate));
      if (!live) continue;
      if ((text(live.name) || `Room ${live.id}`).toLowerCase() === lower) {
        entry = candidate;
        room = live;
        break;
      }
    }
  }
  if (!entry) return { ok: false, code: "not_allowed" };
  // The allow-list entry names this instance's contact_groups id. A group that is gone, or that is a
  // plain organizational group with no room thread (no `room_uid`), cannot be a conversation.
  if (!room) {
    const { rows } = await db.execute({ sql: "SELECT id FROM contact_groups WHERE id = ?", args: [Number(entry.id)] });
    return { ok: false, code: rows && rows.length ? "group_not_a_room" : "group_gone" };
  }
  const resolved = await membersForGroup(db, Number(entry.id), entry.members);
  if (!resolved.ok) return resolved;
  return {
    ok: true,
    group: { id: Number(entry.id), name: text(room.name) || `Room ${entry.id}`, members: resolved.members },
  };
}

/**
 * The bot's allow-list as the door's `crow_list_contacts` reports it: names and ids only — no keys,
 * no online state, no blocked flag, nothing about anybody outside the list.
 *
 * A contact row that is gone is still LISTED (the operator allowed it; the door will refuse it with
 * `contact_gone`). Its name falls back to the pinned crow id, exactly as the Bot Builder shows it.
 */
export async function listAllowedTargets(db, entry) {
  const allowed = (entry && Array.isArray(entry.contacts) ? entry.contacts : []);
  const rows = await contactsByCrowId(db, allowed.map((contact) => contact.crow_id));
  const contacts = allowed.map((contact) => {
    const live = rows.get(text(contact.crow_id));
    return {
      kind: "contact",
      crow_id: text(contact.crow_id),
      name: (live && (text(live.display_name) || text(live.crow_id))) || text(contact.crow_id),
    };
  });
  const groups = [];
  for (const group of (entry && Array.isArray(entry.groups) ? entry.groups : [])) {
    const room = await getRoom(db, Number(group.id));
    groups.push({
      kind: room ? "room" : "group",
      group_id: Number(group.id),
      name: room ? (text(room.name) || `Room ${group.id}`) : `Group ${group.id}`,
      members: (group.members || []).map((member) => text(member.crow_id)),
    });
  }
  return { contacts, groups };
}