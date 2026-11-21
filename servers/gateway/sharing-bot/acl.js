/**
 * The bot sharing door's allow-list: which contacts and which groups ONE bot may write to, and how
 * many drafts it may leave for the owner in an hour.
 *
 * It is a FILE, not a table: `<CROW_HOME>/secrets/sharing-bot-acl.json`, mode 0600 in the 0700
 * `secrets/` directory the pi sandbox masks for every bot. That placement is the whole security
 * argument. A contained bot has crow.db bound read-write (the documented Phase-1 residual), so a
 * DB-held allow-list could be widened by the very bot it constrains — it could add a contact, or
 * silently re-point one at its own key. The file is out of its reach, and only the gateway writes it
 * (the owner's own route, servers/gateway/routes/sharing-bot-acl-api.js, and the Bot Builder section
 * part 2 adds on top of it).
 *
 * Shape, one entry per bot:
 *
 *   {
 *     "<bot_id>": {
 *       "contacts": [ { "crow_id": "crow:…", "secp256k1_pubkey": "…" } ],
 *       "groups":   [ { "id": 7, "members": [ { "crow_id": "crow:…", "secp256k1_pubkey": "…" } ] } ],
 *       "rate":     { "per_hour": 20 }
 *     }
 *   }
 *
 * Three rules the store keeps, and why each exists:
 *
 *  - THE PUBKEY IS PART OF THE PERMISSION. An entry pins the secp256k1 key the contact held when the
 *    operator allowed it. A contact re-keyed since (a re-invite, a new device, somebody else) is NOT
 *    the person the operator allowed, so the door refuses that send (`pubkey_changed`) instead of
 *    delivering to whoever now answers to the crow id. The same holds for a group: its pinned member
 *    set is compared by crow id AND key, so a membership change refuses (`group_changed`) rather than
 *    quietly reaching a new person.
 *  - A GROUP'S ID IS THIS INSTANCE'S contact_groups.id, never a crow id: the door resolves it here.
 *    `members` exists so the pinned set is a snapshot, not a live query.
 *  - THE FILE IS STRICT AND SMALL. Unknown fields are refused (a typo in a hand-edited file is a
 *    silent widening otherwise), duplicates are refused, and the whole map is capped well under any
 *    real use — this is a list of people one bot may talk to, not a directory.
 *
 * Writes are atomic: a temp file in the same directory (O_EXCL, 0600), then a rename over the target.
 * A reader therefore sees the old file or the new one, never a half-written allow-list, and a bot
 * that reads nothing gets a refusal rather than a truncated one. A read that cannot be parsed is
 * reported as `unreadable` and the door turns it into a refusal — never into "no restrictions".
 *
 * The default rate cap is DEFAULT_RATE_PER_HOUR when an entry omits `rate`; an explicit value is
 * validated into 1..MAX_RATE_PER_HOUR.
 *
 * Nothing here decides a send. This module owns the file's shape and its bytes; the door
 * (servers/gateway/sharing-bot/*.js) owns what a permitted entry may do.
 */
import {
  chmodSync, closeSync, existsSync, lstatSync, openSync, readFileSync, renameSync,
  statSync, unlinkSync, writeSync,
} from "node:fs";
import { randomBytes } from "node:crypto";
import { join } from "node:path";
import { ensureSecretsDir } from "../../shared/peer-credentials.js";
import { resolveCrowHome } from "../../shared/crow-home.js";
import { BOT_ID_RE } from "../../../scripts/pi-bots/bot-workspace-env.mjs";

/** The default cap on drafts one bot may leave per hour, when its entry does not say. */
export const DEFAULT_RATE_PER_HOUR = 20;

/** The largest a cap may be set to. The door counts these per bot per hour. */
export const MAX_RATE_PER_HOUR = 1000;

/** The largest allow-list file the store will read. A real one is a few hundred bytes per bot. */
export const MAX_ACL_BYTES = 64 * 1024;

/** The fields one bot's entry may carry, and one group's entry. Everything else is refused. */
const ENTRY_FIELDS = Object.freeze(["contacts", "groups", "rate"]);
const GROUP_FIELDS = Object.freeze(["id", "members"]);
const MEMBER_FIELDS = Object.freeze(["crow_id", "secp256k1_pubkey"]);
const RATE_FIELDS = Object.freeze(["per_hour"]);

/** A contact's crow id as this store writes it: text, bounded, no control characters. */
const CROW_ID_MAX = 200;
/** A secp256k1 key as a hex string: 64 (x-only) or 66 (compressed) in practice; the shape is the check. */
const PUBKEY_RE = /^[0-9a-fA-F]{2,200}$/;

/** A caller's refusal: a field name, never a value. */
export class AclError extends Error {
  constructor(code, detail) {
    super(`${code}:${detail}`);
    this.name = "AclError";
    this.code = code;
    this.detail = detail;
  }
}

const bad = (detail) => new AclError("BAD_INPUT", detail);

/** The allow-list file for an instance home (default: this process's CROW_HOME). */
export function sharingBotAclPath(crowHome = resolveCrowHome()) {
  return join(crowHome, "secrets", "sharing-bot-acl.json");
}

/* ------------------------------------------------------------------- validation */

function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

/** Every key of `obj` is one of `fields`: an unknown one is a typo, and a typo widens or vanishes. */
function keysWithin(obj, fields, detail) {
  for (const key of Object.keys(obj)) if (!fields.includes(key)) throw bad(detail);
}

function requireBotId(value) {
  if (typeof value !== "string" || !BOT_ID_RE.test(value)) throw bad("botId");
  return value;
}

function requireCrowId(value) {
  if (typeof value !== "string") throw bad("crow_id");
  const text = value.trim();
  if (!text || text.length > CROW_ID_MAX || /[\u0000-\u001f\u007f]/.test(text)) throw bad("crow_id");
  return text;
}

function requirePubkey(value) {
  if (typeof value !== "string") throw bad("secp256k1_pubkey");
  const text = value.trim();
  // secp256k1 hex is 64 (x-only) or 66 (compressed) characters; the bound keeps a hand-edited file
  // from smuggling a PEM or a whole JSON blob into a field the door compares literally.
  if (!PUBKEY_RE.test(text) || text.length % 2 !== 0) throw bad("secp256k1_pubkey");
  return text;
}

function requireGroupId(value) {
  const id = typeof value === "string" && /^[0-9]{1,12}$/.test(value.trim()) ? Number(value.trim()) : value;
  if (!Number.isInteger(id) || id <= 0) throw bad("group.id");
  return id;
}

function requireRate(value) {
  if (value == null) return { per_hour: DEFAULT_RATE_PER_HOUR };
  if (!isPlainObject(value)) throw bad("rate");
  keysWithin(value, RATE_FIELDS, "rate");
  const per = value.per_hour == null ? DEFAULT_RATE_PER_HOUR : value.per_hour;
  if (!Number.isInteger(per) || per < 1 || per > MAX_RATE_PER_HOUR) throw bad("rate.per_hour");
  return { per_hour: per };
}

/** One pinned member: who, and the key they held when the operator allowed the group. */
function normalizeMember(value) {
  if (!isPlainObject(value)) throw bad("members");
  keysWithin(value, MEMBER_FIELDS, "members");
  return { crow_id: requireCrowId(value.crow_id), secp256k1_pubkey: requirePubkey(value.secp256k1_pubkey) };
}

/** One allowed contact, by crow id and the key pinned with it. */
function normalizeContact(value) {
  if (!isPlainObject(value)) throw bad("contacts");
  keysWithin(value, MEMBER_FIELDS, "contacts");
  return { crow_id: requireCrowId(value.crow_id), secp256k1_pubkey: requirePubkey(value.secp256k1_pubkey) };
}

/** One allowed group: its local id and the member set that was allowed with it. */
function normalizeGroup(value) {
  if (!isPlainObject(value)) throw bad("groups");
  keysWithin(value, GROUP_FIELDS, "groups");
  if (!Array.isArray(value.members) || value.members.length === 0) throw bad("members");
  const members = value.members.map(normalizeMember);
  const seen = new Set();
  for (const member of members) {
    if (seen.has(member.crow_id)) throw bad("members");
    seen.add(member.crow_id);
  }
  return { id: requireGroupId(value.id), members };
}

/**
 * A group entry's id, as `normalizeBotEntry` stores it: the entry is `{ id, members }` — the file's own
 * spelling is `id`, never `group_id` (`GROUP_FIELDS` is strict, so a file carrying `group_id` is
 * refused as unreadable rather than half-read). EVERY reader of an entry's groups goes through this,
 * so the recipient picker, the send's own room re-check and the door can never disagree about which
 * group an entry names. Answers null for an id that is not a positive integer.
 *
 * @param {{id?: unknown}} group
 * @returns {number|null}
 */
export function groupEntryId(group) {
  const id = Number(group?.id);
  return Number.isInteger(id) && id > 0 ? id : null;
}

/**
 * One bot's entry in its canonical stored form: contacts, groups, rate — sorted, de-duplicated,
 * defaults filled. Throws an AclError naming the field for anything else.
 *
 * @param {object} value
 * @returns {{contacts: Array<{crow_id: string, secp256k1_pubkey: string}>,
 *   groups: Array<{id: number, members: Array<{crow_id: string, secp256k1_pubkey: string}>}>,
 *   rate: {per_hour: number}}}
 */
export function normalizeBotEntry(value) {
  if (!isPlainObject(value)) throw bad("bot");
  keysWithin(value, ENTRY_FIELDS, "bot");
  const contacts = (value.contacts == null ? [] : value.contacts);
  const groups = (value.groups == null ? [] : value.groups);
  if (!Array.isArray(contacts)) throw bad("contacts");
  if (!Array.isArray(groups)) throw bad("groups");
  const normalizedContacts = contacts.map(normalizeContact).sort((a, b) => (a.crow_id < b.crow_id ? -1 : a.crow_id > b.crow_id ? 1 : 0));
  const seenContacts = new Set();
  for (const contact of normalizedContacts) {
    if (seenContacts.has(contact.crow_id)) throw bad("contacts");
    seenContacts.add(contact.crow_id);
  }
  const normalizedGroups = groups.map(normalizeGroup).sort((a, b) => a.id - b.id);
  const seenGroups = new Set();
  for (const group of normalizedGroups) {
    if (seenGroups.has(group.id)) throw bad("groups");
    seenGroups.add(group.id);
  }
  return { contacts: normalizedContacts, groups: normalizedGroups, rate: requireRate(value.rate) };
}

/** The whole file in its canonical form: `{ "<bot_id>": entry }`, bots sorted. */
export function normalizeSharingBotAcl(value) {
  if (!isPlainObject(value)) throw bad("acl");
  const acl = {};
  for (const botId of Object.keys(value).sort()) acl[requireBotId(botId)] = normalizeBotEntry(value[botId]);
  return acl;
}

/* ------------------------------------------------------------------------ reads */

/**
 * The allow-list map. Never throws:
 *
 *   - `{ok: true, acl: {}}` when there is no file at all (an instance whose owner has never allowed
 *     a bot anything — the operator's Q5 starting state, which is "nobody");
 *   - `{ok: true, acl}` for a file this store (or a person) wrote correctly;
 *   - `{ok: false, reason: "unreadable"}` for a file that exists but cannot be read, is too large, is
 *     not JSON, or is not the documented shape. The door refuses every call that needs the ACL, so a
 *     damaged allow-list narrows a bot to nothing instead of opening it to everything.
 *
 * @param {string} [crowHome]
 * @returns {{ok: true, acl: object} | {ok: false, reason: "unreadable"}}
 */
export function readSharingBotAcl(crowHome = resolveCrowHome()) {
  const path = sharingBotAclPath(crowHome);
  let raw;
  try {
    const st = lstatSync(path);
    if (!st.isFile() || st.size > MAX_ACL_BYTES) return { ok: false, reason: "unreadable" };
    raw = readFileSync(path, "utf8");
  } catch (err) {
    if (err && err.code === "ENOENT") return { ok: true, acl: {} };
    return { ok: false, reason: "unreadable" };
  }
  if (!raw.trim()) return { ok: true, acl: {} };
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return { ok: false, reason: "unreadable" };
  }
  try {
    return { ok: true, acl: normalizeSharingBotAcl(parsed) };
  } catch {
    return { ok: false, reason: "unreadable" };
  }
}

/**
 * One bot's entry, or why it has none: `no_entry` (the file is fine, the bot was never allowed
 * anything) is the operator's starting state and the Fix-it card's condition, distinct from
 * `unreadable` (a fault an operator has to see).
 *
 * @param {string} crowHome
 * @param {string} botId
 * @returns {{ok: true, entry: object} | {ok: false, reason: "unreadable"|"no_entry"|"bad_bot_id"}}
 */
export function readBotAcl(crowHome, botId) {
  if (typeof botId !== "string" || !BOT_ID_RE.test(botId)) return { ok: false, reason: "bad_bot_id" };
  const all = readSharingBotAcl(crowHome);
  if (!all.ok) return { ok: false, reason: "unreadable" };
  if (!Object.prototype.hasOwnProperty.call(all.acl, botId)) return { ok: false, reason: "no_entry" };
  return { ok: true, entry: all.acl[botId] };
}

/** Every bot that has an entry, sorted. Empty for a missing file and for an unreadable one. */
export function sharingBotAclBotIds(crowHome = resolveCrowHome()) {
  const all = readSharingBotAcl(crowHome);
  return all.ok ? Object.keys(all.acl) : [];
}

/* ----------------------------------------------------------------------- writes */

/**
 * Replace the whole allow-list. The map is normalized (which validates every entry) BEFORE anything
 * touches the disk, so a refused write leaves the previous allow-list exactly as it was.
 *
 * @param {string} crowHome
 * @param {object} acl
 * @returns {{ok: true, acl: object}}
 * @throws {AclError} for an invalid shape or an unwritable path
 */
export function writeSharingBotAcl(crowHome, acl) {
  const normalized = normalizeSharingBotAcl(acl);
  const path = sharingBotAclPath(crowHome);
  const dir = join(crowHome, "secrets");
  ensureSecretsDir(dir);
  const tmp = `${path}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
  let fd = null;
  try {
    fd = openSync(tmp, "wx", 0o600);
    writeSync(fd, JSON.stringify(normalized, null, 2) + "\n");
    chmodSync(tmp, 0o600);
    closeSync(fd);
    fd = null;
    renameSync(tmp, path);
  } catch (err) {
    if (fd !== null) {
      try { closeSync(fd); } catch { /* already closed */ }
    }
    try { unlinkSync(tmp); } catch { /* never created, or already renamed */ }
    throw new AclError("WRITE_FAILED", err && err.code ? String(err.code) : "write");
  }
  // The rename carries the temp file's 0600 across, but a pre-existing file written by an older
  // build (or by hand) may have been 0644: the replacement is ours, and it is tightened here.
  try { chmodSync(path, 0o600); } catch { /* best effort; the dir is 0700 either way */ }
  return { ok: true, acl: normalized };
}

/**
 * Set (or replace) one bot's entry, leaving every other bot's entry alone. Refuses when the existing
 * file cannot be read: merging into a file we do not understand would silently drop another bot's
 * allow-list.
 *
 * @returns {{ok: true, entry: object} | {ok: false, reason: "unreadable"}}
 */
export function setSharingBotAclEntry(crowHome, botId, entry) {
  requireBotId(botId);
  const normalizedEntry = normalizeBotEntry(entry);
  const all = readSharingBotAcl(crowHome);
  if (!all.ok) return { ok: false, reason: "unreadable" };
  const next = { ...all.acl, [botId]: normalizedEntry };
  writeSharingBotAcl(crowHome, next);
  return { ok: true, entry: normalizedEntry };
}

/**
 * Remove one bot's entry (the "Remove messaging from this bot" undo still to come). Answers whether
 * there was one; a file that cannot be read is refused for the same reason as above.
 *
 * @returns {{ok: true, removed: boolean} | {ok: false, reason: "unreadable"}}
 */
export function removeSharingBotAclEntry(crowHome, botId) {
  requireBotId(botId);
  const all = readSharingBotAcl(crowHome);
  if (!all.ok) return { ok: false, reason: "unreadable" };
  if (!Object.prototype.hasOwnProperty.call(all.acl, botId)) return { ok: true, removed: false };
  const next = { ...all.acl };
  delete next[botId];
  writeSharingBotAcl(crowHome, next);
  return { ok: true, removed: true };
}

/**
 * Does the file exist? Used by the boot check that part 2 turns into a Fix-it card, and by nothing
 * that can change a decision.
 */
export function sharingBotAclExists(crowHome = resolveCrowHome()) {
  try {
    return existsSync(sharingBotAclPath(crowHome));
  } catch {
    return false;
  }
}

/** The file's own size and mode, for the ACL route's answer and for tests. Never its contents. */
export function sharingBotAclStat(crowHome = resolveCrowHome()) {
  try {
    const st = statSync(sharingBotAclPath(crowHome));
    return { present: true, mode: st.mode & 0o777, size: st.size };
  } catch {
    return { present: false, mode: null, size: 0 };
  }
}

/** Is there a 0700 directory holding several small private files? Used to prove the file's home. */
export function sharingBotSecretsDirMode(crowHome = resolveCrowHome()) {
  try {
    return statSync(join(crowHome, "secrets")).mode & 0o777;
  } catch {
    return null;
  }
}