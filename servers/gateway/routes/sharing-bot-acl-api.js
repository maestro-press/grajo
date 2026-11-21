/**
 * The bot sharing allow-list's owner route: which contacts and rooms ONE bot may write to, and the
 * draft cap that goes with them. This is the file half of the bot sharing door
 * (servers/gateway/sharing-bot/acl.js, whose header explains why the allow-list is a file in
 * `secrets/` rather than a table a bot could edit).
 *
 * It exists in this PR for two callers: the tests (the whole rule set is exercised through the real
 * router), and part 2, which adds the Bot Builder "Sharing" section on top of it. There is no UI here
 * yet — a bot's allow-list starts EMPTY (the operator's decision: nobody), so until part 2 lands a bot
 * drafts nothing.
 *
 * Mounted in servers/gateway/dashboard/index.js, AFTER dashboardAuth and csrfMiddleware, so both rails
 * apply — exactly the slot Crow Messages' draft API and Crow Mail's API occupy, and where a
 * feature-mounts router would silently skip the CSRF check. On its own it re-applies, in this order:
 *
 *   1. `dashboardAuth` on its own prefix (closed wherever it is mounted);
 *   2. `Cache-Control: no-store` (the file names the people this bot may write to);
 *   3. the OWNER: `isLocalPasswordSessionOn` — this machine's own password session, from the owner's
 *      own client. A peer's single-sign-on session gets 403 `owner_only` with no data;
 *   4. the same-origin fetch-metadata rail on the unsafe methods;
 *   5. its own small JSON parser (32 KB: an allow-list is a list of ids, not a document).
 *
 * THE ROUTES TAKE SELECTIONS, NOT KEYS. `PUT` names crow ids and group ids; the KEYS ARE READ FROM
 * `contacts` / `contact_group_members` AT SAVE TIME and pinned into the file. A caller can therefore
 * never pin a key of its own choosing — which is the entire point of pinning (the door compares the
 * pinned key against the live contact row at every send). The whole map is rewritten atomically by the
 * store; this route never writes a byte itself.
 *
 *   GET    /                    the whole allow-list (every bot's entry), as stored
 *   GET    /:botId              this bot's entry plus the CHOICES the section draws: live contacts and
 *                               groups with `allowed` flags (owner-only data, never a bot's)
 *   PUT    /:botId              replace this bot's entry from {contacts, groups, rate}
 *   DELETE /:botId              remove this bot's entry ("Remove messaging from this bot")
 *
 * Error bodies are `{error, message}` with a fixed sentence per code; a caller's own text is never
 * echoed, and a refusal leaves the previous allow-list exactly as it was.
 */
import { Router, json as jsonParserOf } from "express";
import { createDbClient } from "../../db.js";
import { isLocalPasswordSessionOn } from "../dashboard/local-session.js";
import { isSameOriginRequest } from "../dashboard/same-origin.js";
import { resolveCrowHome } from "../../shared/crow-home.js";
import { listRoomMembers } from "../dashboard/panels/messages/rooms-store.js";
import {
  AclError, DEFAULT_RATE_PER_HOUR, MAX_RATE_PER_HOUR,
  readSharingBotAcl, readBotAcl, removeSharingBotAclEntry, setSharingBotAclEntry,
} from "../sharing-bot/acl.js";

/** The mount point. */
export const SHARING_BOT_ACL_API_PREFIX = "/dashboard/bot-builder/api/sharing";

/** The fixed sentences a caller can show. Codes without one answer their code alone. */
const FIXED_TEXT = Object.freeze({
  not_found: "Not found.",
  owner_only: "Only the owner can change who a bot may message.",
  cross_site: "That request came from another site.",
  bad_input: "That request is not valid.",
  acl_unreadable: "The Sharing allow-list could not be read, so nothing was changed. Fix or remove the file first.",
  unknown_contact: "One of those contacts no longer exists on this Crow.",
  unknown_group: "One of those groups no longer exists on this Crow.",
  group_empty: "One of those groups has nobody in it, so a message to it could not reach anyone.",
  internal: "Something went wrong.",
});

/** Bounds on one request: a handful of people per bot, never a list of the whole address book. */
const MAX_SELECTIONS = 200;
const MAX_BODY_BYTES = 32 * 1024;

/* ------------------------------------------------------------------ answers */

function messageFor(code) {
  return FIXED_TEXT[code] || FIXED_TEXT.internal;
}

function sendError(res, status, code) {
  if (res.headersSent) return;
  res.status(status).json({ error: code, message: messageFor(code) });
}

function storeError(res, err) {
  if (err instanceof AclError) return sendError(res, 400, "bad_input");
  return sendError(res, 500, "internal");
}

/* ------------------------------------------------------------------ validation */

function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

function keysWithin(obj, keys) {
  for (const key of Object.keys(obj)) if (!keys.includes(key)) return false;
  return true;
}

/** The selection arrays a PUT accepts, or null. Ids only; the keys come from the database. */
function readPutBody(body) {
  if (!isPlainObject(body)) return null;
  if (!keysWithin(body, ["contacts", "groups", "rate"])) return null;
  const contacts = body.contacts === undefined ? [] : body.contacts;
  const groups = body.groups === undefined ? [] : body.groups;
  if (!Array.isArray(contacts) || !Array.isArray(groups)) return null;
  if (contacts.length > MAX_SELECTIONS || groups.length > MAX_SELECTIONS) return null;
  const crowIds = [];
  for (const value of contacts) {
    if (typeof value !== "string") return null;
    const text = value.trim();
    if (!text || text.length > 200) return null;
    if (!crowIds.includes(text)) crowIds.push(text);
  }
  const groupIds = [];
  for (const value of groups) {
    const id = typeof value === "string" && /^[0-9]{1,12}$/.test(value.trim()) ? Number(value.trim()) : value;
    if (!Number.isInteger(id) || id <= 0) return null;
    if (!groupIds.includes(id)) groupIds.push(id);
  }
  let rate = null;
  if (body.rate !== undefined) {
    if (!isPlainObject(body.rate) || !keysWithin(body.rate, ["per_hour"])) return null;
    const per = body.rate.per_hour;
    if (!Number.isInteger(per) || per < 1 || per > MAX_RATE_PER_HOUR) return null;
    rate = { per_hour: per };
  }
  return { crowIds, groupIds, rate };
}

/* --------------------------------------------------------------------- choices */

/** The live contacts the section offers: id, crow id, the name a person reads, and blocked. */
async function contactChoices(db, allowedCrowIds) {
  const { rows } = await db.execute({
    sql: `SELECT id, crow_id, display_name, secp256k1_pubkey, is_blocked
            FROM contacts ORDER BY display_name COLLATE NOCASE, id LIMIT ?`,
    args: [500],
  });
  const allowed = new Set(allowedCrowIds);
  return (rows || []).map((row) => {
    const crowId = String(row.crow_id ?? "").trim();
    return {
      contact_id: Number(row.id),
      crow_id: crowId,
      name: String(row.display_name ?? "").trim() || crowId,
      blocked: Number(row.is_blocked ?? 0) === 1,
      allowed: allowed.has(crowId),
    };
  });
}

/** The groups the section offers, and whether each is a room (the only kind a message can reach). */
async function groupChoices(db, allowedGroupIds) {
  const { rows } = await db.execute({
    sql: "SELECT id, name, room_uid FROM contact_groups ORDER BY name COLLATE NOCASE, id LIMIT ?",
    args: [500],
  });
  const allowed = new Set(allowedGroupIds);
  const groups = [];
  for (const row of rows || []) {
    const id = Number(row.id);
    const members = await listRoomMembers(db, id);
    groups.push({
      group_id: id,
      name: String(row.name ?? "").trim() || `Group ${id}`,
      kind: row.room_uid == null ? "group" : "room",
      member_count: members.length,
      allowed: allowed.has(id),
    });
  }
  return groups;
}

/* --------------------------------------------------------------------- the router */

/**
 * The allow-list router.
 *
 * @param {Function} dashboardAuth the dashboard's auth middleware
 * @param {{openDb?: Function, ownerCheck?: Function, crowHome?: string|Function}} [deps]
 * @returns {import("express").Router}
 */
export function sharingBotAclRouter(dashboardAuth, deps = {}) {
  const router = Router();
  const openDb = typeof deps.openDb === "function" ? deps.openDb : () => createDbClient();
  const ownerCheck = typeof deps.ownerCheck === "function" ? deps.ownerCheck : isLocalPasswordSessionOn;
  const homeOf = () => (typeof deps.crowHome === "function" ? deps.crowHome() : deps.crowHome) || resolveCrowHome();
  const base = SHARING_BOT_ACL_API_PREFIX;
  const jsonParser = jsonParserOf({ limit: MAX_BODY_BYTES });

  /** One client per request, closed in `finally`. */
  const route = (handler) => async (req, res) => {
    const db = openDb();
    try {
      await handler(db, req, res);
    } catch (err) {
      storeError(res, err);
    } finally {
      try { db.close(); } catch { /* already closed */ }
    }
  };

  router.use(base, dashboardAuth);

  router.use(base, (req, res, next) => {
    res.setHeader("Cache-Control", "no-store");
    next();
  });

  router.use(base, async (req, res, next) => {
    const db = openDb();
    try {
      let owner = false;
      try {
        owner = (await ownerCheck(db, req)) === true;
      } catch {
        owner = false;
      }
      if (!owner) return sendError(res, 403, "owner_only");
      next();
    } finally {
      try { db.close(); } catch { /* already closed */ }
    }
  });

  // A browser that says another site sent this, or names another origin, is refused before a body is
  // parsed. Reads change nothing and are left alone.
  router.use(base, (req, res, next) => {
    if (req.method === "GET" || req.method === "HEAD" || req.method === "OPTIONS") return next();
    if (!isSameOriginRequest(req)) return sendError(res, 403, "cross_site");
    next();
  });

  router.use(base, (req, res, next) => jsonParser(req, res, (err) => {
    if (!err) return next();
    return sendError(res, 400, "bad_input");
  }));

  /* ----------------------------------------------------------------- reads */

  // GET / — every bot's entry, as stored. An unreadable file answers 409 rather than an empty map: an
  // empty map would read as "no bot may message anyone", which is not the same as "we cannot tell".
  router.get(base, route(async (_db, _req, res) => {
    const read = readSharingBotAcl(homeOf());
    if (!read.ok) return sendError(res, 409, "acl_unreadable");
    res.json({ bots: read.acl, defaultRatePerHour: DEFAULT_RATE_PER_HOUR, maxRatePerHour: MAX_RATE_PER_HOUR });
  }));

  // GET /:botId — this bot's entry plus the choices the section offers.
  router.get(`${base}/:botId`, route(async (db, req, res) => {
    const botId = String(req.params.botId ?? "");
    const read = readBotAcl(homeOf(), botId);
    if (!read.ok && read.reason === "unreadable") return sendError(res, 409, "acl_unreadable");
    if (!read.ok && read.reason === "bad_bot_id") return sendError(res, 400, "bad_input");
    const entry = read.ok ? read.entry : { contacts: [], groups: [], rate: { per_hour: DEFAULT_RATE_PER_HOUR } };
    res.json({
      entry,
      contacts: await contactChoices(db, entry.contacts.map((contact) => contact.crow_id)),
      groups: await groupChoices(db, entry.groups.map((group) => group.id)),
      defaultRatePerHour: DEFAULT_RATE_PER_HOUR,
      maxRatePerHour: MAX_RATE_PER_HOUR,
    });
  }));

  /* ---------------------------------------------------------------- writes */

  // PUT /:botId — pin this bot's people. Keys are read here, from live rows, never from the body.
  router.put(`${base}/:botId`, route(async (db, req, res) => {
    const botId = String(req.params.botId ?? "");
    const body = readPutBody(req.body);
    if (!body) return sendError(res, 400, "bad_input");

    const contacts = [];
    if (body.crowIds.length) {
      const placeholders = body.crowIds.map(() => "?").join(", ");
      const { rows } = await db.execute({
        sql: `SELECT crow_id, secp256k1_pubkey, is_blocked FROM contacts
               WHERE crow_id IN (${placeholders})`,
        args: body.crowIds,
      });
      const byCrowId = new Map((rows || []).map((row) => [String(row.crow_id ?? "").trim(), row]));
      for (const crowId of body.crowIds) {
        const row = byCrowId.get(crowId);
        // A contact that is gone cannot be pinned. A BLOCKED one is pinned as it is: the door refuses
        // it (`blocked`) until the operator unblocks it, which is the honest state of the permission.
        if (!row) return sendError(res, 400, "unknown_contact");
        const pubkey = String(row.secp256k1_pubkey ?? "").trim();
        if (!pubkey) return sendError(res, 400, "unknown_contact");
        contacts.push({ crow_id: crowId, secp256k1_pubkey: pubkey });
      }
    }

    const groups = [];
    for (const id of body.groupIds) {
      const { rows } = await db.execute({ sql: "SELECT id FROM contact_groups WHERE id = ?", args: [id] });
      if (!rows || !rows.length) return sendError(res, 400, "unknown_group");
      // The pinned member set is the SAME list the door and the room panel use, so a saving never
      // disagrees with them about who is in the room.
      const members = await listRoomMembers(db, id);
      if (!members.length) return sendError(res, 400, "group_empty");
      groups.push({
        id,
        members: members.map((member) => ({
          crow_id: String(member.crow_id ?? "").trim(),
          secp256k1_pubkey: String(member.secp256k1_pubkey ?? "").trim(),
        })),
      });
    }

    const written = setSharingBotAclEntry(homeOf(), botId, {
      contacts,
      groups,
      rate: body.rate || { per_hour: DEFAULT_RATE_PER_HOUR },
    });
    if (!written.ok) return sendError(res, 409, "acl_unreadable");
    res.json({ entry: written.entry });
  }));

  // DELETE /:botId — "Remove messaging from this bot": no entry, so the door refuses `no_allowlist`.
  router.delete(`${base}/:botId`, route(async (_db, req, res) => {
    const removed = removeSharingBotAclEntry(homeOf(), String(req.params.botId ?? ""));
    if (!removed.ok) return sendError(res, 409, "acl_unreadable");
    res.json({ ok: true, removed: removed.removed });
  }));

  // A malformed body on any route is answered in this router's own words, not the parser's.
  router.use(base, (err, _req, res, _next) => {
    if (err) return sendError(res, 400, "bad_input");
  });

  return router;
}

export default sharingBotAclRouter;