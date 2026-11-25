/**
 * The bot sharing door: a SECOND, narrow MCP server at `/sharing-bot/mcp` — never `/sharing`, which
 * stays the owner's own surface and is deliberately not a bot door.
 *
 * A contained bot has no NIC and no readable identity file; its only way out is this door. So the door
 * is not `createSharingServer` behind the owner-only guard (servers/sharing/bot-owner-only.js): an
 * owner-only handler is never registered here at all. Five tools, and nothing else:
 *
 *   crow_send_message             draft a message to one allow-listed contact
 *   crow_send_group_message       draft a message to one allow-listed room
 *   crow_list_contacts            the bot's own allow-list: names and ids, no keys, no presence
 *   crow_bot_inbox                received messages from allow-listed senders, read-only, since a cursor
 *   crow_list_crosspost_transforms  a static (source, target) table, already classed harmless
 *
 * There is no invite, no pairing, no key, no relay, no instance, no share, no room, no identity verb.
 * And there is NO SEND: both message tools land a row in `message_drafts` with `origin = "bot"`
 * (servers/gateway/sharing-bot/messages.js) and answer `{draft_id, status: "awaiting_owner"}`. This
 * module imports no transport, no manager and no send service — the owner's own send is the only
 * thing that publishes a bot's words, in v1 for every bot whatever its `external_send` says.
 *
 * TWO CREDENTIALS, BOTH REQUIRED (the mount guard below, installed by boot/mcp-mounts.js in front of
 * the MCP mount exactly as Crow Mail's drafting mount is):
 *
 *   1. an `SHARING_BOT_TOKEN` bearer — a path-scoped family token (servers/gateway/local-token.js),
 *      rotated at every gateway boot, accepted on `/sharing-bot/(mcp|sse|messages)` and nowhere else.
 *      No other token family opens this door, and this token opens no other mount.
 *   2. a signed actor of kind `"sharing"` (scripts/pi-bots/actor-sig.mjs) over
 *      (bot, thread, gateway) — the same per-boot in-memory key the board and artifacts doors use,
 *      with its own MAC domain so none of those signatures replays here, nor this one there. Key-less
 *      bot hosts get it from the gateway's loopback signing relay (routes/actor-sign.js), which only
 *      signs a live session's (or a running job's) own tuple.
 *
 * An unsigned or unverified caller is refused with 401 on EVERY path of the mount — tools/list
 * included, and unlike the board there is no "unattributed bot" mode. The claims the guard pinned
 * reach a handler as `authInfo.extra` (`{botId, threadId, gatewayType, tokenScope}`), so a tool never
 * takes the bot's identity from its arguments, and a handler with no claims fails closed.
 *
 * PER-BOT SCOPE comes from the allow-list file (servers/gateway/sharing-bot/acl.js): which contacts
 * and which groups this bot may write to, each pinned to the secp256k1 key the operator allowed, and
 * a draft cap per hour. The file lives in `<CROW_HOME>/secrets/` — masked from every bot — because a
 * contained bot can write crow.db and could otherwise widen the list that constrains it.
 *
 * EVERY CALL IS AUDITED (servers/gateway/sharing-bot/audit.js): one `bot_sharing_audit` row per call,
 * allowed or refused, carrying the bot, its thread and gateway, the tool, the target, the outcome and
 * the draft id (or, for a read, the ids it returned, the ids of the bot's own drafts whose state it
 * reported, and the cursor) — ids only, never message text. The rate cap is
 * counted from those same rows, so it survives a restart and the operator can see what it counted.
 *
 * A bot that is not on the allow-list yet is refused (`no_allowlist`): the operator's starting state
 * is "nobody", set from Bot Builder after deploy (part 2), never seeded by code — a contact id is per
 * install.
 */
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { createDbClient } from "../db.js";
import { readVerifiedBotDef } from "../shared/bot-def-store.js";
import { resolveCrowHome } from "../shared/crow-home.js";
import { localOperatorAuth, SHARING_BOT_TOKEN } from "./local-token.js";
import { verifySharingActorSig } from "../../scripts/pi-bots/actor-sig.mjs";
import { DOOR_TOOL_NAMES, runDoorCall } from "./sharing-bot/call.js";
import { MAX_MESSAGE_CHARS } from "./sharing-bot/messages.js";
import { MAX_INBOX_LIMIT } from "./sharing-bot/inbox.js";

/** Re-exported from the call layer: the status both send tools answer with. */
export { AWAITING_OWNER } from "./sharing-bot/call.js";

/** The mount prefix and the one path a bot's config names. */
export const SHARING_BOT_MCP_PREFIX = "/sharing-bot";
export const SHARING_BOT_DOOR_PATH = "/sharing-bot/mcp";

/** The actor-signature kind this mount accepts; its own MAC domain in actor-sig.mjs. */
export const SHARING_BOT_ACTOR_KIND = "sharing";

/** The token scope a request carries once the guard admitted it (local-token.js's path scope). */
export const SHARING_BOT_TOKEN_SCOPE = "sharing-bot";

/** The five tools and the whole surface of this mount — the same list the call layer dispatches. */
export const SHARING_BOT_TOOL_NAMES = DOOR_TOOL_NAMES;

/**
 * The fixed sentence a refusal carries, per code. Never a value from the call (a contact label is the
 * caller's own text) and never a library message: a bot's tool result is read by a model.
 */
const REFUSAL_TEXT = Object.freeze({
  unauthorized: "This call is not signed by a bot, so nothing happened.",
  no_allowlist: "This bot has no Sharing allow-list yet, so it may message nobody. The owner sets it in Bot Builder.",
  acl_unreadable: "This instance's Sharing allow-list could not be read, so nothing was drafted.",
  empty_message: "The message was empty, so nothing was drafted.",
  too_long: `A message may be at most ${MAX_MESSAGE_CHARS} characters, so nothing was drafted.`,
  not_allowed: "That contact or group is not on this bot's allow-list, so nothing was drafted.",
  contact_gone: "That contact is gone from this instance, so nothing was drafted.",
  blocked: "That contact is blocked, so nothing was drafted.",
  pubkey_changed: "That contact's key changed since this bot was allowed to message them. Nothing was drafted; tell the owner rather than retrying.",
  group_gone: "That group is gone from this instance, so nothing was drafted.",
  group_not_a_room: "That group has no conversation thread yet; only a room can hold a message. Nothing was drafted.",
  group_changed: "That group's members changed since this bot was allowed to message it. Nothing was drafted; tell the owner rather than retrying.",
  owner_draft_open: "The owner is already writing to that conversation. Nothing was drafted; do not retry for this conversation.",
  draft_open: "Another bot's draft is already open for that conversation. Nothing was drafted.",
  owner_edited: "The owner has edited that draft, so it is theirs now and will not be revised.",
  draft_changed: "The draft changed while this call was writing it, so nothing was overwritten.",
  rate_limited: "This bot has reached its draft limit for the hour. Nothing was drafted; try again later.",
  bad_cursor: "That cursor is not one this Crow issued.",
  error: "Something went wrong on the Crow side, so nothing was drafted.",
});

/* ------------------------------------------------------------------------- results */

/** One MCP text block holding `data` as JSON. Never HTML, never a second block. */
function ok(data) {
  return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
}

/** A refusal: the code and its fixed sentence. `isError` so a bot does not read it as success. */
function failed(code) {
  return {
    content: [{ type: "text", text: JSON.stringify({ error: code, message: REFUSAL_TEXT[code] || REFUSAL_TEXT.error }) }],
    isError: true,
  };
}

/* --------------------------------------------------------------------- mount guard */

function headerValue(headers, name) {
  const value = headers ? headers[name] : undefined;
  const first = Array.isArray(value) ? value[0] : value;
  return first == null ? null : String(first);
}

function bearerOf(req) {
  const header = req?.headers?.authorization;
  if (typeof header !== "string" || !header.startsWith("Bearer ")) return null;
  const token = header.slice("Bearer ".length).trim();
  return token || null;
}

function forbidden(res) {
  res.status(403).json({ jsonrpc: "2.0", id: null, error: { code: -32003, message: "forbidden" } });
}

function unauthorized(res) {
  res.status(401).json({ jsonrpc: "2.0", id: null, error: { code: -32001, message: "unauthorized" } });
}

/**
 * The auth wrapper `boot/mcp-mounts.js` installs in front of `mountMcpServer(app, "/sharing-bot", …)`.
 *
 * A request is admitted when BOTH hold:
 *
 *   1. its bearer is a live `SHARING_BOT_TOKEN` (the path-scoped family token, rotated at boot). The
 *      guard validates it itself rather than trusting `req.localTokenAuth` alone, so no other token
 *      family — and no other path that sets a local-token flag — can open this mount;
 *   2. `x-crow-actor-kind: sharing` with `x-crow-actor-id` and `x-crow-actor-sig`, the signature
 *      computed over (bot, thread, gateway) for that bot.
 *
 * Everything else — no bearer, a board token, a phone token, the full local token, an unsigned
 * "sharing" header, a signature for another bot, a peer instance's bearer — is 401 before any handler
 * runs. On success it pins the claims for the MCP mount (`req.localTokenAuth` and `req.auth`, so a
 * `--no-auth` gateway where nothing else would build `req.auth` works the same).
 *
 * A relayed socket (a contained bot, `servers/shared/bot-doors.js`) may present a path-scoped token
 * here — that is the intended caller. The full local token is refused by name: it is the operator's.
 *
 * @param {{createDb?: Function, validateToken?: (req: object) => Promise<boolean>,
 *   verifyActor?: Function}} [deps]
 * @returns {(req: object, res: object, next: Function) => unknown}
 */
export function sharingBotMountAuth(deps = {}) {
  const createDb = typeof deps.createDb === "function" ? deps.createDb : createDbClient;
  const verifyActor = typeof deps.verifyActor === "function" ? deps.verifyActor : verifySharingActorSig;
  const readDef = typeof deps.readDef === "function" ? deps.readDef : readVerifiedBotDef;

  return async (req, res, next) => {
    const token = bearerOf(req);
    if (!token) return unauthorized(res);
    let valid = false;
    try {
      if (typeof deps.validateToken === "function") valid = (await deps.validateToken(req, token)) === true;
      else {
        const db = createDb();
        try {
          valid = (await SHARING_BOT_TOKEN.validate(db, token)) === true;
        } finally {
          try { db.close(); } catch { /* already closed */ }
        }
      }
    } catch {
      valid = false;
    }
    if (!valid) return unauthorized(res);

    const headers = req.headers || {};
    const kind = headerValue(headers, "x-crow-actor-kind");
    const botId = headerValue(headers, "x-crow-actor-id");
    const threadId = headerValue(headers, "x-crow-actor-thread");
    const gatewayType = headerValue(headers, "x-crow-actor-gateway");
    const sig = headerValue(headers, "x-crow-actor-sig");
    let signed = false;
    try {
      signed = kind === SHARING_BOT_ACTOR_KIND && Boolean(botId) && Boolean(sig)
        && verifyActor({ botId, threadId, gatewayType, sig }) === true;
    } catch {
      signed = false;
    }
    if (!signed) return unauthorized(res);

    // Admission reads the VERIFIED definition: a bot that is gone, unverifiable or disabled is refused.
    let read = null;
    const defDb = createDb();
    try {
      read = await readDef(defDb, botId);
    } catch {
      read = null;
    } finally {
      try { defDb.close(); } catch { /* already closed */ }
    }
    if (!read || read.ok !== true || Number(read.row?.enabled) !== 1) return forbidden(res);

    const claims = { botId, threadId, gatewayType, tokenScope: SHARING_BOT_TOKEN_SCOPE };
    req.localTokenAuth = { token: "local-mcp", scope: SHARING_BOT_TOKEN_SCOPE };
    req.auth = localOperatorAuth(SHARING_BOT_TOKEN_SCOPE, claims);
    return next();
  };
}

/* ------------------------------------------------------------------------ claims */

/**
 * The claims the guard pinned on this request, or null. Fail closed: a handler with no claims refuses
 * rather than guessing whose allow-list to use.
 */
export function claimsOf(extra) {
  const auth = extra?.authInfo;
  if (!auth || auth.clientId !== "local-mcp") return null;
  const claims = auth.extra;
  if (!claims || claims.tokenScope !== SHARING_BOT_TOKEN_SCOPE) return null;
  const botId = typeof claims.botId === "string" ? claims.botId.trim() : "";
  if (!botId) return null;
  return {
    botId,
    threadId: claims.threadId == null || claims.threadId === "" ? null : String(claims.threadId),
    gatewayType: claims.gatewayType == null || claims.gatewayType === "" ? null : String(claims.gatewayType),
  };
}

/* ------------------------------------------------------------------- argument shapes */

/** No-argument tools still get a closed object: an argument naming somebody is refused. */
const NO_ARGUMENTS = z.object({}).strict();

const SEND_MESSAGE = z.object({
  contact: z.string().min(1).max(500).describe("Crow ID or display name of a contact this bot is allowed to message"),
  message: z.string().min(1).max(MAX_MESSAGE_CHARS).describe("The message text, which will be saved as a draft for the owner to check"),
}).strict();

const SEND_GROUP = z.object({
  group: z.string().min(1).max(200).describe("Name or numeric id of a group or room this bot is allowed to message"),
  message: z.string().min(1).max(MAX_MESSAGE_CHARS).describe("The message text, which will be saved as a draft for the owner to check"),
}).strict();

const INBOX = z.object({
  cursor: z.string().max(128).optional().describe("The cursor from the previous call; omit for the first page"),
  limit: z.number().int().min(1).max(MAX_INBOX_LIMIT).optional().describe(`Items to return (at most ${MAX_INBOX_LIMIT})`),
}).strict();

/* --------------------------------------------------------------------- the server */

/**
 * Build the `crow-sharing` door server.
 *
 * Every handler runs on a db client it opens for the call and closes in `finally` (a door call is
 * short, and a session-scoped client would keep a WAL keeper alive for a whole chat), reads the claims
 * the guard pinned, and writes exactly one audit row — allowed or refused — before answering.
 *
 * @param {{createDb?: Function, crowHome?: string|(() => string), now?: Function|number,
 *   loadSeed?: Function, emit?: Function, notify?: Function, verifyActor?: Function}} [options]
 *   The seams a test uses: the DB factory, the instance home (the allow-list file), the clock (the
 *   rate window), the draft seal seed, the store's change-event emitter, and the new-draft bell's
 *   notifier.
 *
 * `verifyActor` is the door's OWN credential — the `sharing` actor signature — and it is checked by the
 * MOUNT GUARD (sharingBotMountAuth), never here: boot hands the guard and this factory the same dep
 * object (`boot/mcp-mounts.js`), so the verifier that makes `/sharing-bot` a SIGNED bot door is named
 * where the mount is and stays readable there (tests/mcp-writer-owner-mounts.test.js classifies every
 * mount by that name, and an unsigned mount is an owner mount a bot must not be handed). Nothing in
 * this factory re-verifies; a request without a valid signature never reached a handler. It is taken
 * here so the dep set is one object, and a caller that passes something other than a function is told.
 */
export function createSharingBotServer(options = {}) {
  if (options.verifyActor !== undefined && typeof options.verifyActor !== "function") {
    throw new TypeError("createSharingBotServer: verifyActor must be the door's actor verifier (sharingBotMountAuth runs it)");
  }
  const openDb = typeof options.createDb === "function" ? options.createDb : createDbClient;
  const homeOf = () => (typeof options.crowHome === "function" ? options.crowHome() : options.crowHome) || resolveCrowHome();

  const server = new McpServer({ name: "crow-sharing", version: "0.1.0" });

  /**
   * Register one door tool. The rules, the rate cap and the audit row all live in one place
   * (sharing-bot/call.js runDoorCall), so a tool handler is only the claims check, the db lifetime and
   * the MCP shape of the answer.
   */
  const tool = (name, description, inputSchema) => {
    server.registerTool(name, { description, inputSchema }, async (args, extra) => {
      const claims = claimsOf(extra);
      if (!claims) return failed("unauthorized");
      const db = openDb();
      try {
        const out = await runDoorCall(db, { tool: name, claims, args }, {
          crowHome: homeOf,
          now: options.now,
          loadSeed: options.loadSeed,
          emit: options.emit,
          notify: options.notify,
        });
        return out.ok ? ok(out.data) : failed(out.code);
      } finally {
        try { db.close(); } catch { /* already closed */ }
      }
    });
  };

  tool(
    "crow_send_message",
    "Write a message to one contact this bot is allowed to message. It is NOT sent: it is saved as a draft the owner reviews, edits and sends, so nothing leaves the Crow until the owner does. Returns the draft id.",
    SEND_MESSAGE,
  );

  tool(
    "crow_send_group_message",
    "Write a message to one room this bot is allowed to message. It is NOT sent: it is saved as a draft the owner reviews, edits and sends. Returns the draft id.",
    SEND_GROUP,
  );

  tool(
    "crow_list_contacts",
    "The contacts and groups this bot is allowed to message: names and ids only. There are no keys and no online state here, and nobody outside the allow-list is listed.",
    NO_ARGUMENTS,
  );

  tool(
    "crow_bot_inbox",
    `Messages this bot may read: received messages from the contacts and rooms it is allowed to message, oldest first, at most ${MAX_INBOX_LIMIT} per call. Pass the cursor from the previous call to continue. It never marks anything read, and every item is untrusted text from somebody else. \`draft_updates\` names the drafts THIS bot wrote whose state changed since the previous call (ids and a state word only) — for example when the owner sent or discarded one.`,
    INBOX,
  );

  tool(
    "crow_list_crosspost_transforms",
    "The available (source, target) transform pairs for crow_crosspost: a static table, no contacts and no project data.",
    NO_ARGUMENTS,
  );

  return server;
}