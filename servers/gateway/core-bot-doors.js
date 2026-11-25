/**
 * The core bot doors (design D2): the memory and project tools served BY THE GATEWAY to a bot, at
 * `/memory-bot/mcp` and `/projects-bot/mcp` — never `/memory` or `/projects`, which stay the owner's
 * surfaces and are deliberately not bot doors.
 *
 * WHY. A contained bot used to run `crow-memory` and `crow-projects` as stdio children INSIDE its
 * sandbox, with crow.db bound read-write. Identity in a stdio child is env-only, so a bot that can
 * rewrite its child's env (or spawn the server itself) is indistinguishable from the owner. Through
 * these doors the bot never opens the database for those tools: the gateway runs the very same
 * server factories (`createMemoryServer`, `createProjectServer`) with a BOT base actor it verified
 * itself, so every existing bot rule in those servers — the share gate
 * (servers/shared/project-share-scope.js), the owner-only schedule, notification and context rules,
 * the workspace file rules — applies with an identity the bot cannot choose. (Removing the database
 * bind is a later step; until then the doors narrow what a bot does through these tools, and the
 * stdio path stays available behind the rollout flag.)
 *
 * THREE CREDENTIALS, ALL REQUIRED (the mount guard below, installed by boot/mcp-mounts.js in front of
 * each MCP mount exactly as the sharing and reports doors' guards are):
 *
 *   1. a bearer of the door's OWN path-scoped family (`MEMORY_BOT_TOKEN` / `PROJECTS_BOT_TOKEN`,
 *      servers/gateway/local-token.js), rotated at every boot and accepted on that door's
 *      `(mcp|sse|messages)` paths only. The guard validates it itself, so no other family — not the
 *      operator's full local token, not the other door's token, not a peer's bearer — opens a door;
 *   2. a signed actor of the door's own kind (`memory` / `projects`, scripts/pi-bots/actor-sig.mjs)
 *      over (bot, thread, gateway), with its own MAC domain so no other door's signature replays
 *      here, nor this one there;
 *   3. the bot's VERIFIED definition (servers/shared/bot-def-store.js readVerifiedBotDef), which
 *      must carry the owner's opt-in `core_doors: true`. A definition that does not verify — changed
 *      outside Crow, its MAC gone, an unknown bot — is refused 403, as is one that never opted in:
 *      the opt-in is MAC'd, so only the owner can set it, and the door serves exactly the canary bots.
 *
 * An unsigned or unverified caller is refused on EVERY path of the mount, tools/list included. The
 * claims the guard pinned (`{botId, threadId, gatewayType, projectId, tokenScope}`) reach the mount
 * as `req.auth.extra`, and the caller context this module builds for the mount (`coreBotDoorCaller`)
 * is what the server factory reads: the bot is the server's BASE actor
 * (`{kind: "bot", id, botSession: true}`, frozen), so no per-call `_meta` or header can widen it, and
 * `botSession` keeps the reserved voice-bot id an ordinary bound bot. The bot's home project comes
 * from the verified definition through the share gate's own verified read.
 *
 * A SESSION BELONGS TO ITS BOT. A session is opened by one verified (bot, thread, gateway) and the
 * mount records that tuple as the session's owner; a later request on the same session id that is
 * verified for a different tuple is refused 401, so one bot cannot ride another bot's session even
 * if it learned the id.
 *
 * A CONTAINED BOT GETS NO NEW EGRESS. A relayed socket (servers/shared/bot-doors.js isRelayedSocket)
 * is a contained bot, which has no network of its own; the project tools that fetch a page or run a
 * web search would otherwise fetch FOR it from the gateway. On a relayed session those two seams are
 * replaced by refusals, so a contained bot reaches no more of the network through the door than it
 * did through its stdio child. A host-tier bot (not relayed) keeps them, as it has today.
 *
 * HOST-ONLY: imported by the gateway's boot alone. Nothing bot-reachable imports this module.
 */
import { createDbClient } from "../db.js";
import { createMemoryServer } from "../memory/server.js";
import { createProjectServer } from "../research/server.js";
import { askerRank, RANK_CLOUD } from "../memory/summary-recall.js";
import { readVerifiedBotDef } from "../shared/bot-def-store.js";
import { isRelayedSocket } from "../shared/bot-doors.js";
import { CORE_DOORS_DEF_KEY, defOptsIntoCoreDoors } from "../shared/core-doors-flag.js";
import { currentCaller } from "./caller-context.js";
import { MEMORY_BOT_TOKEN, PROJECTS_BOT_TOKEN, localOperatorAuth } from "./local-token.js";
import { verifyMemoryActorSig, verifyProjectsActorSig } from "../../scripts/pi-bots/actor-sig.mjs";

/** The mount prefixes and the one path each bot config names. */
export const MEMORY_BOT_MCP_PREFIX = "/memory-bot";
export const MEMORY_BOT_DOOR_PATH = "/memory-bot/mcp";
export const PROJECTS_BOT_MCP_PREFIX = "/projects-bot";
export const PROJECTS_BOT_DOOR_PATH = "/projects-bot/mcp";

/** The actor-signature kinds; each its own MAC domain in actor-sig.mjs. */
export const MEMORY_BOT_ACTOR_KIND = "memory";
export const PROJECTS_BOT_ACTOR_KIND = "projects";

/** The token scopes a request carries once a guard admitted it (local-token.js's path scopes). */
export const MEMORY_BOT_TOKEN_SCOPE = "memory-bot";
export const PROJECTS_BOT_TOKEN_SCOPE = "projects-bot";

/**
 * The per-bot opt-in is a field of the bot DEFINITION (servers/shared/core-doors-flag.js). The
 * definition is MAC'd (bot-def-mac.js), so only the owner's own writes can set it; a contained bot
 * that writes it into its row makes the row fail verification, and the door then refuses it outright.
 */
export { CORE_DOORS_DEF_KEY, defOptsIntoCoreDoors };

const DOORS = Object.freeze({
  memory: Object.freeze({
    prefix: MEMORY_BOT_MCP_PREFIX, kind: MEMORY_BOT_ACTOR_KIND, scope: MEMORY_BOT_TOKEN_SCOPE,
    token: MEMORY_BOT_TOKEN, verify: verifyMemoryActorSig,
  }),
  projects: Object.freeze({
    prefix: PROJECTS_BOT_MCP_PREFIX, kind: PROJECTS_BOT_ACTOR_KIND, scope: PROJECTS_BOT_TOKEN_SCOPE,
    token: PROJECTS_BOT_TOKEN, verify: verifyProjectsActorSig,
  }),
});

function doorOf(name) {
  const door = DOORS[name];
  if (!door) throw new TypeError(`core bot door must be "memory" or "projects", got ${String(name)}`);
  return door;
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

function unauthorized(res) {
  res.status(401).json({ jsonrpc: "2.0", id: null, error: { code: -32001, message: "unauthorized" } });
}

function forbidden(res) {
  res.status(403).json({ jsonrpc: "2.0", id: null, error: { code: -32003, message: "forbidden" } });
}

/**
 * The owner tag a door session is recorded under (routes/mcp.js stores `req.auth.clientId` as the
 * session's owner). The whole verified tuple, plus whether the socket was relayed, so a session is
 * reusable only by the same bot, thread and gateway, through the same kind of socket.
 */
export function doorSessionOwner(scope, { botId, threadId, gatewayType, relayed }) {
  return `bot-door:${JSON.stringify([scope, botId, threadId ?? null, gatewayType ?? null, relayed === true])}`;
}

/** The session id a request continues, if any (streamable header, or the SSE messages query). */
function sessionIdOf(req) {
  const header = headerValue(req?.headers, "mcp-session-id");
  if (header) return header;
  const q = req?.query && typeof req.query.sessionId === "string" ? req.query.sessionId : null;
  return q || null;
}

/**
 * The auth wrapper `boot/mcp-mounts.js` installs in front of `mountMcpServer(app, "/memory-bot", …)`
 * (door "memory") or `mountMcpServer(app, "/projects-bot", …)` (door "projects").
 *
 * A request is admitted when ALL hold: its bearer is a live token of the door's own family; the
 * actor headers carry the door's kind, a bot id and a signature over (bot, thread, gateway) that
 * verifies; the bot's definition verifies and opted in (`core_doors: true`); and, for a request on an
 * existing session, that session was opened by this same verified tuple. A token or signature
 * failure is 401; a verified bot whose definition does not verify or never opted in is 403.
 *
 * @param {"memory"|"projects"} doorName
 * @param {{createDb?: Function, validateToken?: (req: object, token: string) => Promise<boolean>,
 *   verifyActor?: Function, readDef?: (db: object, botId: string) => Promise<object>,
 *   sessionStores?: () => Array<Map<string, {owner?: string}>>}} [deps]
 * @returns {(req: object, res: object, next: Function) => unknown}
 */
export function coreBotDoorMountAuth(doorName, deps = {}) {
  const door = doorOf(doorName);
  const createDb = typeof deps.createDb === "function" ? deps.createDb : createDbClient;
  const verifyActor = typeof deps.verifyActor === "function" ? deps.verifyActor : door.verify;
  const readDef = typeof deps.readDef === "function" ? deps.readDef : readVerifiedBotDef;

  return async (req, res, next) => {
    const token = bearerOf(req);
    if (!token) return unauthorized(res);

    const headers = req.headers || {};
    const kind = headerValue(headers, "x-crow-actor-kind");
    const botId = headerValue(headers, "x-crow-actor-id");
    const threadId = headerValue(headers, "x-crow-actor-thread");
    const gatewayType = headerValue(headers, "x-crow-actor-gateway");
    const sig = headerValue(headers, "x-crow-actor-sig");

    let db = null;
    const openDb = () => (db ||= createDb());
    try {
      let valid = false;
      try {
        if (typeof deps.validateToken === "function") valid = (await deps.validateToken(req, token)) === true;
        else valid = (await door.token.validate(openDb(), token)) === true;
      } catch {
        valid = false;
      }
      if (!valid) return unauthorized(res);

      let signed = false;
      try {
        signed = kind === door.kind && Boolean(botId) && Boolean(sig)
          && verifyActor({ botId, threadId, gatewayType, sig }) === true;
      } catch {
        signed = false;
      }
      if (!signed) return unauthorized(res);

      // The identity and scope come from the VERIFIED definition, never from the request.
      let read = null;
      try {
        read = await readDef(openDb(), botId);
      } catch {
        read = null;
      }
      if (!read || read.ok !== true) {
        if (read && read.reason && read.reason !== "unknown-bot") {
          console.warn(`[bot-def] ${botId} settings could not be verified (${read.reason}); the ${door.kind} door refused it`);
        }
        return forbidden(res);
      }
      if (!defOptsIntoCoreDoors(read.def)) return forbidden(res);
      if (Number(read.row?.enabled) !== 1) return forbidden(res);

      const relayed = isRelayedSocket(req.socket);
      const claims = {
        botId,
        threadId: threadId || null,
        gatewayType: gatewayType || null,
        projectId: read.row?.project_id == null ? null : Number(read.row.project_id),
        relayed,
      };
      const owner = doorSessionOwner(door.scope, claims);

      // One session id source per request: a header AND a query id could name two different sessions.
      if (headerValue(headers, "mcp-session-id") && typeof req.query?.sessionId === "string") return unauthorized(res);

      // A session belongs to the tuple that opened it.
      const sid = sessionIdOf(req);
      if (sid && typeof deps.sessionStores === "function") {
        for (const store of deps.sessionStores() || []) {
          const session = store && typeof store.get === "function" ? store.get(sid) : undefined;
          if (session && session.owner !== owner) return unauthorized(res);
        }
      }

      req.localTokenAuth = { token: "local-mcp", scope: door.scope };
      req.auth = { ...localOperatorAuth(door.scope, claims), clientId: owner };
      return next();
    } finally {
      if (db) { try { db.close(); } catch { /* already closed */ } }
    }
  };
}

/* ---------------------------------------------------------------- caller context */

/** The claims a door guard pinned on this request, for this door's scope only; else null. */
function claimsFor(req, scope) {
  const extra = req?.auth?.extra;
  if (!extra || extra.tokenScope !== scope) return null;
  const botId = typeof extra.botId === "string" ? extra.botId.trim() : "";
  if (!botId) return null;
  return extra;
}

/**
 * The caller context a door mount runs its handlers in (mountMcpServer's `callerFor` option): the
 * verified bot, never the owner. A request the door's guard did not admit has no caller at all, and
 * the server factory then refuses to build.
 */
export function coreBotDoorCaller(doorName) {
  const door = doorOf(doorName);
  return (req) => {
    const c = claimsFor(req, door.scope);
    if (!c) return { caller: null, peer: false, crossHost: false, botId: null, doorScope: null };
    return {
      caller: `bot:${c.botId}`,
      botId: c.botId,
      threadId: c.threadId ?? null,
      gatewayType: c.gatewayType ?? null,
      projectId: c.projectId ?? null,
      relayed: c.relayed === true,
      peer: false,
      crossHost: false,
      doorScope: door.scope,
    };
  };
}

/** The verified bot this server is being built for, from the caller context; throws without one. */
function doorBot(scope, caller = currentCaller()) {
  if (!caller || caller.doorScope !== scope || typeof caller.botId !== "string" || !caller.botId) {
    throw new Error("a core bot door server is built only for a request its guard admitted");
  }
  return {
    actor: Object.freeze({ kind: "bot", id: caller.botId, botSession: true }),
    threadId: caller.threadId ?? null,
    relayed: caller.relayed === true,
  };
}

/* --------------------------------------------------------------------- the servers */

/** The refusal a contained bot's page fetch gets on the projects door (no new egress). */
const NO_EGRESS_REASON = "network fetches are not available to a contained bot";

/** A fetchPage seam that refuses: the shape fetch-page.js answers a failed fetch with. */
async function refusedFetch(url) {
  return { ok: false, fetch_status: "failed", reason: NO_EGRESS_REASON, final_url: typeof url === "string" ? url : null, http_status: null };
}

/** A webSearch seam that refuses: the shape brave-search.js answers a failed search with. */
async function refusedSearch() {
  return { ok: false, reason: "Web search is not available to a contained bot." };
}

/**
 * The summary-recall rank for a door bot: only a bot whose definition verifies is ranked by where its
 * model runs (summary-recall.js askerRank); anything else ranks as the cloud (fail closed), so an
 * unverified row never raises what session summaries a bot may recall.
 */
function verifiedAskerRank({ createDb, threadId, readDef }) {
  return async (actor) => {
    let db = null;
    try {
      db = createDb();
      const read = await readDef(db, actor.id);
      if (!read || read.ok !== true) return RANK_CLOUD;
      return await askerRank(db, actor, { threadId });
    } catch {
      return RANK_CLOUD;
    } finally {
      if (db) { try { db.close(); } catch { /* already closed */ } }
    }
  };
}

/**
 * Build the memory server for the bot the door's guard verified (read from the caller context).
 *
 * `verifyActor` is the door's own credential, checked by the MOUNT GUARD (coreBotDoorMountAuth) and
 * never here; boot names it on this factory so the mount reads as a SIGNED bot door in
 * boot/mcp-mounts.js (tests/mcp-writer-owner-mounts.test.js classifies every mount by that name).
 *
 * @param {{instructions?: string, syncManager?: object, verifyActor?: Function, createDb?: Function,
 *   readDef?: Function, createServer?: Function, caller?: object}} [options]
 */
export function createMemoryBotServer(options = {}) {
  if (options.verifyActor !== undefined && typeof options.verifyActor !== "function") {
    throw new TypeError("createMemoryBotServer: verifyActor must be the door's actor verifier (the mount guard runs it)");
  }
  const { actor, threadId } = doorBot(MEMORY_BOT_TOKEN_SCOPE, options.caller);
  const build = typeof options.createServer === "function" ? options.createServer : createMemoryServer;
  return build(options.dbPath, {
    ...(options.instructions ? { instructions: options.instructions } : {}),
    syncManager: options.syncManager || null,
    actor,
    actorThread: threadId,
    summaryAskerRank: verifiedAskerRank({
      createDb: typeof options.createDb === "function" ? options.createDb : createDbClient,
      readDef: typeof options.readDef === "function" ? options.readDef : readVerifiedBotDef,
      threadId,
    }),
  });
}

/**
 * Build the projects server for the bot the door's guard verified (read from the caller context).
 * A relayed (contained) session gets refusing page-fetch and web-search seams; see the header.
 *
 * @param {{instructions?: string, verifyActor?: Function, createServer?: Function, caller?: object,
 *   fetchPage?: Function, webSearch?: Function}} [options]
 */
export function createProjectsBotServer(options = {}) {
  if (options.verifyActor !== undefined && typeof options.verifyActor !== "function") {
    throw new TypeError("createProjectsBotServer: verifyActor must be the door's actor verifier (the mount guard runs it)");
  }
  const { actor, relayed } = doorBot(PROJECTS_BOT_TOKEN_SCOPE, options.caller);
  const build = typeof options.createServer === "function" ? options.createServer : createProjectServer;
  const seams = relayed
    ? { fetchPage: refusedFetch, webSearch: refusedSearch }
    : {
      ...(typeof options.fetchPage === "function" ? { fetchPage: options.fetchPage } : {}),
      ...(typeof options.webSearch === "function" ? { webSearch: options.webSearch } : {}),
    };
  return build(options.dbPath, {
    ...(options.instructions ? { instructions: options.instructions } : {}),
    actor,
    ...seams,
  });
}
