#!/usr/bin/env node
/**
 * Crow Bot Builder — the per-instance Crow server catalog.
 *
 * THE INVARIANT: a bot must never resolve a Crow server bound to an instance
 * other than its own. Stated structurally, which is how this module achieves
 * it: no file that can name an instance may describe a Crow server.
 *
 * So Crow servers are DERIVED, never copied out of the user-global
 * ~/.pi/agent/mcp.json:
 *   - core servers  -> scripts/server-registry.js, run from the repo root,
 *                      env bound to THIS instance
 *   - bundle servers -> <crowHome>/mcp-addons.json, cwd under THIS instance
 * The homedir config keeps only third-party servers, which carry credentials
 * rather than instance identity.
 *
 * Imports are deliberately limited to server-registry.js and instance-paths.mjs
 * so neither ext_registry.mjs nor mcp_writer.mjs can form a cycle through here.
 */
import { resolveAddonCommand, checkLauncherArgs } from "../../servers/shared/resolve-command.js";
import { existsSync, lstatSync, readFileSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { homedir } from "node:os";
import {
  CORE_SERVERS,
  CONDITIONAL_SERVERS,
  ROOT,
  loadEnv,
  resolveEnvValue,
} from "../server-registry.js";
import { botsDbPath, resolveSqlitePath } from "./instance-paths.mjs";
import { signActor, signBoardActor, signArtifactsActor, signBoardThreadActor, signSecretsActor, signSharingActor, signReportsActor, signMemoryActor, signProjectsActor } from "./actor-sig.mjs";
// Leaf module (no imports): the core bot doors' rollout rule, shared with the gateway's door guard.
import { coreDoorsRequested } from "../../servers/shared/core-doors-flag.js";
// Leaf module (registry read only): no path back to ext_registry.mjs or mcp_writer.mjs.
import { isLegacyConfiguredAddon, addonDerivedEnv } from "../../servers/gateway/services/legacy-sources.js";
// Leaf module (no imports): loader/injection names a child must never inherit from the
// addon entry — NODE_OPTIONS --require and LD_PRELOAD run code before the server does.
import { withoutLoaderEnv } from "../../servers/shared/loader-env.js";
// Names only, never a value: this module resolves no keychain handle and unseals nothing
// (the spawning process hydrates; see addonKeychainNeeds below). INSTANCE_ENV_KEYS comes from
// there too: the shared module needs the same list to drop a listed instance key, and this
// module may not be imported BY it (that would be a cycle).
import { ADDON_KEYCHAIN_FIELD, ADDON_SECRET_SHARES, INSTANCE_ENV_KEYS, keychainEnvNames } from "../../servers/shared/addon-secrets.js";
// The REVIEWED storage-consumer table (servers/gateway/addon-env.js: STORAGE_ENV_CONSUMERS).
// A bundle manifest's `needs` is a REQUEST, never a grant: the installed manifest is
// operator-writable and a store add-on is not reviewed code, so an id must ALSO be on that
// code-held list before a bot turn pipes it this instance's storage credentials. Imported
// rather than copied, so the two can never drift; that module pulls only leaf shared/gateway
// modules (bot-env, bundles-config, addon-secrets), so no cycle back to this file forms.
import { isStorageEnvConsumer } from "../../servers/gateway/addon-env.js";

/**
 * The env vars that name an instance. r4-deploy.sh warns that a child missing
 * any of these silently resolves to the PRIMARY instance, which is exactly the
 * failure this list exists to prevent. Defined in servers/shared/addon-secrets.js
 * (keychainEnvNames drops a listed instance key) and re-exported here.
 */
export { INSTANCE_ENV_KEYS };

/** The default primary-instance home — the one botsDbPath()/tasksDbPath() fall back to. */
const DEFAULT_CROW_HOME = join(homedir(), ".crow");

/**
 * This instance's canonical values for the four instance-scoped env vars.
 *
 * botsDbPath()/tasksDbPath() (instance-paths.mjs) resolve from the PROCESS
 * env (CROW_DB_PATH / CROW_DATA_DIR, and since queue item 33 a non-default
 * process CROW_HOME), never from the `crowHome` argument, so a caller that
 * hands us a `crowHome` for ANOTHER instance would otherwise resolve to this
 * process's database — silently rebinding a correct block onto the wrong
 * instance, which is worse than not rebinding at all. So when the env doesn't
 * decide, honor the crowHome argument itself (unless it IS the default, in
 * which case botsDbPath()'s own fallback is already correct).
 *
 * The tasks path is normalized through resolveSqlitePath(): production stores
 * `file:` URIs in project_spaces.tasks_db_uri and better-sqlite3 has no URI
 * support, so an un-normalized value reaches a bundle as an unopenable
 * filename (the PR #278 defect).
 */
export function instanceBinding(crowHome, opts = {}) {
  let dbPath = opts.dbPath;
  if (!dbPath) {
    if (process.env.CROW_DB_PATH) {
      dbPath = process.env.CROW_DB_PATH;
    } else if (process.env.CROW_DATA_DIR) {
      dbPath = join(process.env.CROW_DATA_DIR, "crow.db");
    } else if (crowHome && crowHome !== DEFAULT_CROW_HOME) {
      dbPath = join(crowHome, "data", "crow.db");
    } else {
      dbPath = botsDbPath();
    }
  }
  const tasksPath =
    opts.tasksDbPath ||
    process.env.CROW_TASKS_DB_PATH ||
    join(dirname(dbPath), "tasks.db");
  return {
    CROW_HOME: crowHome,
    CROW_DATA_DIR: dirname(dbPath),
    CROW_DB_PATH: dbPath,
    CROW_TASKS_DB_PATH: resolveSqlitePath(tasksPath),
  };
}

/** A bundle cwd under SOME instance home: /…/.crow<suffix>/bundles/<id>. */
const INSTANCE_BUNDLE_CWD = /\/\.crow[^/]*\/bundles\/([^/]+)\/?$/;

/**
 * The board MCP entry (Track 1 Task 7, D-T1.3/D-T1.5) — a direct
 * streamable-HTTP `{url, headers}` block at THIS instance's gateway
 * `/board/mcp` mount. Unlike every other catalog entry, there is nothing to
 * spawn: the gateway process already runs the mount in-process, so this is a
 * remote reference, not a stdio command.
 *
 * Bearer = the RAW board token at `<crowHome>/board-token` (minted by
 * ensureBoardToken at gateway boot, servers/gateway/local-token.js) — read
 * directly off disk, like the peer-relay token the remote-forward-proxy
 * blocks name (this module stays DB-agnostic on purpose). Actor headers (D-T1.3) let board-mcp.js's
 * resolveActor attribute a mutation to this bot and, when a job dispatched
 * the turn, to that job — the SAME botId/jobId that land in bot_sessions and
 * bot_jobs, which is what makes the result-service lock exemption
 * (card-service.js's lockExemptMatches) actually match.
 *
 * Missing/unreadable token file -> return null (never throw): config
 * generation must survive a not-yet-booted gateway or a pre-Task-6 install.
 * The caller (crowServerCatalog) surfaces this through `unconfigured`, the
 * same channel every other not-available-right-now server uses — so a bot
 * that never selects "board" never sees a warning, and one that does gets
 * exactly one line, once, from buildBotMcp's existing warnings plumbing.
 */
function boardTokenPath(crowHome) {
  return join(crowHome, "board-token");
}

function boardBlock(crowHome, { botId, jobId, threadId, gatewayType, port } = {}) {
  let token;
  try {
    token = readFileSync(boardTokenPath(crowHome), "utf8").trim();
  } catch {
    return null;
  }
  if (!token) return null;
  // Same loopback-gateway convention as scripts/pi-bots/warm.mjs
  // (PIBOT_WARM_GATEWAY_URL / CROW_GATEWAY_PORT, default :3001).
  const gatewayPort = port || process.env.CROW_GATEWAY_PORT || 3001;
  const headers = { Authorization: "Bearer " + token, "X-Crow-Actor-Kind": "bot" };
  if (botId) headers["X-Crow-Actor-Id"] = String(botId);
  if (jobId) headers["X-Crow-Job-Id"] = String(jobId);
  // S5: board-mcp honours the actor headers only with this signature (present
  // only when this process holds the per-boot key; see actor-sig.mjs).
  const sig = signBoardActor({ botId, jobId });
  if (sig) headers["X-Crow-Actor-Sig"] = sig;
  // P5: when the turn belongs to a chat, bind (bot, thread, gateway) under its
  // own kind so /board/mcp can offer a card back into that conversation.
  if (threadId) {
    headers["X-Crow-Actor-Thread"] = String(threadId);
    if (gatewayType) headers["X-Crow-Actor-Gateway"] = String(gatewayType);
    const tsig = signBoardThreadActor({ botId, threadId, gatewayType });
    if (tsig) headers["X-Crow-Actor-Thread-Sig"] = tsig;
  }
  return { url: `http://127.0.0.1:${gatewayPort}/board/mcp`, headers };
}

function phoneTokenPath(crowHome) { return join(crowHome, "phone-token"); }

/** Phone bundle: {url, headers} block for /phone/mcp. The actor headers carry
 *  the bot, the thread and the gateway so the call result can be delivered
 *  back to the conversation that asked for it. Absent token file → null. */
function phoneBlock(crowHome, { botId, threadId, gatewayType, port } = {}) {
  let token;
  try { token = readFileSync(phoneTokenPath(crowHome), "utf8").trim(); } catch { return null; }
  if (!token) return null;
  const gatewayPort = port || process.env.CROW_GATEWAY_PORT || 3001;
  const headers = { Authorization: "Bearer " + token, "X-Crow-Actor-Kind": "bot" };
  if (botId) headers["X-Crow-Actor-Id"] = String(botId);
  if (threadId) headers["X-Crow-Actor-Thread"] = String(threadId);
  if (gatewayType) headers["X-Crow-Actor-Gateway"] = String(gatewayType);
  // S2: bind the actor headers to this (bot, thread, gateway). The key lives
  // only in this process's memory (actor-sig.mjs); without it no signature is
  // written and /phone/mcp treats the caller as unattributed.
  const sig = signActor({ kind: "bot", botId, threadId, gatewayType });
  if (sig) headers["X-Crow-Actor-Sig"] = sig;
  return { url: `http://127.0.0.1:${gatewayPort}/phone/mcp`, headers };
}

function artifactsTokenPath(crowHome) { return join(crowHome, "artifacts-token"); }

/** Crow Artifacts: {url, headers} block for /artifacts/mcp, signed with kind
 *  "artifacts" (actor-sig.mjs) so the mount can attribute — and, for an
 *  untrusted round, scope — every call. Absent token file → null. */
function artifactsBlock(crowHome, { botId, threadId, gatewayType, port } = {}) {
  let token;
  try { token = readFileSync(artifactsTokenPath(crowHome), "utf8").trim(); } catch { return null; }
  if (!token) return null;
  const gatewayPort = port || process.env.CROW_GATEWAY_PORT || 3001;
  const headers = { Authorization: "Bearer " + token, "X-Crow-Actor-Kind": "bot" };
  if (botId) headers["X-Crow-Actor-Id"] = String(botId);
  if (threadId) headers["X-Crow-Actor-Thread"] = String(threadId);
  if (gatewayType) headers["X-Crow-Actor-Gateway"] = String(gatewayType);
  const sig = signArtifactsActor({ botId, threadId, gatewayType });
  if (sig) headers["X-Crow-Actor-Sig"] = sig;
  return { url: `http://127.0.0.1:${gatewayPort}/artifacts/mcp`, headers };
}

/** The catalog name of the credential card's mount (spec §10.2). */
export const SECRETS_SERVER = "crow-secrets";

/**
 * Crow servers that exist on this instance but are NEVER handed to a bot as a STDIO server.
 *
 * `crow-sharing` is the operator's own sharing surface: since servers/shared/bot-owner-only refuses
 * every sharing tool to a bot (all but crow_list_crosspost_transforms), a bot config that named it
 * could only fail calls — and the stdio server still reads the instance's identity material to start.
 * So the STDIO entry is never catalogued for bots (mcp_writer disables it even when the operator's own
 * canonical ~/.pi/agent/mcp.json carries it), while the REGISTRY entry stays exactly as it is for the
 * operator's own MCP config (`npm run mcp-config`, unchanged).
 *
 * A bot instead gets `sharingBotBlock()` below — an HTTP `{url, headers}` entry under the SAME catalog
 * name, pointing at this instance's own narrow door `/sharing-bot/mcp` (a new mount, never /sharing).
 * It is the one exception to this list, and `isSharingDoorBlock()` is how mcp_writer tells the two
 * apart: a name in this list may be handed to a bot only as that block.
 */
export const BOT_EXCLUDED_SERVERS = Object.freeze(["crow-sharing"]);

/** The catalog name the bot's sharing entry carries: the operator's own server name, so a def that
 *  already selected `crow-sharing/*` resolves its tools against the door. */
export const BOT_SHARING_SERVER = "crow-sharing";

/** The one path a bot's sharing entry may point at (the door, never the owner surface). */
export const SHARING_BOT_DOOR_PATH = "/sharing-bot/mcp";

/**
 * The hosts a bot's door block may name: this instance's own gateway, on the loopback interface. The
 * catalog always mints `127.0.0.1` (boardBlock's convention); `[::1]`/`localhost` are the same machine
 * and only the spelling differs, so both are accepted for a block somebody wrote by hand.
 */
const SHARING_DOOR_HOSTS = Object.freeze(["127.0.0.1", "::1", "[::1]", "localhost"]);

/**
 * Is this catalog block the sharing DOOR (an HTTP block at this instance's /sharing-bot/mcp)? That is
 * the only shape a bot may receive under a BOT_EXCLUDED_SERVERS name; a stdio block under the same
 * name is the owner's server and never a bot's.
 *
 * TWO HALVES, and the second is not decoration. The PATH is the door's address, and the HOST must be
 * THIS machine's loopback interface: a block whose path is /sharing-bot/mcp but whose url names another
 * host is not this instance's door — it is somebody else's server wearing the door's path, and handing
 * it to a bot would send the door's bearer and actor headers to that host. So a remote url is refused
 * here exactly like a stdio block, and the caller treats the result as "not the door".
 */
export function isSharingDoorBlock(block) {
  if (!block || typeof block !== "object" || typeof block.url !== "string" || block.command) return false;
  let url;
  try {
    url = new URL(block.url);
  } catch {
    return false;
  }
  // A door is a loopback HTTP(s) mount; anything else (a unix path, a `file:`, a bare host) is not one.
  if (url.protocol !== "http:" && url.protocol !== "https:") return false;
  if (!SHARING_DOOR_HOSTS.includes(url.hostname.toLowerCase())) return false;
  return url.pathname.replace(/\/+$/, "") === SHARING_BOT_DOOR_PATH;
}

/**
 * True for a Crow server a bot's MCP config must never contain. Both spellings
 * of a per-tool selection reduce to the server name (`crow-sharing/x`, and
 * `crow-sharing__x` — the shape pi registers a tool under), so neither can slip
 * a block in.
 */
export function isBotExcludedServer(name) {
  const base = String(name || "").split("/")[0].split("__")[0];
  return BOT_EXCLUDED_SERVERS.includes(base);
}

// The secrets token lives in <crowHome>/secrets (the 700 dir the pi sandbox hides from bots),
// rotated at every gateway boot (local-token.js SECRETS_TOKEN); this runs outside the sandbox.
function secretsTokenPath(crowHome) { return join(crowHome, "secrets", "secrets-token"); }

/** Credential card: {url, headers} block for /secrets/mcp, signed with kind "secrets" like
 *  artifactsBlock. crow_request_secret answers only a signed Perch actor (secrets/mcp.js).
 *  Absent token file → null. */
function secretsBlock(crowHome, { botId, threadId, gatewayType, port } = {}) {
  let token;
  try { token = readFileSync(secretsTokenPath(crowHome), "utf8").trim(); } catch { return null; }
  if (!token) return null;
  const gatewayPort = port || process.env.CROW_GATEWAY_PORT || 3001;
  const headers = { Authorization: "Bearer " + token, "X-Crow-Actor-Kind": "bot" };
  if (botId) headers["X-Crow-Actor-Id"] = String(botId);
  if (threadId) headers["X-Crow-Actor-Thread"] = String(threadId);
  if (gatewayType) headers["X-Crow-Actor-Gateway"] = String(gatewayType);
  const sig = signSecretsActor({ botId, threadId, gatewayType });
  if (sig) headers["X-Crow-Actor-Sig"] = sig;
  return { url: `http://127.0.0.1:${gatewayPort}/secrets/mcp`, headers };
}

/** The sharing door's token file: <crowHome>/secrets, the 0700 dir the pi sandbox masks for bots. */
function sharingBotTokenPath(crowHome) { return join(crowHome, "secrets", "sharing-bot-token"); }

/**
 * The bot sharing door: `{url, headers}` for /sharing-bot/mcp, signed with kind "sharing"
 * (actor-sig.mjs) so the mount can attribute every call and refuse an unsigned one.
 *
 * It is returned only when this build can mint a COMPLETE block: the token file exists, the caller
 * named a bot, and this process holds the per-boot actor key (or a presigned tuple for it). A door
 * block missing any of those would be refused at the mount after a spawn, so it is not emitted at all
 * — the caller surfaces the reason through `unconfigured`, exactly as the board entry's missing token
 * is surfaced.
 *
 * SELECTION IS UNCHANGED: like every catalog entry, this block reaches a bot's config only when the
 * bot's def selects `crow-sharing` (`buildBotMcp`'s closed-world pass); the operator's stdio
 * `crow-sharing` is a BOT_EXCLUDED_SERVERS entry and is never emitted under this name.
 */
function sharingBotBlock(crowHome, { botId, threadId, gatewayType, port } = {}) {
  let token;
  try {
    token = readFileSync(sharingBotTokenPath(crowHome), "utf8").trim();
  } catch {
    return null;
  }
  if (!token || botId == null || String(botId).trim() === "") return null;
  const sig = signSharingActor({ botId, threadId, gatewayType });
  // No key in this process (a GUI/CLI build for a validation, or a host that signs over the relay):
  // an unsigned door block would be refused at the mount, so it is not emitted at all.
  if (!sig) return null;
  const gatewayPort = port || process.env.CROW_GATEWAY_PORT || 3001;
  const headers = {
    Authorization: "Bearer " + token,
    "X-Crow-Actor-Kind": "sharing",
    "X-Crow-Actor-Id": String(botId),
    "X-Crow-Actor-Sig": sig,
  };
  if (threadId) headers["X-Crow-Actor-Thread"] = String(threadId);
  if (gatewayType) headers["X-Crow-Actor-Gateway"] = String(gatewayType);
  return { url: `http://127.0.0.1:${gatewayPort}${SHARING_BOT_DOOR_PATH}`, headers };
}

/** The catalog name of the reports door (the bot tools for building reports). */
export const REPORTS_SERVER = "reports";

/** The reports door's token file: <crowHome>/secrets, the 0700 dir the pi sandbox masks for bots. */
function reportsTokenPath(crowHome) { return join(crowHome, "secrets", "reports-token"); }

/**
 * The reports door: `{url, headers}` for /reports/mcp, signed with kind "reports" (actor-sig.mjs) so
 * the mount can attribute every call and refuse an unsigned one. The project a call lands in is
 * derived from the verified bot, never from an argument, which is why the tuple is signed here.
 *
 * It is returned only when this build can mint a COMPLETE block: the token file exists, the caller
 * named a bot, and this process holds the per-boot actor key (or a presigned tuple for it). A door
 * block missing any of those would be refused at the mount after a spawn, so it is not emitted at
 * all, and the bot simply has no reports tools.
 *
 * SELECTION IS UNCHANGED: like every catalog entry, this block reaches a bot's config only when the
 * bot's def selects `reports` (`buildBotMcp`'s closed-world pass). No Crow server carries that name,
 * so there is no stdio shape to keep away from a bot and nothing to exclude.
 */
function reportsBlock(crowHome, { botId, threadId, gatewayType, port } = {}) {
  let token;
  try {
    token = readFileSync(reportsTokenPath(crowHome), "utf8").trim();
  } catch {
    return null;
  }
  if (!token || botId == null || String(botId).trim() === "") return null;
  const sig = signReportsActor({ botId, threadId, gatewayType });
  // No key in this process (a GUI/CLI build for a validation, or a host that signs over the relay):
  // an unsigned door block would be refused at the mount, so it is not emitted at all.
  if (!sig) return null;
  const gatewayPort = port || process.env.CROW_GATEWAY_PORT || 3001;
  const headers = {
    Authorization: "Bearer " + token,
    "X-Crow-Actor-Kind": "reports",
    "X-Crow-Actor-Id": String(botId),
    "X-Crow-Actor-Sig": sig,
  };
  if (threadId) headers["X-Crow-Actor-Thread"] = String(threadId);
  if (gatewayType) headers["X-Crow-Actor-Gateway"] = String(gatewayType);
  return { url: `http://127.0.0.1:${gatewayPort}/reports/mcp`, headers };
}

/**
 * The core bot doors (design D2): the catalog names a bot's memory and project selections keep
 * (`crow-memory`, `crow-projects`), the door each maps to, its token file (in <crowHome>/secrets, the
 * 0700 dir the pi sandbox masks for bots) and its signed actor kind.
 */
export const CORE_DOOR_SERVERS = Object.freeze({
  "crow-memory": Object.freeze({ path: "/memory-bot/mcp", tokenFile: "memory-bot-token", kind: "memory", sign: signMemoryActor }),
  "crow-projects": Object.freeze({ path: "/projects-bot/mcp", tokenFile: "projects-bot-token", kind: "projects", sign: signProjectsActor }),
});

/**
 * The ONE reviewed table of servers the gateway serves through a door: name -> the exact mount path
 * of THIS instance's gateway its http `{url, headers}` block points at (each is where that door's
 * block is built above), so the stdio child that would open crow.db / tasks.db is not spawned for
 * them. Anything NOT in the table (crow-blog, crow-storage, every installed bundle's server,
 * pm-workspace, the remote proxy, ...) counts as NEEDING the database. A listed name only counts
 * while its block is really that door: an http url on loopback, at the gateway's port, at exactly
 * that path (a name-collision block aimed anywhere else still needs the database), never a stdio one.
 */
const DOOR_PATHS = Object.freeze({
  "crow-memory": CORE_DOOR_SERVERS["crow-memory"].path,     // the core doors (CORE_DOOR_SERVERS)
  "crow-projects": CORE_DOOR_SERVERS["crow-projects"].path,
  [BOT_SHARING_SERVER]: SHARING_BOT_DOOR_PATH,              // /sharing-bot/mcp
  [REPORTS_SERVER]: "/reports/mcp",
  board: "/board/mcp",
  phone: "/phone/mcp",
  artifacts: "/artifacts/mcp",                              // the Phone and Artifacts bundle doors
  [SECRETS_SERVER]: "/secrets/mcp",                         // the credential-request door
});
export const DOOR_SERVED_SERVERS = Object.freeze(Object.keys(DOOR_PATHS));

const DOOR_LOOPBACK_HOSTS = Object.freeze(["127.0.0.1", "[::1]", "localhost"]);

/** True when `block` is the door block `name` is served by: http, loopback, the gateway's port, the exact path. */
export function isDoorServedBlock(name, block, gatewayPort) {
  const path = DOOR_PATHS[name];
  if (!path || !block || typeof block !== "object" || block.command) return false;
  if (typeof block.url !== "string" || block.url === "") return false;
  let u;
  try { u = new URL(block.url); } catch { return false; }
  const port = Number(gatewayPort || process.env.CROW_GATEWAY_PORT || 3001);
  return u.protocol === "http:" && DOOR_LOOPBACK_HOSTS.includes(u.hostname) && Number(u.port) === port
    && u.pathname === path && !u.search && !u.hash && !u.username && !u.password;
}

/** An object holding the inert (stdio) blocks as NON-enumerable properties: it can be carried by
 *  reference through Object.assign / spreads, and no JSON / log / clone of the carrier shows a block. */
export function sealInertBlocks(blocks) {
  const out = {};
  for (const [k, v] of Object.entries(blocks || {})) Object.defineProperty(out, k, { value: v, enumerable: false });
  return out;
}

/**
 * Hard-link check for a no-database spawn: every database file the gateway uses (and its -wal /
 * -shm / -journal) must have exactly ONE link. A bot that hard-linked one into its workspace in an
 * earlier database-bound turn would otherwise keep a writable path to it. Returns a reason or null.
 * Fails closed when no paths were given.
 */
export function databaseLinkProblem(dbPaths) {
  if (!Array.isArray(dbPaths) || dbPaths.length === 0) return "the database paths are unknown";
  // (A host bind-mount alias of the data dir is not detectable from here.)
  for (const configured of dbPaths) {
    if (typeof configured !== "string" || configured === "") return "the database paths are unknown";
    const base = resolveSqlitePath(configured); // a file: URI becomes its path
    for (const suffix of ["", "-wal", "-shm", "-journal"]) {
      let l;
      try { l = lstatSync(base + suffix); } catch (e) {
        // A companion may be absent; the base file may not (fail closed).
        if (e && e.code === "ENOENT" && suffix !== "") continue;
        return "the database could not be checked";
      }
      if (l.isSymbolicLink()) return "the database path is a link";
      let st;
      try { st = statSync(base + suffix); } catch { return "the database could not be checked"; }
      if (st.nlink > 1) return "the database has another link";
    }
  }
  return null;
}

/**
 * The all-or-nothing decision for ONE spawn (design D5a): `noDb` is true only when the opt-in is
 * requested AND every active server in the FINAL config is a gateway door block, so the sandbox
 * can hold no database at all. Otherwise the whole opt-in is inert (the caller rebuilds without
 * door blocks and keeps the bind). Computed once per spawn by writeBotMcp; the same object feeds
 * the MCP config and the contain plan, so they cannot disagree. Pure.
 *
 * @param {{requested: boolean, mcpServers: object, botLabel?: string, gatewayPort?: number}} a
 * @returns {{requested: boolean, noDb: boolean, blockers: string[], doorUnavailable: string[], warning: string|null}}
 */
export function decideCoreDoors({ requested, mcpServers, botLabel, gatewayPort } = {}) {
  if (requested !== true) return { requested: false, noDb: false, blockers: [], doorUnavailable: [], warning: null };
  const blockers = [];
  const doorUnavailable = [];
  for (const [name, block] of Object.entries(mcpServers || {})) {
    if (!block || typeof block !== "object" || block.disabled === true) continue;
    if (isDoorServedBlock(name, block, gatewayPort)) continue;
    // A listed name as a stdio block (a door with no token yet) is "door unavailable"; a listed name
    // whose http block points anywhere but its door (a collision) needs the database like any other.
    if (DOOR_SERVED_SERVERS.includes(name) && (block.command || typeof block.url !== "string" || block.url === "")) doorUnavailable.push(name);
    else blockers.push(name);
  }
  if (!blockers.length && !doorUnavailable.length) return { requested: true, noDb: true, blockers, doorUnavailable, warning: null };
  const why = blockers.length
    ? `still needs the database: ${blockers.join(", ")}`
    : `door unavailable: ${doorUnavailable.join(", ")}`;
  return { requested: true, noDb: false, blockers, doorUnavailable, warning: `[core-doors] ${botLabel || "bot"}: core doors stay off (${why})` };
}

/**
 * The FINAL judgement, self-enforcing: the incoming `noDb` is NOT trusted (and not read). PiRpc
 * (bridge.mjs) hands the final `mcpConfig` here before the contain plan is built and before the
 * config is serialised, and the answer is recomputed from that config alone: if any core door
 * block is present, `noDb` is true only when (1) every active server passes the door-served rule
 * (decideCoreDoors), (2) the spawn is contained (`containedSpawn === true`: an uncontained spawn has
 * the full filesystem, so a door beside it is no containment), and (3) no database file has a second
 * link (`dbPaths`). Otherwise every core door block is replaced by its `inertBlocks[name]` stdio
 * block (held in memory, never written); a core door with no inert block is dropped and the one
 * warning says so. No core door block present: noDb false. It can never return a door with noDb false. Pure
 * apart from the lstat of `dbPaths`.
 *
 * @returns {{noDb: boolean, warning: string|null, mcpConfig: object, flipped: boolean}}
 */
export function finalizeCoreDoors({ mcpConfig, botLabel, inertBlocks, containedSpawn, dbPaths, gatewayPort } = {}) {
  const servers0 = (mcpConfig && mcpConfig.mcpServers) || {};
  const live = (b) => b && typeof b === "object" && b.disabled !== true;
  const coreDoorNames = Object.keys(CORE_DOOR_SERVERS).filter((n) => live(servers0[n]) && !servers0[n].command
    && typeof servers0[n].url === "string" && servers0[n].url !== "");
  if (!coreDoorNames.length) return { noDb: false, warning: null, mcpConfig, flipped: false };
  const d = decideCoreDoors({ requested: true, mcpServers: servers0, botLabel, gatewayPort });
  let warning = d.warning;
  if (d.noDb) {
    const why = containedSpawn !== true ? "not contained" : databaseLinkProblem(dbPaths);
    if (!why) return { noDb: true, warning: null, mcpConfig, flipped: false };
    warning = `[core-doors] ${botLabel || "bot"}: core doors stay off (${why})`;
  }
  const servers = { ...servers0 };
  const dropped = [];
  for (const name of coreDoorNames) {
    const inert = inertBlocks && inertBlocks[name];
    if (inert && typeof inert === "object" && inert.command) servers[name] = inert;
    else { delete servers[name]; dropped.push(name); }
  }
  warning += (dropped.length ? ` (no stdio block to fall back to, dropped: ${dropped.join(", ")})` : "");
  return { noDb: false, warning, mcpConfig: { ...mcpConfig, mcpServers: servers }, flipped: true };
}

/** The paths a core door block may point at. */
export const CORE_DOOR_PATHS = Object.freeze(Object.values(CORE_DOOR_SERVERS).map((d) => d.path));

/**
 * One core door block: `{url, headers}` for the door's path at THIS instance's loopback gateway,
 * signed with the door's own actor kind. Returned only when it can be COMPLETE — the token file
 * exists, a bot is named, and this process holds the actor key (or a presigned tuple) — and
 * otherwise `{block: null, reason}`, so the caller keeps the stdio block and says why.
 */
function coreDoorBlock(crowHome, name, { botId, threadId, gatewayType, port } = {}) {
  const door = CORE_DOOR_SERVERS[name];
  if (!door) return { block: null, reason: "is not a core door" };
  if (botId == null || String(botId).trim() === "") return { block: null, reason: "no bot was named for its door" };
  let token;
  try {
    token = readFileSync(join(crowHome, "secrets", door.tokenFile), "utf8").trim();
  } catch {
    return { block: null, reason: "its door has no token on this instance yet" };
  }
  if (!token) return { block: null, reason: "its door has no token on this instance yet" };
  const sig = door.sign({ botId, threadId, gatewayType });
  if (!sig) return { block: null, reason: "this build holds no signed actor for its door" };
  const gatewayPort = port || process.env.CROW_GATEWAY_PORT || 3001;
  const headers = {
    Authorization: "Bearer " + token,
    "X-Crow-Actor-Kind": door.kind,
    "X-Crow-Actor-Id": String(botId),
    "X-Crow-Actor-Sig": sig,
  };
  if (threadId) headers["X-Crow-Actor-Thread"] = String(threadId);
  if (gatewayType) headers["X-Crow-Actor-Gateway"] = String(gatewayType);
  return { block: { url: `http://127.0.0.1:${gatewayPort}${door.path}`, headers }, reason: null };
}

/**
 * Should THIS bot's catalog serve memory and projects through the doors? The instance flag
 * (`CROW_BOT_CORE_DOORS`) AND the definition's own `core_doors: true` (core-doors-flag.js). The
 * definition handed here may be a raw read: an opt-in a bot forged into its own row only routes it
 * to a door that re-reads the VERIFIED definition and refuses it, and an opt-in it removed only
 * returns it to today's stdio path, so neither direction widens anything.
 */
export function coreDoorsWanted(def, env = process.env) {
  return coreDoorsRequested(def, env);
}

function applyJournalGuard(env) {
  // The WAL-unlink scar: every server touching a crow.db runs journal DELETE.
  if (env && env.CROW_DB_PATH) env.CROW_JOURNAL_MODE = "DELETE";
  return env;
}

/**
 * The env NAMES an add-on cannot start without, read from the entries alone — never a value.
 *
 * Two sources: the entry's own `keychainEnv` (its sealed settings) and ADDON_SECRET_SHARES
 * (another add-on's settings this one reads, R6 — e.g. sunvox-studio reading Funkwhale's
 * URL and access token). Producing the values is the CALLER's business (the gateway hydrates
 * from its own keychain); a bot config only learns which names are owed.
 *
 * A SHARE name is owed only when the SOURCE add-on's own entry lists it in `keychainEnv`:
 * sunvox-studio never seals Funkwhale's settings itself, so with Funkwhale not installed (no
 * entry) or unsealed (nothing listed) it owes no keychain name at all — and a file-mode bot
 * keeps it instead of dropping it with a warning about keys that do not exist. `opts.addons`
 * is the whole mcp-addons.json map (the source entries live there, not in this entry).
 *
 * Empty for an add-on with neither, which is what keeps today's entries byte-identical.
 */
export function addonKeychainNeeds(id, entry, opts = {}) {
  const names = [...keychainEnvNames(entry)];
  const shares = typeof id === "string" && Object.prototype.hasOwnProperty.call(ADDON_SECRET_SHARES, id)
    ? ADDON_SECRET_SHARES[id]
    : null;
  if (shares && typeof shares === "object") {
    const addons = opts.addons && typeof opts.addons === "object" ? opts.addons : {};
    for (const [sourceId, wanted] of Object.entries(shares)) {
      // The source must be installed (it has an entry) and must itself seal the name.
      const source = Object.prototype.hasOwnProperty.call(addons, sourceId) ? addons[sourceId] : null;
      if (!source || typeof source !== "object") continue;
      const listed = keychainEnvNames(source);
      for (const name of Array.isArray(wanted) ? wanted : []) {
        if (typeof name !== "string" || name === "" || !listed.includes(name)) continue;
        if (!names.includes(name)) names.push(name);
      }
    }
  }
  return names;
}

/**
 * A block's env with the plain value of every keychain-listed name removed.
 *
 * A listed name is authoritative at spawn: its value comes from the keychain, so any plain
 * copy left in the entry is stale by definition and must not board a bot's MCP config.
 * An entry with no listed names gets the SAME object back (today's behaviour, byte for
 * byte). Instance-scoped keys are never stripped: they name the instance, not a secret,
 * and removing one would let the child inherit whatever ambient value the caller has.
 *
 * `listed` is the caller's already-read keychainEnvNames() result when it has one (a
 * caller that reads the names twice would log a malformed entry's warning twice);
 * omitted, the entry is read here.
 */
export function withoutKeychainValues(entry, env, listed) {
  const source = env && typeof env === "object" ? env : null;
  if (!source) return env;
  const names = (Array.isArray(listed) ? listed : keychainEnvNames(entry))
    .filter((n) => !INSTANCE_ENV_KEYS.includes(n));
  if (names.length === 0) return env;
  const out = { ...source };
  for (const name of names) delete out[name];
  return out;
}

/**
 * Rebind a server block that did NOT come from the catalog — a third-party or
 * `crow-browser` entry out of the homedir config — onto this instance.
 *
 * Returns {block, rebound} or {disabled, reason}. `optIn` is stripped: pi
 * activates an optIn server only when a project file says {"enabled": true},
 * so a verbatim copy of an optIn block silently never loads. Selecting the
 * server IS the opt-in.
 *
 * The /.crow anchor is deliberate. `/home/alex/crow/bundles/browser` and
 * `/home/alex/crow` do not match, so the repo is left alone — it is
 * instance-neutral, correctly.
 */
export function rebindBlock(name, block, binding, crowHome) {
  const clone = JSON.parse(JSON.stringify(block));
  delete clone.optIn;
  const rebound = [];
  if (clone.env) {
    for (const k of INSTANCE_ENV_KEYS) {
      if (k in clone.env && clone.env[k] !== binding[k]) {
        clone.env[k] = binding[k];
        rebound.push(k);
      }
    }
  }
  const m = clone.cwd ? INSTANCE_BUNDLE_CWD.exec(clone.cwd) : null;
  if (m) {
    const target = join(crowHome, "bundles", m[1]);
    if (!existsSync(target)) {
      return {
        disabled: true,
        reason: `bundle '${m[1]}' is not installed on this instance (${target})`,
      };
    }
    if (clone.cwd !== target) {
      clone.cwd = target;
      rebound.push("cwd");
    }
  }
  applyJournalGuard(clone.env);
  return { block: clone, rebound };
}

function readAddons(crowHome) {
  try {
    return JSON.parse(readFileSync(join(crowHome, "mcp-addons.json"), "utf8")) || {};
  } catch {
    return {};
  }
}

/**
 * The manifest `needs` an add-on declares ("shared-storage" today): the app-side pieces a
 * spawning process must HYDRATE into that server's block, because the child itself may not
 * read the instance's identity. Empty for an unreadable/absent manifest, so an installed
 * copy from before the declaration simply gets no hydration (and no warning).
 *
 * Read from the INSTALLED copy (`<crowHome>/bundles/<id>/manifest.json`), never the repo: a
 * manifest bump is what ships the declaration (`refreshVersionedBundle`), and the entry in
 * mcp-addons.json is written at install time — it may predate the field.
 *
 * This is the DECLARATION only. What a bot turn actually grants is decided together with
 * isStorageEnvConsumer() — see sharedStorageUnreviewed in crowServerCatalog().
 */
export function manifestNeeds(crowHome, id) {
  if (typeof crowHome !== "string" || crowHome === "" || typeof id !== "string" || id === "") return [];
  try {
    const m = JSON.parse(readFileSync(join(crowHome, "bundles", id, "manifest.json"), "utf8"));
    return Array.isArray(m && m.needs) ? m.needs.filter((n) => typeof n === "string" && n !== "") : [];
  } catch {
    return [];
  }
}

/** The one `needs` entry this file knows (see servers/storage/s3-client.js adoptHostStorage). */
export const SHARED_STORAGE_NEED = "shared-storage";

/**
 * Build a core-server block from its registry entry. Instance-scoped env keys
 * come from the binding; everything else resolves against the repo .env.
 * Returns {block, missing} — `missing` names required templates (no `:-`
 * default) that resolved empty.
 */
function coreBlock(spec, binding, repoEnv, node) {
  const env = {};
  const missing = [];
  for (const [k, tmpl] of Object.entries(spec.mcpEnv || {})) {
    if (INSTANCE_ENV_KEYS.includes(k)) {
      env[k] = binding[k];
      continue;
    }
    const v = resolveEnvValue(tmpl, repoEnv);
    if (!v && /\$\{\w+\}/.test(tmpl)) missing.push(k);
    // An optional key (`${KEY:-}`) with no value is left OUT: an empty string in block.env
    // would shadow a real value the child inherits from process.env.
    else if (!v && /\$\{\w+:-\}/.test(tmpl)) continue;
    else env[k] = v;
  }
  applyJournalGuard(env);
  return { block: { command: node, args: [...spec.args], cwd: ROOT, env }, missing };
}

/**
 * Every Crow server available to THIS instance, plus the ones that exist but
 * cannot be spawned here and why.
 *
 * `unconfigured` is not an error channel — it is what the GUI renders so an
 * operator sees "crow-storage: unconfigured, missing MINIO_ENDPOINT" instead
 * of an opaque spawn failure.
 *
 * `needsKeys` / `needsSharedStorage` are what an EMITTED block needs the spawning
 * process to hydrate (a sealed add-on's keychain values; this instance's opened Shared
 * Storage settings). Names only, never a value: nothing is opened here.
 *
 * `sharedStorageUnreviewed` is the other half of that decision: bundles whose manifest
 * declared `needs: ["shared-storage"]` but whose id is NOT on the reviewed code-held
 * allow-list (servers/gateway/addon-env.js: STORAGE_ENV_CONSUMERS). They owe nothing and get
 * nothing — the caller leaves them storage-OFF with one warning naming them.
 *
 * `coreNames` names the subset of `servers` sourced from the registry
 * (CORE_SERVERS + CONDITIONAL_SERVERS, plus the core-mounted `phone` http
 * entry when its token exists) rather than from mcp-addons.json. It
 * exists so a consumer that wants ONLY the registry-sourced servers (the ones
 * that vanish from the picker once Crow entries leave the homedir config) can
 * select them without re-deriving the split — `probeExtensions` already owns
 * the addon half of `servers` and is already instance-correct, so folding
 * addons back in elsewhere would double-list and double-spawn them.
 */
export function crowServerCatalog(crowHome = process.env.CROW_HOME || join(homedir(), ".crow"), opts = {}) {
  const binding = opts.binding || instanceBinding(crowHome, opts);
  const node = opts.node || process.execPath;
  const repoEnv = loadEnv();
  const servers = {};
  const unconfigured = {};
  const coreNames = [];
  // id -> the env names it owes the keychain. Names only, and only for blocks this catalog
  // actually emitted: the caller hydrates them (or refuses the spawn) — this module never does.
  const needsKeys = {};
  // Block names whose child needs this instance's OPENED Shared Storage settings piped into
  // its env. Two grants reach this list: a REGISTRY `needs` (core servers — code in this
  // repo, reviewed by definition), and a bundle manifest's `needs` ONLY when that bundle id
  // is also on the reviewed, code-held allow-list (isStorageEnvConsumer). Names only and
  // emitted blocks only, like needsKeys: the writer opens and pipes them on an fd turn, and a
  // file turn leaves the child with no shared storage plus one warning — nothing is opened here.
  const needsSharedStorage = [];
  // Block names that DECLARED `needs: ["shared-storage"]` and were refused because their id
  // is not a reviewed storage consumer. The writer leaves each one storage-OFF (marker 0, no
  // credentials) plus ONE warning naming it — a request from an operator-writable manifest is
  // not a grant, and silence would look like a working storage block to its author.
  const sharedStorageUnreviewed = [];

  // Board entry FIRST (Track 1 Task 7) — the one {url, headers} block in an
  // otherwise all-stdio catalog. See boardBlock() above.
  const board = boardBlock(crowHome, { botId: opts.botId, jobId: opts.jobId, threadId: opts.threadId, gatewayType: opts.gatewayType, port: opts.gatewayPort });
  if (board) servers.board = board;
  else unconfigured.board = "board token not found — mint one from the dashboard (or ensureBoardToken at boot)";
  const phone = phoneBlock(crowHome, { botId: opts.botId, threadId: opts.threadId, gatewayType: opts.gatewayType, port: opts.gatewayPort });
  // Phone joins coreNames so serversForProbe offers its tools in the Bot
  // Builder Tools tab (an http block; probeServerTools speaks HTTP). Only when
  // the gateway minted a phone token, i.e. the Phone bundle is installed.
  if (phone) { servers.phone = phone; coreNames.push("phone"); }
  const artifacts = artifactsBlock(crowHome, { botId: opts.botId, threadId: opts.threadId, gatewayType: opts.gatewayType, port: opts.gatewayPort });
  if (artifacts) { servers.artifacts = artifacts; coreNames.push("artifacts"); }
  const secrets = secretsBlock(crowHome, { botId: opts.botId, threadId: opts.threadId, gatewayType: opts.gatewayType, port: opts.gatewayPort });
  if (secrets) { servers[SECRETS_SERVER] = secrets; coreNames.push(SECRETS_SERVER); }
  // The bot sharing door (bot door + saved message drafts): an http block under the SAME catalog name
  // the operator's stdio server has, so a def that already selected `crow-sharing/*` resolves to the
  // door's tools and never to the identity-reading stdio spawn. Emitted only when it can be complete
  // (token + a signed actor); see sharingBotBlock. A bot that never selects it never sees it.
  const sharing = sharingBotBlock(crowHome, { botId: opts.botId, threadId: opts.threadId, gatewayType: opts.gatewayType, port: opts.gatewayPort });
  if (sharing) { servers[BOT_SHARING_SERVER] = sharing; coreNames.push(BOT_SHARING_SERVER); }
  else unconfigured[BOT_SHARING_SERVER] = "is not available to bots yet: the sharing door has no token, or this build holds no signed actor for the bot";
  // The reports door (bot tools for building reports): an http block at THIS instance's
  // /reports/mcp, under the reports token and a signed `reports` actor, emitted only when it can be
  // complete (token + a signed actor); see reportsBlock. A def that never selects `reports` never
  // sees it. No `unconfigured` line: the name stands for its own mount alone, so a bot that selects
  // it with no door available just has no reports tools.
  const reports = reportsBlock(crowHome, { botId: opts.botId, threadId: opts.threadId, gatewayType: opts.gatewayType, port: opts.gatewayPort });
  if (reports) { servers[REPORTS_SERVER] = reports; coreNames.push(REPORTS_SERVER); }

  // The core bot doors (design D2): with `opts.coreDoors` (the caller decided the flag AND the
  // bot's opt-in, coreDoorsWanted), `crow-memory` and `crow-projects` are emitted as HTTP door
  // blocks under their own names, so a def's existing selection resolves to the doors and the bot
  // never spawns them as stdio children. A door block that cannot be complete leaves the stdio
  // block in place and says why in `coreDoors.fellBack`; writeBotMcp then treats the WHOLE opt-in
  // as inert for that spawn (decideCoreDoors), rebuilding with no door blocks at all.
  const coreDoors = { requested: opts.coreDoors === true, served: [], fellBack: {} };
  const doorBlocks = {};
  if (coreDoors.requested) {
    for (const name of Object.keys(CORE_DOOR_SERVERS)) {
      const { block, reason } = coreDoorBlock(crowHome, name, { botId: opts.botId, threadId: opts.threadId, gatewayType: opts.gatewayType, port: opts.gatewayPort });
      if (block) { doorBlocks[name] = block; coreDoors.served.push(name); }
      else coreDoors.fellBack[name] = reason;
    }
  }

  for (const spec of CORE_SERVERS) {
    if (isBotExcludedServer(spec.name)) continue; // never in a bot's config (BOT_EXCLUDED_SERVERS)
    if (doorBlocks[spec.name]) {
      servers[spec.name] = doorBlocks[spec.name];
      coreNames.push(spec.name);
      continue;
    }
    const { block } = coreBlock(spec, binding, repoEnv, node);
    servers[spec.name] = block;
    coreNames.push(spec.name);
    if (Array.isArray(spec.needs) && spec.needs.includes(SHARED_STORAGE_NEED)) needsSharedStorage.push(spec.name);
  }
  for (const spec of CONDITIONAL_SERVERS) {
    if (isBotExcludedServer(spec.name)) continue; // never in a bot's config (BOT_EXCLUDED_SERVERS)
    const { block, missing } = coreBlock(spec, binding, repoEnv, node);
    if (missing.length) unconfigured[spec.name] = `unconfigured: missing ${missing.join(", ")}`;
    else {
      servers[spec.name] = block;
      if (Array.isArray(spec.needs) && spec.needs.includes(SHARED_STORAGE_NEED)) needsSharedStorage.push(spec.name);
    }
    coreNames.push(spec.name);
  }
  // A service add-on's fields count as set in its entry, the repo .env, or the
  // caller's environment (the child inherits it), as in the gateway's proxy.
  const addonEnv = { ...repoEnv, ...process.env };
  // Read once: a SHARE name is owed only when the SOURCE add-on's own entry lists it
  // (addonKeychainNeeds), which needs the whole map, not this entry.
  const addons = readAddons(crowHome);
  for (const [id, addon] of Object.entries(addons)) {
    // Satellite-hosted bundles have no local MCP server to spawn: crow reaches them through its
    // own satellite tool entry (spec §8, §9.1), so they are never catalog blocks here.
    if (addon?.transport === "satellite") {
      unconfigured[id] = "satellite: its tools come from the paired server";
      continue;
    }
    // The names this entry seals in the keychain (never a value). Read once, before the
    // block is built: a listed name's plain copy is dropped and no derived env is rendered.
    const listed = keychainEnvNames(addon);
    if (!isLegacyConfiguredAddon(id, addon, undefined, addonEnv)) {
      unconfigured[id] = "service: its account fields are not set";
      continue;
    }
    const cwd = resolve(addon.cwd || join(crowHome, "bundles", id));
    if (!existsSync(cwd)) {
      unconfigured[id] = `bundle not installed on this instance (${cwd})`;
      continue;
    }
    const r = rebindBlock(id, { ...addon, cwd }, binding, crowHome);
    if (r.disabled) {
      unconfigured[id] = r.reason;
    } else {
      // A bundle server runs UNDER this instance, so it must be told which one.
      // rebindBlock only rewrites instance keys a block already carries, and most
      // addon blocks carry none — which left CROW_HOME to whatever ambient
      // environment the caller happened to have (the browser bundle wrote its
      // sessions wherever that pointed). CROW_HOME only: injecting CROW_DB_PATH
      // would trip touchesCrowDb() and apply the journal guard to bundles that
      // never open crow.db.
      // A service add-on also gets its manifest's derived env (Render's AUTH_HEADER), rendered
      // from the entry's own env ONLY: those values are already in this block, so nothing new
      // is written. A field the child would inherit from the environment is never rendered into
      // the block (that would copy a gateway .env secret into the bot's MCP config).
      // A SEALED add-on (keychainEnv lists a name) gets no derived env at all: `derived` is
      // rendered from the entry's plain values, so a listed name's stale plaintext could come
      // back through a derived header (Render's `AUTH_HEADER: Bearer ${...}`) even after the
      // plain value itself was stripped below.
      const derived = listed.length > 0 ? {} : addonDerivedEnv(id, addon.env, undefined, {});
      // Loader names (NODE_OPTIONS, LD_PRELOAD, …) are stripped from BOTH sides: the block's
      // env is cloned from the addon entry, and `derived` is rendered from that same entry's
      // env, so a loader name can reach the child through either. CROW_HOME is added here by
      // the catalog itself and is never stripped.
      // A listed name is authoritative at spawn (its value comes from the keychain), so its
      // plain copy is removed — the value is unsealed by the spawning process, never here.
      r.block.env = { ...withoutLoaderEnv(withoutKeychainValues(addon, r.block.env, listed)),
        ...withoutLoaderEnv(derived), CROW_HOME: crowHome };
      // The list itself is not part of a spawn block: no `keychainEnv` field ever reaches a
      // bot's MCP config (only the names the caller still owes travel, via needsKeys).
      delete r.block[ADDON_KEYCHAIN_FIELD];
      // A bare command (uvx, uv, npx) is resolved to an absolute path here:
      // the gateway's systemd PATH usually lacks ~/.local/bin, so the bot's
      // pi child failed with ENOENT and the server silently dropped.
      if (typeof r.block.command === "string") {
        const rc = resolveAddonCommand(r.block.command, { sha256: r.block.command_sha256, cwd: r.block.cwd || cwd });
        const argProblem = rc.missing ? null : checkLauncherArgs(rc.command, r.block.args);
        if (argProblem) { unconfigured[id] = `command '${r.block.command}' not usable: ${argProblem}`; continue; }
        if (rc.missing) {
          unconfigured[id] = `command '${r.block.command}' not usable: ${rc.reason || "not found"} (searched the gateway PATH, ~/.local/bin, ~/.cargo/bin, ~/bin, /usr/local/bin)`;
          continue;
        }
        r.block.command = rc.command;
        // A pinned launcher keeps its pin: pi-lab's mcp-client re-hashes it
        // right before it spawns the server (verification at spawn time).
        if (rc.sha256) r.block.command_sha256 = rc.sha256; else delete r.block.command_sha256;
      }
      servers[id] = r.block;
      // Only an EMITTED block owes keys: an unconfigured or unusable add-on is not in the
      // config at all, so there is nothing for the caller to hydrate.
      const needs = addonKeychainNeeds(id, addon, { addons });
      if (needs.length > 0) needsKeys[id] = needs;
      // The same rule for the app-side hydrations its manifest declares (`needs`):
      // shared storage is opened by the SPAWNER and piped over the fd — but the manifest only
      // ASKS. The grant needs both halves: the installed manifest declares the need, AND the
      // bundle id is on the reviewed code-held list. A store add-on that declares the need is
      // refused (storage off, one warning), never handed this instance's credentials.
      if (manifestNeeds(crowHome, id).includes(SHARED_STORAGE_NEED)) {
        if (isStorageEnvConsumer(id)) needsSharedStorage.push(id);
        else sharedStorageUnreviewed.push(id);
      }
    }
  }
  return { servers, unconfigured, coreNames, needsKeys, needsSharedStorage, sharedStorageUnreviewed, coreDoors };
}
