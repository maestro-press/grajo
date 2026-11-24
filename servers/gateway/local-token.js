/**
 * Local MCP token — a single, per-instance, full-tool-access static bearer
 * token for headless / no-browser MCP clients (the remote-HTTP path that does
 * not run the OAuth dance). Only the KEYED verifier of the token is stored (an `h1.` HMAC under
 * <CROW_HOME>/secrets/token-hmac.key, `mintSettingsToken` below), in a local-scoped dashboard
 * setting that never syncs to paired instances; the raw value is shown exactly once at
 * generation. See the private engineering notes.
 *
 * EVERY family in this file (this one, board, phone, artifacts, models, peer relay, kiosk
 * announce, llm cloud and the path-scoped loopback families) stores its verifier the same way
 * and verifies it through `verifySettingsToken`, which is `verifyStored` under the family's own
 * MAC domain: the setting key IS the domain, so a value copied from one family's setting never
 * verifies in another, and a bare sha256 in a converted family is refused and alarmed instead
 * of accepted (design §1a/§2.2/§3.3). No validator here compares hashes itself.
 */
import { randomBytes } from "node:crypto";
import { resolveCrowHome } from "../shared/crow-home.js";
import { writeFileSync, existsSync, chmodSync, mkdirSync, renameSync, unlinkSync, lstatSync, openSync, writeSync, closeSync, fchmodSync, fstatSync, ftruncateSync, constants } from "node:fs";
import { join, dirname } from "node:path";
import { ensureSecretsDir, migrateLegacySecretFile } from "../shared/peer-credentials.js";
import { isRelayedSocket } from "../shared/bot-doors.js";
import { verifyTurnToken } from "./mail/drafts/turn-token.js";
import {
  readSetting, writeSetting, deleteLocalSetting,
} from "./dashboard/settings/registry.js";
import {
  mintSettingsToken, settingsTokenRawFile, verifySettingsToken, readStoredSettingsToken,
} from "./token-settings.js";
import { readHardenedTokenFile } from "./token-file-read.js";

const HASH_KEY = "mcp_local_token_hash";
const CREATED_KEY = "mcp_local_token_created";

// Board token (Track 1 Task 6, D-T1.1 §3): a SECOND per-instance static
// token, same hash-in-settings shape as the local token above, but scoped at
// the TRANSPORT level to /board/(mcp|sse|messages) — see BOARD_PATH_RE below
// and its use in localTokenAuthMiddleware. Handing bots this token instead of
// the full-surface local token bounds their reach to exactly the board-mcp
// mount (which itself registers ONLY board_* tools), without a second
// tool-level allowlist. The raw token is never shown in the dashboard (there
// is no bot-facing UI reveal flow yet) — it is minted at boot when absent and
// persisted to <crowHome>/board-token mode 0600, the exact peer-tokens.json
// precedent mcp_writer.mjs already reads beside it (see crow-server-catalog.mjs).
const BOARD_HASH_KEY = "mcp_board_token_hash";
const BOARD_CREATED_KEY = "mcp_board_token_created";
const BOARD_PATH_RE = /^\/board\/(?:mcp|sse|messages)$/;

// Phone token (Phone bundle plan A): same shape as the board token, PATH-SCOPED
// to /phone/(mcp|sse|messages). Lets bots propose calls; nothing on that
// mount can dial (dialing requires an owner-approved single-use token).
const PHONE_HASH_KEY = "mcp_phone_token_hash";
const PHONE_CREATED_KEY = "mcp_phone_token_created";
const PHONE_PATH_RE = /^\/phone\/(?:mcp|sse|messages)$/;
function phoneTokenPath() {
  return settingsTokenRawFile(PHONE_HASH_KEY, crowHome());
}

// Artifacts token (Crow Artifacts, spec §7.1): same shape, PATH-SCOPED to
// /artifacts/(mcp|sse|messages). A caller with only this token and no valid
// signed actor is UNATTRIBUTED there and sees nothing (fail closed).
const ARTIFACTS_HASH_KEY = "mcp_artifacts_token_hash";
const ARTIFACTS_CREATED_KEY = "mcp_artifacts_token_created";
const ARTIFACTS_PATH_RE = /^\/artifacts\/(?:mcp|sse|messages)$/;
function artifactsTokenPath() {
  return settingsTokenRawFile(ARTIFACTS_HASH_KEY, crowHome());
}

// Not importing resolveCrowHome from ./proxy.js — proxy.js pulls in the
// McpServer/Client/StdioClientTransport machinery. The shared resolver is
// dependency-free.
function crowHome() {
  return resolveCrowHome();
}

function boardTokenPath() {
  return settingsTokenRawFile(BOARD_HASH_KEY, crowHome());
}

/** Generate a new token, overwriting any existing one (this is also "rotate").
 *  Stores only the keyed verifier; returns the raw token for one-time display. */
export async function generateLocalToken(db) {
  const token = randomBytes(32).toString("hex");
  await writeSetting(db, HASH_KEY, await mintSettingsToken(db, HASH_KEY, token), { scope: "local" });
  await writeSetting(db, CREATED_KEY, new Date().toISOString(), { scope: "local" });
  return token;
}

export async function revokeLocalToken(db) {
  await deleteLocalSetting(db, HASH_KEY);
  await deleteLocalSetting(db, CREATED_KEY);
}

/** Non-sensitive status for the UI. Never returns the raw token or the hash. */
export async function getLocalTokenMeta(db) {
  const hash = await readStoredSettingsToken(db, HASH_KEY);
  if (!hash) return { present: false, createdAt: null };
  const createdAt = await readSetting(db, CREATED_KEY);
  return { present: true, createdAt: createdAt || null };
}

export async function validateLocalToken(db, token) {
  return verifySettingsToken(db, HASH_KEY, token);
}

/** Synthesized req.auth for a validated local-operator token request. Full
 *  tool access, identical surface to an OAuth client (scopes ["mcp:tools"]).
 *  The 300s expiry is NOT a session lifetime: skipAuthForInstance re-runs and
 *  re-synthesizes per request, exactly like the peer branch (mcp.js:247).
 *  Nothing downstream re-checks expiresAt. */
export function localOperatorAuth(tokenScope, claims = null) {
  const auth = {
    token: "local-mcp",
    clientId: "local-mcp",
    scopes: ["mcp:tools"],
    expiresAt: Math.floor(Date.now() / 1000) + 300,
  };
  // S2: which static token authenticated ("phone" for the path-scoped phone
  // token). Lets /phone/mcp tell a bot's shared token from the operator's full
  // local token; the full token carries no scope, exactly as before.
  // `claims` carries what a scoped token proved (Crow Mail's mail-draft mount
  // passes the draft, the turn and the head hash the turn started from), so a
  // tool handler reads them off `authInfo.extra` and never from its arguments.
  // `tokenScope` is written LAST: it is the caller's own scope, never something a
  // claims object may restate (a claims object carrying `tokenScope` cannot widen
  // or change the scope this auth stands for).
  if (tokenScope) auth.extra = { ...(claims && typeof claims === "object" ? claims : {}), tokenScope };
  return auth;
}

/** Turn a validated local-token flag into a full-access req.auth. Returns true
 *  when it handled the request (caller should next()), false to fall through to
 *  OAuth. Deliberately takes ONLY req: it has no peerGate dependency, so a local
 *  token is never run through the peer exposure gate. Called by
 *  skipAuthForInstance in routes/mcp.js, after the instance branch. */
export function applyLocalTokenAuth(req) {
  if (!req.localTokenAuth) return false;
  // A mount guard that ran earlier on this request may already have built the full auth for this
  // scope (Crow Mail's mail-draft guard pins the draft, the turn and the head hash the turn started
  // from on `req.auth`). Rebuilding it here would drop those claims, so a same-scope auth is kept.
  // A scoped auth only: the full local token carries no scope, and an absent scope must never match
  // an absent tokenScope (that would leave `req.auth` unset for the operator's own token).
  if (req.localTokenAuth.scope && req.auth?.extra?.tokenScope === req.localTokenAuth.scope) return true;
  const { scope, draftId, turnId } = req.localTokenAuth;
  req.auth = localOperatorAuth(scope, scope === "mail-draft" ? { draftId, turnId } : null);
  return true;
}

/** Write a token file IN PLACE on its existing inode (truncate, write), so a
 *  running bot sandbox's mask over it (a bind mount on that inode) stays
 *  attached: a rename over a mount point would detach it and the bot would read
 *  the new token mid-turn. The exception is a path that is not a plain file of
 *  ours with one name (a symlink, a directory, a FIFO, a hard link, another
 *  owner's file): it is unlinked and created fresh (O_EXCL, 0600), so another
 *  name for the old inode never sees the new token and a symlink is never
 *  followed. Such a file cannot have been masked at spawn anyway.
 *  The in-place path opens with O_NOFOLLOW and O_NONBLOCK and WITHOUT O_TRUNC
 *  or O_CREAT, then proves from the fd itself that it holds the very inode lstat
 *  saw (same dev+ino), a regular file, one name, our uid — and only then
 *  truncates and writes. A path swapped between the lstat and the open
 *  (a symlink, a FIFO, another file) therefore costs a replaced path, never a
 *  write through it. */
export function writeTokenFile(path, token) {
  const ours = typeof process.getuid === "function" ? process.getuid() : null;
  // Two passes at most: a racer that recreates the path between our unlink and
  // the O_EXCL create just makes the second pass look at the new entry.
  for (let pass = 0; ; pass++) {
    const st = lstatOrNull(path);
    if (st) {
      if (st.isDirectory()) throw new Error("token path is a directory: " + path);
      if (isPlainFileOfOurs(st, ours)) {
        const fd = openSameInode(path, st, ours);
        if (fd !== null) {
          try { ftruncateSync(fd, 0); writeSync(fd, token); fchmodSync(fd, 0o600); } finally { closeSync(fd); }
          return;
        }
      }
      // A symlink, a FIFO, a second name for the inode, another owner's file:
      // replaced, never written through.
      try { unlinkSync(path); } catch { /* already gone: the create below decides */ }
    }
    let fd;
    try {
      fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    } catch (err) {
      if (err && err.code === "EEXIST" && pass < 2) continue;
      throw err;
    }
    try { writeSync(fd, token); fchmodSync(fd, 0o600); } finally { closeSync(fd); }
    return;
  }
}

/** lstat, or null when the path is absent. Any other failure is thrown: nothing
 *  was written, and a path we could not even look at is not ours to replace. */
function lstatOrNull(path) {
  try { return lstatSync(path); } catch (err) { if (err && err.code === "ENOENT") return null; throw err; }
}

/** One name, a regular file, our uid (when the platform has one). */
function isPlainFileOfOurs(st, ours) {
  return st.isFile() && st.nlink === 1 && (ours === null || st.uid === ours);
}

/** An fd on `path` only when it still holds the inode `st` describes and is
 *  still a plain file of ours; null when the caller must replace the path.
 *  O_NOFOLLOW: a symlink at the path fails instead of being followed.
 *  O_NONBLOCK: a FIFO with no reader fails with ENXIO instead of hanging.
 *  No O_TRUNC and no O_CREAT: nothing is written or created until the inode is
 *  confirmed. A resource failure (EMFILE/ENFILE) is not about the path and is
 *  thrown rather than costing a file we could have rewritten. */
function openSameInode(path, st, ours) {
  let fd;
  try {
    fd = openSync(path, constants.O_WRONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch (err) {
    if (err && (err.code === "EMFILE" || err.code === "ENFILE")) throw err;
    return null;                                                    // ELOOP, ENXIO, EACCES, ENOENT, …
  }
  let fst = null;
  try { fst = fstatSync(fd); } catch { /* treated as a mismatch below */ }
  if (fst && fst.dev === st.dev && fst.ino === st.ino && isPlainFileOfOurs(fst, ours)) return fd;
  closeSync(fd);
  return null;
}

/** Generate a new board token, overwriting any existing one. Stores only the
 *  hash (local-scope setting) plus persists the raw value to
 *  <crowHome>/board-token mode 0600 (bot configs read the raw file directly,
 *  db-agnostic mcp_writer.mjs never touches the settings registry). Returns
 *  the raw token. */
export async function generateBoardToken(db) {
  const token = randomBytes(32).toString("hex");
  await writeSetting(db, BOARD_HASH_KEY, await mintSettingsToken(db, BOARD_HASH_KEY, token), { scope: "local" });
  await writeSetting(db, BOARD_CREATED_KEY, new Date().toISOString(), { scope: "local" });
  const path = boardTokenPath();
  mkdirSync(dirname(path), { recursive: true });
  writeTokenFile(path, token);
  return token;
}

export async function validateBoardToken(db, token) {
  return verifySettingsToken(db, BOARD_HASH_KEY, token);
}

/** Non-sensitive status. Never returns the raw token or the hash. */
export async function getBoardTokenMeta(db) {
  const hash = await readStoredSettingsToken(db, BOARD_HASH_KEY);
  if (!hash) return { present: false, createdAt: null };
  const createdAt = await readSetting(db, BOARD_CREATED_KEY);
  return { present: true, createdAt: createdAt || null };
}

/**
 * Does the raw token file at `path` still hold the token `family`'s stored verifier stands for?
 * Verified through `verifySettingsToken` (never a hash compare of its own), so a legacy file on an
 * unconverted family and an `h1.` file under the current key both match — and `false` only ever
 * means the two really disagree (or there is no file, or it cannot be read).
 *
 * The file is read through the same hardened helper the boot converter uses
 * (`servers/gateway/token-file-read.js`: `O_RDONLY | O_NOFOLLOW | O_NONBLOCK`, regular file only,
 * capped at 4 KiB, read from the fd that was judged). A plain `readFileSync` here followed a
 * symlink, blocked forever on a FIFO planted at a token path, and slurped a file of any size. A
 * refusal now answers `false` — a DEFINITE mismatch, so the family is re-minted (and
 * `writeTokenFile` unlinks and recreates the path with `O_EXCL | O_NOFOLLOW`, so the planted
 * entry is replaced, never written through).
 *
 * `null` is a third answer, "could not tell": the VERIFIER threw rather than answering (a
 * transient SQLITE_BUSY from a write lock another process holds at boot, a settings store that
 * will not open). That is not a mismatch, and a caller must never re-mint on it — a rotation is
 * irreversible for every consumer of the file.
 *
 * @returns {Promise<true|false|null>}
 */
async function fileTokenVerifies(db, family, path) {
  const read = readHardenedTokenFile(path);
  if (!read.ok || !read.token) return false;
  try { return await verifySettingsToken(db, family, read.token); } catch { return null; }
}

/**
 * The ensure shared by every FILE-BACKED family (spec §3.4): the stored verifier and the raw token
 * file must AGREE, not merely both exist.
 *
 *  - no stored verifier → mint (a fresh instance, or a family the operator reset cleared);
 *  - a stored verifier and a file whose token verifies against it → no-op (the common case on
 *    every boot after the first);
 *  - a stored verifier and a file that does NOT verify against it — junk, a legacy value, another
 *    family's token, a value minted under a key this box no longer holds, a file somebody else
 *    wrote, or an entry that is not a readable regular file at all (a symlink, a FIFO, a file
 *    past the token-size cap) — → RE-MINT: a new token, a new file and a new keyed stored value,
 *    so the family's door works again off the file its consumers read, and the value a writer
 *    planted is gone.
 *  - a stored verifier and a verifier that could not ANSWER (a transient SQLITE_BUSY while another
 *    process held the store at boot, an unopenable settings store) → LEAVE IT ALONE
 *    (`{minted:false}`): "we could not tell" is never "they disagree", and a re-mint here would
 *    rotate the family's token over a lock that clears in milliseconds. One fixed line says so
 *    (never the value, never a hash), so the next boot can check again.
 *
 * One fixed line reports a replaced file (never the value, never a hash). `mint` throws whatever
 * its key/mint path throws — a lost key cannot mint, and the caller's own failure handling says
 * so; it must never be reported as "nothing to do".
 *
 * @returns {Promise<{minted: boolean}>}
 */
async function ensureFileBackedToken(db, { family, path, mint }) {
  const stored = await readStoredSettingsToken(db, family);
  if (stored) {
    const verdict = await fileTokenVerifies(db, family, path);
    if (verdict === true) return { minted: false };
    if (verdict === null) {
      console.warn(`[gateway] left ${path} alone: its token could not be checked against this instance's stored verifier`);
      return { minted: false };
    }
  }
  await mint();
  if (stored) console.warn(`[gateway] re-minted ${path}: the file did not match this instance's stored verifier`);
  return { minted: true };
}

/** Idempotent boot mint (called from boot/mcp-mounts.js): the hash setting and the raw file must
 *  AGREE (see `ensureFileBackedToken`). Hash present but the file is missing (deleted disk, fresh
 *  restore) → re-mint both, since the raw file is the ONLY place a bot config could have read the
 *  token from. Hash present but the file holds something that does not verify against it →
 *  re-mint both, so the stored verifier and the file its consumers read never disagree. No hash
 *  at all → mint fresh. Returns {minted:boolean}. */
export async function ensureBoardToken(db) {
  return ensureFileBackedToken(db, {
    family: BOARD_HASH_KEY, path: boardTokenPath(), mint: () => generateBoardToken(db),
  });
}

export async function generatePhoneToken(db) {
  const token = randomBytes(32).toString("hex");
  await writeSetting(db, PHONE_HASH_KEY, await mintSettingsToken(db, PHONE_HASH_KEY, token), { scope: "local" });
  await writeSetting(db, PHONE_CREATED_KEY, new Date().toISOString(), { scope: "local" });
  const path = phoneTokenPath();
  mkdirSync(dirname(path), { recursive: true });
  writeTokenFile(path, token);
  return token;
}

export async function validatePhoneToken(db, token) {
  return verifySettingsToken(db, PHONE_HASH_KEY, token);
}

export async function ensurePhoneToken(db) {
  return ensureFileBackedToken(db, {
    family: PHONE_HASH_KEY, path: phoneTokenPath(), mint: () => generatePhoneToken(db),
  });
}

export const PHONE_TOKEN_KEYS = { PHONE_HASH_KEY, PHONE_CREATED_KEY };

export async function generateArtifactsToken(db) {
  const token = randomBytes(32).toString("hex");
  await writeSetting(db, ARTIFACTS_HASH_KEY, await mintSettingsToken(db, ARTIFACTS_HASH_KEY, token), { scope: "local" });
  await writeSetting(db, ARTIFACTS_CREATED_KEY, new Date().toISOString(), { scope: "local" });
  const path = artifactsTokenPath();
  mkdirSync(dirname(path), { recursive: true });
  writeTokenFile(path, token);
  return token;
}

export async function validateArtifactsToken(db, token) {
  return verifySettingsToken(db, ARTIFACTS_HASH_KEY, token);
}

export async function ensureArtifactsToken(db) {
  return ensureFileBackedToken(db, {
    family: ARTIFACTS_HASH_KEY, path: artifactsTokenPath(), mint: () => generateArtifactsToken(db),
  });
}

// Peer-relay token (item 46 PR-B): same shape as the artifacts token (hash in
// a local-scope setting, raw value in <crowHome>/secrets/peer-relay-token 600,
// in the 700 dir the pi sandbox hides from bots; older versions kept it at
// <crowHome>/peer-relay-token and it is moved at boot). The bot engine reads
// it outside the sandbox and hands its VALUE to the remote proxy in the
// proxy's block env, never a path a bot shell could open. A pi
// bot's remote proxy presents it, with its signed actor headers, to the
// loopback relay at /peer-relay/... (routes/peer-relay.js), which validates it
// itself. It is accepted NOWHERE else: localTokenAuthMiddleware never consults
// it, so it authenticates no MCP mount.
const PEER_RELAY_HASH_KEY = "mcp_peer_relay_token_hash";
const PEER_RELAY_CREATED_KEY = "mcp_peer_relay_token_created";
export function peerRelayTokenPath() {
  return settingsTokenRawFile(PEER_RELAY_HASH_KEY, crowHome());
}
function legacyPeerRelayTokenPath() {
  return join(crowHome(), "peer-relay-token");
}

export async function generatePeerRelayToken(db) {
  const token = randomBytes(32).toString("hex");
  await writeSetting(db, PEER_RELAY_HASH_KEY, await mintSettingsToken(db, PEER_RELAY_HASH_KEY, token), { scope: "local" });
  await writeSetting(db, PEER_RELAY_CREATED_KEY, new Date().toISOString(), { scope: "local" });
  const path = peerRelayTokenPath();
  ensureSecretsDir(dirname(path));
  writeTokenFile(path, token);
  return token;
}

export async function validatePeerRelayToken(db, token) {
  if (!token || typeof token !== "string") return false;
  return verifySettingsToken(db, PEER_RELAY_HASH_KEY, token);
}

export async function ensurePeerRelayToken(db) {
  const hash = await readStoredSettingsToken(db, PEER_RELAY_HASH_KEY);
  // An older version's token at <crowHome>/peer-relay-token moves into
  // secrets/ only when it is the minted one (it verifies against this family's stored verifier,
  // keyed or legacy, while the family is unconverted): a bot shell can write the old path, so
  // anything else there is discarded.
  const legacy = legacyPeerRelayTokenPath();
  try {
    if (existsSync(legacy)) {
      // Hardened read too: this path is even easier to plant (it sits in CROW_HOME itself), and a
      // FIFO here would block this pre-listen boot just as surely.
      const read = readHardenedTokenFile(legacy);
      const tok = read.ok ? read.token : "";
      if (hash && tok && await verifySettingsToken(db, PEER_RELAY_HASH_KEY, tok)) migrateLegacySecretFile(legacy, peerRelayTokenPath());
      else { unlinkSync(legacy); console.warn(`[gateway] discarded ${legacy}: not this instance's minted relay token`); }
    }
  } catch (err) {
    console.warn(`[gateway] could not move the peer-relay token into secrets/: ${err.message}`);
  }
  // The stored verifier and the file must AGREE, not merely both exist (see
  // `ensureFileBackedToken`): a file left by another key, or one that holds something else
  // entirely, is re-minted rather than trusted.
  return ensureFileBackedToken(db, {
    family: PEER_RELAY_HASH_KEY, path: peerRelayTokenPath(), mint: () => generatePeerRelayToken(db),
  });
}

// Kiosk announce token (kiosk spec §4.1): lets the kiosk bundle's stdio MCP
// server reach the gateway's live display sessions through loopback-only
// /api/kiosk/internal/*. Same shape as the board/phone tokens (hash in a
// local-scope setting, raw value in <crowHome>/kiosk-announce-token 0600) but
// accepted NOWHERE else — validateLocalToken never consults it.
const KIOSK_ANNOUNCE_HASH_KEY = "kiosk_announce_token_hash";
const KIOSK_ANNOUNCE_CREATED_KEY = "kiosk_announce_token_created";
function kioskAnnounceTokenPath() {
  return settingsTokenRawFile(KIOSK_ANNOUNCE_HASH_KEY, crowHome());
}

export async function generateKioskAnnounceToken(db) {
  const token = randomBytes(32).toString("hex");
  await writeSetting(db, KIOSK_ANNOUNCE_HASH_KEY, await mintSettingsToken(db, KIOSK_ANNOUNCE_HASH_KEY, token), { scope: "local" });
  await writeSetting(db, KIOSK_ANNOUNCE_CREATED_KEY, new Date().toISOString(), { scope: "local" });
  const path = kioskAnnounceTokenPath();
  mkdirSync(dirname(path), { recursive: true });
  writeTokenFile(path, token);
  return token;
}

export async function validateKioskAnnounceToken(db, token) {
  return verifySettingsToken(db, KIOSK_ANNOUNCE_HASH_KEY, token);
}

export async function ensureKioskAnnounceToken(db) {
  return ensureFileBackedToken(db, {
    family: KIOSK_ANNOUNCE_HASH_KEY, path: kioskAnnounceTokenPath(), mint: () => generateKioskAnnounceToken(db),
  });
}

export const KIOSK_ANNOUNCE_TOKEN_KEYS = { HASH: KIOSK_ANNOUNCE_HASH_KEY, CREATED: KIOSK_ANNOUNCE_CREATED_KEY };

// Models token (models arc plan 2, Task 6): path-scoped to the lifecycle API
// under /llm/models. pi-lab reads it from <crowHome>/models-token. It cannot
// reach any MCP mount: the MCP middleware never consults it.
const MODELS_HASH_KEY = "mcp_models_token_hash";
const MODELS_CREATED_KEY = "mcp_models_token_created";
export function modelsTokenPath() {
  return settingsTokenRawFile(MODELS_HASH_KEY, crowHome());
}

export async function generateModelsToken(db) {
  const token = randomBytes(32).toString("hex");
  await writeSetting(db, MODELS_HASH_KEY, await mintSettingsToken(db, MODELS_HASH_KEY, token), { scope: "local" });
  await writeSetting(db, MODELS_CREATED_KEY, new Date().toISOString(), { scope: "local" });
  const path = modelsTokenPath();
  mkdirSync(dirname(path), { recursive: true });
  writeTokenFile(path, token);
  return token;
}

export async function validateModelsToken(db, token) {
  return verifySettingsToken(db, MODELS_HASH_KEY, token);
}

export async function ensureModelsToken(db) {
  return ensureFileBackedToken(db, {
    family: MODELS_HASH_KEY, path: modelsTokenPath(), mint: () => generateModelsToken(db),
  });
}

export const MODELS_TOKEN_KEYS = { MODELS_HASH_KEY, MODELS_CREATED_KEY };

// Cloud-door token (roles phase 2, Task 14): lets bots reach cloud models
// through the gateway's /llm/c door without ever holding a provider key. pi
// reads it per request from a models.json `!<command>` apiKey (pi runs that
// command uncached on every auth resolve), so a token rotated at boot reaches
// a pi process that is already running.
//
// The file deliberately lives at <crowHome>/llm-cloud-token, OUTSIDE
// <crowHome>/secrets/: the bot sandbox (bwrap) hides secrets/ from pi, so a
// token there would be unreadable to the bots it exists for. Peer tokens are
// moving INTO secrets/; this one is different on purpose: it is meant for
// bots, and it is scoped to the cloud door only. validateLlmCloudToken checks
// this one hash and nothing else, so no other token (local, board, phone,
// artifacts, kiosk, models) opens the door, and this token opens nothing but
// the door (no other validator consults its hash).
//
// Rotated on EVERY boot (no ensure/no-op path): a fresh random value per start.
const LLM_CLOUD_HASH_KEY = "mcp_llm_cloud_token_hash";
const LLM_CLOUD_CREATED_KEY = "mcp_llm_cloud_token_created";
export function llmCloudTokenPath() {
  return join(crowHome(), "llm-cloud-token");
}

/** New random 32-byte hex token every call. Order keeps the file and the
 *  stored hash matching whenever a step fails:
 *    1. write the raw value to a temp file in the same directory (wx, 0600),
 *       then chmod 0600: a failure here changes nothing;
 *    2. store the new hash (local scope): a failure here removes the temp
 *       file, and the old file and old hash still match;
 *    3. rename the temp file over the old one: a failure here puts the old
 *       hash back, so the old file keeps validating.
 *  A reader sees the old token or the new one, never a partial or
 *  world-readable file. Returns the raw token. */
export async function rotateLlmCloudToken(db) {
  return rotateTokenFile(db, {
    path: llmCloudTokenPath(), hashKey: LLM_CLOUD_HASH_KEY, createdKey: LLM_CLOUD_CREATED_KEY, label: "llm-cloud-token",
    ensureDir: (d) => mkdirSync(d, { recursive: true }), onFailure: "restore",
  });
}

/**
 * The one rotation both per-boot token shapes use (the cloud-door token and
 * every pathScopedToken). Steps 1-3 as rotateLlmCloudToken describes. What a
 * failure leaves behind is the caller's choice:
 *  - "restore" (the cloud door): the old file and the old hash keep matching,
 *    so the old token keeps validating;
 *  - "fail-closed" (the loopback tool families, "rotated every boot"): ANY
 *    failure deletes the stored hash, so no token validates (not even the
 *    previous boot's) until a rotation succeeds.
 * Throws the step's error either way.
 */
async function rotateTokenFile(db, { path, hashKey, createdKey, label, ensureDir, onFailure }) {
  const token = randomBytes(32).toString("hex");
  // The keyed verifier is computed BEFORE anything is written, so a lost or invalid key changes
  // nothing at all (no temp file, no stored value) and the caller's failure path stays as it was.
  const stored = await mintSettingsToken(db, hashKey, token);
  const failClosed = async (err) => {
    try { await deleteLocalSetting(db, hashKey); } catch (e) {
      console.warn(`[${label}] could not delete the stored hash after a failed rotation: ${e.message}`);
    }
    throw err;
  };
  const bail = async (err) => { if (onFailure === "fail-closed") return failClosed(err); throw err; };
  try { ensureDir(dirname(path)); } catch (err) { return bail(err); }
  const tmp = `${path}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
  const dropTmp = () => { try { unlinkSync(tmp); } catch { /* already gone */ } };
  try {
    writeFileSync(tmp, token, { mode: 0o600, flag: "wx" });
    chmodSync(tmp, 0o600);
  } catch (err) {
    dropTmp();
    return bail(err);
  }
  let oldHash;
  try {
    oldHash = await readStoredSettingsToken(db, hashKey);
    await writeSetting(db, hashKey, stored, { scope: "local" });
  } catch (err) {
    dropTmp();
    return bail(err);
  }
  try {
    renameSync(tmp, path);
  } catch (err) {
    dropTmp();
    if (onFailure === "fail-closed") return failClosed(err);
    try {
      // The old stored value goes back EXACTLY as it was read: an `h1.` value on a converted
      // family, so the previous boot's token keeps validating (§3.2).
      if (oldHash) await writeSetting(db, hashKey, oldHash, { scope: "local" });
      else await deleteLocalSetting(db, hashKey);
    } catch (restoreErr) {
      // Best effort: the next boot rotates again. Until then the stored hash
      // matches no file, so nothing validates.
      console.warn(`[${label}] could not put the old hash back after a failed rename: ${restoreErr.message}`);
    }
    throw err;
  }
  try {
    await writeSetting(db, createdKey, new Date().toISOString(), { scope: "local" });
  } catch { /* informational only */ }
  return token;
}

/** Timing-safe check against the cloud-door family ONLY (a keyed `verifyStored` compare). */
export async function validateLlmCloudToken(db, token) {
  if (!token || typeof token !== "string") return false;
  return verifySettingsToken(db, LLM_CLOUD_HASH_KEY, token);
}

export const LLM_CLOUD_TOKEN_KEYS = { HASH: LLM_CLOUD_HASH_KEY, CREATED: LLM_CLOUD_CREATED_KEY };

// Path-scoped token factory (loopback mount helper, spec §2.1): ONE shape for
// every loopback-mounted family (services, satellite tools, ...). The raw token
// lives at <crowHome>/secrets/<name>-token (0600), only its sha256 in a
// local-scope setting under the family's OWN hash key, so validate() accepts
// that family's token and nothing else: no local/board/phone/... token opens a
// family mount, and a family token opens no other validator (none of them
// consult these keys). `home` (string or () => string) overrides the crow home
// for tests. Rotated on EVERY boot (see boot/mcp-mounts.js), never "ensure".
export function pathScopedToken({ name, hashKey, createdKey, home }) {
  const root = () => (typeof home === "function" ? home() : home) || crowHome();
  const path = () => join(root(), "secrets", `${name}-token`);
  return {
    name,
    path,
    /** rotateTokenFile's ordering (a reader sees the old token or the new
     *  one, never a partial or world-readable file), failing CLOSED: any
     *  failure deletes this family's stored hash, so the previous boot's
     *  token stops validating and the family refuses every request until a
     *  rotation succeeds (the next boot). secrets/ is made (and tightened)
     *  0700 by the shared ensureSecretsDir. */
    async rotate(db) {
      return rotateTokenFile(db, { path: path(), hashKey, createdKey, label: `${name}-token`, ensureDir: ensureSecretsDir, onFailure: "fail-closed" });
    },    /** Timing-safe check against this family's stored verifier ONLY. */
    async validate(db, token) {
      try {
        if (!token || typeof token !== "string") return false;
        return await verifySettingsToken(db, hashKey, token);
      } catch { return false; }
    },
  };
}

// Key names follow this file's existing `mcp_<x>_token_hash` / `_created` shape.
export const SERVICES_TOKEN = pathScopedToken({ name: "services", hashKey: "mcp_services_token_hash", createdKey: "mcp_services_token_created" });
export const SATELLITE_TOOLS_TOKEN = pathScopedToken({ name: "satellite-tools", hashKey: "mcp_satellite_tools_token_hash", createdKey: "mcp_satellite_tools_token_created" });
// Credential card (spec §10.2): the bots' token for /secrets/(mcp|sse|messages) only, rotated at
// boot like the families above (a bot's config is rebuilt every turn). On that mount it proves
// nothing on its own: crow_request_secret also needs a signed Perch actor (secrets/mcp.js).
export const SECRETS_TOKEN = pathScopedToken({ name: "secrets", hashKey: "mcp_secrets_token_hash", createdKey: "mcp_secrets_token_created" });
const SECRETS_PATH_RE = /^\/secrets\/(?:mcp|sse|messages)$/;

// Bot sharing door (bot door + saved drafts, PR B part 1): the bots' token for the narrow
// /sharing-bot/(mcp|sse|messages) mount ONLY (servers/gateway/sharing-bot-mcp.js). Same family shape
// as the secrets token: <crowHome>/secrets/sharing-bot-token, 0600 in the 0700 dir the pi sandbox
// masks, rotated at every boot (a bot's config is rebuilt every turn). It opens nothing else, and on
// that mount it proves only "a bot's config", never who: the mount guard also requires a signed
// `sharing` actor, so a token alone (a leaked config, a replayed header) drafts nothing. The raw
// value is read by the bot catalog (scripts/pi-bots/crow-server-catalog.mjs) when it mints the door
// block, exactly as the board token is.
export const SHARING_BOT_TOKEN = pathScopedToken({ name: "sharing-bot", hashKey: "mcp_sharing_bot_token_hash", createdKey: "mcp_sharing_bot_token_created" });
const SHARING_BOT_PATH_RE = /^\/sharing-bot\/(?:mcp|sse|messages)$/;

// Reports door: the bots' token for the narrow /reports/(mcp|sse|messages) mount ONLY
// (servers/gateway/reports/mcp.js). Same family shape as the secrets and sharing-bot tokens:
// <crowHome>/secrets/reports-token, 0600 in the 0700 dir the pi sandbox masks, rotated at every
// boot (a bot's config is rebuilt every turn). It opens nothing else, and on that mount it proves
// only "a bot's config", never who: the mount's guard also requires a signed `reports` actor, so a
// token alone proposes nothing. The raw value is read by the bot catalog
// (scripts/pi-bots/crow-server-catalog.mjs) when it mints the door block, exactly as the board
// token is.
export const REPORTS_TOKEN = pathScopedToken({ name: "reports", hashKey: "mcp_reports_token_hash", createdKey: "mcp_reports_token_created" });
const REPORTS_PATH_RE = /^\/reports\/(?:mcp|sse|messages)$/;

/** The reports door's boot-mint entry point: the same rotation the family list runs, under the
 *  name the mount's callers use. A fresh value every call, so `minted` is always true. */
export async function ensureReportsToken(db) {
  await REPORTS_TOKEN.rotate(db);
  return { minted: true };
}

// MCP transport paths are `/mcp`, `/sse`, `/messages`, optionally under ONE
// server-prefix segment (e.g. /router/mcp, /memory/sse, /tools-x/messages,
// /blog-mcp/mcp; see mcp.js:194-196 and the single-segment mountMcpServer
// prefixes in index.js). req.localTokenAuth is only consumed on these, so the
// middleware reads the DB only for them. Anchoring to this exact shape avoids
// matching unrelated routes that merely end in /messages (e.g.
// /dashboard/streams/messages, /api/chat/.../messages).
const MCP_PATH_RE = /^(?:\/[a-z0-9-]+)?\/(?:mcp|sse|messages)$/;
function isMcpPath(p) {
  return typeof p === "string" && MCP_PATH_RE.test(p);
}

// Crow Mail (plan 3, Task 8a): the drafting turn's mount. Its ONLY credential is the per-turn `mdt_`
// token a turn mints in this process's memory (mail/drafts/turn-token.js) — see the early branch in
// localTokenAuthMiddleware. The full local token is deliberately not tried on this path (it is tried
// first on every MCP path, so it has to be skipped by name), no other family's token authenticates
// here, and an `mdt_` token authenticates nowhere else. A relayed socket may present one: bots are
// relayed, and the token's per-draft, per-turn scope is what limits it.
const MAIL_DRAFT_PATH_RE = /^\/mail-draft\/(?:mcp|sse|messages)$/;

/** Express middleware. Mounted globally right after instanceAuthMiddleware, but
 *  it only reads the DB for MCP-path requests (cost guard). Sets
 *  req.localTokenAuth on a valid local token. Yields to instance auth, never
 *  hard-rejects (falls through to OAuth), and fast-exits with no Bearer header,
 *  no token configured, or a non-MCP path. */
export function localTokenAuthMiddleware(db) {
  return async (req, res, next) => {
    try {
      if (req.instanceAuth) return next();
      if (!isMcpPath(req.path)) return next();
      const h = req.headers?.authorization;
      if (!h || !h.startsWith("Bearer ")) return next();
      const token = h.slice(7);
      // Crow Mail's drafting turn (plan 3, Task 8a): this path accepts the `mdt_` turn token and
      // nothing else, so the full-local-token branch below is skipped here by name. The turn token
      // is verified against this process's in-memory map; a value it does not know sets nothing, and
      // the request falls through to OAuth (401) like any other unrecognized bearer.
      if (MAIL_DRAFT_PATH_RE.test(req.path)) {
        if (token.startsWith("mdt_")) {
          const turn = verifyTurnToken(token);
          if (turn) {
            req.localTokenAuth = {
              token: "local-mcp", scope: "mail-draft", draftId: turn.draftId, turnId: turn.turnId,
            };
          }
        }
        return next();
      }
      // A socket that came through the egress relay is never the operator. A
      // contained bot has crow.db bound read-write (Phase 1), so it can write
      // mcp_local_token_hash — and on /board/mcp, which is a door, that used to
      // be the operator's full local token. The setting is a keyed MAC now
      // (verifySettingsToken), so a value the bot can compute no longer
      // verifies; the rule stays anyway, because "a relayed caller is never the
      // owner" must not depend on which stored form a build happened to read.
      // Only the path-scoped board, phone and artifacts tokens may authenticate
      // a relayed request.
      const relayed = isRelayedSocket(req.socket);
      if (!relayed && await validateLocalToken(db, token)) {
        req.localTokenAuth = { token: "local-mcp" };
        return next();
      }
      // Board token (Track 1 Task 6): PATH-SCOPED — only tried, and only ever
      // authenticates, on the /board/(mcp|sse|messages) transport paths. A
      // board token presented against any other MCP mount (e.g. /memory/mcp)
      // falls through unauthenticated here and 401s downstream via OAuth,
      // same as any other unrecognized bearer token. Synthesizes the SAME
      // req.localTokenAuth flag as the full local token: the scoping this
      // token provides is entirely the path check above — /board/mcp itself
      // registers only board_* tools, so there is no separate tool-level
      // allowlist to apply.
      if (BOARD_PATH_RE.test(req.path) && await validateBoardToken(db, token)) {
        // S5: scope "board" lets board-mcp tell the bots' shared token from
        // the operator's full local token (a board-token caller is never the
        // owner 'session' actor). Same mechanism as the phone scope below.
        req.localTokenAuth = { token: "local-mcp", scope: "board" };
      }
      if (!req.localTokenAuth && PHONE_PATH_RE.test(req.path) && await validatePhoneToken(db, token)) {
        req.localTokenAuth = { token: "local-mcp", scope: "phone" };
      }
      if (!req.localTokenAuth && ARTIFACTS_PATH_RE.test(req.path) && await validateArtifactsToken(db, token)) {
        req.localTokenAuth = { token: "local-mcp", scope: "artifacts" };
      }
      if (!req.localTokenAuth && SECRETS_PATH_RE.test(req.path) && await SECRETS_TOKEN.validate(db, token)) {
        req.localTokenAuth = { token: "local-mcp", scope: "secrets" };
      }
      // The bot sharing door's token (PR B part 1): same path-scoped rule as the families above, so
      // it authenticates on /sharing-bot/(mcp|sse|messages) and nowhere else. The mount's own guard
      // (servers/gateway/sharing-bot-mcp.js) re-validates it AND requires a signed `sharing` actor, so
      // this branch is the transport-level half, not the decision.
      if (!req.localTokenAuth && SHARING_BOT_PATH_RE.test(req.path) && await SHARING_BOT_TOKEN.validate(db, token)) {
        req.localTokenAuth = { token: "local-mcp", scope: "sharing-bot" };
      }
      // The reports door's token: the same path-scoped rule once more, so it authenticates on
      // /reports/(mcp|sse|messages) and nowhere else. The mount's own guard
      // (servers/gateway/reports/mcp.js) re-validates it AND requires a signed `reports` actor, so
      // this branch is the transport-level half, not the decision.
      if (!req.localTokenAuth && REPORTS_PATH_RE.test(req.path) && await REPORTS_TOKEN.validate(db, token)) {
        req.localTokenAuth = { token: "local-mcp", scope: "reports" };
      }
    } catch (err) {
      // Treat a DB/read error as non-fatal: log and fall through to the other
      // auth methods (OAuth) rather than propagating a 500. A transient settings
      // read must never block a legitimate OAuth-authenticated MCP request.
      console.warn("[local-token] auth check error:", err.message);
    }
    return next();
  };
}

export const LOCAL_TOKEN_KEYS = { HASH_KEY, CREATED_KEY };
export const BOARD_TOKEN_KEYS = { HASH_KEY: BOARD_HASH_KEY, CREATED_KEY: BOARD_CREATED_KEY };
