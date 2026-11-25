/**
 * A report pickup's token: a per-turn credential a bot presents on `/report-pickup/mcp`, and nothing
 * else.
 *
 * The guarantee is scope, not secrecy. A copy of the token stands for exactly one pickup of one
 * report: the comments it is allowed to answer and the artifact they live on. It is never written to
 * disk and never survives a gateway restart, so nothing outlives the work it was minted for. That is
 * why the store is this module's own memory and why the map is keyed by the token's SHA-256: the raw
 * value is handed to the turn once and is not kept here to leak from a heap dump or a log.
 *
 * A token is bound to everything the mount and its tools need, all supplied by the turn that mints it:
 *   - `reportId` and `pickupId`, so a pickup's reply can only land on its own report (and the mount can
 *     tell one pickup from another);
 *   - `turnId`, the one turn this token was minted for. The mount's actor signature is computed over
 *     `<pickupId>:<turnId>` (scripts/pi-bots/actor-sig.mjs), so the turn id has to travel with the token
 *     the signature must match: a block signed for another turn of the same pickup admits nothing;
 *   - `botId`, the bot the turn runs as, so the mount can refuse a signature presented for any other bot
 *     of the same tuple;
 *   - `threadIds` and `commentIds`, the exact batch this pickup is about, so a reply is checked against
 *     the set the row names rather than a set a caller supplied;
 *   - `artifactId`, the version-carrying artifact whose threads those ids belong to.
 *
 * The row id and the token live in visibly different id spaces: a row is `rpu-…`
 * (servers/shared/reports-schema.js), a token is `rpk_` followed by 32 random bytes as hex. A value
 * with any other prefix is never verified here.
 *
 * Expiry is the turn's own timeout plus a margin, never a fixed number of minutes: a token must not die
 * while its turn can still legitimately run, and must not outlive it by more than the margin. The
 * turn's `finally` revokes it, which is the answer that actually arrives first in normal operation.
 *
 * Not a `pathScopedToken` family: those are hashes in `dashboard_settings`, rotated at boot. This one is
 * per turn, in memory only, and meaningless after a restart.
 *
 * This module also holds the pickup's REPLY LEDGER (`reserveReplySlot`/`releaseReplySlot`): one reply per
 * thread per pickup, in memory beside the token and dropped with the LAST live token of that pickup,
 * because one pickup turn reads the whole batch at once and must not answer the same thread twice.
 */
import { createHash, randomBytes } from "node:crypto";

/** The prefix that marks this credential. `rpk_` authenticates on `/report-pickup/*` and nowhere else. */
const PICKUP_TOKEN_PREFIX = "rpk_";
/** 32 random bytes, hex. */
const TOKEN_BYTES = 32;
/**
 * `bridge.mjs`'s own fallback for a turn's timeout, copied so a token minted here never expires before
 * the turn it belongs to can: `scripts/pi-bots/bridge.mjs` has
 * `const TURN_TIMEOUT_MS = Number(process.env.PIBOT_TURN_TIMEOUT_MS || 600000);`
 */
const DEFAULT_TURN_TIMEOUT_MS = 600_000;
/** The margin on top of the turn's timeout. */
export const PICKUP_TOKEN_MARGIN_MS = 60_000;

/**
 * Live tokens: `sha256(token)` hex → the claims it was minted for. Module memory, never a file.
 * @type {Map<string, {reportId: string, pickupId: string, turnId: string, botId: string,
 *   threadIds: string[], commentIds: string[], artifactId: string, expiresAt: number}>}
 */
const pickupTokens = new Map();

/**
 * The reply ledger: `pickupId` -> the thread ids that pickup has already answered. A pickup turn reads a
 * whole batch in ONE turn, so at most one reply may land in each of its threads: the door reserves a slot
 * here before it writes one, and gives it back if the write itself failed. Keyed on the PICKUP id and not
 * on the token, so two tokens of one pickup share the ledger — and an entry is dropped only once NO live
 * token names that pickup any more (dropStoredToken). A token minted beside another live one is a second
 * turn of the same pickup, and it must see the answers the first one already wrote; a re-minted token
 * after the last one was revoked or expired still starts clean.
 * @type {Map<string, Set<string>>}
 */
const pickupReplies = new Map();

/**
 * The card ledger: `pickupId` -> the thread keys (a thread id, or `-` for a card that names no thread) that
 * pickup has already made a card for. One card per thread per pickup, and at most `MAX_PICKUP_CARDS` cards
 * in all. Same life as `pickupReplies`: dropped with the LAST live token of the pickup.
 * @type {Map<string, Set<string>>}
 */
const pickupCards = new Map();

/** The pickups that have already suggested a change (at most one each). Same life as the ledgers above. */
const pickupProposals = new Set();

/** The most cards one pickup may make. */
export const MAX_PICKUP_CARDS = 3;

/** The ledger key of a card that names no thread. */
export const NO_THREAD_KEY = "-";

function sha256Hex(text) {
  return createHash("sha256").update(text).digest("hex");
}

function requireText(value, field) {
  if (typeof value !== "string" || value.trim() === "") {
    throw new TypeError(`mintPickupToken needs a ${field}`);
  }
  return value.trim();
}

/** A set of ids as the token stores it: trimmed strings, copied, so nothing shares an array with a
 *  caller (an array is optional; anything that is not an array is refused rather than guessed at). */
function requireIdList(value, field) {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) throw new TypeError(`mintPickupToken needs ${field} to be an array`);
  return value.map((id) => requireText(id, `${field} entry`));
}

/** Drop every entry whose expiry has passed, so a long-lived process does not accumulate them. A
 *  pickup's reply ledger goes with the LAST live token of that pickup (dropStoredToken), so a sweep
 *  leaves it alone while another live token still names the pickup. */
function sweep(now) {
  for (const [key, entry] of pickupTokens) {
    if (now >= entry.expiresAt) dropStoredToken(key, entry);
  }
}

/** Is a live (unexpired, still-stored) token naming this pickup? Called AFTER the token that is going
 *  away has been deleted, so it answers for the tokens that remain. */
function hasLiveTokenFor(pickupId) {
  const now = Date.now();
  for (const other of pickupTokens.values()) {
    if (other && other.pickupId === pickupId && now < other.expiresAt) return true;
  }
  return false;
}

/** Forget one token's claims, and — only when no OTHER live token names the same pickup — that pickup's
 *  reply ledger. Two tokens of one pickup are two turns of it: the one still running must keep seeing
 *  the answers the other already wrote, so the ledger outlives the token that goes first. */
function dropStoredToken(key, entry) {
  pickupTokens.delete(key);
  if (!entry || typeof entry.pickupId !== "string") return;
  if (hasLiveTokenFor(entry.pickupId)) return;
  pickupReplies.delete(entry.pickupId);
  pickupCards.delete(entry.pickupId);
  pickupProposals.delete(entry.pickupId);
}

/**
 * Take this pickup's one reply slot for `threadId`. TRUE the first time, FALSE after — and FALSE for a
 * malformed id rather than inventing a ledger entry. In memory only, like the token store.
 *
 * @param {string} pickupId
 * @param {string} threadId
 * @returns {boolean} whether the slot is now held
 */
export function reserveReplySlot(pickupId, threadId) {
  if (typeof pickupId !== "string" || pickupId === "") return false;
  if (typeof threadId !== "string" || threadId === "") return false;
  let slots = pickupReplies.get(pickupId);
  if (!slots) {
    slots = new Set();
    pickupReplies.set(pickupId, slots);
  }
  if (slots.has(threadId)) return false;
  slots.add(threadId);
  return true;
}

/**
 * How many threads this pickup has answered so far (the ledger's size). Read by the launcher BEFORE it
 * revokes the turn's token, because the ledger goes with the last live token of the pickup.
 *
 * @param {string} pickupId
 * @returns {number}
 */
export function pickupReplyCount(pickupId) {
  const slots = pickupReplies.get(pickupId);
  return slots ? slots.size : 0;
}

/**
 * Give a reserved slot back, for a write that FAILED (a written reply keeps its slot). TRUE when this call
 * gave one back, FALSE when there was nothing to release.
 *
 * @param {string} pickupId
 * @param {string} threadId
 * @returns {boolean}
 */
export function releaseReplySlot(pickupId, threadId) {
  const slots = pickupReplies.get(pickupId);
  if (!slots) return false;
  const released = slots.delete(threadId);
  if (slots.size === 0) pickupReplies.delete(pickupId);
  return released;
}

/**
 * Take one of this pickup's card slots for `threadKey` (a thread id, or `NO_THREAD_KEY`). TRUE when held;
 * FALSE when that thread already has a card from this pickup or the pickup is at `MAX_PICKUP_CARDS`.
 *
 * @param {string} pickupId
 * @param {string} threadKey
 * @returns {boolean}
 */
export function reserveCardSlot(pickupId, threadKey) {
  if (typeof pickupId !== "string" || pickupId === "") return false;
  if (typeof threadKey !== "string" || threadKey === "") return false;
  let slots = pickupCards.get(pickupId);
  if (!slots) {
    slots = new Set();
    pickupCards.set(pickupId, slots);
  }
  if (slots.has(threadKey) || slots.size >= MAX_PICKUP_CARDS) return false;
  slots.add(threadKey);
  return true;
}

/** Give a reserved card slot back, for a card that was NOT made. */
export function releaseCardSlot(pickupId, threadKey) {
  const slots = pickupCards.get(pickupId);
  if (!slots) return false;
  const released = slots.delete(threadKey);
  if (slots.size === 0) pickupCards.delete(pickupId);
  return released;
}

/** Take this pickup's one suggest-a-change slot. TRUE the first time, FALSE after. */
export function reserveProposalSlot(pickupId) {
  if (typeof pickupId !== "string" || pickupId === "") return false;
  if (pickupProposals.has(pickupId)) return false;
  pickupProposals.add(pickupId);
  return true;
}

/** Give the suggest-a-change slot back, for a change that was NOT saved. */
export function releaseProposalSlot(pickupId) {
  return pickupProposals.delete(pickupId);
}

/**
 * What a pickup has done so far, read by the launcher BEFORE it revokes the turn's token (the ledgers go
 * with the last live token): `{replies, cards, proposals}` counts of what actually landed.
 *
 * @param {string} pickupId
 * @returns {{replies: number, cards: number, proposals: number}}
 */
export function pickupActivity(pickupId) {
  return {
    replies: pickupReplyCount(pickupId),
    cards: pickupCards.get(pickupId)?.size ?? 0,
    proposals: pickupProposals.has(pickupId) ? 1 : 0,
  };
}

/**
 * The outcome word for a pickup's activity: `answered` (replies only), `carded` (cards, no change),
 * `proposed` (a change was suggested, nothing else), `mixed` (two or more kinds), `no_action` (the turn
 * finished and acted on nothing), `failed` (none, and the turn did not finish).
 *
 * @param {{replies: number, cards: number, proposals: number}} activity
 * @returns {"answered"|"carded"|"proposed"|"mixed"|"no_action"|"failed"}
 */
export function pickupOutcomeOf(activity, { turnFinished = false } = {}) {
  const kinds = [
    ["answered", activity?.replies > 0],
    ["carded", activity?.cards > 0],
    ["proposed", activity?.proposals > 0],
  ].filter(([, on]) => on);
  // Nothing landed: a turn that ran to its end without error and chose to act on nothing is `no_action`
  // (its comments are not tried again); one that did not finish is `failed` (a retry).
  if (kinds.length === 0) return turnFinished ? "no_action" : "failed";
  return kinds.length === 1 ? kinds[0][0] : "mixed";
}

/**
 * How long a minted token lives: the pickup turn's `PIBOT_TURN_TIMEOUT_MS` (the same default `bridge.mjs`
 * uses) plus a 60 s margin. An unreadable value falls back to the default rather than minting a token
 * that expires at once.
 *
 * @param {NodeJS.ProcessEnv} [env]
 * @returns {number} milliseconds
 */
export function pickupTokenTtlMs(env = process.env) {
  const raw = Number(env?.PIBOT_TURN_TIMEOUT_MS || DEFAULT_TURN_TIMEOUT_MS);
  const turnTimeout = Number.isFinite(raw) && raw > 0 ? raw : DEFAULT_TURN_TIMEOUT_MS;
  return turnTimeout + PICKUP_TOKEN_MARGIN_MS;
}

/**
 * Mint one pickup's token. Returns the raw value (the only copy of it that exists) and stores nothing but
 * its hash.
 *
 * @param {{reportId: string, pickupId: string, turnId: string, botId: string, threadIds?: string[],
 *   commentIds?: string[], artifactId: string, ttlMs?: number}} fields `turnId` is the turn this token
 *   belongs to (the signature's other half), `threadIds`/`commentIds` are the batch this pickup may act
 *   on, `artifactId` the artifact that batch lives on, `ttlMs` the turn's own timeout plus the margin
 *   (defaulted here when a caller has none)
 * @returns {string} the bearer token, `rpk_` + 32 random bytes as hex
 */
export function mintPickupToken({
  reportId, pickupId, turnId, botId, threadIds, commentIds, artifactId, ttlMs,
} = {}) {
  const report = requireText(reportId, "reportId");
  const pickup = requireText(pickupId, "pickupId");
  const turn = requireText(turnId, "turnId");
  const bot = requireText(botId, "botId");
  const artifact = requireText(artifactId, "artifactId");
  const threads = requireIdList(threadIds, "threadIds");
  const comments = requireIdList(commentIds, "commentIds");
  const ttl = Number.isFinite(ttlMs) && ttlMs >= 0 ? Number(ttlMs) : pickupTokenTtlMs();
  const now = Date.now();
  sweep(now);
  const token = PICKUP_TOKEN_PREFIX + randomBytes(TOKEN_BYTES).toString("hex");
  pickupTokens.set(sha256Hex(token), {
    reportId: report,
    pickupId: pickup,
    turnId: turn,
    botId: bot,
    threadIds: threads,
    commentIds: comments,
    artifactId: artifact,
    expiresAt: now + ttl,
  });
  return token;
}

/**
 * Revoke one token — the turn's `finally`. Answers whether a live token was there to revoke; an
 * already-expired, already-revoked or never-minted token changes nothing.
 *
 * @param {string} token
 * @returns {boolean}
 */
export function revokePickupToken(token) {
  if (typeof token !== "string" || !token.startsWith(PICKUP_TOKEN_PREFIX)) return false;
  const key = sha256Hex(token);
  const entry = pickupTokens.get(key);
  if (!entry) return false;
  dropStoredToken(key, entry);
  return true;
}

/**
 * The claims a presented token stands for, or null when it is unknown, expired or revoked. The lookup is
 * by the hash of the exact string, so a token with one character changed is simply not in the map. Every
 * answer is a COPY (the two id lists included), so a caller can never mutate what the store holds or
 * widen what a later check reads.
 *
 * @param {string} token
 * @returns {{reportId: string, pickupId: string, turnId: string, botId: string, threadIds: string[],
 *   commentIds: string[], artifactId: string, expiresAt: number}|null}
 */
export function verifyPickupToken(token) {
  if (typeof token !== "string" || !token.startsWith(PICKUP_TOKEN_PREFIX)) return null;
  const key = sha256Hex(token);
  const entry = pickupTokens.get(key);
  if (!entry) return null;
  if (Date.now() >= entry.expiresAt) {
    dropStoredToken(key, entry);
    return null;
  }
  return {
    reportId: entry.reportId,
    pickupId: entry.pickupId,
    turnId: entry.turnId,
    botId: entry.botId,
    threadIds: [...entry.threadIds],
    commentIds: [...entry.commentIds],
    artifactId: entry.artifactId,
    expiresAt: entry.expiresAt,
  };
}

/** Test seam only: forget every minted token and every reply slot (module state is per process, like a
 *  restart). */
export function _resetPickupTokensForTests() {
  pickupTokens.clear();
  pickupReplies.clear();
  pickupCards.clear();
  pickupProposals.clear();
}