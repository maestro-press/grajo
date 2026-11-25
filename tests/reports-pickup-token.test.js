// Crow Recurring Reports: a pickup turn's token (servers/gateway/reports/pickup-token.js), and the
// `/report-pickup` branch of localTokenAuthMiddleware that is its only consumer.
//
// A pickup's token is minted in the gateway process's memory, bound to one report, one pickup, the bot
// the turn runs as, the exact comment/thread batch and the artifact that batch lives on, and revoked when
// the turn ends. It is a scope, not a secret cached anywhere: nothing survives a restart because nothing
// is on disk, and only the hash of the token is held as a key. The middleware cases drive the real
// middleware with fake requests; the db is a stub whose settings make one full local token valid, so
// "the full local token does nothing here" is a real check rather than a vacuous one.
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import {
  mintPickupToken, revokePickupToken, verifyPickupToken, pickupTokenTtlMs, _resetPickupTokensForTests,
  reserveReplySlot, releaseReplySlot,
} from "../servers/gateway/reports/pickup-token.js";
import { mintTurnToken, _resetTurnTokensForTests } from "../servers/gateway/mail/drafts/turn-token.js";
import {
  localTokenAuthMiddleware, localOperatorAuth, applyLocalTokenAuth,
} from "../servers/gateway/local-token.js";
import { RELAY_SOURCE_V4 } from "../servers/shared/bot-doors.js";

const REPORT_A = "rpt-0123456789abcdef";
const REPORT_B = "rpt-fedcba9876543210";
const PICKUP_A = "rpu-0123456789abcdef";
const TURN_A = "turn-a";
const BOT_A = "alex-bot";
const BOT_B = "sam-bot";
const ARTIFACT_A = "art-0123456789abcdef";
const MINUTE = 60_000;

const mintA = (over = {}) => mintPickupToken({
  reportId: REPORT_A,
  pickupId: PICKUP_A,
  turnId: TURN_A,
  botId: BOT_A,
  threadIds: ["7", "8"],
  commentIds: ["12", "13"],
  artifactId: ARTIFACT_A,
  ...over,
});

beforeEach(() => {
  _resetPickupTokensForTests();
  _resetTurnTokensForTests();
});

test("a token verifies to the report, pickup, bot, batch and artifact it was minted for", () => {
  const token = mintA({ ttlMs: 5 * MINUTE });
  assert.match(token, /^rpk_[0-9a-f]{64}$/, "rpk_ and 32 random bytes as hex");
  const claims = verifyPickupToken(token);
  assert.equal(claims.reportId, REPORT_A);
  assert.equal(claims.pickupId, PICKUP_A);
  assert.equal(claims.turnId, TURN_A, "the mount signs over <pickupId>:<turnId>, so the turn travels here");
  assert.equal(claims.botId, BOT_A, "the mount checks the actor id against this");
  assert.deepEqual(claims.threadIds, ["7", "8"]);
  assert.deepEqual(claims.commentIds, ["12", "13"]);
  assert.equal(claims.artifactId, ARTIFACT_A);
  assert.equal(typeof claims.expiresAt, "number");
  assert.equal(Object.hasOwn(claims, "token"), false, "the raw value is not part of the claims");
});

test("the claims are copies: a caller cannot mutate what the store holds", () => {
  const token = mintA({ ttlMs: 5 * MINUTE });
  const first = verifyPickupToken(token);
  first.threadIds.push("999");
  first.commentIds.length = 0;
  first.reportId = REPORT_B;
  const second = verifyPickupToken(token);
  assert.deepEqual(second.threadIds, ["7", "8"], "the stored thread set is unchanged");
  assert.deepEqual(second.commentIds, ["12", "13"], "the stored comment set is unchanged");
  assert.equal(second.reportId, REPORT_A, "the stored report is unchanged");
  assert.notEqual(second.threadIds, first.threadIds, "each answer is its own array");
});

test("minting refuses a missing report, pickup, turn, bot or artifact, and a batch that is not a list", () => {
  const base = {
    reportId: REPORT_A, pickupId: PICKUP_A, turnId: TURN_A, botId: BOT_A, artifactId: ARTIFACT_A,
  };
  for (const field of ["reportId", "pickupId", "turnId", "botId", "artifactId"]) {
    assert.throws(() => mintPickupToken({ ...base, [field]: undefined }), TypeError, field);
    assert.throws(() => mintPickupToken({ ...base, [field]: "  " }), TypeError, `${field} whitespace-only`);
  }
  assert.throws(() => mintPickupToken({ ...base, threadIds: "7" }), TypeError, "an id list, not a string");
  assert.throws(() => mintPickupToken({ ...base, commentIds: [12] }), TypeError, "ids are strings");
});

test("the batch is optional and defaults to empty lists", () => {
  const token = mintPickupToken({
    reportId: REPORT_A, pickupId: PICKUP_A, turnId: TURN_A, botId: BOT_A, artifactId: ARTIFACT_A,
  });
  const claims = verifyPickupToken(token);
  assert.deepEqual(claims.threadIds, []);
  assert.deepEqual(claims.commentIds, []);
});

test("a token minted with no ttlMs expires at pickupTokenTtlMs(), the turn's timeout plus the margin", () => {
  const ttl = pickupTokenTtlMs();
  const before = Date.now();
  const claims = verifyPickupToken(mintA());
  const after = Date.now();
  assert.ok(claims, "the default lifetime is still a live token");
  assert.ok(
    claims.expiresAt >= before + ttl && claims.expiresAt <= after + ttl,
    `expiresAt ${claims.expiresAt} is one default lifetime from the mint`,
  );
  assert.ok(ttl > MINUTE, "the default lifetime includes the margin, not a bare timeout");
});

test("expiry follows PIBOT_TURN_TIMEOUT_MS plus the margin", () => {
  assert.equal(pickupTokenTtlMs({}), 600_000 + MINUTE);
  assert.equal(pickupTokenTtlMs({ PIBOT_TURN_TIMEOUT_MS: "1000" }), 1_000 + MINUTE);
  assert.equal(pickupTokenTtlMs({ PIBOT_TURN_TIMEOUT_MS: "1800000" }), 1_800_000 + MINUTE);
  assert.equal(pickupTokenTtlMs({ PIBOT_TURN_TIMEOUT_MS: "soon" }), 600_000 + MINUTE, "unreadable falls back");
});

test("two mints are two different tokens, and each names its own report and pickup", () => {
  const a = mintA();
  const b = mintPickupToken({
    reportId: REPORT_B, pickupId: "rpu-fedcba9876543210", turnId: "turn-b", botId: BOT_B, artifactId: "art-fedcba9876543210",
  });
  assert.notEqual(a, b);
  assert.equal(verifyPickupToken(a).reportId, REPORT_A);
  assert.equal(verifyPickupToken(b).reportId, REPORT_B);
  // A changed token is not a token: the map key is the hash of the exact string.
  const flipped = a.slice(0, -1) + (a.endsWith("0") ? "1" : "0");
  assert.equal(verifyPickupToken(flipped), null);
  assert.equal(verifyPickupToken(a + "0"), null);
  assert.equal(verifyPickupToken(a.slice(0, -1)), null);
});

test("an expired, revoked or unknown token is refused", () => {
  const expired = mintA({ ttlMs: 0 });
  assert.equal(verifyPickupToken(expired), null, "ttlMs 0 is already past");

  const revoked = mintA({ ttlMs: 5 * MINUTE });
  assert.equal(verifyPickupToken(revoked).reportId, REPORT_A, "live before the revoke");
  assert.equal(revokePickupToken(revoked), true);
  assert.equal(verifyPickupToken(revoked), null);

  assert.equal(verifyPickupToken("rpk_" + "0".repeat(64)), null, "never minted here");
  assert.equal(verifyPickupToken("not-a-token"), null);
  assert.equal(verifyPickupToken(undefined), null);
  assert.equal(verifyPickupToken(null), null);
});

test("revoking a token that was never minted answers false and leaves the live ones alone", () => {
  const live = mintA({ ttlMs: 5 * MINUTE });
  assert.equal(revokePickupToken("rpk_" + "1".repeat(64)), false);
  assert.equal(revokePickupToken(null), false);
  assert.equal(verifyPickupToken(live).reportId, REPORT_A, "an unrelated revoke revokes nothing");
});

test("only the rpk_ prefix is ever verified here, and mdt_ stays the mail door's", () => {
  const mailTurn = mintTurnToken({ draftId: "md-0123456789abcdef", turnId: "turn-a", startHash: "a".repeat(64), botId: BOT_A });
  assert.match(mailTurn, /^mdt_/);
  assert.equal(verifyPickupToken(mailTurn), null, "an mdt_ token is never a pickup token");

  const pickup = mintA({ ttlMs: 5 * MINUTE });
  assert.equal(verifyPickupToken(pickup).pickupId, PICKUP_A);
  // The runtime check above is backed by the prefix the module writes: there is no other prefix.
  const src = readFileSync(
    new URL("../servers/gateway/reports/pickup-token.js", import.meta.url), "utf8");
  assert.match(src, /const PICKUP_TOKEN_PREFIX = "rpk_";/);
});

test("a token minted before a simulated restart is refused", async () => {
  const token = mintA({ ttlMs: 5 * MINUTE });
  assert.equal(verifyPickupToken(token).pickupId, PICKUP_A);
  // A second module instance is a restarted gateway: the map is process memory, so it is empty there.
  const restarted = await import("../servers/gateway/reports/pickup-token.js?restart=1");
  assert.notEqual(restarted.verifyPickupToken, verifyPickupToken, "a fresh instance");
  assert.equal(restarted.verifyPickupToken(token), null);
});

// ---- the reply ledger: one answer per thread per pickup, in memory like the token ----

test("the reply ledger gives one slot per pickup and thread, and releases it on demand", () => {
  assert.equal(reserveReplySlot(PICKUP_A, "7"), true, "the first reply takes the slot");
  assert.equal(reserveReplySlot(PICKUP_A, "7"), false, "a second reply in that thread is refused");
  assert.equal(reserveReplySlot(PICKUP_A, "8"), true, "another thread of the same pickup is its own slot");
  assert.equal(reserveReplySlot("rpu-fedcba9876543210", "7"), true, "another pickup is independent");

  assert.equal(releaseReplySlot(PICKUP_A, "7"), true, "a failed write gives its slot back");
  assert.equal(reserveReplySlot(PICKUP_A, "7"), true, "and the retry can take it again");
  assert.equal(releaseReplySlot(PICKUP_A, "never-taken"), false, "nothing to release answers false");
  assert.equal(releaseReplySlot("rpu-never-used", "7"), false);

  // A malformed id fails closed rather than inventing an entry.
  for (const [pickupId, threadId] of [
    ["", "7"], [null, "7"], [undefined, "7"], [PICKUP_A, ""], [PICKUP_A, null],
  ]) {
    assert.equal(reserveReplySlot(pickupId, threadId), false, JSON.stringify([pickupId, threadId]));
  }
});

test("revoking a token drops its pickup's reply ledger", () => {
  const token = mintA({ ttlMs: 5 * MINUTE });
  assert.equal(reserveReplySlot(PICKUP_A, "7"), true);
  assert.equal(verifyPickupToken(token).pickupId, PICKUP_A, "live before the revoke");
  assert.equal(revokePickupToken(token), true);
  assert.equal(reserveReplySlot(PICKUP_A, "7"), true, "a re-minted token for that pickup starts clean");
});

test("sweeping an expired token drops its pickup's reply ledger", () => {
  const expiredPickup = "rpu-0123456789abcdee";
  mintA({ pickupId: expiredPickup, ttlMs: 0 });
  assert.equal(reserveReplySlot(expiredPickup, "7"), true);
  // A later mint sweeps the expired entry (and with it that pickup's ledger).
  mintA({ pickupId: "rpu-0123456789abcdef", ttlMs: 5 * MINUTE });
  assert.equal(reserveReplySlot(expiredPickup, "7"), true, "the expired pickup's slot was dropped by the sweep");
});

test("a revoked token leaves the ledger while ANOTHER live token names the same pickup", () => {
  const first = mintA({ ttlMs: 5 * MINUTE });
  const second = mintA({ ttlMs: 5 * MINUTE });
  assert.notEqual(first, second, "two distinct tokens");
  assert.equal(verifyPickupToken(second).pickupId, PICKUP_A, "and they name one pickup");

  assert.equal(reserveReplySlot(PICKUP_A, "7"), true, "the first turn answers thread 7");
  assert.equal(revokePickupToken(first), true);
  // The second turn of the SAME pickup is still live: it must keep seeing what the first one wrote.
  assert.equal(reserveReplySlot(PICKUP_A, "7"), false, "the slot is still held after one token goes");
  assert.equal(reserveReplySlot(PICKUP_A, "8"), true, "and the rest of the pickup's ledger survives intact");

  // Only when the LAST live token goes does the ledger go with it.
  assert.equal(revokePickupToken(second), true);
  assert.equal(reserveReplySlot(PICKUP_A, "7"), true, "with no live token left, the ledger is gone");
  assert.equal(reserveReplySlot(PICKUP_A, "8"), true, "every thread of it, not only the revoked token's");
});

test("an EXPIRED token leaves the ledger while another live token names the same pickup", () => {
  const live = mintA({ ttlMs: 5 * MINUTE });
  assert.equal(reserveReplySlot(PICKUP_A, "7"), true, "the live turn answers thread 7");
  const short = mintA({ ttlMs: 0 });
  assert.equal(verifyPickupToken(short), null, "an expired token is refused, and dropped");
  assert.equal(reserveReplySlot(PICKUP_A, "7"), false, "its removal left the live token's slot alone");
  mintA({ ttlMs: 0 });
  // A mint sweeps every expired entry; one of them names this pickup, which the live token still holds.
  mintA({ pickupId: "rpu-0123456789abcdea", ttlMs: 5 * MINUTE });
  assert.equal(reserveReplySlot(PICKUP_A, "7"), false, "the sweep kept it: a live token still names this pickup");
  revokePickupToken(live);
  assert.equal(reserveReplySlot(PICKUP_A, "7"), true, "the last token's revoke drops it");
});

test("the test reset forgets the reply ledger too", () => {
  assert.equal(reserveReplySlot(PICKUP_A, "7"), true);
  _resetPickupTokensForTests();
  assert.equal(reserveReplySlot(PICKUP_A, "7"), true, "a reset leaves no slot behind");
});

// ---- the middleware branch: /report-pickup accepts a live rpk_ token and nothing else ----

const FULL = "test-full-local-token";
const REPORT_TOKEN = "test-reports-token";
const sha256 = (t) => createHash("sha256").update(t).digest("hex");

/** The settings registry answers `{rows:[{value}]}`; only the two families below are configured. */
const HASHES = {
  mcp_local_token_hash: sha256(FULL),
  mcp_reports_token_hash: sha256(REPORT_TOKEN),
};
const db = {
  execute: async ({ args }) => {
    const key = args && args[0];
    return Object.prototype.hasOwnProperty.call(HASHES, key)
      ? { rows: [{ value: HASHES[key] }] }
      : { rows: [] };
  },
};

function fakeReq({ path, token, remoteAddress = RELAY_SOURCE_V4 }) {
  return { socket: { remoteAddress }, path, headers: token ? { authorization: "Bearer " + token } : {} };
}

async function run(req) {
  let nexted = 0;
  await localTokenAuthMiddleware(db)(req, {}, () => { nexted++; });
  assert.equal(nexted, 1, "the middleware always yields, never hard-rejects");
  return req;
}

test("a live rpk_ token authenticates /report-pickup/(mcp|sse|messages), with the report and pickup", async () => {
  const token = mintA({ ttlMs: 5 * MINUTE });
  for (const path of ["/report-pickup/mcp", "/report-pickup/sse", "/report-pickup/messages"]) {
    const req = await run(fakeReq({ path, token }));
    assert.deepEqual(req.localTokenAuth, {
      token: "local-mcp", scope: "report-pickup", reportId: REPORT_A, pickupId: PICKUP_A,
    }, path);
  }
});

test("the full local token and every other family's token are skipped on /report-pickup by name", async () => {
  for (const token of [FULL, REPORT_TOKEN, "mdt_" + "a".repeat(64)]) {
    const req = await run(fakeReq({ path: "/report-pickup/mcp", token }));
    assert.equal(req.localTokenAuth, undefined, `no local-token auth from ${token.slice(0, 4)}…`);
  }
  const unknown = await run(fakeReq({ path: "/report-pickup/mcp", token: "rpk_" + "0".repeat(64) }));
  assert.equal(unknown.localTokenAuth, undefined, "an unknown rpk_ value authenticates nothing");
  const revoked = mintA({ ttlMs: 5 * MINUTE });
  revokePickupToken(revoked);
  assert.equal((await run(fakeReq({ path: "/report-pickup/mcp", token: revoked }))).localTokenAuth, undefined,
    "a revoked token authenticates nothing");
  const bare = await run(fakeReq({ path: "/report-pickup/mcp" }));
  assert.equal(bare.localTokenAuth, undefined, "no bearer at all");
});

test("an rpk_ token authenticates nowhere else", async () => {
  const token = mintA({ ttlMs: 5 * MINUTE });
  for (const path of ["/memory/mcp", "/board/mcp", "/reports/mcp", "/secrets/mcp", "/mail-draft/mcp",
    "/report-pickup/mcp-x", "/report-pickup"]) {
    const req = await run(fakeReq({ path, token }));
    assert.equal(req.localTokenAuth, undefined, `the rpk_ token opens nothing but its own mount (${path})`);
  }
});

test("applyLocalTokenAuth carries the report and pickup as claims, and never lets a claim restate the scope", async () => {
  const req = await run(fakeReq({ path: "/report-pickup/mcp", token: mintA({ ttlMs: 5 * MINUTE }) }));
  assert.equal(applyLocalTokenAuth(req), true);
  assert.equal(req.auth.extra.tokenScope, "report-pickup");
  assert.equal(req.auth.extra.reportId, REPORT_A);
  assert.equal(req.auth.extra.pickupId, PICKUP_A);
  assert.deepEqual(req.auth.scopes, ["mcp:tools"]);

  // A claims object cannot widen or change the scope it is written for (tokenScope is written last).
  const auth = localOperatorAuth("report-pickup", { tokenScope: "board", reportId: REPORT_A });
  assert.equal(auth.extra.tokenScope, "report-pickup");
  assert.equal(auth.extra.reportId, REPORT_A);
});