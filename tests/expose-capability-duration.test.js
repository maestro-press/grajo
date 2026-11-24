/**
 * The Allow card's duration must come from the CLICKED action id, and from
 * nothing else.
 *
 * The card renders three buttons (30 days / 7 days / until removed) and each
 * posts its own `actionId`. `args` travel with the stored card and are a
 * snapshot of what the detector wrote — they are NOT the operator's choice at
 * click time. Before this fix `resolveDuration(args)` alone decided the grant,
 * so a stored/fabricated `untilRemoved: true` (or `days: 3650`) turned any click
 * into a longer grant than the button said — "Allow for 30 days" could mean
 * forever.
 *
 * These tests drive the remedy directly (a later step wires `cfg.actionId` in
 * production) with a card context and an `actionId`, and pin down:
 *   - forged: args that DISAGREE with the action id's duration refuse, and
 *     nothing is written (tests 1-3);
 *   - genuine: every button of CARD_DURATIONS grants exactly its own duration
 *     (test 4);
 *   - unknown or missing action id refuses (test 5);
 *   - the legacy `expose-capability` id from old cards means 30 days (test 6);
 *   - a duration that will not coerce to a number (`"3650"`, NaN, an array,
 *     a boolean, `""`, a fraction) and a `null` behind a finite button are
 *     forged too, and a contradictory `untilRemoved: true` beside `days`
 *     behind the forever button agrees with nothing (tests 7-9);
 *   - a stored legacy card's own duration never overrides the legacy id's
 *     30 days (test 10);
 *   - the same holds through the real click path (`handleFixItAction`): a
 *     stored card that lies about its button writes no grant, a genuine card
 *     grants its button's duration (test 11).
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createDbClient } from "../servers/db.js";
import { getPeerExposures } from "../servers/gateway/peer-exposure.js";
import { pairingTag } from "../servers/shared/peer-id.js";
import * as store from "../servers/shared/fix-it/store.js";
import { CARD_DURATIONS, cardRemedies } from "../servers/gateway/fix-it/peer-card-policy.js";

let dir, db, idx, remedy;

const DAY = 24 * 60 * 60 * 1000;
/** How far a computed expiry may sit from the expected instant. */
const EXPIRY_TOLERANCE_MS = 60 * 1000;
/** The duration the legacy action id (old cards, no duration in args) means. */
const LEGACY_DAYS = 30;

before(async () => {
  dir = mkdtempSync(join(tmpdir(), "expose-capability-duration-"));
  execFileSync(process.execPath, ["scripts/init-db.js"], {
    env: { ...process.env, CROW_DATA_DIR: dir }, stdio: "pipe", cwd: join(import.meta.dirname, ".."),
  });
  process.env.CROW_DATA_DIR = dir;
  db = createDbClient();
  idx = await import("../servers/gateway/fix-it/index.js");
  remedy = (await import("../servers/gateway/fix-it/remedies/expose-capability.js")).default;
});

after(() => { try { db.close(); } catch {} try { rmSync(dir, { recursive: true, force: true }); } catch {} });

const tokenHashFor = (id) => `test-token-hash-${id}`;

/**
 * A trusted peer row carrying the bearer hash the card is bound to (the remedy
 * compares `context.pairingTag` with the tag of the peer's CURRENT hash).
 */
async function trustPeer(...ids) {
  for (const id of ids) {
    await db.execute({
      sql: "INSERT OR REPLACE INTO crow_instances (id, name, crow_id, status, trusted, auth_token_hash) VALUES (?, ?, ?, 'active', 1, ?)",
      args: [id, `Peer ${id}`, "crow-test", tokenHashFor(id)],
    });
  }
}

/** The stored card a denial from `id` under its current pairing produces. */
const cardFor = (id) => ({ context: { requestingInstance: id, pairingTag: pairingTag(tokenHashFor(id)) } });

/** The stored grant for (peer, capability), or undefined when none was written. */
async function grantFor(peerId, capability = "funkwhale") {
  return (await getPeerExposures(db)).get(peerId)?.get(capability);
}

/** Assert a refusal wrote NOTHING for the peer (no allowance row at all). */
async function assertNoGrant(peerId, capability = "funkwhale") {
  assert.equal((await getPeerExposures(db)).has(peerId), false, `no allowance was written for ${peerId}`);
  assert.equal(await grantFor(peerId, capability), undefined);
}

/** Find the remedy args the card writes for one of its buttons. */
const argsFor = (capability, peerId, actionId) =>
  cardRemedies(capability, peerId).find((r) => r.actionId === actionId).args;

/**
 * Store a card and click one of its buttons through the real action handler
 * (`handleFixItAction`), exactly as the Nest's POST does. Returns the redirect
 * URL so a test can read the flash.
 */
async function storeAndClick(peerId, remedies, actionId, dedupKey) {
  const { id } = await store.upsertItem(db, {
    source: "remote-exposure",
    dedupKey,
    title: "Another device tried to use Music",
    why: "Allow it?",
    severity: "warn",
    remedies,
    context: cardFor(peerId).context,
  });
  let redirected = null;
  await idx.handleFixItAction(
    { body: { action: "remedy", item_id: String(id), action_id: actionId } },
    { redirectAfterPost: (u) => { redirected = u; } },
    { db },
  );
  return redirected;
}

// ---------------------------------------------------------------------------
// Forged args: the stored card's duration disagrees with the clicked button
// ---------------------------------------------------------------------------

test("1. forged untilRemoved:true behind the 30-day button refuses, nothing written", async () => {
  const peer = "peer-forged-forever";
  await trustPeer(peer);
  const r = await remedy(
    { capability: "funkwhale", requestingInstance: peer, untilRemoved: true },
    { db, item: cardFor(peer), actionId: "expose-capability-30d" },
  );
  assert.equal(r.resolved, false, "a permanent duration behind a 30-day button must refuse");
  assert.equal(r.message, "Could not record the allowance.");
  await assertNoGrant(peer);
});

test("2. forged days:3650 behind the 30-day button refuses, nothing written", async () => {
  const peer = "peer-forged-3650";
  await trustPeer(peer);
  const r = await remedy(
    { capability: "funkwhale", requestingInstance: peer, days: 3650 },
    { db, item: cardFor(peer), actionId: "expose-capability-30d" },
  );
  assert.equal(r.resolved, false, "a 10-year duration behind a 30-day button must refuse");
  assert.equal(r.message, "Could not record the allowance.");
  await assertNoGrant(peer);
});

test("3. forged days behind the forever (and 7-day) buttons refuses, nothing written", async () => {
  const foreverPeer = "peer-forged-forever-finite";
  const sevenPeer = "peer-forged-7d-30";
  await trustPeer(foreverPeer, sevenPeer);

  const forever = await remedy(
    { capability: "funkwhale", requestingInstance: foreverPeer, days: 30 },
    { db, item: cardFor(foreverPeer), actionId: "expose-capability-forever" },
  );
  assert.equal(forever.resolved, false, "a 30-day duration behind the forever button must refuse");
  assert.equal(forever.message, "Could not record the allowance.");
  await assertNoGrant(foreverPeer);

  const seven = await remedy(
    { capability: "funkwhale", requestingInstance: sevenPeer, days: 30 },
    { db, item: cardFor(sevenPeer), actionId: "expose-capability-7d" },
  );
  assert.equal(seven.resolved, false, "a 30-day duration behind the 7-day button must refuse");
  assert.equal(seven.message, "Could not record the allowance.");
  await assertNoGrant(sevenPeer);
});

// ---------------------------------------------------------------------------
// Genuine clicks: every button grants exactly its own duration
// ---------------------------------------------------------------------------

test("4. every CARD_DURATIONS button grants its own duration", async () => {
  assert.ok(CARD_DURATIONS.length >= 3, "the card still offers 30 days / 7 days / forever");

  for (const { days, actionId } of CARD_DURATIONS) {
    // A distinct peer per button so each grant is read on its own.
    const peer = `peer-genuine-${actionId}`;
    await trustPeer(peer);

    const r = await remedy(argsFor("funkwhale", peer, actionId), { db, item: cardFor(peer), actionId });
    assert.equal(r.resolved, true, `${actionId} grants`);

    const grant = await grantFor(peer);
    assert.ok(grant, `${actionId} wrote an allowance`);

    if (days == null) {
      assert.equal(grant.expiresAt, null, `${actionId} ("until I remove it") stores no expiry`);
    } else {
      const expected = Date.now() + days * DAY;
      const actual = Date.parse(grant.expiresAt);
      assert.ok(Number.isFinite(actual), `${actionId} stores a parseable expires_at`);
      assert.ok(
        Math.abs(actual - expected) <= EXPIRY_TOLERANCE_MS,
        `${actionId} expires in ~${days} days (expected ~${new Date(expected).toISOString()}, got ${grant.expiresAt})`,
      );
    }
  }
});

// ---------------------------------------------------------------------------
// Unknown / missing action id
// ---------------------------------------------------------------------------

test("5. an unknown action id or a missing one refuses, nothing written", async () => {
  const unknownPeer = "peer-unknown-action";
  const missingPeer = "peer-missing-action";
  await trustPeer(unknownPeer, missingPeer);

  const unknown = await remedy(
    { capability: "funkwhale", requestingInstance: unknownPeer, days: 30 },
    { db, item: cardFor(unknownPeer), actionId: "expose-capability-999d" },
  );
  assert.equal(unknown.resolved, false, "an action id the card never offers must refuse");
  assert.equal(unknown.message, "Could not record the allowance.");
  await assertNoGrant(unknownPeer);

  const missing = await remedy(
    { capability: "funkwhale", requestingInstance: missingPeer, days: 30 },
    { db, item: cardFor(missingPeer) },
  );
  assert.equal(missing.resolved, false, "a click with no action id must refuse");
  assert.equal(missing.message, "Could not record the allowance.");
  await assertNoGrant(missingPeer);
});

// ---------------------------------------------------------------------------
// Legacy action id
// ---------------------------------------------------------------------------

test('6. the legacy "expose-capability" action id (no duration in args) means 30 days', async () => {
  const peer = "peer-legacy-action";
  await trustPeer(peer);

  const r = await remedy(
    { capability: "funkwhale", requestingInstance: peer },
    { db, item: cardFor(peer), actionId: "expose-capability" },
  );
  assert.equal(r.resolved, true, "an old card's button still grants");

  const grant = await grantFor(peer);
  assert.ok(grant, "the allowance was written");
  const expected = Date.now() + LEGACY_DAYS * DAY;
  assert.ok(
    Math.abs(Date.parse(grant.expiresAt) - expected) <= EXPIRY_TOLERANCE_MS,
    `the legacy button means ${LEGACY_DAYS} days, got ${grant.expiresAt}`,
  );
});

// ---------------------------------------------------------------------------
// Ill-shaped durations: nothing that is not the button's number may grant
// ---------------------------------------------------------------------------

/** Values that are not the 30-day button's duration, however they coerce. */
const NOT_30_DAYS = [
  ["string 3650", "3650"],
  ["NaN", NaN],
  ["array [3650]", [3650]],
  ["boolean true", true],
  ["empty string", ""],
  ["fraction 30.5", 30.5],
];

test("7. ill-shaped or wrong day counts behind the 30-day button refuse, nothing written", async (t) => {
  for (const [label, days] of NOT_30_DAYS) {
    await t.test(label, async () => {
      const peer = `peer-coerced-${label.replace(/[^a-z0-9]+/gi, "-")}`;
      await trustPeer(peer);
      const r = await remedy(
        { capability: "funkwhale", requestingInstance: peer, days },
        { db, item: cardFor(peer), actionId: "expose-capability-30d" },
      );
      assert.equal(r.resolved, false, `${label} behind a 30-day button must refuse`);
      assert.equal(r.message, "Could not record the allowance.");
      await assertNoGrant(peer);
    });
  }
});

test("8. days:null behind a finite (30-day / 7-day) button refuses, nothing written", async () => {
  const thirtyPeer = "peer-null-30d";
  const sevenPeer = "peer-null-7d";
  await trustPeer(thirtyPeer, sevenPeer);

  for (const [peer, actionId] of [
    [thirtyPeer, "expose-capability-30d"],
    [sevenPeer, "expose-capability-7d"],
  ]) {
    const r = await remedy(
      { capability: "funkwhale", requestingInstance: peer, days: null },
      { db, item: cardFor(peer), actionId },
    );
    assert.equal(r.resolved, false, `days:null behind ${actionId} must refuse`);
    assert.equal(r.message, "Could not record the allowance.");
    await assertNoGrant(peer);
  }
});

test("9. untilRemoved:true beside days:30 behind the forever button does not grant", async () => {
  const peer = "peer-forever-contradiction";
  await trustPeer(peer);
  const r = await remedy(
    { capability: "funkwhale", requestingInstance: peer, untilRemoved: true, days: 30 },
    { db, item: cardFor(peer), actionId: "expose-capability-forever" },
  );
  assert.equal(r.resolved, false, "contradictory stored args behind the forever button must refuse");
  assert.equal(r.message, "Could not record the allowance.");
  await assertNoGrant(peer);
});

// ---------------------------------------------------------------------------
// Legacy id: a stored duration still cannot override the 30 days it means
// ---------------------------------------------------------------------------

test("10. the legacy action id refuses stored args that are not its 30 days", async () => {
  const foreverPeer = "peer-legacy-stored-forever";
  const sevenPeer = "peer-legacy-stored-7d";
  await trustPeer(foreverPeer, sevenPeer);

  for (const [peer, args] of [
    [foreverPeer, { capability: "funkwhale", requestingInstance: foreverPeer, untilRemoved: true }],
    [sevenPeer, { capability: "funkwhale", requestingInstance: sevenPeer, days: 7 }],
  ]) {
    const r = await remedy(args, { db, item: cardFor(peer), actionId: "expose-capability" });
    assert.equal(r.resolved, false, `stored ${JSON.stringify(args)} behind the legacy id must refuse`);
    assert.equal(r.message, "Could not record the allowance.");
    await assertNoGrant(peer);
  }
});

// ---------------------------------------------------------------------------
// The real click path: handleFixItAction
// ---------------------------------------------------------------------------

test("11. a stored card whose 30-day button carries untilRemoved:true writes no grant on click", async () => {
  const peer = "peer-click-forged";
  await trustPeer(peer);
  // The card is stored data: the remedy args can claim a longer duration than
  // the button the operator actually presses.
  const remedies = cardRemedies("funkwhale", peer).map((r) =>
    r.actionId === "expose-capability-30d"
      ? { ...r, args: { capability: r.args.capability, requestingInstance: r.args.requestingInstance, untilRemoved: true } }
      : r);

  const redirected = await storeAndClick(peer, remedies, "expose-capability-30d", `expose|funkwhale|${peer}|forged-click`);
  assert.match(String(redirected), /fixit_error/, "the click is reported as an error");
  await assertNoGrant(peer);

  // The genuine 7-day button of a real card still grants about 7 days.
  const sevenPeer = "peer-click-7d";
  await trustPeer(sevenPeer);
  const ok = await storeAndClick(
    sevenPeer, cardRemedies("funkwhale", sevenPeer), "expose-capability-7d",
    `expose|funkwhale|${sevenPeer}|genuine-click`,
  );
  assert.doesNotMatch(String(ok), /fixit_error/);
  const grant = await grantFor(sevenPeer);
  assert.ok(grant, "the genuine 7-day click wrote an allowance");
  assert.ok(
    Math.abs(Date.parse(grant.expiresAt) - (Date.now() + 7 * DAY)) <= EXPIRY_TOLERANCE_MS,
    `the 7-day button expires in ~7 days, got ${grant.expiresAt}`,
  );
});