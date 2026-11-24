/**
 * An expose-capability click runs ONLY on a remote-exposure card, and only on a
 * button that card would actually render.
 *
 * The action handler (`fix-it/index.js` `handleFixItAction`) looks a remedy up by
 * `action_id` on the stored card and runs whatever the registry holds for that
 * id. The expose remedy is registered under three duration ids, and every one of
 * them grants a peer access to a capability. Two holes follow from that:
 *
 *   1. the card's SOURCE is not consulted, so a pending card of ANY other source
 *      whose stored remedies name an expose action id (a crow.db column the
 *      add-ons sharing the database can write) gets that allowance when the
 *      operator clicks the button — a card that says nothing about peer exposure
 *      would hand out access;
 *   2. the renderer hides a remote-exposure remedy whose actionId has no
 *      code-held label (`cardRemedyLabel` null — the pre-N1b legacy
 *      "expose-capability" id, an invented id), but the handler still RUNS it: a
 *      button the operator never sees can be posted by hand.
 *
 * These tests pin the handler's own gate:
 *   1. another source's card, with a genuine-looking forever entry (trusted peer,
 *      matching pairing tag, consistent args), grants nothing and answers the
 *      error flash;
 *   2. a remote-exposure card carrying only the legacy id grants nothing and
 *      answers the error flash;
 *   3. a genuine remote-exposure card's 30-day button still grants ~30 days.
 */
import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createDbClient } from "../servers/db.js";
import { getPeerExposures } from "../servers/gateway/peer-exposure.js";
import { pairingTag } from "../servers/shared/peer-id.js";
import * as store from "../servers/shared/fix-it/store.js";
import { cardRemedies } from "../servers/gateway/fix-it/peer-card-policy.js";

let dir, db, idx;

const DAY = 24 * 60 * 60 * 1000;
/** How far a computed expiry may sit from the expected instant. */
const EXPIRY_TOLERANCE_MS = 60 * 1000;

/** The source the remote-exposure detector writes its cards under. */
const SOURCE = "remote-exposure";
/** The source of a card that has nothing to do with peer exposure. */
const OTHER_SOURCE = "other-test";

before(async () => {
  dir = mkdtempSync(join(tmpdir(), "fixit-expose-source-gate-"));
  execFileSync(process.execPath, ["scripts/init-db.js"], {
    env: { ...process.env, CROW_DATA_DIR: dir }, stdio: "pipe", cwd: join(import.meta.dirname, ".."),
  });
  process.env.CROW_DATA_DIR = dir;
  db = createDbClient();
  idx = await import("../servers/gateway/fix-it/index.js");
  idx.wireFixIt();
});
after(() => { try { db.close(); } catch { /* already closed */ } try { rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ } });

beforeEach(async () => {
  await db.execute("DELETE FROM fix_it_items");
  for (const key of ["remote_exposed_tools", "remote_exposed_tools_by_peer"]) {
    await db.execute({ sql: "DELETE FROM dashboard_settings WHERE key = ?", args: [key] });
    await db.execute({ sql: "DELETE FROM dashboard_settings_overrides WHERE key = ?", args: [key] });
  }
});

const tokenHashFor = (id) => `test-token-hash-${id}`;

/** A peer row that passes the trust predicate the remedy checks. */
async function trustPeer(...ids) {
  for (const id of ids) {
    await db.execute({
      sql: "INSERT OR REPLACE INTO crow_instances (id, name, crow_id, status, trusted, auth_token_hash) VALUES (?, ?, ?, 'active', 1, ?)",
      args: [id, `Peer ${id}`, "crow-test", tokenHashFor(id)],
    });
  }
}

/** The pairing tag the gate would publish for a peer trusted by `trustPeer`. */
const tagFor = (id) => pairingTag(tokenHashFor(id));

/** Store one card row and answer its id. */
async function seedRow({ source, dedupKey, remedies, context = null }) {
  const { id } = await store.upsertItem(db, {
    source,
    dedupKey,
    title: "Stored title",
    why: "Stored body",
    severity: "warn",
    remedies,
    context,
  });
  return id;
}

/** POST a remedy click through the real handler; answers the redirect URL. */
async function click(itemId, actionId) {
  let redirected = null;
  await idx.handleFixItAction(
    { body: { action: "remedy", item_id: String(itemId), action_id: actionId } },
    { redirectAfterPost: (u) => { redirected = u; } },
    { db },
  );
  assert.equal(typeof redirected, "string", "handleFixItAction must always redirect");
  return redirected;
}

/** The stored grant for (peer, capability), or undefined when none was written. */
const grantFor = (peerId, capability = "funkwhale") =>
  getPeerExposures(db).then((all) => all.get(peerId)?.get(capability));

/** Assert a refusal wrote NOTHING for the peer. */
async function assertNoGrant(peerId) {
  assert.equal((await getPeerExposures(db)).has(peerId), false, `no allowance was written for ${peerId}`);
  assert.equal(await grantFor(peerId), undefined);
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Another source's card never runs an expose action
// ─────────────────────────────────────────────────────────────────────────────
test("an expose action on another source's card grants nothing and answers the error flash", async () => {
  const peer = "peer-other-source";
  await trustPeer(peer);
  // Every input the remedy reads is genuine: a trusted peer, the card's own
  // verified id, a matching pairing tag, and args that agree with the forever
  // action. The ONLY thing wrong is the card's source — it is not a
  // remote-exposure card, so it may not hand out an allowance.
  const id = await seedRow({
    source: OTHER_SOURCE,
    dedupKey: "other-source/forever",
    remedies: [{
      label: "Allow until I remove it",
      actionId: "expose-capability-forever",
      kind: "instant",
      args: { capability: "funkwhale", requestingInstance: peer, untilRemoved: true },
    }],
    context: { capability: "funkwhale", requestingInstance: peer, pairingTag: tagFor(peer) },
  });

  const redirected = await click(id, "expose-capability-forever");
  assert.match(String(redirected), /flash=fixit_error/, "the click is reported as an error");
  await assertNoGrant(peer);
  assert.equal((await store.getItem(db, id)).status, "pending",
    "the card is still open — a refused click changes nothing");
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. A remote-exposure card's legacy id is not rendered, so it must not run
// ─────────────────────────────────────────────────────────────────────────────
test("the legacy expose-capability id on a remote-exposure card grants nothing and answers the error flash", async () => {
  const peer = "peer-legacy-id";
  await trustPeer(peer);
  // The pre-N1b button. `cardRemedyLabel` holds no words for this id, so the
  // renderer hides it — the handler must refuse it too, not run what the
  // operator cannot see.
  const id = await seedRow({
    source: SOURCE,
    dedupKey: "legacy-id/only",
    remedies: [{
      label: "Allow",
      actionId: "expose-capability",
      kind: "instant",
      args: { capability: "funkwhale", requestingInstance: peer },
    }],
    context: { capability: "funkwhale", requestingInstance: peer, pairingTag: tagFor(peer) },
  });

  const redirected = await click(id, "expose-capability");
  assert.match(String(redirected), /flash=fixit_error/, "the click is reported as an error");
  await assertNoGrant(peer);
  assert.equal((await store.getItem(db, id)).status, "pending",
    "the card is still open — a refused click changes nothing");
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. A genuine card still works
// ─────────────────────────────────────────────────────────────────────────────
test("a genuine remote-exposure card's 30-day button still grants about 30 days", async () => {
  const peer = "peer-genuine";
  await trustPeer(peer);
  const id = await seedRow({
    source: SOURCE,
    dedupKey: "genuine/30d",
    remedies: cardRemedies("funkwhale", peer),
    context: { capability: "funkwhale", requestingInstance: peer, pairingTag: tagFor(peer) },
  });

  const before = Date.now();
  const redirected = await click(id, "expose-capability-30d");
  assert.doesNotMatch(String(redirected), /fixit_error/, "a genuine click is not an error");
  assert.equal((await store.getItem(db, id)).status, "resolved", "and it resolves the card");

  const grant = await grantFor(peer);
  assert.ok(grant, "the allowance was written");
  const expected = before + 30 * DAY;
  assert.ok(
    Math.abs(Date.parse(grant.expiresAt) - expected) <= EXPIRY_TOLERANCE_MS,
    `the 30-day button grants about 30 days, got ${grant.expiresAt}`,
  );
});