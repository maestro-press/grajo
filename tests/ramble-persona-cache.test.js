/**
 * Ramble public-persona cache (bot turns without the identity file).
 *
 * A bot turn runs the Ramble stdio server with the instance identity hidden (the
 * file holds the master seed every bot key derives from). That server never
 * signs — the GATEWAY signs every mark and caw — so the only thing it needs is
 * the x-only AUTHOR. The gateway derives all of its personas at boot anyway, and
 * now also records their public authors in `ramble_settings`
 * (`local.persona.real` / `.world` / `.caw`, `local.`-prefixed so instance sync
 * never carries them). The stdio server reads those rows FIRST; only when they
 * are absent does it fall back to `loadIdentityIfPresent` (never
 * `loadOrCreateIdentity`).
 *
 * What the cache CAN represent, and what it cannot, is worth stating here
 * because the rotating-caw case is the subtle one: `local.persona.caw` is
 * derived with the same per-boot `local.session_id` the gateway signs with, so
 * the per-session persona IS representable — the row rotates in the same boot
 * the session id does, and the stdio server re-reads it on every call.
 *
 * Env discipline: CROW_DATA_DIR points at a scratch dir with NO identity.json,
 * set before anything that resolves the seed is imported (identity.js caches its
 * IDENTITY_PATH at module load). That is what makes "no identity file" real here
 * rather than a claim about ~/.crow.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { mkdtempSync, rmSync, existsSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createClient } from "@libsql/client";
import { generateSecretKey, getPublicKey } from "nostr-tools/pure";

const __dir = dirname(fileURLToPath(import.meta.url));
const BUNDLE_DIR = join(__dir, "../bundles/ramble/server");

// A data dir of our own, with no identity.json in it. Set BEFORE the dynamic
// imports below: servers/sharing/identity.js resolves IDENTITY_PATH once, at
// module load, from this env.
const DATA_DIR = mkdtempSync(join(tmpdir(), "ramble-persona-cache-"));
process.env.CROW_DATA_DIR = DATA_DIR;
const IDENTITY_FILE = join(DATA_DIR, "identity.json");

// The exact sentence the stdio server answers when there is no persona cache
// and no readable identity (owner-approved wording — copied byte for byte).
const GATEWAY_ERROR = "Ramble needs the Crow gateway (with sharing on) to have run.";

const { startRambleTransport } = await import("../servers/gateway/boot/ramble-transport.js");
const { initRambleTables } = await import("../bundles/ramble/server/init-tables.js");
const { createRambleServer } = await import("../bundles/ramble/server/server.js");
const { getMark } = await import("../bundles/ramble/server/marks.js");
const { setMaster, setCell } = await import("../bundles/ramble/server/grid.js");
const { PERSONA_CACHE_KEYS, PERSONA_CAW_SESSION_KEY, personaCacheKey, resolveAuthor } = await import("../bundles/ramble/server/persona.js");

after(() => { try { rmSync(DATA_DIR, { recursive: true, force: true }); } catch { /* scratch */ } });

// Real secp256k1 keys: the gateway's drain really signs (finalizeEvent throws on
// a hash-derived fake key), and a real key makes the "which author signed"
// assertions mean something.
const keys = new Map();
function fakeKey(id) {
  if (!keys.has(id)) {
    const secp256k1Priv = generateSecretKey();
    keys.set(id, { secp256k1Priv, secp256k1Pubkey: `02${getPublicKey(secp256k1Priv)}` });
  }
  return keys.get(id);
}
const fakeDerive = (_seed, botId) => fakeKey(`derive:${botId}`);
const identity = { crowId: "crow_T", ...fakeKey("real") };
const SEED = "seed";

const REAL_AUTHOR = getPublicKey(identity.secp256k1Priv);
const WORLD_AUTHOR = getPublicKey(fakeDerive(SEED, "ramble-world").secp256k1Priv);
const cawAuthorFor = (sessionId) => getPublicKey(fakeDerive(SEED, "ramble-session:" + sessionId).secp256k1Priv);

const LAT = 30.46;
const LON = -98.08;

/** The relay/publisher stub the transport needs; records what was signed. */
function makeManager() {
  const published = [];
  const relay = {
    connected: true,
    connect: async () => {},
    subscribe: () => {
      const handle = { close: () => {} };
      return handle;
    },
  };
  const nostrManager = {
    relays: new Map([["wss://fake", relay]]),
    connectRelays: async () => [],
    publishRendezvousEvent: async (event) => { published.push(event); return ["wss://fake"]; },
    sendControl: async () => ({ eventId: "ctl", relays: ["wss://fake"] }),
  };
  return { nostrManager, published };
}

async function bootTransport(db) {
  const m = makeManager();
  const transport = await startRambleTransport({
    db, nostrManager: m.nostrManager, identity, seed: SEED,
    bus: new EventEmitter(), bundleDir: BUNDLE_DIR, _derive: fakeDerive, autoStart: false,
  });
  return { transport, published: m.published };
}

async function settings(db) {
  const { rows } = await db.execute({ sql: "SELECT key, value FROM ramble_settings" });
  return Object.fromEntries(rows.map((r) => [r.key, r.value]));
}

/** What the gateway writes at boot, for a db the gateway is not running on. */
async function writeCache(db, { real = REAL_AUTHOR, world = WORLD_AUTHOR, caw, sessionId = "s1" } = {}) {
  const rows = [
    [PERSONA_CACHE_KEYS.real, real],
    [PERSONA_CACHE_KEYS.world, world],
    [PERSONA_CACHE_KEYS.caw, caw ?? cawAuthorFor(sessionId)],
    [PERSONA_CAW_SESSION_KEY, sessionId],
    ["local.session_id", sessionId],
  ];
  for (const [key, value] of rows) {
    // eslint-disable-next-line no-await-in-loop
    await db.execute({
      sql: `INSERT INTO ramble_settings (key, value) VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
      args: [key, value],
    });
  }
}

function handlersFor(db) {
  const handlers = {};
  // No identity/seed/_derive: this is the bot's spawn, which cannot read them.
  createRambleServer(db, { _exposeHandlers: handlers, emit: async () => {} });
  return handlers;
}

const payload = (res) => JSON.parse(res.content[0].text);

test("(a) gateway boot writes local.persona.real/.world/.caw with the derived authors, every boot", async () => {
  const db = createClient({ url: "file::memory:" });
  const first = await bootTransport(db);
  const rows = await settings(db);

  assert.equal(rows[PERSONA_CACHE_KEYS.real], REAL_AUTHOR, "the real persona is the instance x-only pubkey");
  assert.equal(rows[PERSONA_CACHE_KEYS.world], WORLD_AUTHOR, "the world persona is the stable pseudonym");
  assert.equal(rows[PERSONA_CACHE_KEYS.caw], cawAuthorFor(first.transport.sessionId),
    "the caw persona is the per-boot session key — the same local.session_id the gateway signs with");
  assert.equal(rows[PERSONA_CAW_SESSION_KEY], first.transport.sessionId,
    "the caw row records the session it was derived from, so a later boot can tell it is stale");
  assert.equal(rows["local.session_id"], first.transport.sessionId);
  // One row per key: a re-boot upserts, it never appends.
  const { rows: counts } = await db.execute({
    sql: `SELECT key, count(*) AS n FROM ramble_settings
          WHERE key IN ('local.persona.real', 'local.persona.world', 'local.persona.caw') GROUP BY key`,
  });
  assert.equal(counts.length, 3, "all three cache rows exist");
  for (const c of counts) assert.equal(c.n, 1, `${c.key} is written once`);

  // The (level, kind) -> slot mapping is the one resolvePersona itself applies.
  assert.equal(personaCacheKey({ level: "real", kind: "mark" }), PERSONA_CACHE_KEYS.real);
  assert.equal(personaCacheKey({ level: "rotating", kind: "mark" }), PERSONA_CACHE_KEYS.world);
  assert.equal(personaCacheKey({ level: "pseudonym", kind: "caw" }), PERSONA_CACHE_KEYS.world);
  assert.equal(personaCacheKey({ level: "rotating", kind: "caw" }), PERSONA_CACHE_KEYS.caw);
  const cache = {
    real: rows[PERSONA_CACHE_KEYS.real],
    world: rows[PERSONA_CACHE_KEYS.world],
    caw: rows[PERSONA_CACHE_KEYS.caw],
  };
  assert.deepEqual(resolveAuthor(cache, "real", "mark"), { author: REAL_AUTHOR, author_level: "real" });
  assert.deepEqual(resolveAuthor(cache, "rotating", "mark"), { author: WORLD_AUTHOR, author_level: "rotating" });
  assert.deepEqual(resolveAuthor(cache, "pseudonym", "mark"), { author: WORLD_AUTHOR, author_level: "pseudonym" });
  assert.deepEqual(resolveAuthor(cache, "rotating", "caw"),
    { author: cawAuthorFor(first.transport.sessionId), author_level: "rotating" });
  assert.equal(resolveAuthor(null, "rotating", "mark"), null, "no cache is no author, not a throw");
  assert.equal(resolveAuthor({ world: "not-a-pubkey" }, "rotating", "mark"), null, "a junk row is no author either");

  // A second boot (a gateway restart) rewrites the rows instead of appending.
  const second = await bootTransport(db);
  const again = await settings(db);
  assert.equal(again[PERSONA_CACHE_KEYS.real], REAL_AUTHOR);
  assert.equal(again[PERSONA_CACHE_KEYS.world], WORLD_AUTHOR);
  assert.equal(again[PERSONA_CACHE_KEYS.caw], cawAuthorFor(second.transport.sessionId));
  assert.equal(again[PERSONA_CAW_SESSION_KEY], second.transport.sessionId, "the caw stamp rotates with the row");
  assert.notEqual(second.transport.sessionId, first.transport.sessionId, "a restart mints a new session id");
  assert.equal(again["local.session_id"], second.transport.sessionId);
});

test("(a2) a failed caw derivation leaves local.persona.caw_session at the OLD boot, so the row reads as stale", async () => {
  // The gateway writes local.session_id BEFORE it derives the personas, so a caw
  // derivation (or its write) that failed on a restart leaves the previous
  // boot's caw row beside a fresh session id. The stamp is what tells the two
  // apart — and it is written only WITH its row, never on its own.
  const db = createClient({ url: "file::memory:" });
  const first = await bootTransport(db);
  const before = await settings(db);
  assert.equal(before[PERSONA_CAW_SESSION_KEY], first.transport.sessionId);

  // A second boot whose caw derivation throws: the loop logs and moves on.
  const m = makeManager();
  const second = await startRambleTransport({
    db, nostrManager: m.nostrManager, identity, seed: SEED, bus: new EventEmitter(),
    bundleDir: BUNDLE_DIR, autoStart: false,
    _derive: (_seed, botId) => {
      if (botId.startsWith("ramble-session:")) throw new Error("seed unavailable this boot");
      return fakeDerive(_seed, botId);
    },
  });
  const after = await settings(db);
  assert.equal(after["local.session_id"], second.sessionId, "the session id rotated anyway");
  assert.equal(after[PERSONA_CACHE_KEYS.caw], before[PERSONA_CACHE_KEYS.caw], "the old caw row is still there");
  assert.equal(after[PERSONA_CAW_SESSION_KEY], first.transport.sessionId,
    "and it still carries the OLD session id, so no reader mistakes it for this boot's");
  second.stop();
});

test("(b) with the cache rows and NO readable identity, a mark and a caw take the cached authors", async () => {
  const db = createClient({ url: "file::memory:" });
  await initRambleTables(db);
  await writeCache(db, { sessionId: "boot-1" });
  assert.equal(existsSync(IDENTITY_FILE), false, "the premise: no identity file in this data dir");

  const h = handlersFor(db);

  const mark = await h.ramble_leave_mark({ lat: LAT, lon: LON, text: "from a cache", visibility: "public", reveal: "open" });
  assert.ok(!mark.isError, mark.content[0].text);
  assert.equal(payload(mark).author, WORLD_AUTHOR, "a rotating mark uses the world persona");
  assert.equal(payload(mark).author_level, "rotating");

  const caw = await h.ramble_caw({ lat: LAT, lon: LON, text: "caw from a cache" });
  assert.ok(!caw.isError, caw.content[0].text);
  assert.equal(payload(caw).author, cawAuthorFor("boot-1"), "a rotating caw uses the per-session persona");

  // The level the user picked decides the slot: at 'real' a mark is the instance key.
  await db.execute({
    sql: `INSERT INTO ramble_settings (key, value) VALUES ('public_identity_level', 'real')
          ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
    args: [],
  });
  const real = await h.ramble_leave_mark({ lat: LAT, lon: LON, text: "real level", visibility: "public", reveal: "open" });
  assert.ok(!real.isError, real.content[0].text);
  assert.equal(payload(real).author, REAL_AUTHOR);
  assert.equal(payload(real).author_level, "real");

  assert.equal(existsSync(IDENTITY_FILE), false, "the cache path never reads, and so never creates, an identity");
});

test("(c) with no cache rows and no identity file it never creates one, and says the gateway is needed", async () => {
  const db = createClient({ url: "file::memory:" });
  await initRambleTables(db);
  const h = handlersFor(db);
  assert.equal(existsSync(IDENTITY_FILE), false, "the premise: no identity file in this data dir");

  const mark = await h.ramble_leave_mark({ lat: LAT, lon: LON, text: "no author", visibility: "public" });
  assert.ok(mark.isError);
  assert.equal(mark.content[0].text, GATEWAY_ERROR, "the exact approved sentence");

  const caw = await h.ramble_caw({ lat: LAT, lon: LON, text: "no author either" });
  assert.ok(caw.isError);
  assert.equal(caw.content[0].text, GATEWAY_ERROR, "the exact approved sentence, for a caw too");

  // The whole point of the guard this replaces: an absent seed file must never
  // become a second identity (loadOrCreateIdentity would have minted one here).
  assert.equal(existsSync(IDENTITY_FILE), false, "no identity file was created");
  assert.deepEqual(readdirSync(DATA_DIR), [], "nothing at all was written to the data dir");

  // A MASKED identity (the file exists and reads empty, as in a bot sandbox) is
  // a different fault with the sentence the sandbox note documents.
  writeFileSync(IDENTITY_FILE, "");
  const masked = handlersFor(db);
  const maskedMark = await masked.ramble_leave_mark({ lat: LAT, lon: LON, text: "masked", visibility: "public" });
  assert.ok(maskedMark.isError);
  assert.match(maskedMark.content[0].text, /the instance identity is not available to bots/);
  rmSync(IDENTITY_FILE, { force: true });
});

test("(e) a caw row whose caw_session differs from local.session_id is not used; the normal fallback applies", async () => {
  const db = createClient({ url: "file::memory:" });
  await initRambleTables(db);
  // Boot 1 wrote caw + its stamp. Boot 2 minted a NEW local.session_id and then
  // failed to derive the caw persona, so the old row is still sitting there.
  await writeCache(db, { sessionId: "boot-1" });
  await db.execute({
    sql: `INSERT INTO ramble_settings (key, value) VALUES ('local.session_id', 'boot-2')
          ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
    args: [],
  });
  assert.equal(existsSync(IDENTITY_FILE), false, "the premise: no identity file in this data dir");
  const h = handlersFor(db);

  // The boot-scoped slot is the CAW one only: the world/real rows are unaffected.
  const mark = await h.ramble_leave_mark({ lat: LAT, lon: LON, text: "still cached", visibility: "public", reveal: "open" });
  assert.ok(!mark.isError, mark.content[0].text);
  assert.equal(payload(mark).author, WORLD_AUTHOR);

  // The stale caw row reads as MISSING, so the identity fallback runs — and with
  // no identity file to read that is the gateway sentence, never boot-1's key.
  const caw = await h.ramble_caw({ lat: LAT, lon: LON, text: "stale caw" });
  assert.ok(caw.isError, "a stale caw row must not author a caw");
  assert.ok(caw.content[0].text.includes(GATEWAY_ERROR), "the gateway sentence: " + caw.content[0].text);
  assert.ok(!caw.content[0].text.includes(cawAuthorFor("boot-1")), "boot-1's caw author never appears");
});

test("(d) a forged local.persona.world row is rewritten to the true author when the gateway publishes", async () => {
  const db = createClient({ url: "file::memory:" });
  const { transport, published } = await bootTransport(db);
  await initRambleTables(db);
  await setMaster(db, true);
  await setCell(db, "public", "geo", true);

  const forged = "ab".repeat(32);
  await db.execute({
    sql: `INSERT INTO ramble_settings (key, value) VALUES ('local.persona.world', ?)
          ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
    args: [forged],
  });

  // The stdio server trusts the row (it cannot tell a forged author from a real
  // one — and it does not have to: it never signs).
  const h = handlersFor(db);
  const res = await h.ramble_leave_mark({ lat: LAT, lon: LON, text: "forged author", visibility: "public", reveal: "open" });
  assert.ok(!res.isError, res.content[0].text);
  const markId = payload(res).mark_id;
  assert.equal(payload(res).author, forged, "the row was written with the forged cached author");

  await transport.drainOnce();

  const event = published.find((e) => JSON.parse(e.content).text === "forged author");
  assert.ok(event, "the mark reached the wire");
  assert.equal(event.pubkey, WORLD_AUTHOR, "the gateway signed with its OWN world persona, not the forged row");
  const row = await getMark(db, markId);
  assert.equal(row.publish_state, "published");
  assert.equal(row.author, WORLD_AUTHOR, "and the stored author was rewritten to the signer");
});