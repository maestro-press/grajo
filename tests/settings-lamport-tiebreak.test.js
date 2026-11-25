/**
 * M6: equal-Lamport writes of one synced dashboard_settings key must converge.
 *
 * Before: `_applyDashboardSetting` skipped only a strictly older op, so two
 * instances writing different values at the same Lamport each took the other's
 * and swapped for good. After: the row records the instance that wrote its
 * Lamport (`lamport_origin`, carried in the wire row) and the tie goes to the
 * greater origin id via `incomingLosesLww` (same rule as the Ramble tables).
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createClient } from "@libsql/client";
import { createDbClient } from "../servers/db.js";
import { InstanceSyncManager } from "../servers/sharing/instance-sync.js";
import { stampSql, ensureLamportOriginColumn, NO_ORIGIN_COLUMN, _failOriginEnsureForTest, normalizeLamportOrigin } from "../servers/shared/sync-stamp.js";
import * as ed from "../node_modules/@noble/ed25519/index.js";

const TEST_PRIV = Buffer.alloc(32, 0xAB);
const TEST_PUB_HEX = Buffer.from(await ed.getPublicKey(TEST_PRIV)).toString("hex");
const IDENTITY = { ed25519Priv: TEST_PRIV, ed25519Pubkey: TEST_PUB_HEX };

const ID_A = "aaaaaaaa-0000-4000-8000-000000000001";
const ID_B = "bbbbbbbb-0000-4000-8000-000000000002"; // ID_B > ID_A
const KEY = "profile_display_name";

function freshMgr(label, id) {
  const d = mkdtempSync(join(tmpdir(), `crow-m6-${label}-`));
  execFileSync(process.execPath, ["scripts/init-db.js"], { env: { ...process.env, CROW_DATA_DIR: d }, stdio: "pipe", cwd: join(import.meta.dirname, "..") });
  after(() => rmSync(d, { recursive: true, force: true }));
  const m = new InstanceSyncManager(IDENTITY, createDbClient(join(d, "crow.db")), id);
  m.feedsDisabled = false;
  m.emitted = [];
  m.outFeeds.set("peer-1", { append: async () => {} });
  // Capture the signed entry exactly as it would go to the peer's feed.
  m._appendToPeer = async (_peer, entry) => { m.emitted.push(entry); return "appended"; };
  return m;
}

/** A local write as emitChange makes it: the value, then the production stamp with this Crow's id. */
async function localWrite(m, value, ts) {
  await m.db.execute({
    sql: `INSERT INTO dashboard_settings (key, value, updated_at) VALUES (?, ?, datetime('now'))
          ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
    args: [KEY, value],
  });
  await m.db.execute(stampSql("dashboard_settings", { key: KEY }, ts, m.localInstanceId));
}
/** The wire row a Crow emits for its own live write. */
const wire = (value, origin) => ({ key: KEY, value, instance_id: null, ...(origin === undefined ? {} : { lamport_origin: origin }) });
async function read(m) {
  return (await m.db.execute({ sql: "SELECT value, lamport_ts, lamport_origin FROM dashboard_settings WHERE key = ?", args: [KEY] })).rows[0];
}

for (const deliverFirst of ["A", "B"]) {
  test(`MUTUAL tie (delivered ${deliverFirst} first): different values at the same Lamport converge on the greater origin`, async () => {
    const a = freshMgr(`mt-a-${deliverFirst}`, ID_A);
    const b = freshMgr(`mt-b-${deliverFirst}`, ID_B);
    await localWrite(a, "from-A", 14);
    await localWrite(b, "from-B", 14);
    const steps = [
      () => b._applyDashboardSetting("update", wire("from-A", ID_A), 14),
      () => a._applyDashboardSetting("update", wire("from-B", ID_B), 14),
    ];
    if (deliverFirst === "B") steps.reverse();
    for (const s of steps) await s(); // eslint-disable-line no-await-in-loop
    const ra = await read(a);
    const rb = await read(b);
    assert.equal(ra.value, rb.value, `diverged: A=${ra.value} B=${rb.value}`);
    assert.equal(ra.value, "from-B", "ID_B is the greater origin, so B's write wins on both");
    assert.equal(ra.lamport_origin, ID_B);
    assert.equal(rb.lamport_origin, ID_B);
  });
}

test("a NULL-origin local row loses an equal-Lamport tie to a stamped incoming", async () => {
  const m = freshMgr("null-local", ID_A);
  await m.db.execute({ sql: "INSERT INTO dashboard_settings (key, value, updated_at, lamport_ts) VALUES (?, 'legacy', datetime('now'), 14)", args: [KEY] });
  assert.equal((await read(m)).lamport_origin, null, "existing rows keep NULL");
  await m._applyDashboardSetting("update", wire("stamped", ID_B), 14);
  assert.equal((await read(m)).value, "stamped");
  assert.equal((await read(m)).lamport_origin, ID_B);
});

test("a stamped local row is NOT replaced at a tie by an origin-less (old peer) row", async () => {
  const m = freshMgr("stamped-local", ID_A);
  await localWrite(m, "mine", 14);
  await m._applyDashboardSetting("update", wire("old-peer"), 14);
  assert.equal((await read(m)).value, "mine");
});

test("a same-origin re-delivery applies once and changes nothing further", async () => {
  const m = freshMgr("redeliver", ID_A);
  await m._applyDashboardSetting("update", wire("v1", ID_B), 14);
  const first = await read(m);
  await m.db.execute({ sql: "UPDATE dashboard_settings SET updated_at = '2000-01-01 00:00:00' WHERE key = ?", args: [KEY] });
  await m._applyDashboardSetting("update", wire("v1", ID_B), 14);
  await m._applyDashboardSetting("update", wire("v1", ID_B), 14);
  const after2 = await read(m);
  assert.deepEqual({ ...after2 }, { ...first });
  const { rows } = await m.db.execute({ sql: "SELECT updated_at FROM dashboard_settings WHERE key = ?", args: [KEY] });
  assert.equal(rows[0].updated_at, "2000-01-01 00:00:00", "equal bytes + same origin is a no-op (no rewrite)");
});

test("strictly older is skipped and strictly newer applies, whatever the origins", async () => {
  const m = freshMgr("strict", ID_A);
  await localWrite(m, "mine", 14);
  await m._applyDashboardSetting("update", wire("older", ID_B), 13);
  assert.equal((await read(m)).value, "mine");
  await m._applyDashboardSetting("update", wire("newer", ID_A < ID_B ? "0000" : ID_A), 15);
  const r = await read(m);
  assert.equal(r.value, "newer");
  assert.equal(r.lamport_ts, 15);
});

test("a row from an old peer (no lamport_origin field) still applies, as NULL origin", async () => {
  const m = freshMgr("old-peer", ID_A);
  await m._applyDashboardSetting("update", wire("old-1"), 20);
  assert.deepEqual({ ...(await read(m)) }, { value: "old-1", lamport_ts: 20, lamport_origin: null });
  await m._applyDashboardSetting("update", wire("old-2"), 20); // two NULLs: apply-on-tie, as before
  assert.equal((await read(m)).value, "old-2");
});

test("a live emit stamps this Crow's origin on the row and carries it on the wire", async () => {
  const m = freshMgr("live", ID_B);
  await m.db.execute({ sql: "INSERT INTO dashboard_settings (key, value, updated_at) VALUES (?, 'live', datetime('now'))", args: [KEY] });
  const lamport = await m.emitChange("dashboard_settings", "update", { key: KEY, value: "live", instance_id: null });
  const r = await read(m);
  assert.equal(r.lamport_ts, lamport);
  assert.equal(r.lamport_origin, ID_B);
  assert.equal(m.emitted.length, 1);
  assert.equal(m.emitted[0].row.lamport_origin, ID_B);
});

test("a preserve-mode re-emit carries the ORIGINAL origin, not the re-emitter's", async () => {
  const m = freshMgr("preserve", ID_B);
  // A row that arrived from A at Lamport 40.
  await m._applyDashboardSetting("update", wire("from-A", ID_A), 40);
  const emitted = await m.emitChange("dashboard_settings", "update", { key: KEY, value: "from-A", instance_id: null, lamport_origin: ID_A }, { lamportTs: 40 });
  assert.equal(emitted, 40);
  assert.equal(m.emitted.at(-1).row.lamport_origin, ID_A, "wire row keeps the original writer");
  assert.equal((await read(m)).lamport_origin, ID_A, "local row is not restamped");
  // A pre-origin row re-emitted in preserve mode stays NULL on the wire.
  await m.emitChange("dashboard_settings", "update", { key: KEY, value: "from-A", instance_id: null }, { lamportTs: 40 });
  assert.equal(m.emitted.at(-1).row.lamport_origin, null);
});

test("reemitSyncableSettingsOnce re-emits each row with its stored origin", async () => {
  const m = freshMgr("reemit", ID_B);
  await m._applyDashboardSetting("update", wire("from-A", ID_A), 40);
  await m.reemitSyncableSettingsOnce();
  const e = m.emitted.find((x) => x.row?.key === KEY);
  assert.ok(e, "the setting was re-emitted");
  assert.equal(e.lamport_ts, 40);
  assert.equal(e.row.lamport_origin, ID_A);
  assert.equal((await read(m)).lamport_origin, ID_A);
});

test("the column is added idempotently to an existing DB that lacks it", async () => {
  const db = createClient({ url: "file::memory:" });
  await db.execute("CREATE TABLE dashboard_settings (key TEXT PRIMARY KEY, value TEXT, updated_at TEXT, lamport_ts INTEGER DEFAULT 0)");
  await db.execute("INSERT INTO dashboard_settings (key, value, lamport_ts) VALUES ('k', 'v', 5)");
  assert.equal(await ensureLamportOriginColumn(db, "dashboard_settings"), true);
  assert.equal(await ensureLamportOriginColumn(db, "dashboard_settings"), true);
  const cols = (await db.execute("PRAGMA table_info(dashboard_settings)")).rows.filter((r) => r.name === "lamport_origin");
  assert.equal(cols.length, 1);
  assert.equal((await db.execute("SELECT lamport_origin FROM dashboard_settings WHERE key='k'")).rows[0].lamport_origin, null);
  // A fresh (un-memoised) handle on the already-altered table is also a no-op.
  assert.equal(await ensureLamportOriginColumn(db, "not_a_synced_table"), false);
});

// ---------------------------------------------------------------------------
// Round 2: the REAL path (emitChange -> signed entry -> _applyEntry)
// ---------------------------------------------------------------------------

const ID_C = "cccccccc-0000-4000-8000-000000000003"; // ID_C > ID_B > ID_A

/** A live local save: the value row, then emitChange (mints, stamps, signs). Returns the signed entry. */
async function liveWrite(m, value) {
  await m.db.execute({
    sql: `INSERT INTO dashboard_settings (key, value, updated_at) VALUES (?, ?, datetime('now'))
          ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
    args: [KEY, value],
  });
  const before = m.emitted.length;
  await m.emitChange("dashboard_settings", "update", { key: KEY, value, instance_id: null });
  assert.equal(m.emitted.length, before + 1, "one entry emitted");
  return m.emitted.at(-1);
}
/** Deliver a signed entry through the receiver's real apply (signature check, then apply); it must emit nothing. */
async function deliver(to, fromId, entry) {
  const n = to.emitted.length;
  await to._applyEntry(fromId, entry);
  assert.equal(to.emitted.length, n, "applying a peer's entry must not emit");
}

for (const order of ["A-first", "B-first"]) {
  test(`REAL PATH mutual tie (${order}): two fresh instances mint lamport 1 and converge on value AND origin`, async () => {
    const a = freshMgr(`rp-a-${order}`, ID_A);
    const b = freshMgr(`rp-b-${order}`, ID_B);
    const ea = await liveWrite(a, "from-A");
    const eb = await liveWrite(b, "from-B");
    assert.equal(ea.lamport_ts, 1);
    assert.equal(eb.lamport_ts, 1, "both fresh instances mint the same lamport");
    assert.equal(ea.row.lamport_origin, ID_A);
    assert.equal(eb.row.lamport_origin, ID_B);
    const steps = [() => deliver(b, ID_A, ea), () => deliver(a, ID_B, eb)];
    if (order === "B-first") steps.reverse();
    for (const st of steps) await st(); // eslint-disable-line no-await-in-loop
    const ra = await read(a);
    const rb = await read(b);
    assert.deepEqual({ ...ra }, { ...rb });
    assert.equal(ra.value, "from-B");
    assert.equal(ra.lamport_origin, ID_B);
  });
}

test("REAL PATH relay: B forwards A's row via reemitSyncableSettingsOnce, origin stays A, A/B/C converge", async () => {
  const a = freshMgr("relay-a", ID_A);
  const b = freshMgr("relay-b", ID_B);
  const c = freshMgr("relay-c", ID_C);
  const ea = await liveWrite(a, "from-A");
  await deliver(b, ID_A, ea);
  assert.equal(await b.reemitSyncableSettingsOnce() >= 1, true);
  const fwd = b.emitted.find((e) => e.row?.key === KEY);
  assert.equal(fwd.instance_id, ID_B, "the forwarder is B");
  assert.equal(fwd.lamport_ts, 1, "preserve-mode keeps A's lamport");
  assert.equal(fwd.row.lamport_origin, ID_A, "forwarded row keeps the ORIGINAL origin");
  assert.equal((await read(b)).lamport_origin, ID_A, "B did not restamp itself");
  await deliver(c, ID_B, fwd);
  const rc = await read(c);
  assert.deepEqual({ ...rc }, { value: "from-A", lamport_ts: 1, lamport_origin: ID_A });
  assert.deepEqual({ ...(await read(a)) }, { ...rc });
  assert.deepEqual({ ...(await read(b)) }, { ...rc });
});

test("REAL PATH relay with a three-way tie: everyone ends on the greatest origin", async () => {
  const a = freshMgr("relay3-a", ID_A);
  const b = freshMgr("relay3-b", ID_B);
  const c = freshMgr("relay3-c", ID_C);
  const ea = await liveWrite(a, "from-A");
  const ec = await liveWrite(c, "from-C");
  await deliver(b, ID_A, ea);
  await b.reemitSyncableSettingsOnce();
  const fwd = b.emitted.find((e) => e.row?.key === KEY);
  await deliver(c, ID_B, fwd); // A's row (origin A) loses to C's own at the tie
  assert.equal((await read(c)).value, "from-C");
  await deliver(a, ID_C, ec);
  await deliver(b, ID_C, ec);
  for (const m of [a, b, c]) {
    assert.deepEqual({ ...(await read(m)) }, { value: "from-C", lamport_ts: 1, lamport_origin: ID_C });
  }
});

// ---------------------------------------------------------------------------
// LOW-1: wire and local stamp never disagree about the origin
// ---------------------------------------------------------------------------

test("LOW-1: a transient ensure failure on a table that HAS the column still stamps and sends the origin", async () => {
  const m = freshMgr("low1-busy", ID_B);
  try {
    for (const failures of [1, 2, 3]) { // retry recovers, then the column probe recovers
      _failOriginEnsureForTest(failures);
      const e = await liveWrite(m, `v${failures}`);
      assert.equal(e.row.lamport_origin, ID_B, `wire carries the origin (failures=${failures})`);
      assert.equal((await read(m)).lamport_origin, ID_B, `local stamp wrote it too (failures=${failures})`);
    }
  } finally { _failOriginEnsureForTest(0); }
});

test("LOW-1: a table that truly lacks the column sends NO origin on the wire and still stamps lamport_ts", async () => {
  const m = freshMgr("low1-absent", ID_B);
  try {
    await m.db.execute("ALTER TABLE dashboard_settings DROP COLUMN lamport_origin");
    _failOriginEnsureForTest(1000); // the ALTER can never put it back
    const e = await liveWrite(m, "no-col");
    assert.equal(Object.hasOwn(e.row, "lamport_origin"), false, "nothing the local row did not record");
    const r = (await m.db.execute({ sql: "SELECT lamport_ts FROM dashboard_settings WHERE key = ?", args: [KEY] })).rows[0];
    assert.equal(Number(r.lamport_ts), e.lamport_ts);
    // Apply still works on the column-less table.
    await m._applyDashboardSetting("update", wire("peer", ID_C), 5);
    assert.equal((await m.db.execute({ sql: "SELECT value FROM dashboard_settings WHERE key = ?", args: [KEY] })).rows[0].value, "peer");
  } finally { _failOriginEnsureForTest(0); }
});

// ---------------------------------------------------------------------------
// LOW-2: a no-origin stamp never leaves a foreign origin behind
// ---------------------------------------------------------------------------

test("LOW-2: an origin-less re-stamp (older code) clears lamport_origin; NO_ORIGIN_COLUMN leaves it alone", async () => {
  const m = freshMgr("low2", ID_A);
  await m._applyDashboardSetting("update", wire("v", ID_B), 7);
  await m.db.execute(stampSql("dashboard_settings", { key: KEY }, 8, NO_ORIGIN_COLUMN));
  assert.deepEqual({ ...(await read(m)) }, { value: "v", lamport_ts: 8, lamport_origin: ID_B });
  await m.db.execute(stampSql("dashboard_settings", { key: KEY }, 9));
  assert.deepEqual({ ...(await read(m)) }, { value: "v", lamport_ts: 9, lamport_origin: null });
  // The outbox-cap NULL re-stamp clears it too.
  await m._applyDashboardSetting("update", wire("w", ID_B), 10);
  await m.db.execute(stampSql("dashboard_settings", { key: KEY }, null));
  assert.equal((await read(m)).lamport_origin, null);
});

// ---------------------------------------------------------------------------
// NIT-1: origin shape cap
// ---------------------------------------------------------------------------

test("NIT-1: normalizeLamportOrigin accepts real and local ids, rejects the rest", () => {
  for (const ok of ["a".repeat(32), ID_A, "local-cli-mcp", "x".repeat(64)]) assert.equal(normalizeLamportOrigin(ok), ok);
  for (const bad of ["", "x".repeat(65), "has space", "a/b", "\u0000", 7, {}, [], null, undefined, "é"]) assert.equal(normalizeLamportOrigin(bad), null);
});

test("NIT-1: an over-long or malformed incoming origin is NULL on apply; a bad stored origin is NULL on re-emit", async () => {
  const m = freshMgr("nit1", ID_A);
  await m._applyDashboardSetting("update", wire("long", "z".repeat(100)), 5);
  assert.equal((await read(m)).lamport_origin, null, "over-long origin stored as NULL");
  await m._applyDashboardSetting("update", { key: KEY, value: "num", instance_id: null, lamport_origin: 12345 }, 6);
  assert.equal((await read(m)).lamport_origin, null);
  // A corrupt stored origin is not carried on the wire.
  await m.db.execute({ sql: "UPDATE dashboard_settings SET lamport_origin = ? WHERE key = ?", args: ["q".repeat(200), KEY] });
  await m.reemitSyncableSettingsOnce();
  assert.equal(m.emitted.find((e) => e.row?.key === KEY).row.lamport_origin, null);
});

// M6 LOW-A: a probe that fails for any reason other than a missing column must
// not read as "no column" (that would stamp a new lamport beside a stale origin
// while the wire carries none).
test("settingsOriginReady: only 'no such column' reads as absent", async () => {
  const { settingsOriginReady, _failOriginEnsureForTest } = await import("../servers/shared/sync-stamp.js");
  const fakeDb = (msg) => ({ execute: async () => { throw new Error(msg); } });
  _failOriginEnsureForTest(2);
  assert.equal(await settingsOriginReady(fakeDb("SQLITE_BUSY: database is locked")), true);
  _failOriginEnsureForTest(2);
  assert.equal(await settingsOriginReady(fakeDb("no such column: lamport_origin")), false);
  _failOriginEnsureForTest(0);
});
