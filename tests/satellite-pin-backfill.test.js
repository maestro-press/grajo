/**
 * The ONE-TIME boot backfill of satellite address pins (servers/gateway/boot/satellite-pin-backfill.js).
 *
 * `satellites.tailnet_host` is bot-writable, so every sender dials the host pinned in
 * <CROW_HOME>/secrets/satellite-pins.json instead. A satellite paired before the pin existed has
 * no entry, and this backfill pins it ONCE from its current row — the last moment that row is
 * still the operator's. This file proves the four properties that make that safe:
 *
 *   1. it pins only NON-revoked, unpinned rows whose value normalizes; an unnormalizable row is
 *      left unpinned and the log names the ID only (never the value);
 *   2. the marker is its own file, so a rewrite of the row — or of the pins file — can never cause
 *      a second pin;
 *   3. no marker is written on a read it could not make (not-migrated DB);
 *   4. no marker is written when a pin write failed, so the next boot retries.
 *
 * Scratch HOME / DB / pin store / marker throughout: nothing here reads or writes a real ~/.crow.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const HOME = mkdtempSync(join(tmpdir(), "satpin-bf-home-"));
process.env.CROW_HOME = HOME;
const dirs = [HOME];
after(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });

const { runSatellitePinBackfill } = await import("../servers/gateway/boot/satellite-pin-backfill.js");
const Pins = await import("../servers/shared/satellite-pins.js");
const { createDbClient } = await import("../servers/db.js");
const { SATELLITE_DDL } = await import("../servers/shared/satellite-schema.js");

const HOST_A = "sat-a.example.ts.net";
const HOST_B = "sat-b.example.ts.net";
const HOST_C = "sat-c.example.ts.net";
const HOST_D = "sat-d.example.ts.net";
const HOST_E = "sat-e.example.ts.net";
const PINNED_E = "old-pin.example.ts.net";
const BAD = "evil.example:8443"; // a row value a string compare would miss, a URL parser would dial
const SAT_A = "sat_aaaaaaaaaaaaaaaaaaaa";
const SAT_B = "sat_bbbbbbbbbbbbbbbbbbbb";
const SAT_C = "sat_cccccccccccccccccccc";
const SAT_D = "sat_dddddddddddddddddddd";
const SAT_E = "sat_eeeeeeeeeeeeeeeeeeee";

let seq = 0;
/** This test's own pin store + marker (the module resolves both at CALL time). */
function scope(name) {
  const dir = mkdtempSync(join(tmpdir(), `satpin-bf-${name}-`));
  dirs.push(dir);
  const pins = join(dir, "satellite-pins.json");
  const marker = join(dir, "satellite-pin-backfill.json");
  process.env.CROW_SATELLITE_PINS_PATH = pins;
  process.env.CROW_SATELLITE_PIN_BACKFILL_PATH = marker;
  return { dir, pins, marker };
}

const at = (n) => new Date(Date.UTC(2026, 10, 1, 0, 0, n)).toISOString();

/** A crow.db with the satellite tables and `rows` (each { id, host, status }), or no tables. */
async function makeDb(rows = [], { migrate = true } = {}) {
  const dir = mkdtempSync(join(tmpdir(), `satpin-bf-db-${seq++}-`));
  dirs.push(dir);
  const path = join(dir, "crow.db");
  const db = createDbClient(path);
  if (migrate) {
    await db.executeMultiple(SATELLITE_DDL);
    let n = 0;
    for (const r of rows) {
      await db.execute({
        sql: `INSERT INTO satellites (id, name, tailnet_host, satellite_pubkey, mgmt_pubkey, cert_json, cert_serial,
                cert_expires_at, primary_url, agent_protocol, status, created_at)
              VALUES (?, ?, ?, ?, ?, '{}', ?, ?, 'https://crow.example.ts.net:8444', 1, ?, ?)`,
        args: [r.id, r.id, r.host, "a".repeat(64), "b".repeat(64), `s-${r.id}`, at(0), r.status || "active", at(n++)],
      });
    }
  }
  db.close();
  return { path, createDbClient: () => createDbClient(path) };
}

const run = (db, logs) => runSatellitePinBackfill({
  createDbClient: db.createDbClient,
  log: (m) => logs.push(m),
  warn: (m) => logs.push(m),
});

const noHostIn = (logs, hosts) => {
  for (const line of logs) {
    for (const h of hosts) assert.equal(line.includes(h), false, `a log line names a host: ${line}`);
    assert.equal(/https?:\/\//.test(line), false, `a log line carries a URL: ${line}`);
  }
};

test("pins each non-revoked unpinned row once, leaves a bad row unpinned, skips revoked, logs ids only", async () => {
  const s = scope("once");
  // SAT_E is already pinned (a hand-written pin): its row must never move it.
  assert.equal(Pins.pinSatelliteHost(SAT_E, PINNED_E), true);
  const db = await makeDb([
    { id: SAT_A, host: HOST_A },
    { id: SAT_B, host: HOST_B },
    { id: SAT_C, host: BAD },
    { id: SAT_D, host: HOST_D, status: "revoked" },
    { id: SAT_E, host: HOST_E },
  ]);
  const logs = [];
  const r = await run(db, logs);
  assert.equal(r.ran, true);
  assert.equal(r.pinned, 2, JSON.stringify(r));
  assert.equal(r.skipped, 3, JSON.stringify(r));
  assert.equal(r.pending, 0);
  assert.equal(Pins.getSatellitePin(SAT_A), HOST_A);
  assert.equal(Pins.getSatellitePin(SAT_B), HOST_B);
  assert.equal(Pins.getSatellitePin(SAT_C), null, "an address that does not normalize is never pinned");
  assert.equal(Pins.getSatellitePin(SAT_D), null, "a revoked row is skipped");
  assert.equal(Pins.getSatellitePin(SAT_E), PINNED_E, "an existing pin is left untouched");
  assert.ok(Pins.satellitePinBackfillDoneAt(), "the one-time marker was written");
  assert.ok(existsSync(s.marker));
  assert.equal(logs.filter((l) => l.startsWith("[satellite-pin] pinned ")).length, 1, logs.join("\n"));
  assert.ok(logs.some((l) => l === `[satellite-pin] pinned 2 satellite(s): ${SAT_A}, ${SAT_B}`), logs.join("\n"));
  assert.ok(logs.some((l) => l === `[satellite-pin] ${SAT_C} left unpinned (its address is not a valid satellite address)`), logs.join("\n"));
  noHostIn(logs, [HOST_A, HOST_B, HOST_C, HOST_D, HOST_E, PINNED_E, "evil.example", "8443"]);
  // The marker is its own file, never a key in the store.
  const store = JSON.parse(readFileSync(s.pins, "utf-8"));
  assert.deepEqual(Object.keys(store).sort(), [SAT_A, SAT_B, SAT_E].sort());
});

test("a second run does nothing, even after a row is rewritten; the pins file is never re-trusted", async () => {
  const s = scope("idempotent");
  const db = await makeDb([{ id: SAT_A, host: HOST_A }]);
  const first = [];
  await run(db, first);
  assert.equal(Pins.getSatellitePin(SAT_A), HOST_A);
  const doneAt = Pins.satellitePinBackfillDoneAt();
  assert.ok(doneAt);

  // A bot rewrites the row, and a brand new satellite appears: the marker means neither is pinned.
  const dup = db.createDbClient();
  await dup.execute({ sql: "UPDATE satellites SET tailnet_host = ? WHERE id = ?", args: [HOST_B, SAT_A] });
  await dup.execute({
    sql: `INSERT INTO satellites (id, name, tailnet_host, satellite_pubkey, mgmt_pubkey, cert_json, cert_serial,
            cert_expires_at, primary_url, agent_protocol, status, created_at)
          VALUES (?, ?, ?, ?, ?, '{}', ?, ?, 'https://crow.example.ts.net:8444', 1, 'active', ?)`,
    args: [SAT_C, SAT_C, HOST_C, "a".repeat(64), "b".repeat(64), "s-late", at(5), at(5)],
  });
  dup.close();
  const second = [];
  const r = await run(db, second);
  assert.equal(r.ran, false);
  assert.equal(r.alreadyDoneAt, doneAt);
  assert.deepEqual(second, [], "a second boot logs nothing");
  assert.equal(Pins.getSatellitePin(SAT_A), HOST_A, "the rewritten row did not move the pin");
  assert.equal(Pins.getSatellitePin(SAT_C), null, "a row written after the marker is never pinned");

  // Deleting or rewriting the pins FILE does not re-trigger it: the marker is its own file.
  rmSync(s.pins, { force: true });
  assert.equal((await run(db, [])).ran, false);
  assert.equal(Pins.getSatellitePin(SAT_A), null);
  writeFileSync(s.pins, JSON.stringify({ [SAT_B]: { pinned_host: HOST_B } }), { mode: 0o600 });
  assert.equal((await run(db, [])).ran, false, "a hand-written store does not make the backfill run again");
  assert.equal(Pins.getSatellitePin(SAT_A), null);
  assert.equal(Pins.satellitePinBackfillDoneAt(), doneAt);
});

test("a not-migrated DB (or an unreadable one) writes NO marker, so the next boot retries", async () => {
  const s = scope("not-migrated");
  const db = await makeDb([], { migrate: false });
  const logs = [];
  const r = await run(db, logs);
  assert.equal(r.ran, true);
  assert.equal(r.pinned, 0);
  assert.equal(existsSync(s.marker), false, "no marker without a satellite table");
  assert.equal(Pins.satellitePinBackfillDoneAt(), null);
  assert.ok(logs.some((l) => /retry on the next boot/.test(l)), logs.join("\n"));
  noHostIn(logs, [HOST_A]);
});

test("zero satellites: the marker is written (there is nothing to trust later)", async () => {
  const s = scope("empty");
  const db = await makeDb([]);
  const r = await run(db, []);
  assert.equal(r.ran, true);
  assert.equal(r.pinned, 0);
  assert.ok(existsSync(s.marker));
  assert.ok(Pins.satellitePinBackfillDoneAt());
});

test("a failed pin write writes NO marker, and the next boot (with a working store) retries", async () => {
  const s = scope("write-failed");
  const db = await makeDb([{ id: SAT_A, host: HOST_A }]);
  // A store whose parent is a regular file: every pin write fails.
  const blocker = join(s.dir, "blocker");
  writeFileSync(blocker, "x");
  const goodPins = s.pins;
  process.env.CROW_SATELLITE_PINS_PATH = join(blocker, "satellite-pins.json");
  const logs = [];
  const r = await run(db, logs);
  assert.equal(r.ran, true);
  assert.equal(r.pinned, 0);
  assert.equal(r.pending, 1);
  assert.equal(existsSync(s.marker), false, "no marker when a pin write failed");
  assert.ok(logs.some((l) => /will run again on the next boot/.test(l)), logs.join("\n"));
  noHostIn(logs, [HOST_A]);

  // Retry with the real store: the row is pinned now, and the marker lands.
  process.env.CROW_SATELLITE_PINS_PATH = goodPins;
  const second = [];
  const r2 = await run(db, second);
  assert.equal(r2.ran, true);
  assert.equal(r2.pinned, 1);
  assert.equal(Pins.getSatellitePin(SAT_A), HOST_A);
  assert.ok(Pins.satellitePinBackfillDoneAt());
  noHostIn(second, [HOST_A]);
});