/**
 * The owner-run satellite ADDRESS pin CLI (scripts/cli/satellite-pin.js).
 *
 * `satellites.tailnet_host` is bot-writable, so the host a satellite is dialled at is pinned in
 * <CROW_HOME>/secrets/satellite-pins.json. When a satellite legitimately moves, every sender
 * refuses until the owner runs this CLI. Here the REAL script is spawned as a child process with a
 * scratch CROW_HOME, DB and pin store, and the file proves:
 *
 *   - a valid pin write succeeds and prints the ID only (never the host);
 *   - `--show` prints `<id> <pinned_host|none>`, adds `row-differs` for a row that disagrees with
 *     its pin, and `revoked` for a revoked row — and NEVER the row's address or a command built
 *     from it;
 *   - a URL, a port, a bad host and an unknown id are all refused, and a refusal never echoes the
 *     input;
 *   - crow.db is byte-for-byte unchanged by every run (the CLI opens it read-only).
 *
 * Scratch dirs throughout: nothing here reads or writes a real ~/.crow.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import Database from "better-sqlite3";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

const REPO = new URL("../", import.meta.url).pathname;
const CLI = join(REPO, "scripts", "cli", "satellite-pin.js");

const { SATELLITE_DDL } = await import("../servers/shared/satellite-schema.js");

const dirs = [];
after(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });

const HOST_A = "sat-a.example.ts.net";
const HOST_B = "sat-b.example.ts.net";
const HOST_C = "sat-c.example.ts.net";
const HOST_D = "sat-d.example.ts.net";
const PIN_C = "pin-c.example.ts.net";
const PIN_E = "pin-e.example.ts.net";
const BAD_ROW = "evil.example:8443";
const SAT_A = "sat_aaaaaaaaaaaaaaaaaaaa";
const SAT_B = "sat_bbbbbbbbbbbbbbbbbbbb";
const SAT_C = "sat_cccccccccccccccccccc";
const SAT_D = "sat_dddddddddddddddddddd";
const SAT_E = "sat_eeeeeeeeeeeeeeeeeeee";
const SAT_UNKNOWN = "sat_zzzzzzzzzzzzzzzzzzzz";

/** A scratch home + crow.db with `rows` + its own pin store and backfill marker. */
function setup(rows = []) {
  const home = mkdtempSync(join(tmpdir(), "satpin-cli-home-"));
  const data = mkdtempSync(join(tmpdir(), "satpin-cli-data-"));
  dirs.push(home, data);
  const dbPath = join(data, "crow.db");
  const db = new Database(dbPath);
  db.exec(SATELLITE_DDL);
  const ins = db.prepare(`INSERT INTO satellites (id, name, tailnet_host, satellite_pubkey, mgmt_pubkey, cert_json,
      cert_serial, cert_expires_at, primary_url, agent_protocol, status, created_at)
    VALUES (?, ?, ?, ?, ?, '{}', ?, '2027-01-01T00:00:00.000Z', 'https://crow.example.ts.net:8444', 1, ?, ?)`);
  let n = 0;
  for (const r of rows) {
    ins.run(r.id, r.id, r.host, "a".repeat(64), "b".repeat(64), `s-${r.id}`, r.status || "active",
      new Date(Date.UTC(2026, 10, 1, 0, 0, n++)).toISOString());
  }
  db.close();
  const pins = join(home, "secrets", "satellite-pins.json");
  const env = {
    ...process.env,
    CROW_HOME: home,
    CROW_DB_PATH: dbPath,
    CROW_SATELLITE_PINS_PATH: pins,
    CROW_SATELLITE_PIN_BACKFILL_PATH: join(home, "secrets", "satellite-pin-backfill.json"),
  };
  delete env.CROW_DATA_DIR;
  return { home, dbPath, pins, env };
}

function run(env, ...args) {
  const res = spawnSync(process.execPath, [CLI, ...args], { cwd: REPO, env, encoding: "utf8", timeout: 60000 });
  return { code: res.status, out: `${res.stdout || ""}${res.stderr || ""}`, stdout: res.stdout || "", stderr: res.stderr || "" };
}

const pinStore = (path) => {
  try { return JSON.parse(readFileSync(path, "utf8")); } catch { return null; }
};

/** Write a 0600 pin store (a store another writer could have left there). */
function writePinStore(path, obj) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  writeFileSync(path, `${JSON.stringify(obj, null, 2)}\n`, { mode: 0o600 });
  chmodSync(path, 0o600);
}

test("a valid re-pin writes the store, prints the ID only, and leaves crow.db untouched", () => {
  const s = setup([{ id: SAT_A, host: HOST_A }]);
  const before = readFileSync(s.dbPath);
  const r = run(s.env, SAT_A, "Sat-A2.Example.TS.NET");
  assert.equal(r.code, 0, r.out);
  assert.equal(r.stdout.trim(), SAT_A, "the success line names the id only");
  assert.equal(r.out.includes("sat-a2"), false, "the host is never echoed");
  assert.equal(pinStore(s.pins)[SAT_A].pinned_host, "sat-a2.example.ts.net", "the host was normalized and stored");
  assert.ok(readFileSync(s.dbPath).equals(before), "crow.db is byte-for-byte unchanged");
});

test("--show lists the pin store and the db, flags row-differs and revoked, and never names a row address", () => {
  const s = setup([
    { id: SAT_A, host: HOST_A },
    { id: SAT_B, host: HOST_B },
    { id: SAT_C, host: BAD_ROW },
    { id: SAT_D, host: HOST_D, status: "revoked" },
  ]);
  // A matches its pin; C was pinned elsewhere; D is revoked.
  for (const [id, host] of [[SAT_A, HOST_A], [SAT_C, PIN_C], [SAT_D, HOST_D]]) {
    const r = run(s.env, id, host);
    assert.equal(r.code, 0, r.out);
  }
  // E has a pin and no row at all: an entry only the pin store knows.
  const store = pinStore(s.pins);
  store[SAT_E] = { pinned_host: PIN_E, pinned_at: "2026-11-01T00:00:00.000Z" };
  writePinStore(s.pins, store);

  const before = readFileSync(s.dbPath);
  const show = run(s.env, "--show");
  assert.equal(show.code, 0, show.out);
  const lines = show.stdout.split("\n").filter(Boolean);
  assert.deepEqual(lines, [
    `${SAT_A} ${HOST_A}`,
    `${SAT_B} none`,
    `${SAT_C} ${PIN_C} row-differs`,
    `${SAT_D} ${HOST_D} revoked`,
    `${SAT_E} ${PIN_E}`,
  ], show.stdout);
  assert.equal(show.out.includes("evil.example"), false, "the row's address is never printed");
  assert.equal(/https?:\/\//.test(show.out), false, "no URL is printed");
  assert.equal(/node scripts\/cli\/satellite-pin\.js\s+sat_/.test(show.out), false, "no runnable command is offered");
  assert.ok(readFileSync(s.dbPath).equals(before), "--show never writes crow.db");
});

test("a URL, a port, a bad host and an unknown id are refused without echoing the input", () => {
  const s = setup([{ id: SAT_A, host: HOST_A }]);
  const before = readFileSync(s.dbPath);
  const cases = [
    ["https://sat-a.example.ts.net", "https://sat-a.example.ts.net"],
    ["sat-a.example.ts.net:443", "sat-a.example.ts.net:443"],
    ["sat-a.example.ts.net/path", "sat-a.example.ts.net/path"],
    ["not a host", "not a host"],
    ["127.0.0.1", "127.0.0.1"],
  ];
  for (const [host, echoed] of cases) {
    const r = run(s.env, SAT_A, host);
    assert.equal(r.code, 1, `${host}: ${r.out}`);
    assert.equal(r.out.includes(echoed), false, `the input must not be echoed: ${r.out}`);
    assert.equal(pinStore(s.pins), null, "a refusal writes nothing");
  }
  const unknown = run(s.env, SAT_UNKNOWN, HOST_B);
  assert.equal(unknown.code, 1);
  assert.equal(unknown.out.includes(HOST_B), false, "nothing was written and the host is not echoed");
  assert.equal(pinStore(s.pins), null);
  // No argument at all is a usage error, not a crash.
  assert.equal(run(s.env).code, 1);
  assert.ok(readFileSync(s.dbPath).equals(before), "no refusal touched crow.db");
});

test("an id that already has a pin may be re-pinned even when the db holds no such row", () => {
  const s = setup([{ id: SAT_A, host: HOST_A }]);
  assert.equal(run(s.env, SAT_A, HOST_A).code, 0);
  // The row goes away (a revoked row pruned by hand, a restore): the pin still names a satellite.
  const db = new Database(s.dbPath);
  db.prepare("DELETE FROM satellites WHERE id = ?").run(SAT_A);
  db.close();
  const again = run(s.env, SAT_A, HOST_B);
  assert.equal(again.code, 0, again.out);
  assert.equal(pinStore(s.pins)[SAT_A].pinned_host, HOST_B);
});