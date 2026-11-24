/**
 * The satellite ADDRESS PIN (servers/shared/satellite-pins.js).
 *
 * `satellites.tailnet_host` is bot-writable crow.db; every satellite sender used to dial it and
 * attach a management-key signature plus the request body. The host is now pinned in
 * <CROW_HOME>/secrets/satellite-pins.json (the dir the pi sandbox hides), and this file proves:
 *
 *   1. the host form (one table of refusals: never trim, never repair);
 *   2. the pin store's shape, mode, atomicity and that its one-time backfill marker is its own file;
 *   3. the gate matrix (ok / no-pin / mismatch / bad-host) and that a refusal names nothing;
 *   4. per sender (satelliteFetch, listVault, putVaultFile, downloadVaultFile, deleteVaultFile,
 *      pullNewestBackup, readHealth): a row that is not at its pin dials NOTHING and reads no key,
 *      while a pinned, matching row reaches the fake fetch exactly once at https://<pinned host>/…
 *
 * The "reads no key" assertion is real, not implied: every sender is handed an `env` that THROWS on
 * any property access, so `loadMgmtKey` (which resolves the secrets dir through it) would fail
 * loudly if it ran before the gate.
 *
 * Scratch CROW_HOME, scratch DB, scratch pin store and scratch mgmt keys throughout: nothing here
 * reads or writes a real ~/.crow.
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";

const HOME = mkdtempSync(join(tmpdir(), "sat-pin-home-"));
process.env.CROW_HOME = HOME;
const SECRETS = join(HOME, "secrets");
mkdirSync(SECRETS, { recursive: true, mode: 0o700 });
// This file's own store and backfill marker: a parallel test file cannot see them.
const PINS = join(SECRETS, `satellite-pins-${process.pid}.json`);
const MARKER = join(SECRETS, `satellite-pin-backfill-${process.pid}.json`);
process.env.CROW_SATELLITE_PINS_PATH = PINS;
process.env.CROW_SATELLITE_PIN_BACKFILL_PATH = MARKER;

const dirs = [HOME];
after(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });

const P = await import("../servers/shared/satellite-pins.js");
const { generateKeypair, signResponse, sha256Hex } = await import("../servers/shared/satellite-protocol.js");
const { satelliteFetch } = await import("../servers/gateway/satellites/client.js");
const { readHealth } = await import("../servers/gateway/satellites/remote.js");
const { pullNewestBackup } = await import("../servers/gateway/satellites/backup-pull.js");
const O = await import("../servers/gateway/satellites/offsite.js");
const { createMgmtKey } = await import("../servers/gateway/satellites/mgmt-keys.js");
const { createDbClient } = await import("../servers/db.js");
const { SATELLITE_DDL } = await import("../servers/shared/satellite-schema.js");
const { insertSatellite } = await import("../servers/gateway/satellites/store.js");

// ── fixtures ────────────────────────────────────────────────────────────────

const SAT = "sat_aaaaaaaaaaaaaaaaaaaa"; // valid satellite id shape
const SAT2 = "sat_bbbbbbbbbbbbbbbbbbbb";
const HOST = "sat1.example.ts.net";
const MOVE = "sat2.example-tailnet.ts.net";

const satKey = generateKeypair();

/** Any key read runs through this env (loadMgmtKey -> secretsDir(env)) and blows up. */
const noKeyReads = new Proxy({}, {
  get() { throw new Error("a management key was read before the pin gate"); },
  has() { throw new Error("a management key was read before the pin gate"); },
});

const sha = (b) => createHash("sha256").update(b).digest("hex");

/** A counting fake fetch that answers every satellite route the senders use. */
function makeFetch({ download = Buffer.from("vault bytes") } = {}) {
  const calls = [];
  const json = (status, obj, nonce, extra = {}) => {
    const text = JSON.stringify(obj);
    const headers = { "content-type": "application/json", ...extra };
    if (nonce) headers["x-crow-sat-resp-sig"] = signResponse(satKey.privHex, { requestNonce: nonce, status, bodySha256: sha256Hex(text) });
    return new Response(text, { status, headers });
  };
  const fetchImpl = async (url, init = {}) => {
    const u = new URL(url);
    const method = (init.method || "GET").toUpperCase();
    const headers = init.headers || {};
    // Drain a streamed body (the vault PUT) so the request really completes.
    const sent = init.body;
    if (sent && typeof sent !== "string" && typeof sent[Symbol.asyncIterator] === "function") {
      for await (const _ of sent) { /* drained */ }
    }
    calls.push({ url: String(url), method, path: u.pathname, accept: headers.Accept });
    const nonce = headers["X-Crow-Sat-Nonce"];

    if (u.pathname === "/health") {
      return new Response(JSON.stringify({ protocol: 1, time: new Date().toISOString() }), { status: 200, headers: { "content-type": "application/json" } });
    }
    if (u.pathname === "/satellite/v1/status") return json(200, { ok: true }, nonce);
    if (u.pathname === "/satellite/v1/vault") return json(200, [], nonce);
    if (u.pathname.startsWith("/satellite/v1/vault/")) {
      if (method === "DELETE") return json(200, { ok: true }, nonce);
      if (String(headers.Accept || "").includes("application/octet-stream")) {
        return new Response(download, { status: 200, headers: { "content-type": "application/octet-stream" } });
      }
      return json(200, { ok: true }, nonce);
    }
    if (u.pathname === "/satellite/v1/bundles/gitea/backups") {
      return json(200, { backups: [{ name: "dump.zip", size: download.length, sha256: sha(download), created_at: "2026-11-02T00:00:00.000Z" }] }, nonce);
    }
    if (u.pathname === "/satellite/v1/bundles/gitea/backups/dump.zip") {
      return new Response(download, { status: 200, headers: { "content-type": "application/octet-stream" } });
    }
    return json(404, { error: "not_found" }, nonce);
  };
  return { fetchImpl, calls };
}

const row = (o = {}) => ({ id: SAT, name: "vps-1", tailnet_host: HOST, satellite_pubkey: satKey.pubHex, ...o });

let db;
before(async () => {
  const dir = mkdtempSync(join(tmpdir(), "sat-pin-db-"));
  dirs.push(dir);
  db = createDbClient(join(dir, "crow.db"));
  await db.executeMultiple(SATELLITE_DDL);
  const at = new Date().toISOString();
  const mk = (id, host) => insertSatellite(db, {
    id, name: `box-${id.slice(-2)}`, tailnet_host: host, satellite_pubkey: satKey.pubHex,
    mgmt_pubkey: "b".repeat(64), cert_json: "{}", cert_serial: "s1",
    cert_expires_at: at, primary_url: "https://crow.example.ts.net:8444", agent_protocol: 1,
    status: "active", created_at: at, last_seen_at: at,
  });
  await mk(SAT, HOST);
  await mk(SAT2, MOVE);
  // Real mgmt keys, so a positive control would fail on a missing key rather than pass by accident.
  createMgmtKey(SAT, { env: process.env });
  createMgmtKey(SAT2, { env: process.env });
});

// ── 1. the host form ────────────────────────────────────────────────────────

test("normalizeSatelliteHost: accepts exactly a MagicDNS name or a tailnet IPv4, and nothing with extras", () => {
  const rejects = [
    "evil.ts.net:8443", "evil.example:8443/x", "u@evil.ts.net", "evil.ts.net#x", "evil.ts.net/x",
    "evil.ts.net?x=1", "evil.ts.net.", " sat1.tailnet-example.ts.net", "sat1.tailnet-example.ts.net ", "sat1 tailnet-example.ts.net",
    "bücher.ts.net", "0x7f.1", "2130706433", "0177.0.0.1", "[::1]", "[fd7a:115c:a1e0::1]",
    "127.0.0.1", "localhost", "evil.example.com", "a.ts.net", "", null, undefined, 42, {}, [],
    "100.128.0.1", "100.63.0.1", "100.64.0.1:9", "https://sat1.example.ts.net", "SAT1.example.ts.net/",
  ];
  for (const input of rejects) assert.equal(P.normalizeSatelliteHost(input), null, `must refuse ${JSON.stringify(input)}`);

  assert.equal(P.normalizeSatelliteHost("sat1.tailnet-example.ts.net"), "sat1.tailnet-example.ts.net");
  assert.equal(P.normalizeSatelliteHost("Sat1.Tailnet-Example.TS.NET"), "sat1.tailnet-example.ts.net");
  assert.equal(P.normalizeSatelliteHost("100.64.20.5"), "100.64.20.5");
  assert.equal(P.normalizeSatelliteHost("100.127.255.254"), "100.127.255.254");
});

test("the pairing module re-exports the moved host form (valid input behaves as before)", async () => {
  const { normalizeHost } = await import("../servers/gateway/satellites/pairing.js");
  assert.equal(normalizeHost, P.normalizeSatelliteHost);
  assert.equal(normalizeHost("Satellite.Example.TS.NET"), "satellite.example.ts.net");
  assert.equal(normalizeHost("100.64.20.5"), "100.64.20.5");
});

// ── 2. the pin store ────────────────────────────────────────────────────────

const writeRawStore = (obj) => {
  writeFileSync(PINS, JSON.stringify(obj, null, 2), { mode: 0o600 });
  chmodSync(PINS, 0o600);
};

test("pin store: mode 0600, atomic replace, invalid host writes nothing", () => {
  rmSync(PINS, { force: true });
  assert.equal(P.getSatellitePin(SAT), null, "no store, no pin");

  assert.equal(P.pinSatelliteHost(SAT, HOST), true);
  assert.equal(statSync(PINS).mode & 0o777, 0o600);
  assert.equal(P.getSatellitePin(SAT), HOST);
  const first = JSON.parse(readFileSync(PINS, "utf-8"));
  assert.equal(first[SAT].pinned_host, HOST);
  assert.match(first[SAT].pinned_at, /^\d{4}-\d\d-\d\dT/);

  // A second write replaces the entry (no duplicate, no dead tmp file left behind).
  assert.equal(P.pinSatelliteHost(SAT, MOVE), true);
  const second = JSON.parse(readFileSync(PINS, "utf-8"));
  assert.equal(second[SAT].pinned_host, MOVE);
  assert.deepEqual(Object.keys(second), [SAT]);
  assert.deepEqual(P.listSatellitePins().map((p) => p.host).sort(), [MOVE]);

  // Refusals write NOTHING.
  const before = readFileSync(PINS, "utf-8");
  for (const bad of ["evil.example:8443", "u@evil.ts.net", "evil.ts.net/x", "", null, "localhost"]) {
    assert.equal(P.pinSatelliteHost(SAT, bad), false, `must refuse ${JSON.stringify(bad)}`);
  }
  assert.equal(P.pinSatelliteHost("not-a-satellite-id", HOST), false);
  assert.equal(readFileSync(PINS, "utf-8"), before, "a refused pin changed nothing");
});

test("pin store: a key that is not a satellite id or a pin entry is skipped, never iterated", () => {
  writeRawStore({
    done_at: "2026-11-01T00:00:00.000Z",
    __meta: { note: "x" },
    sat_zzzzzzzzzzzzzzzzzzzz: "a string, not an entry",
    [SAT]: { pinned_host: HOST, pinned_at: "2026-11-01T00:00:00.000Z" },
    [SAT2]: { pinned_host: 42 },
  });
  assert.deepEqual(P.listSatellitePins(), [{ id: SAT, host: HOST }]);
  assert.equal(P.getSatellitePin("done_at"), null);
  assert.equal(P.getSatellitePin("__meta"), null);
  assert.equal(P.getSatellitePin(SAT2), null, "an entry without a string pinned_host is no pin");

  // A malformed file reads as empty (never throws), and so does an unreadable one.
  writeFileSync(PINS, "{ not json", { mode: 0o600 });
  assert.equal(P.getSatellitePin(SAT), null);
  assert.deepEqual(P.listSatellitePins(), []);
  writeRawStore({ [SAT]: { pinned_host: HOST } });
  chmodSync(PINS, 0o644);
  assert.equal(P.getSatellitePin(SAT), null, "a group/world-readable pin store is not a trust boundary");
  rmSync(PINS, { force: true });
});

test("the backfill marker is its own file: writing a pin never creates or touches it", () => {
  assert.notEqual(P.satellitePinBackfillPath(), P.satellitePinsPath());
  rmSync(MARKER, { force: true });
  assert.equal(P.satellitePinBackfillDoneAt(), null);

  assert.equal(P.pinSatelliteHost(SAT, HOST), true);
  assert.equal(existsSync(MARKER), false, "a pin write never writes the marker");
  const store = JSON.parse(readFileSync(PINS, "utf-8"));
  assert.deepEqual(Object.keys(store), [SAT], "the marker is never a key in the store");

  const at = "2026-11-24T00:00:00.000Z";
  assert.equal(P.markSatellitePinBackfillDone(at), true);
  assert.equal(P.satellitePinBackfillDoneAt(), at);
  assert.equal(statSync(MARKER).mode & 0o777, 0o600);
  assert.equal(P.getSatellitePin(SAT), HOST, "the marker write never touches the pin");

  // unpin removes only the entry.
  assert.equal(P.unpinSatellite(SAT), true);
  assert.equal(P.getSatellitePin(SAT), null);
  assert.equal(P.unpinSatellite(SAT), false, "nothing left to remove");
  assert.equal(P.satellitePinBackfillDoneAt(), at);
  rmSync(MARKER, { force: true });
});

// ── 3. the gate ─────────────────────────────────────────────────────────────

test("satelliteUrlAllowed: ok / no-pin / bad-host / mismatch, in that order", () => {
  rmSync(PINS, { force: true });
  assert.deepEqual(P.satelliteUrlAllowed(SAT, HOST), { ok: false, reason: "no-pin" });
  assert.deepEqual(P.satelliteUrlAllowed(SAT, "evil.example:8443"), { ok: false, reason: "no-pin" });

  assert.equal(P.pinSatelliteHost(SAT, HOST), true);
  assert.deepEqual(P.satelliteUrlAllowed(SAT, HOST), { ok: true, host: HOST });
  assert.deepEqual(P.satelliteUrlAllowed(SAT, "SAT1.Example.TS.NET"), { ok: true, host: HOST }, "case is normalized before the compare");
  assert.deepEqual(P.satelliteUrlAllowed(SAT, MOVE), { ok: false, reason: "mismatch" });
  for (const bad of ["evil.example:8443", "u@example.ts.net", "evil.example/x", "", null, "127.0.0.1"]) {
    assert.deepEqual(P.satelliteUrlAllowed(SAT, bad), { ok: false, reason: "bad-host" }, `row ${JSON.stringify(bad)}`);
  }
  assert.deepEqual(P.satelliteUrlAllowed("not-an-id", HOST), { ok: false, reason: "no-pin" });
});

test("satelliteBaseUrlFor: built from the PIN, and its refusal names no host", () => {
  rmSync(PINS, { force: true });
  assert.equal(P.pinSatelliteHost(SAT, HOST), true);
  assert.equal(P.satelliteBaseUrlFor(row()), `https://${HOST}`);

  const attempts = [
    () => P.satelliteBaseUrlFor(row({ tailnet_host: MOVE })),
    () => P.satelliteBaseUrlFor(row({ tailnet_host: "evil.example:8443" })),
    () => P.satelliteBaseUrlFor(row({ id: SAT2 })), // no pin at all
  ];
  for (const attempt of attempts) {
    let err;
    try { attempt(); } catch (e) { err = e; }
    assert.ok(err, "must throw");
    assert.equal(err.code, "pin_refused");
    assert.equal(err.message, "satellite is not at its paired address");
    for (const host of [HOST, MOVE, "evil.example"]) {
      assert.ok(!err.message.includes(host), "the message names no host");
      assert.ok(!String(err).includes(host), "String(err) names no host");
    }
  }
});

// ── 4. the senders ──────────────────────────────────────────────────────────

const statusRow = (o = {}) => row(o);

/** The DB row of a fixture satellite, made to match the object a sender is handed. */
async function setDbHost(id, host) {
  await db.execute({ sql: "UPDATE satellites SET tailnet_host = ? WHERE id = ?", args: [host, id] });
}

/** Every sender, called with the row's host NOT at the pin (or with no pin), must dial nothing. */
async function assertRefused(sat, pinHost, label) {
  const { fetchImpl, calls } = makeFetch();
  const dest = join(HOME, `dest-${label}.vault`);
  rmSync(dest, { force: true });

  if (pinHost) assert.equal(P.pinSatelliteHost(sat.id, pinHost), true, "fixture pin");
  // pullNewestBackup reads the row from the DB, so it must carry the same (rewritten) host.
  await setDbHost(sat.id, sat.tailnet_host);

  // satelliteFetch: throws with code pin_refused.
  await assert.rejects(
    satelliteFetch(sat, { path: "/satellite/v1/status", caller: "owner-local", fetchImpl, env: noKeyReads }),
    (e) => e.code === "pin_refused" && e.message === "satellite is not at its paired address",
    `${label}: satelliteFetch must refuse`,
  );
  // listVault / deleteVaultFile: throw, with code pin_refused, before the key.
  await assert.rejects(O.listVault({ sat, fetchImpl, env: noKeyReads }), { code: "pin_refused" }, `${label}: listVault`);
  await assert.rejects(O.deleteVaultFile({ sat, name: "crow-db-20261101.vault", fetchImpl, env: noKeyReads }), { code: "pin_refused" }, `${label}: deleteVaultFile`);
  // putVaultFile / downloadVaultFile: their existing failure shapes, and the file stream is never opened.
  assert.deepEqual(await O.putVaultFile({ sat, file: "/nonexistent/never-opened.vault", size: 3, sha256: "0".repeat(64), fetchImpl, env: noKeyReads }),
    { status: 0, json: { error: "pin_refused" } }, `${label}: putVaultFile`);
  assert.deepEqual(await O.downloadVaultFile({ sat, name: "crow-db-20261101.vault", dest, size: 3, sha256: "0".repeat(64), fetchImpl, env: noKeyReads }),
    { ok: false, code: "pin_refused" }, `${label}: downloadVaultFile`);
  assert.equal(existsSync(dest), false);
  // pullNewestBackup: its existing failure shape.
  const pulled = await pullNewestBackup(sat.id, "gitea", { db, fetchImpl, env: noKeyReads, root: join(HOME, `root-${label}`) });
  assert.equal(pulled.pulled, false, `${label}: pullNewestBackup`);
  assert.equal(pulled.code, "pin_refused", `${label}: pullNewestBackup code`);
  // readHealth: unsigned, but gated too — null, as if unreachable.
  assert.equal(await readHealth(sat, { fetchImpl }), null, `${label}: readHealth`);

  assert.deepEqual(calls, [], `${label}: nothing was dialled (and no key was read — env would have thrown)`);
}

test("a rewritten row (mismatch) or an unpinned row sends NOTHING, reads no key, signs nothing", async () => {
  await assertRefused(row({ tailnet_host: MOVE }), HOST, "mismatch");
  await assertRefused(row({ tailnet_host: "evil.example:8443" }), HOST, "bad-host");
  // No pin for this satellite at all: the same refusal, on every sender.
  rmSync(PINS, { force: true });
  await assertRefused(row(), null, "no-pin");
});

test("a pinned, matching row reaches the fake fetch exactly once, at https://<pinned host>/…", async () => {
  rmSync(PINS, { force: true });
  assert.equal(P.pinSatelliteHost(SAT, HOST), true);
  await setDbHost(SAT, HOST);
  const sat = statusRow();

  // satelliteFetch
  {
    const { fetchImpl, calls } = makeFetch();
    const r = await satelliteFetch(sat, { path: "/satellite/v1/status", caller: "owner-local", fetchImpl });
    assert.deepEqual(r, { status: 200, json: { ok: true } });
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, `https://${HOST}/satellite/v1/status`);
  }

  // listVault
  {
    const { fetchImpl, calls } = makeFetch();
    assert.deepEqual(await O.listVault({ sat, fetchImpl }), []);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, `https://${HOST}/satellite/v1/vault`);
  }

  // putVaultFile (a real file, streamed)
  {
    const file = join(HOME, "crow-db-20261101.vault");
    writeFileSync(file, "vault bytes");
    const { fetchImpl, calls } = makeFetch();
    const r = await O.putVaultFile({ sat, file, size: 11, sha256: sha(Buffer.from("vault bytes")), fetchImpl });
    assert.equal(r.status, 200);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].method, "PUT");
    assert.equal(calls[0].url, `https://${HOST}/satellite/v1/vault/crow-db-20261101.vault`);
  }

  // downloadVaultFile
  {
    const bytes = Buffer.from("vault bytes");
    const dest = join(HOME, "downloaded.vault");
    const { fetchImpl, calls } = makeFetch({ download: bytes });
    const r = await O.downloadVaultFile({ sat, name: "crow-db-20261101.vault", dest, size: bytes.length, sha256: sha(bytes), fetchImpl });
    assert.equal(r.ok, true);
    assert.equal(readFileSync(dest, "utf8"), "vault bytes");
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, `https://${HOST}/satellite/v1/vault/crow-db-20261101.vault`);
  }

  // deleteVaultFile
  {
    const { fetchImpl, calls } = makeFetch();
    const r = await O.deleteVaultFile({ sat, name: "crow-db-20261101.vault", fetchImpl });
    assert.equal(r.status, 200);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].method, "DELETE");
    assert.equal(calls[0].url, `https://${HOST}/satellite/v1/vault/crow-db-20261101.vault`);
  }

  // pullNewestBackup: manifest, then the file.
  {
    const bytes = Buffer.from("dump bytes");
    const { fetchImpl, calls } = makeFetch({ download: bytes });
    const r = await pullNewestBackup(SAT, "gitea", { db, fetchImpl, root: join(HOME, "root-ok") });
    assert.equal(r.pulled, true, JSON.stringify(r));
    assert.equal(calls.length, 2);
    assert.equal(calls[0].url, `https://${HOST}/satellite/v1/bundles/gitea/backups`);
    assert.equal(calls[1].url, `https://${HOST}/satellite/v1/bundles/gitea/backups/dump.zip`);
  }

  // readHealth
  {
    const { fetchImpl, calls } = makeFetch();
    const h = await readHealth(sat, { fetchImpl });
    assert.ok(h && typeof h.time === "string");
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, `https://${HOST}/health`);
  }
});

test("env: the pin gate reads the SAME env the key read uses, so two stores never cross", async () => {
  // Two env objects naming two different pin stores. SAT is pinned in A only.
  const dirA = mkdtempSync(join(tmpdir(), "sat-pin-env-a-"));
  const dirB = mkdtempSync(join(tmpdir(), "sat-pin-env-b-"));
  dirs.push(dirA, dirB);
  const envA = { ...process.env, CROW_SATELLITE_PINS_PATH: join(dirA, "satellite-pins.json") };
  const envB = { ...process.env, CROW_SATELLITE_PINS_PATH: join(dirB, "satellite-pins.json") };
  assert.equal(P.pinSatelliteHost(SAT, HOST, { env: envA }), true);
  assert.equal(P.getSatellitePin(SAT, { env: envA }), HOST);
  assert.equal(P.getSatellitePin(SAT, { env: envB }), null, "env B never sees env A's pin");
  assert.deepEqual(P.satelliteUrlAllowed(SAT, HOST, { env: envB }), { ok: false, reason: "no-pin" });
  assert.equal(P.satelliteBaseUrlFor(statusRow(), { env: envA }), `https://${HOST}`);

  // env A: the transport dials at the pinned host (its key read uses the same env).
  {
    const { fetchImpl, calls } = makeFetch();
    assert.deepEqual(await satelliteFetch(statusRow(), { path: "/satellite/v1/status", caller: "owner-local", fetchImpl, env: envA }),
      { status: 200, json: { ok: true } });
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, `https://${HOST}/satellite/v1/status`);
  }
  // …and so does an off-site sender.
  {
    const { fetchImpl, calls } = makeFetch();
    assert.deepEqual(await O.listVault({ sat: statusRow(), fetchImpl, env: envA }), []);
    assert.equal(calls.length, 1);
  }

  // env B: no pin there, so both refuse `no-pin` and dial nothing.
  {
    const { fetchImpl, calls } = makeFetch();
    await assert.rejects(
      satelliteFetch(statusRow(), { path: "/satellite/v1/status", caller: "owner-local", fetchImpl, env: envB }),
      (e) => e.code === "pin_refused" && e.reason === "no-pin",
      "satelliteFetch with env B refuses",
    );
    await assert.rejects(O.listVault({ sat: statusRow(), fetchImpl, env: envB }),
      (e) => e.code === "pin_refused" && e.reason === "no-pin", "listVault with env B refuses");
    assert.deepEqual(calls, [], "env B dialled nothing");
  }

  // The row-shaped helper (used by renewal) reads the row inside the pin module and honours env.
  assert.equal(P.satelliteRowAllowed(statusRow(), { env: envA }).ok, true);
  assert.deepEqual(P.satelliteRowAllowed(statusRow(), { env: envB }), { ok: false, reason: "no-pin" });
});

// ── 5. symlinks ─────────────────────────────────────────────────────────────

test("a symlinked store or marker is never read through and never written over", () => {
  // The decoy holds a VALID pin entry at another host: reading through the link would trust it.
  const decoy = join(HOME, "decoy-store.json");
  writeFileSync(decoy, JSON.stringify({ [SAT]: { pinned_host: MOVE } }, null, 2), { mode: 0o600 });
  chmodSync(decoy, 0o600);
  const decoyBefore = readFileSync(decoy, "utf-8");
  rmSync(PINS, { force: true });
  symlinkSync(decoy, PINS);
  assert.equal(P.getSatellitePin(SAT), null, "a symlinked store reads as no pins");
  assert.deepEqual(P.listSatellitePins(), []);
  assert.deepEqual(P.satelliteUrlAllowed(SAT, MOVE), { ok: false, reason: "no-pin" }, "senders refuse no-pin");
  let refused;
  try { P.satelliteBaseUrlFor(row({ tailnet_host: MOVE })); } catch (e) { refused = e; }
  assert.equal(refused?.reason, "no-pin", "the base URL is refused too");
  assert.equal(P.pinSatelliteHost(SAT, HOST), false, "a symlinked store is never written");
  assert.equal(readFileSync(decoy, "utf-8"), decoyBefore, "the decoy is unchanged");
  assert.ok(lstatSync(PINS).isSymbolicLink(), "the link itself is still there, not replaced");

  // The one-time marker: a link reads as UNUSABLE (so the backfill would retry), and the retry
  // cannot turn into an overwrite of whatever the link names.
  const markerDecoy = join(HOME, "decoy-marker.json");
  writeFileSync(markerDecoy, JSON.stringify({ done_at: "2026-11-01T00:00:00.000Z" }, null, 2), { mode: 0o600 });
  chmodSync(markerDecoy, 0o600);
  const markerBefore = readFileSync(markerDecoy, "utf-8");
  rmSync(MARKER, { force: true });
  symlinkSync(markerDecoy, MARKER);
  assert.equal(P.satellitePinBackfillDoneAt(), null, "a symlinked marker is unusable, not 'done'");
  assert.equal(P.markSatellitePinBackfillDone(), false, "…and is never written over");
  assert.equal(readFileSync(markerDecoy, "utf-8"), markerBefore, "the marker decoy is unchanged");
  assert.ok(lstatSync(MARKER).isSymbolicLink());

  rmSync(PINS, { force: true });
  rmSync(MARKER, { force: true });
});