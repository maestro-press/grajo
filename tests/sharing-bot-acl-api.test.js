// The bot sharing allow-list's owner route (servers/gateway/routes/sharing-bot-acl-api.js): session +
// CSRF, owner-only, ids in and KEYS PINNED FROM LIVE ROWS out, atomic writes, and no way for a caller
// to choose a key.
//
// Harness: tests/message-drafts-api.test.js's — a real init-db'd scratch crow.db copied per test, an
// ephemeral express app wired the way servers/gateway/index.js and dashboard/index.js wire it (a
// session stub, the dashboard's real CSRF middleware, then the real router), and the real allow-list
// store writing into the suite's scratch CROW_HOME. Requests are shaped like the owner's own page:
// the session cookie, the SERVER-BOUND CSRF token for that session, and the same-origin fetch
// metadata a browser writes.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import http from "node:http";
import Database from "better-sqlite3";
import { markFromLaptop } from "./helpers/off-box.js";
import { rmScratch } from "./helpers/safe-rm.js";

const root = mkdtempSync(join(tmpdir(), "sharing-bot-acl-api-"));
/** The scratch home, held in a constant: cleanup never re-reads the env (tests/helpers/safe-rm.js). */
const CROW_HOME = join(root, "home");
process.env.CROW_DATA_DIR = join(root, "master");
process.env.CROW_HOME = CROW_HOME;
delete process.env.CROW_DB_PATH;
mkdirSync(CROW_HOME, { recursive: true });
const REPO = new URL("..", import.meta.url).pathname;
const MASTER = join(root, "master", "crow.db");

const { default: express } = await import("express");
const { createHash } = await import("node:crypto");
const { createDbClient } = await import("../servers/db.js");
const { csrfMiddleware } = await import("../servers/gateway/dashboard/shared/csrf.js");
const { csrfTokenFor } = await import("./helpers/csrf-token.mjs");
const { SHARING_BOT_ACL_API_PREFIX, sharingBotAclRouter } = await import("../servers/gateway/routes/sharing-bot-acl-api.js");
const acl = await import("../servers/gateway/sharing-bot/acl.js");

const OWNER = "owner-local-password-session";
const SSO = "peer-sso-session";
const BASE = SHARING_BOT_ACL_API_PREFIX;
const PEER = { crowId: "crow:peer", name: "Peer", pubkey: "02" + "a".repeat(64) };
const OTHER = { crowId: "crow:other", name: "Other", pubkey: "02" + "b".repeat(64) };
const BOT = "hank";

const hashToken = (t) => createHash("sha256").update(t).digest("hex");
const servers = [];
const open = [];

after(() => {
  for (const server of servers) server.close();
  for (const db of open) { try { db.close(); } catch { /* ignore */ } }
  rmScratch(root);
});

before(() => {
  mkdirSync(join(root, "master"), { recursive: true });
  execFileSync(process.execPath, ["scripts/init-db.js"], {
    env: { ...process.env, CROW_DATA_DIR: join(root, "master") },
    stdio: "pipe",
    cwd: REPO,
  });
  const raw = new Database(MASTER);
  const insert = raw.prepare("INSERT INTO oauth_tokens (token, token_type, client_id, scopes, expires_at) VALUES (?, 'access', 'dashboard', ?, datetime('now','+1 day'))");
  insert.run(hashToken(OWNER), "dashboard");
  insert.run(hashToken(SSO), "dashboard sso src:peer-1");
  raw.pragma("wal_checkpoint(TRUNCATE)");
  raw.close();
});

let n = 0;

/** The scratch app: one per test, the real router and the real CSRF rail. */
async function setup() {
  // A fresh allow-list per test: the file lives in this file's scratch home.
  rmScratch(join(CROW_HOME, "secrets"));
  const dir = join(root, "t" + (++n));
  mkdirSync(dir);
  const crow = join(dir, "crow.db");
  copyFileSync(MASTER, crow);
  const db = createDbClient(crow);
  open.push(db);
  await db.execute({
    sql: `INSERT INTO contacts (crow_id, display_name, secp256k1_pubkey, ed25519_pubkey, contact_type)
          VALUES (?, ?, ?, ?, 'crow')`,
    args: [PEER.crowId, PEER.name, PEER.pubkey, "e".repeat(64)],
  });
  await db.execute({
    sql: `INSERT INTO contacts (crow_id, display_name, secp256k1_pubkey, ed25519_pubkey, contact_type)
          VALUES (?, ?, ?, ?, 'crow')`,
    args: [OTHER.crowId, OTHER.name, OTHER.pubkey, "f".repeat(64)],
  });
  const room = await db.execute({
    sql: "INSERT INTO contact_groups (name, room_uid, host_crow_id, mode) VALUES ('Den', ?, 'crow:me', 'addressed')",
    args: ["r".repeat(32)],
  });
  const roomId = Number(room.lastInsertRowid);
  const peerRow = await db.execute({ sql: "SELECT id FROM contacts WHERE crow_id = ?", args: [PEER.crowId] });
  await db.execute({
    sql: "INSERT INTO contact_group_members (group_id, contact_id) VALUES (?, ?)",
    args: [roomId, Number(peerRow.rows[0].id)],
  });
  await db.execute({ sql: "INSERT INTO contact_groups (name) VALUES ('Choir')" });

  const app = express();
  const sessionGate = (req, res, next) => {
    const cookie = String(req.headers.cookie || "");
    const match = /(?:^|;\s*)crow_session=([^;]+)/.exec(cookie);
    if (!match) return res.status(401).json({ error: "unauthorized" });
    req.dashboardSession = match[1];
    if (req.headers["x-test-from"] === "laptop") markFromLaptop(req);
    next();
  };
  const dash = express.Router();
  dash.use("/dashboard", csrfMiddleware);
  dash.use(sharingBotAclRouter(sessionGate, { openDb: () => createDbClient(crow), crowHome: process.env.CROW_HOME }));
  app.use(dash);
  // The global parser: this router parses its own 32kb body, and in production index.js skips the
  // global one for this prefix (`_hasOwnParser`). Mounting the global parser first here would mask a
  // router-side bug, so it is deliberately NOT mounted.

  const server = await new Promise((resolve) => {
    const listening = app.listen(0, "127.0.0.1", () => resolve(listening));
  });
  servers.push(server);
  const port = server.address().port;
  const origin = `http://127.0.0.1:${port}`;

  const call = (method, path, { body, token = OWNER, csrf, headers = {} } = {}) => {
    const payload = body === undefined ? null : JSON.stringify(body);
    const h = { ...(payload === null ? {} : { "content-type": "application/json", "content-length": Buffer.byteLength(payload) }) };
    if (token) h.cookie = "crow_session=" + token;
    if (token) {
      const value = csrf === undefined ? csrfTokenFor(token) : csrf;
      if (value) h["x-crow-csrf"] = value;
    }
    h["sec-fetch-site"] = "same-origin";
    h.origin = origin;
    h["x-test-from"] = "laptop";
    Object.assign(h, headers);
    return new Promise((resolve, reject) => {
      const req = http.request({ host: "127.0.0.1", port, method, path, headers: h }, (res) => {
        let text = "";
        res.on("data", (chunk) => { text += chunk; });
        res.on("end", () => {
          let json = null;
          try { json = JSON.parse(text); } catch { /* csrf refusals are plain text */ }
          resolve({ status: res.statusCode, text, json });
        });
      });
      req.on("error", reject);
      req.end(payload === null ? undefined : payload);
    });
  };

  return { db, crow, roomId, call };
}

/* -------------------------------------------------------------------- rails */

test("no session, a peer's SSO session, and a missing CSRF token are each refused before a write", async () => {
  const s = await setup();
  assert.equal((await s.call("GET", `${BASE}/${BOT}`, { token: null })).status, 401);
  assert.equal((await s.call("GET", `${BASE}/${BOT}`, { token: SSO })).status, 403);
  assert.equal((await s.call("GET", `${BASE}/${BOT}`, { token: SSO })).json.error, "owner_only");

  const noCsrf = await s.call("PUT", `${BASE}/${BOT}`, { body: { contacts: [PEER.crowId] }, csrf: null });
  assert.equal(noCsrf.status, 403);
  assert.match(noCsrf.text, /CSRF/);
  assert.equal(acl.readSharingBotAcl(process.env.CROW_HOME).acl[BOT], undefined, "nothing was written");

  // A cross-site shape is refused by the route's own rail, with a token that is otherwise valid.
  const crossSite = await s.call("PUT", `${BASE}/${BOT}`, {
    body: { contacts: [PEER.crowId] }, headers: { "sec-fetch-site": "cross-site" },
  });
  assert.equal(crossSite.status, 403);
  assert.equal(crossSite.json.error, "cross_site");
});

/* --------------------------------------------------------------------- reads */

test("GET offers the live contacts and groups, with what is allowed marked", async () => {
  const s = await setup();
  const res = await s.call("GET", `${BASE}/${BOT}`);
  assert.equal(res.status, 200, res.text);
  assert.deepEqual(res.json.entry, { contacts: [], groups: [], rate: { per_hour: acl.DEFAULT_RATE_PER_HOUR } }, "starting state: nobody");
  assert.deepEqual(res.json.contacts.map((contact) => [contact.crow_id, contact.allowed]).sort((a, b) => (a[0] < b[0] ? -1 : 1)),
    [[OTHER.crowId, false], [PEER.crowId, false]]);
  const room = res.json.groups.find((group) => group.group_id === s.roomId);
  assert.equal(room.kind, "room");
  assert.equal(room.member_count, 1);
  assert.equal(room.allowed, false);
  const plain = res.json.groups.find((group) => group.name === "Choir");
  assert.equal(plain.kind, "group", "a plain group is shown, and is not a room");
});

/* -------------------------------------------------------------------- writes */

test("PUT pins the keys from the live rows — the body names ids, never keys", async () => {
  const s = await setup();
  const res = await s.call("PUT", `${BASE}/${BOT}`, {
    body: { contacts: [PEER.crowId], groups: [s.roomId], rate: { per_hour: 5 } },
  });
  assert.equal(res.status, 200, res.text);
  assert.deepEqual(res.json.entry, {
    contacts: [{ crow_id: PEER.crowId, secp256k1_pubkey: PEER.pubkey }],
    groups: [{ id: s.roomId, members: [{ crow_id: PEER.crowId, secp256k1_pubkey: PEER.pubkey }] }],
    rate: { per_hour: 5 },
  });

  const path = acl.sharingBotAclPath(process.env.CROW_HOME);
  assert.equal(statSync(path).mode & 0o777, 0o600);
  assert.deepEqual(JSON.parse(readFileSync(path, "utf8"))[BOT], res.json.entry);

  // The section then shows what was allowed.
  const after1 = await s.call("GET", `${BASE}/${BOT}`);
  assert.equal(after1.json.contacts.find((contact) => contact.crow_id === PEER.crowId).allowed, true);
  assert.equal(after1.json.groups.find((group) => group.group_id === s.roomId).allowed, true);
});

test("a key of the caller's own choosing cannot be pinned: the body is refused, not honoured", async () => {
  const s = await setup();
  const res = await s.call("PUT", `${BASE}/${BOT}`, {
    body: {
      contacts: [{ crow_id: PEER.crowId, secp256k1_pubkey: "02" + "f".repeat(64) }],
    },
  });
  assert.equal(res.status, 400, res.text);
  assert.equal(res.json.error, "bad_input");
  assert.equal(acl.readSharingBotAcl(process.env.CROW_HOME).acl[BOT], undefined);

  // Unknown contacts and groups are refused with their own codes.
  assert.equal((await s.call("PUT", `${BASE}/${BOT}`, { body: { contacts: ["crow:nobody"] } })).json.error, "unknown_contact");
  assert.equal((await s.call("PUT", `${BASE}/${BOT}`, { body: { groups: [999] } })).json.error, "unknown_group");
  // A group with nobody in it could not reach anyone: refused at save time, not silently useless.
  const emptyRoom = Number((await s.db.execute({
    sql: "INSERT INTO contact_groups (name, room_uid) VALUES ('Empty', ?)",
    args: ["q".repeat(32)],
  })).lastInsertRowid);
  assert.equal((await s.call("PUT", `${BASE}/${BOT}`, { body: { groups: [emptyRoom] } })).json.error, "group_empty");
});

test("a re-keyed contact is re-pinned by saving again; the old pin is what the door checks", async () => {
  const s = await setup();
  assert.equal((await s.call("PUT", `${BASE}/${BOT}`, { body: { contacts: [PEER.crowId] } })).status, 200);
  await s.db.execute({ sql: "UPDATE contacts SET secp256k1_pubkey = ? WHERE crow_id = ?", args: ["02" + "9".repeat(64), PEER.crowId] });
  const saved = await s.call("PUT", `${BASE}/${BOT}`, { body: { contacts: [PEER.crowId] } });
  assert.equal(saved.status, 200, saved.text);
  assert.equal(saved.json.entry.contacts[0].secp256k1_pubkey, "02" + "9".repeat(64), "the new pin is the new live key");
});

test("DELETE removes the bot's entry (the 'remove messaging' undo) and is idempotent", async () => {
  const s = await setup();
  await s.call("PUT", `${BASE}/${BOT}`, { body: { contacts: [PEER.crowId] } });
  const removed = await s.call("DELETE", `${BASE}/${BOT}`);
  assert.equal(removed.status, 200, removed.text);
  assert.deepEqual(removed.json, { ok: true, removed: true });
  assert.equal(acl.readBotAcl(process.env.CROW_HOME, BOT).reason, "no_entry");
  assert.deepEqual((await s.call("DELETE", `${BASE}/${BOT}`)).json, { ok: true, removed: false });
});

test("an unreadable allow-list file is a refusal, not an empty one", async () => {
  const s = await setup();
  mkdirSync(join(process.env.CROW_HOME, "secrets"), { recursive: true, mode: 0o700 });
  const path = acl.sharingBotAclPath(process.env.CROW_HOME);
  writeFileSync(path, "{broken", { mode: 0o600 });
  assert.equal((await s.call("GET", BASE)).status, 409);
  assert.equal((await s.call("GET", `${BASE}/${BOT}`)).status, 409);
  const put = await s.call("PUT", `${BASE}/${BOT}`, { body: { contacts: [PEER.crowId] } });
  assert.equal(put.status, 409);
  assert.equal(put.json.error, "acl_unreadable");
  rmSync(path, { force: true });
});