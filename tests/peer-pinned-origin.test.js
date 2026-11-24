/**
 * The paired gateway ORIGIN pin (security stopgap, 2026-10-06).
 *
 * `crow_instances.gateway_url` is bot-writable (a contained bot has crow.db
 * bound read-write, and instance sync writes the row), so every sender of a
 * peer credential — the peer bearer, or a pair-key signature — used to take its
 * destination from a row a bot could rewrite, and the owner's next call handed
 * the bearer to the bot's own server. The peer's gateway origin is now recorded
 * in <CROW_HOME>/secrets/peer-tokens.json (which the pi sandbox hides) at
 * pairing, and a credential may only go to a URL whose origin is that pin.
 *
 * This file proves, per sender, that a rewritten row sends NOTHING: a stub
 * server stands in for "the bot's own server" and records every request and
 * every header it sees — it must see zero requests, which is stronger than
 * "no Authorization header". The positive control on each leg reaches the
 * pinned origin and does carry the credential, so a leg cannot pass by
 * refusing everything.
 *
 * Scratch CROW_HOME / DB / credential store throughout: nothing here reads or
 * writes a real ~/.crow.
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes, randomUUID } from "node:crypto";
import express from "express";
import Database from "better-sqlite3";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { createDbClient } from "../servers/db.js";
import { peerRelayRouter } from "../servers/gateway/routes/peer-relay.js";
import { createRemoteInstanceClient } from "../servers/gateway/proxy.js";
import { createRemoteRouterClient } from "../servers/gateway/ai/remote-voice-tools.js";
import { forwardSignedRequest } from "../servers/shared/peer-forward.js";
import { ensurePeerRelayToken } from "../servers/gateway/local-token.js";
import { initGatewayActorKey, signPeerRelayActor } from "../scripts/pi-bots/actor-sig.mjs";
import { runPeerOriginBackfill } from "../servers/gateway/boot/peer-origin-backfill.js";
import { reconcilePeerCreds } from "../servers/gateway/peer-trust-sweeper.js";
import { main as peerPinMain } from "../scripts/cli/peer-pin.js";
import * as PC from "../servers/shared/peer-credentials.js";

// ---- a credential store of this file's own, inside the scratch Crow home ----
// (inside secrets/, so the store is never flagged as bot-readable; per pid, so a
// parallel test file cannot see these peers).
const secretsDir = join(process.env.CROW_HOME, "secrets");
mkdirSync(secretsDir, { recursive: true, mode: 0o700 });
const TOKENS_PATH = join(secretsDir, `peer-pinned-origin-${process.pid}.json`);
process.env.CROW_PEER_TOKENS_PATH = TOKENS_PATH;
// The one-time backfill marker is its own file (never a store key). Beside this
// file's private store, so a parallel test file's boot backfill cannot set it.
const BACKFILL_PATH = join(secretsDir, `peer-pin-backfill-${process.pid}.json`);
process.env.CROW_PEER_PIN_BACKFILL_PATH = BACKFILL_PATH;

let dir, dbPath, relay, relayBase, upstream, upstreamPort, evil, evilPort, relayToken;
const seenUpstream = []; // requests the real MCP upstream saw
const seenEvil = []; // requests "the bot's own server" saw — must stay empty
let storeFileMode;

const GOOD_ORIGIN = () => `http://127.0.0.1:${upstreamPort}`;
const EVIL_ORIGIN = () => `http://127.0.0.1:${evilPort}`;

const PEER_GOOD = "inst-pin-good-0001"; // row + pin agree
const PEER_MOVED = "inst-pin-moved-0002"; // pin stays put, the row is rewritten
const BOT = "pinbot";
const LOCAL = "inst-pin-local-0001";
const PEER_TOKENS = { [PEER_GOOD]: "good-peer-bearer", [PEER_MOVED]: "moved-peer-bearer" };
const PAIR_KEY = randomBytes(32).toString("hex");
let SESSION_ID;

const listen = (srv) => new Promise((r) => srv.listen(0, "127.0.0.1", () => r(srv.address().port)));

/** A real MCP server (so the positive controls really connect), recording every request. */
function upstreamServer() {
  const sessions = new Map();
  const mk = () => {
    const s = new McpServer({ name: "pin-fake-peer", version: "0" });
    s.registerTool("pin_touch", { description: "touch", inputSchema: { marker: z.string() } }, async ({ marker }) => ({ content: [{ type: "text", text: "touched:" + marker }] }));
    return s;
  };
  return http.createServer(async (req, res) => {
    let raw = ""; for await (const c of req) raw += c;
    const body = raw ? JSON.parse(raw) : undefined;
    seenUpstream.push({ path: req.url, method: req.method, headers: { ...req.headers }, body });
    // A plain signed federation call (not MCP): answer it 200, so the forwarder's
    // positive control sees success rather than a protocol error.
    if (!body || typeof body !== "object" || !body.jsonrpc) {
      res.writeHead(200, { "content-type": "application/json" });
      return res.end(JSON.stringify({ ok: true }));
    }
    const sid = req.headers["mcp-session-id"];
    if (sid && sessions.has(sid)) return sessions.get(sid).handleRequest(req, res, body);
    if (!sid && req.method === "POST" && isInitializeRequest(body)) {
      const t = new StreamableHTTPServerTransport({ sessionIdGenerator: () => randomUUID(), onsessioninitialized: (id) => sessions.set(id, t) });
      await mk().connect(t);
      return t.handleRequest(req, res, body);
    }
    res.writeHead(400, { "content-type": "application/json" });
    res.end(JSON.stringify({ jsonrpc: "2.0", error: { code: -32000, message: "no session" }, id: null }));
  });
}

/** "The bot's own server": records everything, answers 200 to anything. */
function evilServer() {
  return http.createServer(async (req, res) => {
    let raw = ""; for await (const c of req) raw += c;
    seenEvil.push({ path: req.url, method: req.method, headers: { ...req.headers }, body: raw });
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ jsonrpc: "2.0", id: 1, result: {} }));
  });
}

function pointRow(id, url) {
  const d = new Database(dbPath);
  d.pragma("busy_timeout = 5000");
  try { d.prepare("UPDATE crow_instances SET gateway_url = ? WHERE id = ?").run(url, id); } finally { d.close(); }
}
const goodBase = () => `${GOOD_ORIGIN()}`;
const evilBase = () => `${EVIL_ORIGIN()}`;

before(async () => {
  assert.ok(process.env.CROW_SUITE_SCRATCH, "runs only in the scratch suite env");
  dir = mkdtempSync(join(tmpdir(), "peer-pinned-origin-"));
  dbPath = join(dir, "crow.db");
  execFileSync(process.execPath, ["scripts/init-db.js"], { env: { ...process.env, CROW_DATA_DIR: dir, CROW_DB_PATH: dbPath }, cwd: join(import.meta.dirname, ".."), stdio: "pipe" });

  upstream = upstreamServer();
  upstreamPort = await listen(upstream);
  evil = evilServer();
  evilPort = await listen(evil);

  const d = new Database(dbPath);
  d.pragma("busy_timeout = 5000");
  const ins = d.prepare("INSERT INTO crow_instances (id, name, crow_id, gateway_url, status, trusted) VALUES (?, ?, ?, ?, 'active', 1)");
  ins.run(PEER_GOOD, "good", PEER_GOOD, `${goodBase()}/`);
  ins.run(PEER_MOVED, "moved", PEER_MOVED, `${goodBase()}/`);
  d.prepare("INSERT INTO pi_bot_defs (bot_id, display_name, definition) VALUES (?, ?, ?)")
    .run(BOT, "Pin Bot", JSON.stringify({ tools: { remote_mcp: [`${PEER_GOOD}::crow-memory`, `${PEER_MOVED}::crow-memory`] } }));
  d.prepare("INSERT OR REPLACE INTO dashboard_settings (key, value) VALUES ('feature_flags', ?)")
    .run(JSON.stringify({ remote_invocation: true }));
  SESSION_ID = String(d.prepare("INSERT INTO bot_sessions (bot_id, gateway_type, gateway_thread_id, status) VALUES (?, 'discord', 'discord:42', 'active')").run(BOT).lastInsertRowid);
  d.close();

  const tdb = createDbClient(dbPath);
  try { await ensurePeerRelayToken(tdb); } finally { tdb.close(); }
  relayToken = readFileSync(join(secretsDir, "peer-relay-token"), "utf8").trim();
  initGatewayActorKey();

  // Pair both peers for real: an entry with the bearer, its origin pinned.
  for (const id of [PEER_GOOD, PEER_MOVED]) {
    PC.setPeerCreds(id, { auth_token: PEER_TOKENS[id], signing_key: PAIR_KEY });
    assert.equal(PC.pinPeerOrigin(id, `${goodBase()}/`), true, `pinned ${id}`);
  }
  storeFileMode = statSync(TOKENS_PATH).mode & 0o777;

  const app = express();
  app.use(express.json({ limit: "1mb" }));
  app.use(peerRelayRouter({ createDbClient: () => createDbClient(dbPath), deps: { keyLookup: () => null, localId: () => LOCAL } }));
  relay = http.createServer(app);
  relayBase = `http://127.0.0.1:${await listen(relay)}`;
});

after(async () => {
  relay?.closeAllConnections?.(); upstream?.closeAllConnections?.(); evil?.closeAllConnections?.();
  await Promise.all([relay, upstream, evil].filter(Boolean).map((s) => new Promise((r) => s.close(() => r()))));
  rmSync(dir, { recursive: true, force: true });
  try { rmSync(TOKENS_PATH, { force: true }); } catch { /* gone */ }
  try { rmSync(BACKFILL_PATH, { force: true }); } catch { /* gone */ }
});

const reset = () => { seenUpstream.length = 0; seenEvil.length = 0; };

// ---------------------------------------------------------------------------
// 1. normalizeGatewayOrigin
// ---------------------------------------------------------------------------

test("normalizeGatewayOrigin: explicit default ports, lower case, IPv6 brackets, no userinfo, non-http refused, path/query ignored", () => {
  const ok = [
    ["http://Host.Example:3001/base?x=1#f", "http://host.example:3001"],
    ["http://host.example", "http://host.example:80"],
    ["http://host.example:80/base", "http://host.example:80"],
    ["HTTPS://Host.Example/", "https://host.example:443"],
    ["https://host.example:8443/a/b?q=2", "https://host.example:8443"],
    ["http://[::1]:8080/x", "http://[::1]:8080"],
    ["http://[2001:DB8::1]/x", "http://[2001:db8::1]:80"],
    ["  http://host.example:1/path  ", "http://host.example:1"],
  ];
  for (const [input, want] of ok) assert.equal(PC.normalizeGatewayOrigin(input), want, input);
  const bad = ["", "   ", "ftp://host.example/x", "host.example:3001", "//host.example/x", "http://user:pw@host.example/",
    "http://user@host.example/", "javascript:alert(1)", "http://", "not a url", null, undefined, 42, {}];
  for (const input of bad) assert.equal(PC.normalizeGatewayOrigin(input), null, `${JSON.stringify(input)} must not normalize`);
});

// ---------------------------------------------------------------------------
// 2. The pin is part of the entry and outlives every write of it
// ---------------------------------------------------------------------------

test("a pinned origin survives token rotation and re-enroll patches (and the store stays 0600)", () => {
  assert.equal(storeFileMode, 0o600, "the credential store is owner-only");
  PC.setPeerCreds("inst-rotate-1", { auth_token: "a".repeat(64), signing_key: "b".repeat(64) });
  assert.equal(PC.pinPeerOrigin("inst-rotate-1", "https://peer.example:8443/base"), true);
  // Rotation: a new bearer only.
  PC.setPeerCreds("inst-rotate-1", { auth_token: "c".repeat(64) });
  assert.equal(PC.getPeerCreds("inst-rotate-1").pinned_origin, "https://peer.example:8443");
  // Re-enroll: both secrets replaced at once.
  PC.setPeerCreds("inst-rotate-1", { auth_token: "d".repeat(64), signing_key: "e".repeat(64) });
  assert.equal(PC.getPeerCreds("inst-rotate-1").pinned_origin, "https://peer.example:8443");
  // A direct patch of the entry (the shape a key-rotation path uses).
  PC.updatePeerCreds((all) => { all["inst-rotate-1"].signing_key = "f".repeat(64); return {}; });
  assert.equal(PC.getPeerCreds("inst-rotate-1").pinned_origin, "https://peer.example:8443");
  assert.equal(PC.getPeerCreds("inst-rotate-1").auth_token, "d".repeat(64));
  // A URL that does not normalize never overwrites the pin, and a pin never
  // invents a peer.
  assert.equal(PC.pinPeerOrigin("inst-rotate-1", "ftp://peer.example/"), false);
  assert.equal(PC.getPeerCreds("inst-rotate-1").pinned_origin, "https://peer.example:8443");
  assert.equal(PC.pinPeerOrigin("inst-no-such-peer", "https://peer.example:8443"), false);
  assert.equal(PC.getPeerCreds("inst-no-such-peer"), null);
  PC.deletePeerCreds("inst-rotate-1");
});

// ---------------------------------------------------------------------------
// 3. peerUrlAllowed: pure, synchronous, every refusal reason
// ---------------------------------------------------------------------------

test("peerUrlAllowed: no-creds / no-pin / mismatch / bad-url, and an exact origin match (default ports included)", () => {
  PC.setPeerCreds("inst-reasons-1", { auth_token: "t".repeat(32), signing_key: "k".repeat(32) });
  assert.deepEqual(PC.peerUrlAllowed("inst-reasons-1", "https://peer.example:8443/x"), { ok: false, reason: "no-pin" });
  assert.deepEqual(PC.peerUrlAllowed("inst-nobody-here", "https://peer.example:8443/x"), { ok: false, reason: "no-creds" });
  assert.equal(PC.pinPeerOrigin("inst-reasons-1", "https://Peer.Example/"), true);
  assert.deepEqual(PC.peerUrlAllowed("inst-reasons-1", "https://peer.example:443/deep/path?q=1"), { ok: true });
  assert.deepEqual(PC.peerUrlAllowed("inst-reasons-1", "https://peer.example:8443/x"), { ok: false, reason: "mismatch" });
  assert.deepEqual(PC.peerUrlAllowed("inst-reasons-1", "http://peer.example/x"), { ok: false, reason: "mismatch" });
  assert.deepEqual(PC.peerUrlAllowed("inst-reasons-1", "http://user:pw@peer.example/x"), { ok: false, reason: "bad-url" });
  assert.deepEqual(PC.peerUrlAllowed("inst-reasons-1", null), { ok: false, reason: "bad-url" });
  PC.deletePeerCreds("inst-reasons-1");
});

// ---------------------------------------------------------------------------
// 4. The peer relay (the loopback route a bot's remote proxy talks to)
// ---------------------------------------------------------------------------

const actorHeaders = () => {
  const a = { botId: BOT, sessionId: SESSION_ID, threadId: "discord:42", gatewayType: "discord" };
  return {
    "X-Crow-Actor-Id": a.botId, "X-Crow-Actor-Thread": a.threadId, "X-Crow-Actor-Gateway": a.gatewayType,
    "X-Crow-Actor-Session": a.sessionId, "X-Crow-Actor-Sig": signPeerRelayActor(a),
  };
};
const INIT = { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "t", version: "0" } } };

async function relayPost(instanceId) {
  const r = await fetch(`${relayBase}/peer-relay/${instanceId}/memory/mcp`, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream", Authorization: `Bearer ${relayToken}`, ...actorHeaders() },
    body: JSON.stringify(INIT),
  });
  const text = await r.text();
  let json = null; try { json = JSON.parse(text); } catch { /* SSE */ }
  return { status: r.status, json, text, headers: r.headers };
}

test("peer relay: a rewritten gateway_url is refused 502 and the bot's server sees no request; the paired origin still relays", async () => {
  reset();
  pointRow(PEER_MOVED, `${evilBase()}/`);
  try {
    const r = await relayPost(PEER_MOVED);
    assert.equal(r.status, 502, r.text);
    assert.equal(r.json?.jsonrpc, "2.0");
    assert.match(r.json.error.message, /not at its paired address/);
    assert.equal(seenEvil.length, 0, "the rewritten address was never dialled");
    assert.ok(seenEvil.every((s) => s.headers.authorization === undefined));
    assert.equal(seenUpstream.length, 0, "and the paired origin was not dialled for this one either");
  } finally { pointRow(PEER_MOVED, `${goodBase()}/`); }

  // Positive control: the pinned peer relays, with its bearer.
  reset();
  const ok = await relayPost(PEER_GOOD);
  assert.equal(ok.status, 200, ok.text);
  assert.equal(seenUpstream.length, 1);
  assert.equal(seenUpstream[0].headers.authorization, `Bearer ${PEER_TOKENS[PEER_GOOD]}`);
  assert.equal(seenEvil.length, 0);
});

// ---------------------------------------------------------------------------
// 5. The federation proxy client
// ---------------------------------------------------------------------------

test("proxy federation: a rewritten gateway_url opens no connection and carries no bearer; the paired origin connects", async () => {
  reset();
  pointRow(PEER_MOVED, `${evilBase()}/`);
  const logs = [];
  const origLog = console.log;
  console.log = (...a) => { logs.push(a.join(" ")); };
  try {
    await assert.rejects(
      () => createRemoteInstanceClient({ id: PEER_MOVED, name: "moved", gateway_url: `${evilBase()}/` }),
      /gateway origin is not the paired one \(mismatch\)/,
    );
  } finally {
    console.log = origLog;
    pointRow(PEER_MOVED, `${goodBase()}/`);
  }
  assert.equal(seenEvil.length, 0, "no connection was opened to the rewritten address");
  assert.ok(logs.some((l) => l.includes("[proxy] refused federation to moved: gateway origin is not the paired one (mismatch)")), logs.join("\n"));
  for (const l of logs) assert.ok(!l.includes(PEER_TOKENS[PEER_MOVED]), "no bearer in a log line");

  // Positive control: the pinned origin is dialled, with the peer bearer.
  reset();
  const client = await createRemoteInstanceClient({ id: PEER_GOOD, name: "good", gateway_url: `${goodBase()}/` });
  try { await client.listTools(); } finally { await client.close?.(); }
  assert.ok(seenUpstream.length >= 1);
  for (const s of seenUpstream) assert.equal(s.headers.authorization, `Bearer ${PEER_TOKENS[PEER_GOOD]}`);
  assert.equal(seenEvil.length, 0);
});

// ---------------------------------------------------------------------------
// 6. The voice path's remote router client
// ---------------------------------------------------------------------------

test("remote voice tools: a rewritten gateway_url is refused before any dial; the paired origin connects with the bearer", async () => {
  reset();
  pointRow(PEER_MOVED, `${evilBase()}/`);
  const lines = [];
  const origErr = console.error;
  console.error = (...a) => { lines.push(a.join(" ")); };
  try {
    await assert.rejects(
      () => createRemoteRouterClient({ instanceId: PEER_MOVED, gatewayUrl: `${evilBase()}/` }),
      /gateway origin is not the paired one \(mismatch\)/,
    );
  } finally {
    console.error = origErr;
    pointRow(PEER_MOVED, `${goodBase()}/`);
  }
  assert.equal(seenEvil.length, 0, "no connection was opened to the rewritten address");
  assert.ok(lines.some((l) => l.includes("[voice-remote] refused " + PEER_MOVED + ": gateway origin is not the paired one (mismatch)")), lines.join("\n"));
  for (const l of lines) assert.ok(!l.includes(PEER_TOKENS[PEER_MOVED]), "no bearer in a log line");

  reset();
  const client = await createRemoteRouterClient({ instanceId: PEER_GOOD, gatewayUrl: `${goodBase()}/` });
  try { await client.listTools(); } finally { await client.close?.(); }
  assert.ok(seenUpstream.length >= 1);
  for (const s of seenUpstream) assert.equal(s.headers.authorization, `Bearer ${PEER_TOKENS[PEER_GOOD]}`);
  assert.equal(seenEvil.length, 0);
});

// ---------------------------------------------------------------------------
// 7. The signed forwarder (peer bearer + pair-key signature)
// ---------------------------------------------------------------------------

test("peer-forward: a rewritten gateway_url returns target_not_at_paired_origin and sends nothing; the paired origin is signed and sent", async () => {
  reset();
  const db = createDbClient(dbPath);
  try {
    pointRow(PEER_MOVED, `${evilBase()}/`);
    let r;
    try {
      r = await forwardSignedRequest({
        db, sourceInstanceId: LOCAL, targetInstanceId: PEER_MOVED, method: "GET", path: "/dashboard/overview",
        auditAction: "pin.test", timeoutMs: 5_000,
      });
    } finally { pointRow(PEER_MOVED, `${goodBase()}/`); }
    assert.equal(r.ok, false);
    assert.equal(r.error, "target_not_at_paired_origin");
    assert.equal(r.reason, "mismatch");
    assert.equal(seenEvil.length, 0, "nothing was sent to the rewritten address");
    assert.equal(seenUpstream.length, 0, "and the paired origin was not tried either");

    // Positive control: the pinned peer is reached with the bearer + signature.
    reset();
    const ok = await forwardSignedRequest({
      db, sourceInstanceId: LOCAL, targetInstanceId: PEER_GOOD, method: "GET", path: "/dashboard/overview",
      auditAction: "pin.test", timeoutMs: 5_000,
    });
    assert.equal(ok.error, undefined, JSON.stringify(ok));
    assert.ok(seenUpstream.length >= 1);
    assert.equal(seenUpstream[0].path, "/dashboard/overview");
    assert.equal(seenUpstream[0].headers.authorization, `Bearer ${PEER_TOKENS[PEER_GOOD]}`);
    assert.ok(seenUpstream[0].headers["x-crow-signature"], "the request was signed with the pair key");
    assert.equal(seenEvil.length, 0);
  } finally { db.close(); }
});

// ---------------------------------------------------------------------------
// 8. The one-time boot backfill
// ---------------------------------------------------------------------------

test("boot backfill: pins once from each trusted row, writes the marker, and never re-pins after a rewrite", async () => {
  reset();
  const OLD = "inst-pin-legacy-0003";
  const d = new Database(dbPath);
  d.pragma("busy_timeout = 5000");
  try {
    d.prepare("INSERT INTO crow_instances (id, name, crow_id, gateway_url, status, trusted) VALUES (?, ?, ?, ?, 'active', 1)").run(OLD, "legacy", OLD, `${goodBase()}/`);
  } finally { d.close(); }
  // Paired before the pin existed: credentials, no pin.
  PC.setPeerCreds(OLD, { auth_token: "legacy-bearer", signing_key: PAIR_KEY });
  assert.equal(PC.getPeerCreds(OLD).pinned_origin, undefined);
  assert.equal(PC.pinBackfillDoneAt(), null, "no marker before the first boot");

  const logs = [];
  const first = await runPeerOriginBackfill({ createDbClient: () => createDbClient(dbPath), log: (m) => logs.push(m), warn: (m) => logs.push(m) });
  assert.equal(first.ran, true);
  assert.equal(first.pinned, 1, JSON.stringify(first));
  assert.ok(logs.some((l) => l === "[peer-pin] pinned 1 peer(s) from their current address (one-time)"), logs.join("\n"));
  assert.equal(PC.getPeerCreds(OLD).pinned_origin, `${GOOD_ORIGIN()}`);
  assert.ok(PC.pinBackfillDoneAt(), "the one-time marker is in its own file");
  assert.deepEqual(PC.peerUrlAllowed(OLD, `${goodBase()}/anything`), { ok: true });

  // A bot rewrites the row and a NEW unpinned entry appears afterwards: the
  // marker means the backfill never runs again, so nothing is pinned from it.
  pointRow(OLD, `${evilBase()}/`);
  const LATE = "inst-pin-late-0004";
  const d2 = new Database(dbPath);
  d2.pragma("busy_timeout = 5000");
  try {
    d2.prepare("INSERT INTO crow_instances (id, name, crow_id, gateway_url, status, trusted) VALUES (?, ?, ?, ?, 'active', 1)").run(LATE, "late", LATE, `${evilBase()}/`);
  } finally { d2.close(); }
  PC.setPeerCreds(LATE, { auth_token: "late-bearer", signing_key: PAIR_KEY });

  const logs2 = [];
  const second = await runPeerOriginBackfill({ createDbClient: () => createDbClient(dbPath), log: (m) => logs2.push(m), warn: (m) => logs2.push(m) });
  assert.equal(second.ran, false);
  assert.ok(second.alreadyDoneAt, "the second boot reports the marker");
  assert.equal(PC.getPeerCreds(OLD).pinned_origin, `${GOOD_ORIGIN()}`, "the rewritten row did not move the pin");
  assert.equal(PC.getPeerCreds(LATE).pinned_origin, undefined, "a row rewritten after the marker is never pinned");
  assert.deepEqual(logs2, [], "a second boot logs nothing");
  assert.deepEqual(PC.peerUrlAllowed(OLD, `${evilBase()}/`), { ok: false, reason: "mismatch" });

  // Clean up so later assertions on this store see only what they set up.
  PC.deletePeerCreds(OLD); PC.deletePeerCreds(LATE);
  pointRow(OLD, `${goodBase()}/`);
});

// ---------------------------------------------------------------------------
// 9. The owner's re-pin CLI
// ---------------------------------------------------------------------------

function runPeerPin(argv) {
  let out = "", err = "";
  const sink = (s) => { out += s; };
  const errSink = (s) => { err += s; };
  return peerPinMain({ argv, stdout: { write: sink }, stderr: { write: errSink } }).then((code) => ({ code, out, err }));
}

test("peer-pin CLI: --show lists <id> <pinned_origin|none>; a re-pin prints the normalized origin and takes effect", async () => {
  const shown = await runPeerPin(["--show"]);
  assert.equal(shown.code, 0, shown.err);
  const lines = shown.out.split("\n").filter(Boolean);
  assert.ok(lines.includes(`${PEER_GOOD} ${GOOD_ORIGIN()}`), shown.out);
  assert.ok(lines.some((l) => l.startsWith(`${PEER_MOVED} `)), shown.out);

  // A peer with no pin shows "none".
  PC.setPeerCreds("inst-unpinned-0005", { auth_token: "u".repeat(32), signing_key: "s".repeat(32) });
  const shown2 = await runPeerPin(["--show"]);
  assert.match(shown2.out, /^inst-unpinned-0005 none$/m);

  // Re-pin to a new address: the store takes it, and the old origin then refuses.
  const repinned = await runPeerPin(["inst-unpinned-0005", "HTTPS://New.Example:8443/some/path"]);
  assert.equal(repinned.code, 0, repinned.err);
  assert.equal(repinned.out.trim(), "inst-unpinned-0005 https://new.example:8443");
  assert.equal(PC.getPeerCreds("inst-unpinned-0005").pinned_origin, "https://new.example:8443");
  assert.deepEqual(PC.peerUrlAllowed("inst-unpinned-0005", "https://new.example:8443/x"), { ok: true });
  assert.deepEqual(PC.peerUrlAllowed("inst-unpinned-0005", "https://old.example:8443/x"), { ok: false, reason: "mismatch" });
  PC.deletePeerCreds("inst-unpinned-0005");

  // Refusals: an unusable URL and an unknown peer both write nothing.
  const badUrl = await runPeerPin([PEER_GOOD, "not-a-url"]);
  assert.equal(badUrl.code, 1);
  assert.match(badUrl.err, /not a usable http\(s\) gateway URL/);
  const unknown = await runPeerPin(["inst-never-paired-0006", "http://127.0.0.1:1"]);
  assert.equal(unknown.code, 1);
  assert.match(unknown.err, /no peer credentials/);
  assert.equal(PC.getPeerCreds("inst-never-paired-0006"), null);
  assert.equal(PC.getPeerCreds(PEER_GOOD).pinned_origin, `${GOOD_ORIGIN()}`);
});

// ---------------------------------------------------------------------------
// 10. The one-time marker is its own FILE (never a store key)
// ---------------------------------------------------------------------------

test("the backfill marker lives in its own 0600 file: the trust sweeper never deletes it and a peer id of that name cannot clobber it", async () => {
  rmSync(BACKFILL_PATH, { force: true });
  assert.equal(PC.markPinBackfillDone("2026-02-01T00:00:00.000Z"), true);
  assert.equal(PC.pinBackfillDoneAt(), "2026-02-01T00:00:00.000Z");
  assert.equal(statSync(BACKFILL_PATH).mode & 0o777, 0o600, "the marker file is owner-only");
  // It is NOT a key in the credential store any more.
  assert.equal(Object.prototype.hasOwnProperty.call(JSON.parse(readFileSync(TOKENS_PATH, "utf-8")), PC.PIN_BACKFILL_KEY), false);

  // A peer whose id happens to be the old metadata key is an ordinary peer: its
  // own entry (and its pin) never touches the marker.
  PC.setPeerCreds(PC.PIN_BACKFILL_KEY, { auth_token: "m".repeat(64), signing_key: "n".repeat(64) });
  assert.equal(PC.pinPeerOrigin(PC.PIN_BACKFILL_KEY, "https://peer.example:8443/"), true);
  PC.deletePeerCreds(PC.PIN_BACKFILL_KEY);
  PC.setPeerCreds(PC.PIN_BACKFILL_KEY, { auth_token: "o".repeat(64), signing_key: "p".repeat(64) });
  assert.equal(PC.pinBackfillDoneAt(), "2026-02-01T00:00:00.000Z");

  // The trust sweeper: that id is a REVOKED row here, minted long before the
  // revoke — the sweeper deletes the ENTRY, never the marker (a string value
  // under a metadata key used to be deleted by entryMintMs() = -Infinity).
  PC.deletePeerCreds(PC.PIN_BACKFILL_KEY);
  PC.updatePeerCreds((all) => {
    all[PC.PIN_BACKFILL_KEY] = { auth_token: "q".repeat(64), signing_key: "r".repeat(64), created_at: "2020-01-01T00:00:00.000Z", rotated_at: null };
    return {};
  });
  const d = new Database(dbPath);
  d.pragma("busy_timeout = 5000");
  try {
    d.prepare("INSERT OR REPLACE INTO crow_instances (id, name, crow_id, gateway_url, status, trusted) VALUES (?, ?, ?, ?, 'revoked', 0)")
      .run(PC.PIN_BACKFILL_KEY, "marker-id", PC.PIN_BACKFILL_KEY, `${goodBase()}/`);
  } finally { d.close(); }
  const db = createDbClient(dbPath);
  try { await reconcilePeerCreds(db, { localInstanceId: LOCAL }); } finally { db.close(); }
  assert.equal(PC.pinBackfillDoneAt(), "2026-02-01T00:00:00.000Z", "the sweeper left the marker alone");
  assert.equal(PC.getPeerCreds(PC.PIN_BACKFILL_KEY), null, "its own (revoked) entry was deleted as an entry");
  PC.deletePeerCreds(PC.PIN_BACKFILL_KEY);

  // And a legacy top-level marker STRING in the store is migrated out on read.
  PC.updatePeerCreds((all) => { all[PC.PIN_BACKFILL_KEY] = "2026-03-03T00:00:00.000Z"; return {}; });
  rmSync(BACKFILL_PATH, { force: true });
  assert.equal(PC.pinBackfillDoneAt(), "2026-03-03T00:00:00.000Z", "the legacy key still gates the backfill");
  assert.equal(JSON.parse(readFileSync(BACKFILL_PATH, "utf-8")).done_at, "2026-03-03T00:00:00.000Z", "moved into its own file");
  assert.equal(Object.prototype.hasOwnProperty.call(JSON.parse(readFileSync(TOKENS_PATH, "utf-8")), PC.PIN_BACKFILL_KEY), false, "and dropped from the store");

  // A second boot with the marker in place never re-backfills from a row.
  const LATE2 = "inst-pin-late-0009";
  const d2 = new Database(dbPath);
  d2.pragma("busy_timeout = 5000");
  try {
    d2.prepare("INSERT INTO crow_instances (id, name, crow_id, gateway_url, status, trusted) VALUES (?, ?, ?, ?, 'active', 1)").run(LATE2, "late2", LATE2, `${evilBase()}/`);
  } finally { d2.close(); }
  PC.setPeerCreds(LATE2, { auth_token: "s".repeat(64), signing_key: "t".repeat(64) });
  const second = await runPeerOriginBackfill({ createDbClient: () => createDbClient(dbPath), log: () => {}, warn: () => {} });
  assert.equal(second.ran, false, "the migrated marker blocks a second backfill");
  assert.equal(PC.getPeerCreds(LATE2).pinned_origin, undefined, "a row written after the marker is never pinned");
  PC.deletePeerCreds(LATE2);
  rmSync(BACKFILL_PATH, { force: true });
});

// ---------------------------------------------------------------------------
// 11. What the pair CLI does (and says) when a ceremony supplies no pin
// ---------------------------------------------------------------------------

test("pair CLI: a re-pair with no ceremony address KEEPS the existing pin and says so; a peer with no pin at all is 'left unpinned'", async () => {
  const { storePeerCredsLocally } = await import("../scripts/cli/instance-pair.js");
  const db = createDbClient(dbPath);
  const warns = [];
  const origWarn = console.warn;
  console.warn = (...a) => { warns.push(a.join(" ")); };
  const PINNED = "inst-cli-repin-0010";
  const UNPINNED = "inst-cli-nopin-0011";
  try {
    // First pairing: a ceremony address, so it pins.
    await storePeerCredsLocally(db, {
      peerId: PINNED, peerName: "repin", peerCrowId: PINNED, peerGatewayUrl: `${goodBase()}/`, pinOrigin: `${goodBase()}/`,
      auth_token: "a".repeat(64), signing_key: "b".repeat(64), peerOutboundBearerHash: "1".repeat(64),
    });
    assert.deepEqual(PC.peerUrlAllowed(PINNED, `${goodBase()}/x`), { ok: true });

    // Re-pair with NO ceremony address to pin: setPeerCreds() merges, so the pin
    // from the first pairing is still in place. Saying "left unpinned" here would
    // send the operator to re-pin a pair that is already pinned.
    warns.length = 0;
    await storePeerCredsLocally(db, {
      peerId: PINNED, peerName: "repin", peerCrowId: PINNED, peerGatewayUrl: `${goodBase()}/`, pinOrigin: null,
      auth_token: "c".repeat(64), signing_key: "d".repeat(64), peerOutboundBearerHash: "2".repeat(64),
    });
    assert.equal(PC.getPeerCreds(PINNED).pinned_origin, GOOD_ORIGIN(), "the previous pin is kept");
    assert.equal(PC.getPeerCreds(PINNED).auth_token, "c".repeat(64), "the new credentials did land");
    assert.ok(warns.some((l) => l.includes(`[peer-pin] ${PINNED} kept its previous pin`)), warns.join("\n"));
    assert.ok(!warns.some((l) => l.includes(`${PINNED} left unpinned`)), warns.join("\n"));

    // A peer with NO pin at all: the honest line, with the re-pin command.
    warns.length = 0;
    await storePeerCredsLocally(db, {
      peerId: UNPINNED, peerName: "nopin", peerCrowId: UNPINNED, peerGatewayUrl: `${goodBase()}/`, pinOrigin: null,
      auth_token: "e".repeat(64), signing_key: "f".repeat(64), peerOutboundBearerHash: "3".repeat(64),
    });
    assert.equal(PC.getPeerCreds(UNPINNED).pinned_origin, undefined, "nothing is pinned");
    assert.ok(warns.some((l) => l.includes(`[peer-pin] ${UNPINNED} left unpinned: run node scripts/cli/peer-pin.js ${UNPINNED} <url>`)), warns.join("\n"));
    assert.ok(!warns.some((l) => l.includes(`${UNPINNED} kept its previous pin`)), warns.join("\n"));
  } finally {
    console.warn = origWarn;
    PC.deletePeerCreds(PINNED);
    PC.deletePeerCreds(UNPINNED);
    db.close();
  }
});

// ---------------------------------------------------------------------------
// 12. A peer that answers a redirect
// ---------------------------------------------------------------------------

test("peer-forward never follows a redirect: a 3xx is an error and the bot's server sees nothing", async () => {
  const redir = http.createServer(async (req, res) => {
    for await (const _chunk of req) { /* drain */ }
    res.writeHead(307, { location: `${evilBase()}/stolen` });
    res.end();
  });
  const redirPort = await listen(redir);
  const PEER_REDIR = "inst-redirect-0008";
  const d = new Database(dbPath);
  d.pragma("busy_timeout = 5000");
  try {
    d.prepare("INSERT OR REPLACE INTO crow_instances (id, name, crow_id, gateway_url, status, trusted) VALUES (?, ?, ?, ?, 'active', 1)")
      .run(PEER_REDIR, "redir", PEER_REDIR, `http://127.0.0.1:${redirPort}/`);
  } finally { d.close(); }
  PC.setPeerCreds(PEER_REDIR, { auth_token: "v".repeat(64), signing_key: PAIR_KEY });
  assert.equal(PC.pinPeerOrigin(PEER_REDIR, `http://127.0.0.1:${redirPort}/`), true);
  const db = createDbClient(dbPath);
  try {
    reset();
    const r = await forwardSignedRequest({
      db, sourceInstanceId: LOCAL, targetInstanceId: PEER_REDIR, method: "GET", path: "/dashboard/overview",
      auditAction: "pin.redirect", timeoutMs: 5_000,
    });
    assert.equal(r.ok, false);
    assert.equal(r.error, "redirect_refused", JSON.stringify(r));
    assert.equal(seenEvil.length, 0, "the redirect target was never dialled");
    assert.equal(seenUpstream.length, 0, "and nothing else was dialled either");
  } finally {
    db.close();
    PC.deletePeerCreds(PEER_REDIR);
    await new Promise((r) => { redir.closeAllConnections?.(); redir.close(() => r()); });
  }
});