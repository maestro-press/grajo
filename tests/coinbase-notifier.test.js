/**
 * The Coinbase notifier and the three loops started at gateway boot.
 *
 * Every engine in here is a local fake reached through the real engine client:
 * its `/health`, `/events`, `/lease` and `/lease/cursor` speak the engine's own
 * JSON, check the bearer token, verify the MAC against the key the engine would
 * hold (the install token while unpinned, the owner's key once pinned) and answer
 * the engine's statuses (401, 403 APPROVAL_INVALID, 409 LEASE_NOT_HELD, 422
 * CURSOR_AHEAD).  Nothing opens a socket.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { appImport } from "../bundles/coinbase/server/app-root.js";
import { createEngineClient } from "../bundles/coinbase/server/engine-client.js";
import { macSignature } from "../bundles/coinbase/server/mac.js";
import { createNotifier, makeNotify, mapEvent } from "../bundles/coinbase/server/notifier.js";
import { auditExistsFor, holderId, startLoops } from "../bundles/coinbase/server/loops.js";
import { createDbClient } from "../servers/db.js";

const TOKEN = "test-engine-token-0123456789abcdef";
const OWNER_KEY = "owner-signing-key-0123456789abcdef";
const INSTALL_KEY = "install-signing-key-0123456789abcdef";
const BASE_URL = "http://127.0.0.1:3062";
const HOUR_MS = 60 * 60 * 1000;

// ---------------------------------------------------------------- fakes

function respond(status, body) {
  const text = JSON.stringify(body);
  return { ok: status >= 200 && status < 300, status, headers: {}, text: async () => text };
}

class FakeEngine {
  constructor({ pinned = true, credentials = "ready", stale = false } = {}) {
    this.pinned = pinned;
    this.credentials = credentials;
    this.stale = stale;
    this.events = [];
    this.nextId = 1;
    this.lease = null;
    this.cursor = null;
    this.down = false;
    this.denyLease = false;
    this.requests = [];
    this.keyKinds = [];
    this.fetchImpl = this.fetchImpl.bind(this);
  }

  addEvent({ kind, level = "info", owner = null, message = "", data = null, ts = null }) {
    const event = {
      id: this.nextId,
      ts: ts === null ? `2026-01-01T00:00:${String(this.nextId).padStart(2, "0")}Z` : ts,
      level,
      kind,
      owner,
      message,
      data,
    };
    this.nextId += 1;
    this.events.push(event);
    return event;
  }

  newest() {
    return this.events.length ? this.events[this.events.length - 1].id : 0;
  }

  wipe() {
    this.events = [];
  }

  expireLease() {
    if (this.lease) this.lease.expiresAt = 0;
  }

  leaseLive() {
    return Boolean(this.lease) && this.lease.expiresAt > 0;
  }

  /** The key kind a signed request actually carried, by trying both keys. */
  macKind(init, pathWithQuery) {
    const headers = init.headers || {};
    const ts = headers["X-Crow-Timestamp"];
    const nonce = headers["X-Crow-Nonce"];
    const body = init.body === undefined ? "" : init.body;
    const presented = headers["X-Crow-Signature"];
    if (!presented) return null;
    const owner = macSignature({ key: OWNER_KEY, method: init.method, pathWithQuery, ts, nonce, body });
    if (presented === owner) return "owner";
    const install = macSignature({ key: INSTALL_KEY, method: init.method, pathWithQuery, ts, nonce, body });
    if (presented === install) return "install";
    return null;
  }

  postCursor(body) {
    if (!this.leaseLive() || this.lease.holder !== body.holder) {
      return respond(409, { detail: "LEASE_NOT_HELD: another holder holds the lease" });
    }
    const wanted = Number(body.cursor);
    if (wanted > this.newest()) {
      return respond(422, { detail: "CURSOR_AHEAD: the cursor is past the newest event" });
    }
    this.cursor = this.cursor === null ? wanted : Math.max(this.cursor, wanted);
    return respond(200, { cursor: this.cursor });
  }

  async fetchImpl(url, init = {}) {
    if (this.down) throw new Error("connect ECONNREFUSED 127.0.0.1:3062");
    const parsed = new URL(url);
    const pathWithQuery = parsed.pathname + parsed.search;
    const method = String(init.method || "GET").toUpperCase();
    const headers = init.headers || {};
    this.requests.push({ method, path: parsed.pathname, pathWithQuery });

    if (parsed.pathname === "/health") {
      return respond(this.stale ? 503 : 200, {
        ok: !this.stale,
        live_enabled: false,
        heartbeat_age_s: this.stale ? 120 : 1,
        credentials: this.credentials,
        pinned: this.pinned,
      });
    }
    if (headers.Authorization !== `Bearer ${TOKEN}`) {
      return respond(401, { detail: "unauthorized" });
    }
    if (parsed.pathname === "/events") {
      const after = Number(parsed.searchParams.get("after") || 0);
      const limit = Number(parsed.searchParams.get("limit") || 100);
      const newest = this.newest();
      if (after > newest) {
        return respond(200, { events: [], last_id: newest, reset: true });
      }
      const page = this.events.filter((event) => event.id > after).slice(0, limit);
      const lastId = page.length ? page[page.length - 1].id : after;
      return respond(200, { events: page, last_id: lastId, reset: false });
    }
    if (parsed.pathname === "/lease" || parsed.pathname === "/lease/cursor") {
      if (this.denyLease) return respond(403, { detail: "APPROVAL_INVALID" });
      const kind = this.macKind(init, pathWithQuery);
      if (kind === null || kind !== this.keyKind()) {
        return respond(403, { detail: "APPROVAL_INVALID" });
      }
      this.keyKinds.push(kind);
      const body = JSON.parse(init.body || "{}");
      if (parsed.pathname === "/lease/cursor") return this.postCursor(body);
      if (this.leaseLive() && this.lease.holder !== body.holder) {
        return respond(200, { held: false, cursor: this.cursor });
      }
      this.lease = { holder: body.holder, expiresAt: 1 };
      return respond(200, { held: true, cursor: this.cursor });
    }
    return respond(404, { detail: "NOT_FOUND" });
  }

  /** The key kind this engine holds right now. */
  keyKind() {
    return this.pinned ? "owner" : "install";
  }

  callsTo(path) {
    return this.requests.filter((request) => request.path === path);
  }
}

function engineClient(engine, askedKinds = []) {
  return createEngineClient({
    token: TOKEN,
    baseUrl: BASE_URL,
    fetchImpl: engine.fetchImpl,
    secretProvider: async (kind) => {
      askedKinds.push(kind);
      return kind === "install" ? INSTALL_KEY : OWNER_KEY;
    },
  });
}

function collectNotify() {
  const calls = [];
  const notify = async (note) => {
    calls.push(note);
    return { id: calls.length };
  };
  notify.calls = calls;
  notify.titles = () => calls.map((note) => note.title);
  notify.count = (title) => calls.filter((note) => note.title === title).length;
  return notify;
}

function fakeClock(start = 1_700_000_000_000) {
  let at = start;
  return {
    now: () => at,
    advance(ms) {
      at += ms;
    },
  };
}

function fakeTimers() {
  const list = [];
  const api = {
    setInterval(fn, ms) {
      const handle = {
        fn,
        ms,
        cleared: false,
        unrefed: false,
        unref() {
          handle.unrefed = true;
          return handle;
        },
      };
      list.push(handle);
      return handle;
    },
    clearInterval(handle) {
      handle.cleared = true;
    },
  };
  return { list, api };
}

/** Let the loops' un-awaited startup ticks finish their mock fetches. */
async function settle(rounds = 10) {
  for (let index = 0; index < rounds; index += 1) {
    await new Promise((resolve) => setImmediate(resolve));
  }
}

/** A notifier that already holds the engine's lease, the way the loops leave it. */
async function leasedNotifier(engine, notify, holder, options = {}) {
  const client = engineClient(engine);
  const reply = await client.lease(holder, { keyKind: engine.keyKind() });
  if (!reply.ok || !reply.data.held) throw new Error(`the fake engine refused the lease: ${reply.code}`);
  const notifier = createNotifier({ client, notify, holder, ...options });
  notifier.setHolding(true);
  notifier.setCursor(reply.data.cursor);
  return { client, notifier };
}

function idleConnection(overrides = {}) {
  const conn = {
    projectId: 1,
    engineEpoch: null,
    needsReconnect: false,
    marks: 0,
    repushes: 0,
    repushResult: { ok: true, data: { state: "ok" } },
    ...overrides,
  };
  conn.get = async () => conn;
  conn.markNeedsReconnect = async () => {
    conn.marks += 1;
    conn.needsReconnect = true;
  };
  conn.repush = async () => {
    conn.repushes += 1;
    return conn.repushResult;
  };
  return conn;
}

// ---------------------------------------------------------------- mapEvent

test("notifier_maps_kinds", () => {
  const mapped = [
    { kind: "halt", level: "error", message: "Trading halted on drawdown", priority: "high", title: "Trading halted" },
    { kind: "watchdog", level: "warn", message: "heartbeat stale", priority: "high", title: "Trading engine watchdog" },
    { kind: "live_switch", level: "warn", message: "live off", priority: "high", title: "Live trading switch changed" },
    { kind: "alert", level: "warn", message: "spread wide", priority: "high", title: "Trading alert" },
    { kind: "fill", level: "info", message: "0.01 BTC bought", priority: "normal", title: "Order filled" },
    { kind: "trailing_hold", level: "info", message: "grid below price", priority: "normal", title: "Bot is behind simply holding" },
  ];
  for (const item of mapped) {
    const note = mapEvent({ id: 1, ...item });
    assert.ok(note, item.kind);
    assert.equal(note.priority, item.priority, item.kind);
    assert.equal(note.title, item.title, item.kind);
    assert.equal(note.body, item.message, item.kind);
    assert.equal(note.kind, item.kind, item.kind);
    assert.equal(note.action_url, undefined, item.kind);
  }

  for (const level of ["warn", "error", "high", "WARN"]) {
    const note = mapEvent({ kind: "credentials", level, message: "The engine cannot reach Coinbase" });
    assert.ok(note, level);
    assert.equal(note.priority, "high");
    assert.equal(note.title, "Coinbase connection needs attention");
    assert.equal(note.body, "The engine cannot reach Coinbase");
  }
  assert.equal(mapEvent({ kind: "credentials", level: "info", message: "connected" }), null);

  const preview = mapEvent({ kind: "ai_preview", level: "info", message: "A preview waits", data: { preview_id: "pv/1" } });
  assert.equal(preview.priority, "high");
  assert.equal(preview.title, "The AI proposed an order");
  assert.equal(preview.action_url, "/dashboard/coinbase?preview=pv%2F1");
  const previewWithoutId = mapEvent({ kind: "ai_preview", level: "info", message: "A preview waits", data: null });
  assert.ok(previewWithoutId);
  assert.equal(previewWithoutId.action_url, undefined);

  const paused = mapEvent({ kind: "bot_paused", level: "warn", message: "bot grid-1 paused on a rebase warning" });
  assert.ok(paused);
  assert.equal(paused.priority, "normal");
  assert.equal(paused.body, "bot grid-1 paused on a rebase warning");
  const pausedText = `${paused.title} ${paused.body}`.toLowerCase();
  assert.ok(pausedText.includes("needs attention"));
  assert.equal(paused.title.toLowerCase().includes("paused"), false);
  assert.equal(pausedText.includes("halted"), false);

  // The owner's own Pause is not news: the owner just pressed it, so it earns no note.
  assert.equal(
    mapEvent({
      kind: "bot_paused",
      level: "info",
      message: "bot paused; waiting orders cancelled",
      data: { reason: "owner" },
    }),
    null,
  );
  // Any other bot_paused -- a drawdown or a strategy pause -- still notifies as before.
  const strategyPaused = mapEvent({
    kind: "bot_paused",
    level: "warn",
    message: "bot paused on drawdown",
    data: { reason: "drawdown" },
  });
  assert.ok(strategyPaused, "a strategy pause still notifies");
  assert.equal(strategyPaused.priority, "normal");
  assert.equal(strategyPaused.title, paused.title);
  assert.equal(strategyPaused.body, "bot paused on drawdown");
  // A bot_paused with no data at all is unchanged too.
  assert.ok(mapEvent({ kind: "bot_paused", level: "info", message: "bot paused; no data" }));

  for (const kind of ["refusal", "caps", "ai_expired", "something_else"]) {
    assert.equal(mapEvent({ kind, level: "warn", message: "anything", data: null }), null, kind);
  }
  assert.equal(mapEvent(null), null);
});

// ---------------------------------------------------------------- makeNotify

test("make_notify_shape", async () => {
  const calls = [];
  const db = { name: "instance-db" };
  const createNotification = async (givenDb, opts) => {
    calls.push({ db: givenDb, opts });
    return { id: calls.length };
  };
  const notify = makeNotify(db, createNotification);

  const result = await notify({
    title: "Order filled",
    body: "0.01 BTC bought",
    priority: "normal",
    action_url: "/dashboard/coinbase",
    kind: "fill",
  });
  assert.deepEqual(result, { id: 1 });
  assert.equal(calls[0].db, db);
  assert.deepEqual(calls[0].opts, {
    title: "Order filled",
    body: "0.01 BTC bought",
    type: "system",
    source: "coinbase",
    priority: "normal",
    action_url: "/dashboard/coinbase",
    metadata: { kind: "fill" },
  });

  await notify({ title: "Trading engine is back", body: "The trading engine is answering again", priority: "normal" });
  assert.equal(calls[1].opts.metadata, null);
  assert.equal(calls[1].opts.action_url, undefined);
});

// ---------------------------------------------------------------- rate limit + episodes

test("notifier_rate_limit_and_episode", async () => {
  const engine = new FakeEngine();
  const clock = fakeClock();
  const notify = collectNotify();
  const notched = createNotifier({ client: engineClient(engine), notify, holder: "gw-a", now: clock.now });
  assert.deepEqual(await notched.pollOnce(), { skipped: "not_holding" });
  const { notifier } = await leasedNotifier(engine, notify, "gw-a", { now: clock.now });

  for (let index = 1; index <= 10; index += 1) engine.addEvent({ kind: "fill", message: `fill ${index}` });
  const first = await notifier.pollOnce();
  assert.equal(notify.count("Order filled"), 6);
  const summaries = notify.calls.filter((note) => /more fill updates$/.test(String(note.title)));
  assert.equal(summaries.length, 1);
  assert.equal(summaries[0].title, "4 more fill updates");
  assert.equal(summaries[0].priority, "normal");
  assert.equal(first.sent, 7);
  assert.equal(first.cursor, 10);
  assert.equal(notifier.getCursor(), 10);
  assert.equal(engine.cursor, 10);

  // A second poll inside the hour suppresses and keeps counting: no second summary.
  for (let index = 11; index <= 13; index += 1) engine.addEvent({ kind: "fill", message: `fill ${index}` });
  await notifier.pollOnce();
  assert.equal(notify.count("Order filled"), 6);
  assert.equal(notify.calls.filter((note) => /more fill updates$/.test(String(note.title))).length, 1);
  assert.equal(notifier.state().suppressed.fill, 3);

  // An hour later the summary may go again, carrying what accumulated.
  clock.advance(HOUR_MS + 1);
  await notifier.pollOnce();
  const laterSummaries = notify.calls.filter((note) => /more fill updates$/.test(String(note.title)));
  assert.equal(laterSummaries.length, 2);
  assert.equal(laterSummaries[1].title, "3 more fill updates");
  assert.equal(notifier.state().suppressed.fill, 0);

  // Unreachable: one notice per episode, at the threshold and not before.
  engine.down = true;
  await notifier.pollOnce();
  await notifier.pollOnce();
  assert.equal(notify.count("Trading engine not responding"), 0);
  const third = await notifier.pollOnce();
  assert.equal(third.error, "ENGINE_UNREACHABLE");
  assert.equal(notify.count("Trading engine not responding"), 1);
  const alert = notify.calls.find((note) => note.title === "Trading engine not responding");
  assert.equal(alert.priority, "high");
  await notifier.pollOnce();
  await notifier.pollOnce();
  assert.equal(notify.count("Trading engine not responding"), 1);

  // Recovery is one notice, and ends the episode.
  engine.down = false;
  await notifier.pollOnce();
  assert.equal(notify.count("Trading engine is back"), 1);
  assert.equal(notify.calls.find((note) => note.title === "Trading engine is back").priority, "normal");
  await notifier.pollOnce();
  assert.equal(notify.count("Trading engine is back"), 1);

  // A new episode alerts again.
  engine.down = true;
  await notifier.pollOnce();
  await notifier.pollOnce();
  await notifier.pollOnce();
  assert.equal(notify.count("Trading engine not responding"), 2);
});

test("engine_unreachable_alert", async () => {
  const client = createEngineClient({
    token: TOKEN,
    baseUrl: BASE_URL,
    fetchImpl: async () => {
      throw new Error("connect ECONNREFUSED 127.0.0.1:3062");
    },
    secretProvider: async () => OWNER_KEY,
  });
  const notify = collectNotify();
  const notifier = createNotifier({ client, notify, holder: "gw-a", failureThreshold: 3 });
  notifier.setHolding(true);

  const results = [];
  for (let index = 0; index < 4; index += 1) results.push(await notifier.pollOnce());
  for (const result of results) assert.equal(result.error, "ENGINE_UNREACHABLE");
  assert.equal(notify.calls.length, 1);
  assert.equal(notify.calls[0].title, "Trading engine not responding");
  assert.equal(notify.calls[0].priority, "high");

  const surface = JSON.stringify(notify.calls);
  assert.equal(surface.includes(TOKEN), false);
  assert.equal(surface.includes(OWNER_KEY), false);
  assert.equal(surface.includes(INSTALL_KEY), false);
});

// ---------------------------------------------------------------- cursor handover

test("cursor_handover_no_replay", async () => {
  const engine = new FakeEngine();
  for (let index = 1; index <= 5; index += 1) engine.addEvent({ kind: "fill", message: `fill ${index}` });

  const notifyA = collectNotify();
  const { notifier: notifierA } = await leasedNotifier(engine, notifyA, "gw-a");
  await notifierA.pollOnce();
  assert.equal(notifyA.count("Order filled"), 5);
  assert.equal(engine.cursor, 5);

  // A's lease expires; B takes over and starts where A stopped.
  engine.expireLease();
  engine.addEvent({ kind: "fill", message: "fill 6" });
  engine.addEvent({ kind: "fill", message: "fill 7" });

  const clientB = engineClient(engine);
  const reply = await clientB.lease("gw-b", { keyKind: "owner" });
  assert.equal(reply.ok, true);
  assert.equal(reply.data.held, true);
  assert.equal(reply.data.cursor, 5);

  const notifyB = collectNotify();
  const notifierB = createNotifier({ client: clientB, notify: notifyB, holder: "gw-b" });
  notifierB.setHolding(reply.data.held);
  notifierB.setCursor(reply.data.cursor);
  await notifierB.pollOnce();
  assert.equal(notifyB.count("Order filled"), 2);
  assert.deepEqual(notifyB.calls.map((note) => note.body), ["fill 6", "fill 7"]);
  assert.equal(engine.cursor, 7);

  const bodies = [...notifyA.calls, ...notifyB.calls].map((note) => note.body);
  assert.equal(bodies.length, 7);
  assert.equal(new Set(bodies).size, 7);

  // A holder that is not the lease's holder is refused, and stops polling.
  const notifyC = collectNotify();
  const notifierC = createNotifier({ client: engineClient(engine), notify: notifyC, holder: "gw-c" });
  notifierC.setHolding(true);
  notifierC.setCursor(7);
  const polled = await notifierC.pollOnce();
  assert.equal(polled.cursor, 7);
  assert.equal(notifierC.isHolding(), false);
  assert.equal(notifyC.calls.length, 0);
  assert.equal(engine.cursor, 7);
  assert.equal(engine.lease.holder, "gw-b");
});

test("reset_adopts_last_id", async () => {
  const engine = new FakeEngine();
  for (let index = 1; index <= 3; index += 1) engine.addEvent({ kind: "fill", message: `fill ${index}` });
  const notify = collectNotify();
  const { notifier } = await leasedNotifier(engine, notify, "gw-a");
  await notifier.pollOnce();
  assert.equal(notify.count("Order filled"), 3);
  assert.equal(notifier.getCursor(), 3);

  engine.wipe();
  const resetPoll = await notifier.pollOnce();
  assert.equal(notify.count("Trading engine history was reset"), 1);
  const note = notify.calls.find((entry) => entry.title === "Trading engine history was reset");
  assert.equal(note.priority, "normal");
  assert.equal(note.body, "Trading engine history was reset; some earlier events cannot be shown");
  assert.equal(notifier.getCursor(), 0);
  assert.equal(resetPoll.cursor, 0);
  assert.equal(notify.count("Order filled"), 3);

  // New events flow again, and the reset note is not repeated.
  engine.addEvent({ kind: "fill", message: "fill after the wipe" });
  await notifier.pollOnce();
  assert.equal(notify.count("Order filled"), 4);
  assert.equal(notify.count("Trading engine history was reset"), 1);
  assert.equal(notify.calls[notify.calls.length - 1].body, "fill after the wipe");
});

// ---------------------------------------------------------------- loops

test("loops_start_at_mount_without_panel_open", async () => {
  const engine = new FakeEngine({ pinned: false, credentials: "not_ready" });
  const notify = collectNotify();
  const timers = fakeTimers();
  const loops = startLoops({
    client: engineClient(engine),
    notify,
    connection: idleConnection(),
    holder: "gw-test",
    timers: timers.api,
  });

  assert.equal(timers.list.length, 3);
  assert.deepEqual(timers.list.map((handle) => handle.ms), [20000, 30000, 15000]);
  for (const handle of timers.list) assert.equal(handle.unrefed, true);
  assert.equal(typeof loops.ticks.lease, "function");
  assert.equal(typeof loops.ticks.repush, "function");
  assert.equal(typeof loops.ticks.notify, "function");

  await settle();
  assert.equal(engine.callsTo("/lease").length, 1);
  assert.equal(engine.callsTo("/lease")[0].method, "POST");
  assert.equal(engine.lease.holder, "gw-test");
  assert.equal(engine.callsTo("/events").length, 0);
  assert.equal(loops.state().holding, true);

  loops.stop();
  for (const handle of timers.list) assert.equal(handle.cleared, true);
});

test("wipe_stops_repush_and_asks_reconnect", async () => {
  const engine = new FakeEngine({ pinned: false, credentials: "not_ready" });
  const notify = collectNotify();
  const timers = fakeTimers();
  const connection = idleConnection({ engineEpoch: "epoch-one" });
  const loops = startLoops({
    client: engineClient(engine),
    notify,
    connection,
    holder: "gw-test",
    now: fakeClock().now,
    timers: timers.api,
  });

  await settle();
  assert.equal(connection.marks, 1);
  assert.equal(connection.needsReconnect, true);
  const resets = notify.calls.filter((note) => note.title === "Trading engine was reset");
  assert.equal(resets.length, 1);
  assert.equal(resets[0].priority, "high");
  assert.equal(resets[0].body, "Trading engine was reset; reconnect in the Trading panel");
  assert.equal(resets[0].action_url, "/dashboard/coinbase");
  assert.equal(connection.repushes, 0);

  await loops.ticks.repush();
  await loops.ticks.repush();
  await loops.ticks.lease();
  await settle();
  assert.equal(notify.calls.length, 1);
  assert.equal(connection.marks, 1);
  assert.equal(connection.repushes, 0);

  loops.stop();
});

test("repush_when_credentials_not_ready", async () => {
  const engine = new FakeEngine({ pinned: true, credentials: "not_ready" });
  const clock = fakeClock();
  const notify = collectNotify();
  const timers = fakeTimers();
  const connection = idleConnection({
    engineEpoch: "epoch-one",
    repushResult: { ok: false, status: 429, code: "RATE_LIMITED", message: "Too many attempts", retryAfterS: 90 },
  });
  const loops = startLoops({
    client: engineClient(engine),
    notify,
    connection,
    holder: "gw-test",
    now: clock.now,
    timers: timers.api,
  });

  await settle();
  assert.equal(connection.repushes, 1);
  await loops.ticks.repush();
  assert.equal(connection.repushes, 1);

  clock.advance(89_000);
  await loops.ticks.repush();
  assert.equal(connection.repushes, 1);

  clock.advance(2_000);
  await loops.ticks.repush();
  assert.equal(connection.repushes, 2);

  assert.equal(connection.needsReconnect, false);
  assert.equal(connection.marks, 0);
  assert.equal(notify.calls.length, 0);
  assert.equal(loops.state().lastError, null);

  loops.stop();
});

test("disconnected_engine_is_quiet", async () => {
  // A pinned engine with no connection at all: nothing to sign with.
  const engine = new FakeEngine({ pinned: true, credentials: "ready" });
  const notify = collectNotify();
  const timers = fakeTimers();
  const connection = { get: async () => null, markNeedsReconnect: async () => {}, repush: async () => ({ ok: true }) };
  const loops = startLoops({
    client: engineClient(engine),
    notify,
    connection,
    holder: "gw-test",
    timers: timers.api,
  });
  await settle();
  const baseline = engine.requests.length;
  for (let index = 0; index < 5; index += 1) await loops.ticks.lease();
  assert.equal(engine.requests.length - baseline, 5);
  assert.equal(engine.callsTo("/health").length, engine.requests.length);
  assert.equal(engine.callsTo("/lease").length, 0);
  assert.equal(loops.state().lastError, null);
  assert.equal(loops.state().holding, false);
  assert.equal(loops.state().mode, "not_connected");
  assert.equal(notify.calls.length, 0);
  loops.stop();

  // A pinned engine whose lease route refuses the approval: quiet as well.
  const refusing = new FakeEngine({ pinned: true, credentials: "ready" });
  refusing.denyLease = true;
  const notifyRefusing = collectNotify();
  const loopsRefusing = startLoops({
    client: engineClient(refusing),
    notify: notifyRefusing,
    connection: idleConnection(),
    holder: "gw-test",
    timers: fakeTimers().api,
  });
  await settle();
  const mark = refusing.requests.length;
  for (let index = 0; index < 4; index += 1) await loopsRefusing.ticks.lease();
  const delta = refusing.requests.length - mark;
  assert.equal(delta, 8, "one health and one lease per tick, and no more");
  assert.equal(refusing.callsTo("/lease").length, 5);
  assert.equal(loopsRefusing.state().lastError, null);
  assert.equal(loopsRefusing.state().holding, false);
  assert.equal(notifyRefusing.calls.length, 0);
  loopsRefusing.stop();
});

test("mcp_events_audited", async () => {
  const engine = new FakeEngine({ pinned: true, credentials: "ready" });
  engine.addEvent({ kind: "fill", message: "mcp fill", data: { source: "mcp" } });
  engine.addEvent({ kind: "alert", message: "engine alert", data: null });
  engine.addEvent({ kind: "halt", message: "mcp halt", data: { source: "mcp", note: "kept in the feed" } });

  const audited = new Set();
  const appends = [];
  const dbArgs = [];
  const instanceDb = { name: "instance-db" };
  const notify = collectNotify();
  let captured = null;
  const loops = startLoops({
    client: engineClient(engine),
    notify,
    connection: idleConnection({ engineEpoch: "epoch-one" }),
    holder: "gw-test",
    getProjectId: () => 7,
    db: instanceDb,
    appendAudit: async (db, entry) => {
      dbArgs.push(db);
      appends.push(entry);
      audited.add(entry.target);
    },
    auditExists: async (target) => audited.has(target),
    timers: fakeTimers().api,
    createNotifierImpl: (options) => {
      captured = createNotifier(options);
      return captured;
    },
  });

  await settle();
  await loops.ticks.notify();
  assert.equal(appends.length, 2);
  assert.deepEqual(appends.map((entry) => entry.target), [
    "engine-event:2026-01-01T00:00:01Z:1",
    "engine-event:2026-01-01T00:00:03Z:3",
  ]);
  assert.deepEqual(dbArgs, [instanceDb, instanceDb], "the app's own database is handed to appendAudit");
  const first = appends[0];
  assert.equal(first.project_id, 7);
  assert.equal(first.actor_type, "system");
  assert.equal(first.actor_id, "coinbase-mcp");
  assert.equal(first.action, "coinbase.mcp_event");
  assert.deepEqual(Object.keys(first.payload).sort(), ["id", "kind", "level", "message", "owner", "ts"]);
  assert.equal(first.payload.id, 1);
  assert.equal(first.payload.kind, "fill");
  assert.equal(first.payload.message, "mcp fill");
  assert.equal("data" in first.payload, false);

  // A replay (a handover, or a poll whose cursor did not advance) writes nothing twice.
  assert.ok(captured);
  captured.setCursor(0);
  await loops.ticks.notify();
  assert.equal(appends.length, 2);

  loops.stop();

  // The existence question over a database client answers rows.
  const queries = [];
  const exists = auditExistsFor({
    execute: async (query) => {
      queries.push(query);
      return { rows: [{ 1: 1 }] };
    },
  });
  const rows = await exists("engine-event:2026-01-01T00:00:09Z:9");
  assert.deepEqual(rows, [{ 1: 1 }]);
  assert.equal(queries.length, 1);
  assert.match(queries[0].sql, /project_audit_log/);
  assert.match(queries[0].sql, /action='coinbase\.mcp_event'/);
  assert.deepEqual(queries[0].args, ["engine-event:2026-01-01T00:00:09Z:9"]);
});

test("notifier_no_secret_in_body", async () => {
  const MARKER = "data-note-marker-never-shown";
  const engine = new FakeEngine();
  const kinds = ["fill", "halt", "ai_preview", "credentials", "live_switch", "alert", "watchdog", "trailing_hold", "bot_paused"];
  for (const kind of kinds) {
    engine.addEvent({
      kind,
      level: "warn",
      message: `the engine wrote a sentence about ${kind}`,
      data: { note: MARKER, preview_id: kind === "ai_preview" ? "pv-1" : undefined },
    });
  }
  const notify = collectNotify();
  const { notifier } = await leasedNotifier(engine, notify, "gw-a", { hourlyLimit: 20 });
  await notifier.pollOnce();
  assert.equal(notify.calls.length, kinds.length);

  const shapes = [];
  for (const note of notify.calls) shapes.push(JSON.stringify(note));
  const surface = shapes.join("\n");
  for (const secret of [TOKEN, OWNER_KEY, INSTALL_KEY, "BEGIN", MARKER]) {
    assert.equal(surface.includes(secret), false, secret);
  }
  for (const call of notify.calls) {
    assert.equal(call.body.includes(MARKER), false);
  }

  // The notification writer's own payload keeps only the kind.
  const written = [];
  const write = makeNotify({}, async (db, opts) => {
    written.push(opts);
    return { id: written.length };
  });
  for (const note of notify.calls) await write(note);
  const payload = JSON.stringify(written);
  for (const secret of [TOKEN, OWNER_KEY, INSTALL_KEY, "BEGIN", MARKER]) {
    assert.equal(payload.includes(secret), false, secret);
  }
  for (const opts of written) {
    assert.deepEqual(Object.keys(opts.metadata || {}), ["kind"]);
    assert.equal(opts.source, "coinbase");
    assert.equal(opts.type, "system");
  }
});

test("lease_install_key_before_pin", async () => {
  const askedInstall = [];
  const engine = new FakeEngine({ pinned: false, credentials: "not_ready" });
  const loopsInstall = startLoops({
    client: engineClient(engine, askedInstall),
    notify: collectNotify(),
    connection: idleConnection(),
    holder: "gw-install",
    timers: fakeTimers().api,
  });
  await settle();
  assert.ok(askedInstall.includes("install"));
  assert.deepEqual(engine.keyKinds, ["install"]);
  assert.equal(engine.lease.holder, "gw-install");
  loopsInstall.stop();

  const askedOwner = [];
  const pinnedEngine = new FakeEngine({ pinned: true, credentials: "ready" });
  const loopsOwner = startLoops({
    client: engineClient(pinnedEngine, askedOwner),
    notify: collectNotify(),
    connection: idleConnection({ engineEpoch: "epoch-one" }),
    holder: "gw-owner",
    timers: fakeTimers().api,
  });
  await settle();
  assert.ok(askedOwner.includes("owner"));
  assert.deepEqual(pinnedEngine.keyKinds, ["owner"]);
  assert.equal(pinnedEngine.lease.holder, "gw-owner");
  loopsOwner.stop();

  // The holder id is a legal engine holder, and two homes never share one.
  const id = holderId("/home/example/.crow");
  assert.match(id, /^[A-Za-z0-9_-]{8,64}$/);
  assert.match(id, /^[A-Za-z0-9._:-]{1,128}$/);
  assert.notEqual(id, holderId("/home/example/.crow-r4"));
  assert.equal(id, holderId("/home/example/.crow"));
});

// ---------------------------------------------------------------- reachability

test("note_reachability_one_alert_per_episode", async () => {
  const engine = new FakeEngine();
  const notify = collectNotify();
  const notifier = createNotifier({
    client: engineClient(engine),
    notify,
    holder: "gw-a",
    failureThreshold: 3,
  });
  assert.equal(typeof notifier.noteReachability, "function");
  const notResponding = () => notify.count("Trading engine not responding");
  const back = () => notify.count("Trading engine is back");

  await notifier.noteReachability("unreachable");
  await notifier.noteReachability("unreachable");
  assert.equal(notResponding(), 0, "not before the threshold");
  await notifier.noteReachability("unreachable");
  assert.equal(notResponding(), 1);
  assert.equal(notify.calls[0].priority, "high");
  await notifier.noteReachability("unreachable");
  await notifier.noteReachability("unreachable");
  assert.equal(notResponding(), 1, "one alert for the episode");

  await notifier.noteReachability("up");
  assert.equal(back(), 1);
  assert.equal(notify.calls[notify.calls.length - 1].priority, "normal");
  await notifier.noteReachability("up");
  assert.equal(back(), 1, "one back note for the recovery");

  // A stale heartbeat alerts at once, with no threshold to wait for.
  await notifier.noteReachability("stale");
  assert.equal(notResponding(), 2);
  await notifier.noteReachability("stale");
  assert.equal(notResponding(), 2);
  await notifier.noteReachability("up");
  assert.equal(back(), 2);

  // The episode flag is shared with pollOnce's own counting.
  const feed = new FakeEngine();
  const notifyShared = collectNotify();
  const shared = createNotifier({
    client: engineClient(feed),
    notify: notifyShared,
    holder: "gw-a",
    failureThreshold: 2,
  });
  shared.setHolding(true);
  await shared.noteReachability("unreachable");
  await shared.noteReachability("unreachable");
  assert.equal(notifyShared.count("Trading engine not responding"), 1);
  await shared.pollOnce();
  assert.equal(notifyShared.count("Trading engine is back"), 1, "a poll that answers ends the episode");
  assert.equal(notifyShared.count("Trading engine not responding"), 1);
});

test("unreachable_engine_alerts_without_ever_leasing", async () => {
  const engine = new FakeEngine({ pinned: true, credentials: "ready" });
  engine.down = true;
  const notify = collectNotify();
  const timers = fakeTimers();
  const loops = startLoops({
    client: engineClient(engine),
    notify,
    connection: idleConnection({ engineEpoch: "epoch-one" }),
    holder: "gw-test",
    timers: timers.api,
  });

  await settle();
  assert.equal(notify.count("Trading engine not responding"), 0, "not before the threshold");
  await loops.ticks.lease();
  assert.equal(notify.count("Trading engine not responding"), 0);
  await loops.ticks.lease();
  assert.equal(notify.count("Trading engine not responding"), 1);
  assert.equal(notify.calls[0].priority, "high");
  await loops.ticks.lease();
  await loops.ticks.lease();
  assert.equal(notify.count("Trading engine not responding"), 1, "one alert for the episode");
  assert.equal(loops.state().holding, false, "the lease was never taken");

  engine.down = false;
  await loops.ticks.lease();
  assert.equal(notify.count("Trading engine is back"), 1);
  assert.equal(notify.calls.find((note) => note.title === "Trading engine is back").priority, "normal");
  await loops.ticks.lease();
  assert.equal(notify.count("Trading engine is back"), 1);

  loops.stop();
});

test("stale_heartbeat_keeps_leasing_and_alerts_once", async () => {
  const engine = new FakeEngine({ pinned: true, credentials: "ready", stale: true });
  engine.addEvent({ kind: "watchdog", level: "warn", message: "the engine heartbeat is stale" });
  const notify = collectNotify();
  const timers = fakeTimers();
  const loops = startLoops({
    client: engineClient(engine),
    notify,
    connection: idleConnection({ engineEpoch: "epoch-one" }),
    holder: "gw-test",
    timers: timers.api,
  });

  await settle();
  // A 503 health with a body is an answer: the lease is still taken.
  assert.equal(engine.callsTo("/health").length, 2, "the boot lease and repush ticks both read health");
  assert.equal(engine.callsTo("/lease").length, 1, "a stale heartbeat still takes the lease");
  assert.equal(engine.lease && engine.lease.holder, "gw-test");
  assert.equal(loops.state().holding, true);
  assert.equal(loops.state().mode, "holding");

  await loops.ticks.notify();
  const watchdog = notify.calls.find((note) => note.title === "Trading engine watchdog");
  assert.ok(watchdog, "the watchdog event was notified");
  assert.equal(watchdog.priority, "high");
  assert.equal(watchdog.body, "the engine heartbeat is stale");

  const alerts = () => notify.calls.filter((note) => note.title === "Trading engine not responding");
  assert.equal(alerts().length, 1, "a stale heartbeat is one alert, at once");
  assert.equal(alerts()[0].priority, "high");

  await loops.ticks.lease();
  await loops.ticks.lease();
  assert.equal(alerts().length, 1, "no second alert while the heartbeat stays stale");

  engine.stale = false;
  await loops.ticks.lease();
  assert.equal(notify.count("Trading engine is back"), 1);
  await loops.ticks.lease();
  assert.equal(notify.count("Trading engine is back"), 1);

  loops.stop();
});

// ---------------------------------------------------------------- credential pushes

const ATTENTION = "Coinbase connection needs attention";

function failingRepush(code, status = 422) {
  return { ok: false, status, code, message: "the engine refused that" };
}

function attentionAlerts(notify) {
  return notify.calls.filter((note) => note.title === ATTENTION);
}

function repushLoops(engine, notify, connection, clock) {
  return startLoops({
    client: engineClient(engine),
    notify,
    connection,
    holder: "gw-test",
    now: clock.now,
    timers: fakeTimers().api,
  });
}

// KEY_INVALID is the engine's answer to a passing fault (a Coinbase network
// blip), so it backs off like a transient failure and only reaches the owner
// once the run is long enough to be news.
test("repush_key_invalid_once_then_success_is_quiet", async () => {
  const engine = new FakeEngine({ pinned: true, credentials: "not_ready" });
  const clock = fakeClock();
  const notify = collectNotify();
  const connection = idleConnection({ engineEpoch: "epoch-one", repushResult: failingRepush("KEY_INVALID") });
  const loops = repushLoops(engine, notify, connection, clock);

  await settle();
  assert.equal(connection.repushes, 1);
  assert.equal(attentionAlerts(notify).length, 0, "one passing KEY_INVALID is not news");

  // The push goes through on the first ladder step, thirty seconds in.
  connection.repushResult = { ok: true, data: { state: "ok" } };
  clock.advance(29_000);
  await loops.ticks.repush();
  assert.equal(connection.repushes, 1, "no retry before thirty seconds");
  clock.advance(2_000);
  await loops.ticks.repush();
  assert.equal(connection.repushes, 2, "the retry happens at thirty seconds");
  assert.equal(attentionAlerts(notify).length, 0, "a run that ends quietly never alerts");

  loops.stop();
});

test("repush_key_invalid_three_times_alerts_once", async () => {
  const engine = new FakeEngine({ pinned: true, credentials: "not_ready" });
  const clock = fakeClock();
  const notify = collectNotify();
  const connection = idleConnection({ engineEpoch: "epoch-one", repushResult: failingRepush("KEY_INVALID") });
  const loops = repushLoops(engine, notify, connection, clock);

  await settle();
  assert.equal(connection.repushes, 1);
  assert.equal(attentionAlerts(notify).length, 0, "one failure is below the count");

  clock.advance(31_000);
  await loops.ticks.repush();
  assert.equal(connection.repushes, 2, "the second attempt comes at thirty seconds");
  assert.equal(attentionAlerts(notify).length, 0, "two failures are below the count");

  clock.advance(61_000);
  await loops.ticks.repush();
  assert.equal(connection.repushes, 3, "the third attempt comes sixty seconds later");
  const alerts = attentionAlerts(notify);
  assert.equal(alerts.length, 1, "three consecutive failures are one high alert");
  assert.equal(alerts[0].priority, "high");
  assert.equal(alerts[0].action_url, "/dashboard/coinbase");
  assert.equal(
    alerts[0].body,
    "Coinbase isn't answering; Crow keeps retrying.",
    "a KEY_INVALID run says the engine is not answering and Crow keeps trying",
  );

  clock.advance(121_000);
  await loops.ticks.repush();
  assert.equal(connection.repushes, 4, "the fourth attempt comes a hundred and twenty seconds later");
  assert.equal(attentionAlerts(notify).length, 1, "one alert for the episode");

  loops.stop();
});

test("repush_key_invalid_past_five_minutes_alerts_once", async () => {
  const engine = new FakeEngine({ pinned: true, credentials: "not_ready" });
  const clock = fakeClock();
  const notify = collectNotify();
  const connection = idleConnection({ engineEpoch: "epoch-one", repushResult: failingRepush("KEY_INVALID") });
  const loops = repushLoops(engine, notify, connection, clock);

  await settle();
  assert.equal(connection.repushes, 1);
  assert.equal(attentionAlerts(notify).length, 0);

  // The engine asks for five minutes before the next attempt, so the run is
  // already older than five minutes when the second failure lands.
  connection.repushResult = {
    ok: false,
    status: 429,
    code: "RATE_LIMITED",
    message: "Too many attempts",
    retryAfterS: 300,
  };
  clock.advance(31_000);
  await loops.ticks.repush();
  assert.equal(connection.repushes, 2, "the second attempt comes at thirty seconds");
  assert.equal(attentionAlerts(notify).length, 0, "a rate-limited push is not an alert");

  clock.advance(181_000);
  await loops.ticks.repush();
  assert.equal(connection.repushes, 2, "a rate-limited push waits as long as the engine asked");
  assert.equal(attentionAlerts(notify).length, 0);

  connection.repushResult = failingRepush("KEY_INVALID");
  clock.advance(120_000);
  await loops.ticks.repush();
  assert.equal(connection.repushes, 3);
  const alerts = attentionAlerts(notify);
  assert.equal(alerts.length, 1, "five minutes into the run is one high alert");
  assert.equal(alerts[0].priority, "high");
  assert.equal(alerts[0].action_url, "/dashboard/coinbase");
  assert.equal(
    alerts[0].body,
    "Coinbase isn't answering; Crow keeps retrying.",
    "a KEY_INVALID run six minutes old says the same",
  );

  clock.advance(301_000);
  await loops.ticks.repush();
  assert.equal(connection.repushes, 4);
  assert.equal(attentionAlerts(notify).length, 1, "one alert for the episode");

  loops.stop();
});

test("repush_refused_key_alerts_at_once", async () => {
  const refused = [
    "KEY_CAN_TRANSFER",
    "KEY_WRONG_PORTFOLIO",
    "KEY_DEFAULT_PORTFOLIO",
    "KEY_NOT_PORTFOLIO_SCOPED",
    "KEY_CANNOT_TRADE",
  ];
  for (const code of refused) {
    const engine = new FakeEngine({ pinned: true, credentials: "not_ready" });
    const clock = fakeClock();
    const notify = collectNotify();
    const connection = idleConnection({ engineEpoch: "epoch-one", repushResult: failingRepush(code) });
    const loops = repushLoops(engine, notify, connection, clock);

    await settle();
    assert.equal(connection.repushes, 1, code);
    const alerts = attentionAlerts(notify);
    assert.equal(alerts.length, 1, `${code} is one high alert at once`);
    assert.equal(alerts[0].priority, "high", code);
    assert.equal(alerts[0].action_url, "/dashboard/coinbase", code);
    assert.equal(
      alerts[0].body,
      "Crow could not install the Coinbase key the engine needs; reconnect in the Trading panel",
      `${code} keeps the reconnect sentence`,
    );
    assert.equal(alerts[0].body.includes("retrying"), false, `${code} does not claim a retry`);
    assert.equal(connection.needsReconnect, false, `${code} is not a reconnect`);

    clock.advance(299_000);
    await loops.ticks.repush();
    assert.equal(connection.repushes, 1, `${code} waits five minutes`);
    clock.advance(2_000);
    await loops.ticks.repush();
    assert.equal(connection.repushes, 2, code);
    assert.equal(attentionAlerts(notify).length, 1, `${code} is not repeated on the next retry`);

    loops.stop();
  }
});

test("repush_unknown_failure_alerts_once_per_episode", async () => {
  const engine = new FakeEngine({ pinned: true, credentials: "not_ready" });
  const clock = fakeClock();
  const notify = collectNotify();
  const connection = idleConnection({ engineEpoch: "epoch-one", repushResult: failingRepush("HTTP_404", 404) });
  const loops = repushLoops(engine, notify, connection, clock);

  await settle();
  assert.equal(connection.repushes, 1);
  const alerts = attentionAlerts(notify);
  assert.equal(alerts.length, 1, "an unknown refusal is one high alert");
  assert.equal(alerts[0].priority, "high");
  assert.equal(alerts[0].action_url, "/dashboard/coinbase");
  assert.equal(connection.needsReconnect, false);

  clock.advance(299_000);
  await loops.ticks.repush();
  assert.equal(connection.repushes, 1, "an unknown failure waits five minutes");
  clock.advance(2_000);
  await loops.ticks.repush();
  assert.equal(connection.repushes, 2);
  assert.equal(attentionAlerts(notify).length, 1, "no repeat on the next retry");

  loops.stop();
});

test("repush_key_invalid_run_resets_on_success", async () => {
  const engine = new FakeEngine({ pinned: true, credentials: "not_ready" });
  const clock = fakeClock();
  const notify = collectNotify();
  const connection = idleConnection({ engineEpoch: "epoch-one", repushResult: failingRepush("KEY_INVALID") });
  const loops = repushLoops(engine, notify, connection, clock);

  await settle();
  assert.equal(connection.repushes, 1);
  clock.advance(31_000);
  await loops.ticks.repush();
  assert.equal(connection.repushes, 2);
  assert.equal(attentionAlerts(notify).length, 0, "two failures are below the count");

  // A push that goes through ends the run and clears its counters.
  connection.repushResult = { ok: true, data: { state: "ok" } };
  clock.advance(61_000);
  await loops.ticks.repush();
  assert.equal(connection.repushes, 3);
  assert.equal(attentionAlerts(notify).length, 0);

  connection.repushResult = failingRepush("KEY_INVALID");
  await loops.ticks.repush();
  assert.equal(connection.repushes, 4, "a failure after a success pushes again at once");
  clock.advance(31_000);
  await loops.ticks.repush();
  assert.equal(connection.repushes, 5);
  assert.equal(attentionAlerts(notify).length, 0, "a success starts a fresh run");

  // So does a health that says the credentials are ready.
  engine.credentials = "ready";
  clock.advance(61_000);
  await loops.ticks.repush();
  assert.equal(connection.repushes, 5, "nothing is pushed while the engine holds a key");
  engine.credentials = "not_ready";
  await loops.ticks.repush();
  assert.equal(connection.repushes, 6);
  assert.equal(attentionAlerts(notify).length, 0, "ready credentials closed the previous run");

  assert.equal(notify.count("Trading engine was reset"), 0);
  loops.stop();
});

test("repush_secret_mismatch_asks_for_a_reconnect", async () => {
  const engine = new FakeEngine({ pinned: true, credentials: "not_ready" });
  const clock = fakeClock();
  const notify = collectNotify();
  const connection = idleConnection({ engineEpoch: "epoch-one", repushResult: failingRepush("SECRET_MISMATCH", 403) });
  const loops = repushLoops(engine, notify, connection, clock);

  await settle();
  assert.equal(connection.repushes, 1);
  assert.equal(connection.marks, 1, "the connection is asked to reconnect");
  assert.equal(connection.needsReconnect, true);
  const alerts = attentionAlerts(notify);
  assert.equal(alerts.length, 1);
  assert.equal(alerts[0].priority, "high");
  assert.equal(alerts[0].action_url, "/dashboard/coinbase");

  await loops.ticks.repush();
  clock.advance(301_000);
  await loops.ticks.repush();
  assert.equal(attentionAlerts(notify).length, 1, "no second alert for the same episode");

  loops.stop();
});

test("repush_backoff_is_capped_and_resets_on_success", async () => {
  const engine = new FakeEngine({ pinned: true, credentials: "not_ready" });
  const clock = fakeClock();
  const notify = collectNotify();
  const connection = idleConnection({
    engineEpoch: "epoch-one",
    repushResult: { ok: false, status: 503, code: "HTTP_503", message: "the engine is restarting" },
  });
  const loops = repushLoops(engine, notify, connection, clock);

  await settle();
  assert.equal(connection.repushes, 1, "the boot tick pushed once");

  let repushes = 1;
  const retryAfter = async (waitMs) => {
    clock.advance(waitMs - 1_000);
    await loops.ticks.repush();
    assert.equal(connection.repushes, repushes, `no retry a second before ${(waitMs - 1000) / 1000} s`);
    clock.advance(2_000);
    await loops.ticks.repush();
    repushes += 1;
    assert.equal(connection.repushes, repushes, `a retry a second after ${(waitMs + 1000) / 1000} s`);
  };

  await retryAfter(30_000);
  await retryAfter(60_000);
  await retryAfter(120_000);
  await retryAfter(300_000);
  await retryAfter(300_000);

  // A push that goes through clears the backoff.
  connection.repushResult = { ok: true, data: { state: "ok" } };
  clock.advance(301_000);
  await loops.ticks.repush();
  repushes += 1;
  assert.equal(connection.repushes, repushes);

  connection.repushResult = {
    ok: false,
    status: 0,
    code: "ENGINE_UNREACHABLE",
    message: "The trading engine is not responding",
  };
  await loops.ticks.repush();
  repushes += 1;
  assert.equal(connection.repushes, repushes, "a failure after a success pushes again at once");
  clock.advance(29_000);
  await loops.ticks.repush();
  assert.equal(connection.repushes, repushes, "and then waits thirty seconds, not five minutes");
  clock.advance(2_000);
  await loops.ticks.repush();
  repushes += 1;
  assert.equal(connection.repushes, repushes);

  assert.equal(attentionAlerts(notify).length, 0, "a transient failure is not an alert");
  loops.stop();
});

// ---------------------------------------------------------------- the audit trail

test("audit_target_carries_the_event_ts", async () => {
  const TS_A = "2026-01-01T00:00:01Z";
  const TS_B = "2026-02-02T00:00:01Z";
  const audited = new Set([`engine-event:${TS_A}:1`]);
  const appends = [];

  const engine = new FakeEngine({ pinned: true, credentials: "ready" });
  engine.addEvent({ kind: "fill", ts: TS_A, message: "the first life of id 1", data: { source: "mcp" } });

  const options = (notify) => ({
    client: engineClient(engine),
    notify,
    connection: idleConnection({ engineEpoch: "epoch-one" }),
    holder: "gw-test",
    getProjectId: () => 7,
    db: { name: "instance-db" },
    appendAudit: async (db, entry) => {
      appends.push(entry);
      audited.add(entry.target);
    },
    auditExists: async (target) => audited.has(target),
  });

  const first = startLoops({ ...options(collectNotify()), timers: fakeTimers().api });
  await settle();
  await first.ticks.notify();
  first.stop();
  assert.equal(appends.length, 0, "the same ts and id is already audited");
  assert.equal(audited.size, 1);

  // The engine's table was wiped and its ids restarted: id 1 is a new event.
  engine.wipe();
  engine.nextId = 1;
  engine.lease = null;
  engine.cursor = null;
  engine.addEvent({ kind: "fill", ts: TS_B, message: "a new id 1", data: { source: "mcp" } });

  const second = startLoops({ ...options(collectNotify()), timers: fakeTimers().api });
  await settle();
  await second.ticks.notify();
  second.stop();

  assert.equal(appends.length, 1, "the restarted id is audited");
  assert.equal(appends[0].target, `engine-event:${TS_B}:1`);
  assert.equal(appends[0].payload.id, 1);
  assert.equal(appends[0].payload.ts, TS_B);
  assert.equal(audited.has(`engine-event:${TS_A}:1`), true, "the old row still names the old event");
});

test("real_append_audit_writes_the_event_row", async () => {
  const acl = await appImport("servers/shared/project-acl.js");
  const dir = mkdtempSync(join(tmpdir(), "crow-coinbase-audit-"));
  const db = createDbClient(join(dir, "audit.db"));
  try {
    await db.execute("PRAGMA foreign_keys = OFF");
    await db.executeMultiple(`
      CREATE TABLE IF NOT EXISTS project_audit_log (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        project_id    INTEGER NOT NULL REFERENCES project_spaces(id) ON DELETE CASCADE,
        actor_type    TEXT NOT NULL CHECK (actor_type IN ('local','contact','bot','system')),
        actor_id      TEXT,
        action        TEXT NOT NULL,
        target        TEXT,
        payload       TEXT,
        created_at    TEXT NOT NULL DEFAULT (datetime('now'))
      );
    `);

    const engine = new FakeEngine({ pinned: true, credentials: "ready" });
    engine.addEvent({
      kind: "fill",
      ts: "2026-03-03T00:00:01Z",
      message: "an mcp fill",
      data: { source: "mcp" },
    });
    const loops = startLoops({
      client: engineClient(engine),
      notify: collectNotify(),
      connection: idleConnection({ engineEpoch: "epoch-one" }),
      holder: "gw-test",
      getProjectId: () => 7,
      db,
      appendAudit: acl.appendAudit,
      auditExists: auditExistsFor(db),
      timers: fakeTimers().api,
    });

    await settle();
    await loops.ticks.notify();
    loops.stop();

    const { rows } = await db.execute({
      sql: "SELECT project_id, actor_type, actor_id, action, target, payload FROM project_audit_log",
      args: [],
    });
    assert.equal(rows.length, 1);
    assert.equal(rows[0].action, "coinbase.mcp_event");
    assert.equal(rows[0].target, "engine-event:2026-03-03T00:00:01Z:1");
    assert.equal(rows[0].actor_type, "system");
    assert.equal(rows[0].actor_id, "coinbase-mcp");
    assert.equal(Number(rows[0].project_id), 7);
    assert.equal(JSON.parse(rows[0].payload).kind, "fill");
    assert.equal(JSON.parse(rows[0].payload).id, 1);
  } finally {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------- the hourly limit

test("high_kinds_are_exempt_from_the_hourly_limit", async () => {
  const engine = new FakeEngine();
  const clock = fakeClock();
  const notify = collectNotify();
  const { notifier } = await leasedNotifier(engine, notify, "gw-a", { now: clock.now });

  for (let index = 1; index <= 7; index += 1) {
    engine.addEvent({
      kind: "ai_preview",
      level: "info",
      message: `preview ${index}`,
      data: { preview_id: `pv-${index}` },
    });
  }
  await notifier.pollOnce();

  const previews = notify.calls.filter((note) => note.title === "The AI proposed an order");
  assert.equal(previews.length, 7, "every high notification is sent");
  assert.deepEqual(
    previews.map((note) => note.action_url),
    [1, 2, 3, 4, 5, 6, 7].map((index) => `/dashboard/coinbase?preview=pv-${index}`),
    "each one keeps its own preview link",
  );
  for (const note of previews) assert.equal(note.priority, "high");
  assert.ok(!notifier.state().suppressed.ai_preview, "a high kind is never suppressed");

  for (let index = 1; index <= 9; index += 1) engine.addEvent({ kind: "fill", message: `fill ${index}` });
  await notifier.pollOnce();
  assert.equal(notify.count("Order filled"), 6, "a normal kind stays limited");
  assert.equal(notify.calls.filter((note) => note.title === "3 more fill updates").length, 1);
  assert.equal(notifier.state().suppressed.fill, 0);
});

const PREVIEW_SUMMARY = /more AI order proposals waiting$/;

function previewEvents(engine, from, to) {
  for (let index = from; index <= to; index += 1) {
    engine.addEvent({
      kind: "ai_preview",
      level: "info",
      message: `preview ${index}`,
      data: { preview_id: `pv-${index}` },
    });
  }
}

test("previews_have_their_own_hourly_cap", async () => {
  const engine = new FakeEngine();
  const clock = fakeClock();
  const notify = collectNotify();
  const { notifier } = await leasedNotifier(engine, notify, "gw-a", { now: clock.now });

  previewEvents(engine, 1, 30);
  await notifier.pollOnce();

  const previews = notify.calls.filter((note) => note.title === "The AI proposed an order");
  assert.equal(previews.length, 20, "twenty high notifications in a rolling hour");
  assert.deepEqual(
    previews.map((note) => note.action_url),
    Array.from({ length: 20 }, (_, index) => `/dashboard/coinbase?preview=pv-${index + 1}`),
    "each of the twenty keeps its own preview link",
  );
  for (const note of previews) assert.equal(note.priority, "high");

  const summaries = notify.calls.filter((note) => PREVIEW_SUMMARY.test(String(note.title)));
  assert.equal(summaries.length, 1, "one summary for what the preview cap held back");
  assert.equal(summaries[0].title, "10 more AI order proposals waiting");
  assert.equal(summaries[0].body, "10 more AI order proposals waiting - open the Trading panel");
  assert.equal(summaries[0].priority, "high");
  assert.equal(summaries[0].action_url, "/dashboard/coinbase");
  assert.equal(notify.calls.length, 21, "twenty notes and the summary, nothing else");
  assert.equal(notifier.state().previewsSuppressed, 0, "the summary carried the whole count");
});

test("live_switch_is_never_capped_and_never_counts", async () => {
  const engine = new FakeEngine();
  const clock = fakeClock();
  const notify = collectNotify();
  const { notifier } = await leasedNotifier(engine, notify, "gw-a", { now: clock.now });

  previewEvents(engine, 1, 12);
  for (let index = 1; index <= 12; index += 1) {
    engine.addEvent({ kind: "live_switch", level: "warn", message: `switch ${index}` });
  }
  await notifier.pollOnce();

  assert.equal(notify.count("The AI proposed an order"), 12, "the twelve previews go one by one");
  assert.equal(notify.count("Live trading switch changed"), 12, "every live switch is notified, capped by nothing");
  assert.equal(
    notify.calls.filter((note) => PREVIEW_SUMMARY.test(String(note.title))).length,
    0,
    "nothing was held back, so there is no summary",
  );
  assert.equal(notifier.state().previewsSuppressed, 0);

  // A switch does not count toward the preview window either: eight more
  // previews still fit under the twenty sent this hour.
  previewEvents(engine, 13, 20);
  await notifier.pollOnce();
  assert.equal(notify.count("The AI proposed an order"), 20, "twelve previews plus eight fill the window");
  assert.equal(notify.count("Live trading switch changed"), 12, "no switch is replayed");
  assert.equal(notify.calls.filter((note) => PREVIEW_SUMMARY.test(String(note.title))).length, 0);

  // The twenty-first preview of the hour is the one held back.
  previewEvents(engine, 21, 22);
  await notifier.pollOnce();
  assert.equal(notify.count("The AI proposed an order"), 20, "the window holds at twenty previews");
  const summaries = notify.calls.filter((note) => PREVIEW_SUMMARY.test(String(note.title)));
  assert.equal(summaries.length, 1);
  assert.equal(summaries[0].title, "2 more AI order proposals waiting");
  assert.equal(notifier.state().previewsSuppressed, 0);
});

test("previews_then_a_live_switch_in_one_poll", async () => {
  const engine = new FakeEngine();
  const clock = fakeClock();
  const notify = collectNotify();
  const { notifier } = await leasedNotifier(engine, notify, "gw-a", { now: clock.now });

  previewEvents(engine, 1, 25);
  engine.addEvent({ kind: "live_switch", level: "warn", message: "live trading is on" });
  await notifier.pollOnce();

  const previews = notify.calls.filter((note) => note.title === "The AI proposed an order");
  assert.equal(previews.length, 20, "twenty previews in the rolling hour");
  const switches = notify.calls.filter((note) => note.title === "Live trading switch changed");
  assert.equal(switches.length, 1, "the live switch is not held back by the previews before it");
  assert.equal(switches[0].body, "live trading is on", "and it carries its own sentence");
  assert.equal(switches[0].priority, "high");
  assert.equal(notify.calls.indexOf(switches[0]), 20, "it goes as the poll reaches it, before the summary");

  const summaries = notify.calls.filter((note) => PREVIEW_SUMMARY.test(String(note.title)));
  assert.equal(summaries.length, 1, "one summary for the previews the cap held back");
  assert.equal(summaries[0].title, "5 more AI order proposals waiting");
  assert.equal(summaries[0].body, "5 more AI order proposals waiting - open the Trading panel");
  assert.equal(summaries[0].priority, "high");
  assert.equal(summaries[0].action_url, "/dashboard/coinbase");
  assert.equal(notify.calls.length, 22, "twenty previews, the switch and the summary");
  assert.equal(notifier.state().previewsSuppressed, 0);
});

test("live_switch_storm_never_reaches_the_cap", async () => {
  const engine = new FakeEngine();
  const clock = fakeClock();
  const notify = collectNotify();
  const { notifier } = await leasedNotifier(engine, notify, "gw-a", { now: clock.now });

  for (let index = 1; index <= 30; index += 1) {
    engine.addEvent({ kind: "live_switch", level: "warn", message: `switch ${index}` });
  }
  await notifier.pollOnce();

  assert.equal(notify.count("Live trading switch changed"), 30, "every one of thirty live switches is notified");
  assert.equal(notify.calls.length, 30, "and nothing else is written");
  assert.equal(
    notify.calls.filter((note) => PREVIEW_SUMMARY.test(String(note.title))).length,
    0,
    "no summary, because nothing was held back",
  );
  assert.equal(notifier.state().previewsSuppressed, 0);

  // The switches counted against nothing: the previews still have the window.
  previewEvents(engine, 1, 18);
  await notifier.pollOnce();
  assert.equal(notify.count("The AI proposed an order"), 18, "the preview window was untouched by the switches");
});

test("preview_cap_never_holds_a_halt_after_the_previews", async () => {
  const engine = new FakeEngine();
  const clock = fakeClock();
  const notify = collectNotify();
  const { notifier } = await leasedNotifier(engine, notify, "gw-a", { now: clock.now });

  previewEvents(engine, 1, 25);
  engine.addEvent({ kind: "halt", level: "error", message: "the drawdown limit was hit" });
  await notifier.pollOnce();

  assert.equal(notify.count("The AI proposed an order"), 20, "the previews fill the shared window");
  const halts = notify.calls.filter((note) => note.title === "Trading halted");
  assert.equal(halts.length, 1, "a halt is not held back by the previews before it");
  assert.equal(halts[0].priority, "high");
  assert.equal(halts[0].body, "the drawdown limit was hit");
  assert.equal(halts[0].action_url, undefined);

  const summaries = notify.calls.filter((note) => PREVIEW_SUMMARY.test(String(note.title)));
  assert.equal(summaries.length, 1, "one summary for the five previews held back");
  assert.equal(summaries[0].title, "5 more AI order proposals waiting");
  assert.equal(summaries[0].body, "5 more AI order proposals waiting - open the Trading panel");
  assert.equal(summaries[0].priority, "high");
  assert.equal(summaries[0].action_url, "/dashboard/coinbase");
  assert.equal(notifier.state().previewsSuppressed, 0);
});

test("halts_watchdogs_alerts_and_credentials_are_never_capped_or_counted", async () => {
  const engine = new FakeEngine();
  const clock = fakeClock();
  const notify = collectNotify();
  const { notifier } = await leasedNotifier(engine, notify, "gw-a", { now: clock.now });

  for (let index = 1; index <= 30; index += 1) {
    engine.addEvent({ kind: "halt", level: "error", message: `halt ${index}` });
    engine.addEvent({ kind: "watchdog", level: "warn", message: `watchdog ${index}` });
    engine.addEvent({ kind: "alert", level: "warn", message: `alert ${index}` });
    engine.addEvent({ kind: "credentials", level: "error", message: `credentials ${index}` });
  }
  // A hundred and twenty events outrun the page limit, so the storm arrives in
  // two polls; every one of them still earns its own notification.
  await notifier.pollOnce();
  await notifier.pollOnce();

  assert.equal(notify.count("Trading halted"), 30, "every halt is notified");
  assert.equal(notify.count("Trading engine watchdog"), 30, "every watchdog event is notified");
  assert.equal(notify.count("Trading alert"), 30, "every alert event is notified");
  assert.equal(notify.count("Coinbase connection needs attention"), 30, "every credentials event is notified");
  assert.equal(
    notify.calls.filter((note) => PREVIEW_SUMMARY.test(String(note.title))).length,
    0,
    "nothing was held back, so there is no summary",
  );
  assert.equal(notifier.state().previewsSuppressed, 0);

  // None of those four kinds filled the preview window: the previews still get it.
  previewEvents(engine, 1, 25);
  await notifier.pollOnce();
  const previews = notify.calls.filter((note) => note.title === "The AI proposed an order");
  assert.equal(previews.length, 20, "the preview window was untouched by the other kinds");
  assert.equal(notify.count("Trading halted"), 30, "no halt is replayed");
  const summaries = notify.calls.filter((note) => PREVIEW_SUMMARY.test(String(note.title)));
  assert.equal(summaries.length, 1);
  assert.equal(summaries[0].title, "5 more AI order proposals waiting");
});

test("preview_summary_waits_for_the_hour", async () => {
  const engine = new FakeEngine();
  const clock = fakeClock();
  const notify = collectNotify();
  const { notifier } = await leasedNotifier(engine, notify, "gw-a", { now: clock.now });

  previewEvents(engine, 1, 30);
  await notifier.pollOnce();
  const previewCount = () => notify.calls.filter((note) => note.title === "The AI proposed an order").length;
  const summaries = () => notify.calls.filter((note) => PREVIEW_SUMMARY.test(String(note.title)));
  assert.equal(previewCount(), 20);
  assert.equal(summaries().length, 1);

  // Ten minutes on the cap is still full and the last summary holds: the extra
  // previews are only counted.
  clock.advance(10 * 60 * 1000);
  previewEvents(engine, 31, 35);
  await notifier.pollOnce();
  assert.equal(previewCount(), 20, "the rolling hour is still full");
  assert.equal(summaries().length, 1, "one preview summary an hour");

  // Over an hour on, the window is empty again and the held-back count folds
  // into one summary.
  clock.advance(HOUR_MS + 1);
  previewEvents(engine, 36, 40);
  await notifier.pollOnce();
  assert.equal(previewCount(), 25, "the emptied window lets the new previews through");
  assert.equal(summaries().length, 2);
  assert.equal(summaries()[1].title, "5 more AI order proposals waiting");
  assert.equal(summaries()[1].body, "5 more AI order proposals waiting - open the Trading panel");
  assert.equal(summaries()[1].priority, "high");
  assert.equal(summaries()[1].action_url, "/dashboard/coinbase");
});