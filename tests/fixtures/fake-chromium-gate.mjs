#!/usr/bin/env node
/**
 * A gate-capable fake Chromium, for tests that drive the browser relay's gate.
 *
 * It speaks the real `--remote-debugging-pipe` framing (fd 3 = commands in, fd 4 = replies
 * and events out, JSON + NUL) and keeps an in-memory model of targets and sessions, because
 * the gate's rules are about ORDER and about the Fetch chain: which session is the oldest
 * auto-attacher, which is the oldest Fetch interceptor, which sessions a held target is
 * waiting for, and in what order the Fetch chain visits them.
 *
 * What the model stands for:
 *  - A target auto-attached with `waitForDebuggerOnStart` is HELD (it runs nothing) until
 *    EVERY session that announced it has sent `Runtime.runIfWaitingForDebugger`; a
 *    `shared_worker` or `service_worker` becomes running as soon as the FIRST resumer
 *    resumes it. Both are the measured Chromium behaviours recorded in the private
 *    engineering notes for the S5 spike.
 *  - A request chains through the sessions that have Fetch enabled on its target, NEWEST
 *    session first and OLDEST last. Every one of them must continue it for it to pass, any
 *    `Fetch.failRequest` stops it, and a `continueRequest {url}` override is what the
 *    remaining (older) sessions then see. Request ids are scoped to the session that holds
 *    the request. [same spike]
 *
 * Nothing here is real: no rendering, no network, no Playwright, Node builtins only, and no
 * timer longer than a second.
 *
 * Everything tests/fixtures/fake-chromium.mjs does that is not about targets is kept as it
 * was: the argv/env/pid/profile trace lines at start, one `recv` trace line per message,
 * `Browser.getVersion`, `Browser.close`, `Browser.crash`, `Test.echo`/`Test.event`/
 * `Test.stream`/`Test.exit`, and an unknown method answered with `{}`.
 *
 * The knobs that shape WHAT EXISTS at launch are documented beside the code that creates the
 * targets: `FAKE_CHROME_EXTENSION_WORKERS` / `FAKE_CHROME_EXTENSION_WORKER_TYPE` /
 * `FAKE_CHROME_EXTENSION_WORKER_DELAY_MS` (the component-extension worker that attaches a
 * moment after the first listing, which is how a real Chromium behaves) and
 * `FAKE_CHROME_LISTED_ONLY_TARGETS` (a target that is LISTED in every `Target.getTargets`
 * from launch and NEVER announced — the other real shape), plus
 * `FAKE_CHROME_START_CONTEXT`, `FAKE_CHROME_START_PAGE_NO_URL` and the method hooks
 * `FAKE_CHROME_DELAY_METHODS` / `FAKE_CHROME_FAIL_METHODS`.
 *
 * The knob that shapes the CLOSE WINDOW is `FAKE_CHROME_CLOSE_HANDLE_DELAY_MS` (default 0, cap
 * 2000): with it set, `Browser.close` is traced and answered as it always is, but the fixture
 * does NOT exit and does NOT close fd 4 for that many ms — it keeps serving, so a page's own
 * timers (`Test.armPageRequest`) keep firing and the relay's answers to the requests they make
 * still arrive. After the delay it does exactly what it does today (exit per
 * `FAKE_CHROME_CLOSE_EXIT_MS`). That is the window a real Chromium has between `Browser.close`
 * and its exit, while its pages still run their pagehide beacons and image requests.
 *
 * Session ids are prefix-distinguishable, as in the other fake: `S…` browser sessions,
 * `T…` `Target.attachToTarget`, `A…` auto-attached children. Target ids carry the type they
 * were created as (`P…` page, `FR…` iframe, `WK…` worker, `SW…` shared worker, `SV…` service
 * worker, `PR…` prerender, `OT…` other) so a trace reads without a lookup.
 *
 * SESSIONS BELONG TO WHOEVER ATTACHED THEM. Every session records the envelope `sessionId` of
 * the command that created it (`owner`): the session that auto-attached it
 * (`Target.setAutoAttach` on that session), the session `Target.attachToTarget` was issued on,
 * or null (the root, the sessionless connection) for `Target.attachToBrowserTarget` and for an
 * attach that came in on the root. A real Chromium looks a session up for
 * `Target.detachFromTarget` ONLY in the session that owns it, so the command has to be sent on
 * the owning session's envelope: sent anywhere else it is answered -32602
 * "No session with given id" and NOTHING detaches. Detaching a session takes the sessions it
 * owns with it (they die silently, with no `Target.detachedFromTarget` of their own), which is
 * how detaching a browser session takes every session below it.
 */
import { appendFileSync, closeSync, readFileSync, writeSync } from "node:fs";
import net from "node:net";
import { join } from "node:path";

const LOG = process.env.FAKE_CHROME_LOG || "";
const trace = (obj) => { if (LOG) { try { appendFileSync(LOG, JSON.stringify(obj) + "\n"); } catch { /* gone */ } } };

/**
 * The shutdown window a real Chromium has after `Browser.close`: it closes its pipe first and
 * exits a moment later, while the cookie store is committed on the way out. With a delay set,
 * fd 4 is closed at once and the process exits `FAKE_CHROME_CLOSE_EXIT_CODE` (default 0) after
 * `FAKE_CHROME_CLOSE_EXIT_MS`, so a supervisor that kills on pipe EOF is visible as a browser
 * that never reached its own exit.
 */
const CLOSE_EXIT_MS = Number(process.env.FAKE_CHROME_CLOSE_EXIT_MS || 0);
const CLOSE_EXIT_CODE = Number(process.env.FAKE_CHROME_CLOSE_EXIT_CODE || 0);
/**
 * How long the browser keeps running (and serving) after `Browser.close` — the window in which
 * a real Chromium still runs its pages' pagehide beacons and image requests. 0 (the default)
 * keeps the old behaviour byte for byte: reply, then exit in the same command handler.
 */
const CLOSE_HANDLE_DELAY_MS = Math.max(0, Math.min(2000, Math.trunc(Number(process.env.FAKE_CHROME_CLOSE_HANDLE_DELAY_MS ?? 0)) || 0));

// Deliberately identical to the other fake's version block: a relay cannot tell the two
// fixtures apart, so one can stand in for the other without moving any other needle.
const VERSION = {
  protocolVersion: "1.3",
  product: "FakeChrome/1.0.0",
  revision: "fake-rev-1",
  userAgent: "FakeChrome/1.0.0 (pipe)",
  jsVersion: "11.1.0",
};

trace({ t: "argv", argv: process.argv.slice(1) });
trace({ t: "env", env: { ...process.env } });
trace({ t: "pid", pid: process.pid });

/**
 * The profile Chromium is about to open, read AS IT IS NOW — before the browser itself
 * touches it. `profile` is the parsed file (null when missing or unparseable), `raw` its
 * text, so a test can tell "already clean at launch" from "cleaned afterwards".
 */
const PROFILE_DIR = process.env.CROW_CHROMIUM_PROFILE || "";
function profileSnapshot() {
  const path = PROFILE_DIR ? join(PROFILE_DIR, "Default", "Preferences") : "";
  let raw = null;
  if (path) { try { raw = readFileSync(path, "utf8"); } catch { raw = null; } }
  let profile = null;
  if (typeof raw === "string") { try { profile = JSON.parse(raw); } catch { profile = null; } }
  return { t: "profile", path, raw: typeof raw === "string" ? raw.slice(0, 500) : null, profile };
}
trace(profileSnapshot());

// Replies and events leave on fd 4. Written synchronously, so a reply is already in the
// pipe's buffer on the line after it is sent — which is what lets the exits below happen in
// the same command handler instead of from a timer that could still hold the process up.
let outputClosed = false;
function send(msg) {
  if (outputClosed) return;
  const bytes = Buffer.from(JSON.stringify(msg) + "\0");
  let offset = 0;
  try {
    while (offset < bytes.length) offset += writeSync(4, bytes, offset, bytes.length - offset);
  } catch { process.exit(0); }
}
/** An event: addressed to one session when `sessionId` is given, otherwise to the root. */
const sendEvent = (sessionId, method, params) => send({ method, ...(sessionId ? { sessionId } : {}), params });

// ---------------------------------------------------------------------------------------
// The model
// ---------------------------------------------------------------------------------------

/**
 * The DEFAULT browser context's id, and the shape `Target.getBrowserContexts` answers with.
 *
 * A real Chromium (159, via Playwright 1255) answers at idle with
 * `{"browserContextIds":[],"defaultBrowserContextId":"87CBB1609F3E17EEE60E1BED5B8FA0FE"}`:
 * an OPAQUE id, which is not in `browserContextIds` at all, and every target created without
 * a context carries it in `targetInfo.browserContextId`. That is this fixture's default, so
 * every test runs against the shape the real browser has; `FAKE_CHROME_LEGACY_DEFAULT_CONTEXT=1`
 * gives the older shape the first fixture modelled (the literal "default", LISTED in
 * `browserContextIds`, no `defaultBrowserContextId`), for a build that reports it that way.
 */
const LEGACY_DEFAULT_CONTEXT = process.env.FAKE_CHROME_LEGACY_DEFAULT_CONTEXT === "1";
const DEFAULT_CONTEXT = LEGACY_DEFAULT_CONTEXT ? "default" : "87CBB1609F3E17EEE60E1BED5B8FA0FE-test";

const targets = new Map();        // targetId -> target
const sessions = new Map();       // sessionId -> session
const pausedRequests = new Map(); // requestId -> a request a `Test.request` is waiting on

let seq = 0;                      // global session counter: session ATTACH order
const nextSeq = () => ++seq;

let browserSessions = 0;          // S…
let targetSessions = 0;           // T…
let autoSessions = 0;             // A…
let scriptCount = 0;              // I…
let loaderCount = 0;              // L…
let requestCount = 0;             // R…
let contextCount = 0;             // C…
let targetCount = 1;              // P1 exists from the start; every later id continues it

const createdContexts = [];       // non-default browser contexts this browser has handed out
/** True once the relay's first `Target.getTargets` has been answered (see the workers above). */
let firstListingAnswered = false;

// Test hooks that change how later commands are answered.
const failMethods = new Set();
const delayReplies = new Map();

/**
 * The same two tables, seeded from the environment so a test that drives the fixture THROUGH
 * THE RELAY (a separate process, no `Test.*` channel of its own) can still arm them:
 *
 *   FAKE_CHROME_DELAY_METHODS="Fetch.enable:300,Page.navigate:700"
 *   FAKE_CHROME_FAIL_METHODS="Fetch.enable"
 *
 * Comma-separated `Method` or `Method:ms` entries. A delay is capped by the reply path below
 * (1000 ms), so a test never has to know that ceiling. Both are `Test.delayReplies` and
 * `Test.failCommands` in every other respect, and they can be edited by those hooks later.
 */
function envPairs(text) {
  const out = [];
  for (const part of String(text || "").split(",")) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const at = trimmed.indexOf(":");
    out.push(at < 0 ? [trimmed, NaN] : [trimmed.slice(0, at).trim(), Number(trimmed.slice(at + 1))]);
  }
  return out;
}
for (const [method, ms] of envPairs(process.env.FAKE_CHROME_DELAY_METHODS)) {
  if (method && Number.isFinite(ms) && ms > 0) delayReplies.set(method, ms);
}
for (const [method] of envPairs(process.env.FAKE_CHROME_FAIL_METHODS)) {
  if (method) failMethods.add(method);
}

/**
 * The gate-ack window on a page the BROWSER just made, which is the shape a relay ordering bug
 * shows in: `Target.createTarget` has replied, and the gate's own session is taking its
 * interception place on the new target. The FIRST `Fetch.enable` on a target created by
 * `Target.createTarget` is the gate's — it auto-attached before any client could — so a
 * client's own hook command on that target is a later one and is answered normally.
 *
 *   FAKE_CHROME_NEW_PAGE_ACK_DELAY_MS=400   answer that first interception 400 ms later
 *   FAKE_CHROME_NEW_PAGE_ACK_FAIL=1         refuse it instead
 *
 * Shortened like every other delay knob (1000 ms at most), so no test depends on its ceiling.
 */
const NEW_PAGE_ACK_DELAY_MS = Math.max(0, Math.min(1000, Math.trunc(Number(process.env.FAKE_CHROME_NEW_PAGE_ACK_DELAY_MS ?? 0)) || 0));
const NEW_PAGE_ACK_FAIL = process.env.FAKE_CHROME_NEW_PAGE_ACK_FAIL === "1";
/** The targets `Target.createTarget` made (not the start page, not a `Test.spawnTarget`). */
const createdPages = new Set();
/** The targets whose first gate interception the knob above already answered. */
const newPageAckServed = new Set();

const TARGET_PREFIX = {
  page: "P",
  iframe: "FR",
  worker: "WK",
  shared_worker: "SW",
  service_worker: "SV",
  prerender: "PR",
  other: "OT",
};

function makeTarget({ id, type, url, openerId = null, ownerId = null, contextId = DEFAULT_CONTEXT }) {
  return {
    id,
    type,
    url,
    openerId,
    ownerId,
    contextId,
    // A target nobody has announced with waitingForDebugger starts running, as in a real
    // browser: `new Set()` waiting means "held by nothing".
    running: true,
    held: false,
    closed: false,
    history: [url],
    currentIndex: 0,
    commit: true,
    waiting: new Set(),
    // A target nothing ever announces: present in `Target.getTargets` from launch, and kept out
    // of `targetCreated` and of every `attachedToTarget` (see FAKE_CHROME_LISTED_ONLY_TARGETS).
    listedOnly: false,
  };
}

/**
 * The one page the browser starts with. `FAKE_CHROME_START_PAGE_NO_URL=1` gives it NO url at
 * all (the key is absent from its `targetInfo`), the shape a build whose start page reports
 * nothing — not the same thing as a page that IS at `about:blank`.
 */
const START_PAGE_NO_URL = process.env.FAKE_CHROME_START_PAGE_NO_URL === "1";
const firstTarget = makeTarget({ id: "P1", type: "page", url: START_PAGE_NO_URL ? undefined : "about:blank" });
targets.set(firstTarget.id, firstTarget);

/**
 * Component-extension workers, as a real Chromium has them at idle: a `service_worker` target
 * at `chrome-extension://<id>/background.js`. The load-bearing part is WHEN they appear: a real
 * Chromium does NOT list them in the `Target.getTargets` answer the relay's start sequence makes
 * — they attach to the gate's auto-attach a moment later — which is why this fixture creates
 * them AFTER answering the first `Target.getTargets` unless told otherwise.
 *
 *   FAKE_CHROME_EXTENSION_WORKERS="abc,def"      the ids (default: the one component id below)
 *   FAKE_CHROME_EXTENSION_WORKERS=""             none at all
 *   FAKE_CHROME_EXTENSION_WORKER_TYPE=shared_worker   the target type to create them as
 *                                                (default `service_worker`; a real browser's
 *                                                component extensions are service workers)
 *   FAKE_CHROME_EXTENSION_WORKER_DELAY_MS=250    create them 250 ms after that first listing
 *   FAKE_CHROME_EXTENSION_WORKER_DELAY_MS=start  create them at launch, so the FIRST target
 *                                                listing carries them (the pre-gate shape)
 *
 * They are ownerless, so the browser-level auto-attachers are the ones that see them.
 *
 * The default is the one id the relay's own component allow-list pins (`COMPONENT_EXTENSION_IDS`
 * in cdp-relay.mjs): `nkeimhogjdpnpccoofpliimaahmaaome`, the worker a Chromium 145.0.7632.6
 * start (Playwright 1.58.2's chromium-1208) lists as `thunk.js`. Keep the two in step: an id the
 * relay does not allow-list is not exempt, and now fails its start.
 */
const REAL_EXTENSION_IDS = ["nkeimhogjdpnpccoofpliimaahmaaome"];
const EXTENSION_IDS = (
  process.env.FAKE_CHROME_EXTENSION_WORKERS === undefined
    ? REAL_EXTENSION_IDS
    : String(process.env.FAKE_CHROME_EXTENSION_WORKERS).split(",")
).map((s) => s.trim()).filter(Boolean);
const EXTENSION_WORKER_AT_RAW = String(process.env.FAKE_CHROME_EXTENSION_WORKER_DELAY_MS ?? "100").trim();
const EXTENSION_WORKERS_AT_START = EXTENSION_WORKER_AT_RAW === "start";
const EXTENSION_WORKER_DELAY_MS = EXTENSION_WORKERS_AT_START
  ? 0
  : Math.max(0, Math.min(1000, Math.trunc(Number(EXTENSION_WORKER_AT_RAW)) || 0));
/**
 * The type the component-extension workers are created as. A real browser's are `service_worker`
 * targets; `shared_worker` is the shape a test needs to show that the relay's exemption is
 * limited to a service worker (a shared worker belongs to a document at that origin).
 */
const EXTENSION_WORKER_TYPE = String(process.env.FAKE_CHROME_EXTENSION_WORKER_TYPE ?? "service_worker").trim() || "service_worker";

/**
 * Create the component-extension workers now. Announced exactly like any other new target
 * (discoverers first, then every auto-attacher that can see them), so a late creation is the
 * real browser's "attached a moment after the gate's listing" and an early one is the old
 * "already in the first listing".
 */
function createExtensionWorkers() {
  for (const id of EXTENSION_IDS) {
    const url = `chrome-extension://${id}/background.js`;
    const worker = makeTarget({ id: nextTargetId(EXTENSION_WORKER_TYPE), type: EXTENSION_WORKER_TYPE, url });
    targets.set(worker.id, worker);
    trace({
      t: "extension-worker",
      targetId: worker.id,
      type: EXTENSION_WORKER_TYPE,
      url,
      at: EXTENSION_WORKERS_AT_START ? "start" : `+${EXTENSION_WORKER_DELAY_MS}ms`,
    });
    notifyDiscoverers(worker);
    announceToAutoAttachers(worker);
  }
}

if (EXTENSION_WORKERS_AT_START) createExtensionWorkers();

/**
 * Targets that are LISTED but NEVER ANNOUNCED — the other shape a real Chromium has, side by
 * side with the attach-late workers above: a component extension's worker that appears in every
 * `Target.getTargets` answer from launch, which the browser NEVER announces (no
 * `Target.targetCreated`, no `Target.attachedToTarget`), not even to an auto-attacher that called
 * `Target.setAutoAttach` after it already existed. Chromium 145.0.7632.6 does exactly this with
 * `service_worker chrome-extension://nkeimhogjdpnpccoofpliimaahmaaome/thunk.js`.
 *
 *   FAKE_CHROME_LISTED_ONLY_TARGETS="service_worker|chrome-extension://abc/thunk.js,worker|https://x.example.test/w.js"
 *
 * Comma-separated `type|url` entries (`type` defaults to `other`; a bare entry is a URL). Each
 * becomes a target from launch and a `listed-only-target` trace record carries its targetId.
 * `listedOnly` is what keeps it out of `notifyDiscoverers`, out of `announceToAutoAttachers`,
 * and out of the announce-everything pass of `Target.setAutoAttach` — i.e. out of every path
 * that would announce an existing target. A test can still close it (`Target.closeTarget`), and
 * `Test.state` lists it like any other target.
 */
const LISTED_ONLY_TARGETS = (
  process.env.FAKE_CHROME_LISTED_ONLY_TARGETS === undefined
    ? []
    : String(process.env.FAKE_CHROME_LISTED_ONLY_TARGETS).split(",")
).map((part) => part.trim()).filter(Boolean).map((entry) => {
  const at = entry.indexOf("|");
  if (at < 0) return { type: "other", url: entry };
  return { type: entry.slice(0, at).trim() || "other", url: entry.slice(at + 1).trim() };
});

function createListedOnlyTargets() {
  for (const entry of LISTED_ONLY_TARGETS) {
    const target = makeTarget({ id: nextTargetId(entry.type), type: entry.type, url: entry.url });
    target.listedOnly = true;
    targets.set(target.id, target);
    trace({ t: "listed-only-target", targetId: target.id, type: entry.type, url: entry.url });
  }
}

createListedOnlyTargets();

function noteContext(id) {
  if (id && id !== DEFAULT_CONTEXT && !createdContexts.includes(id)) createdContexts.push(id);
}

/**
 * A browser that already has a browser context of its own at launch
 * (`FAKE_CHROME_START_CONTEXT=1`). The one page is still the clean default-context
 * `about:blank`, so the context itself is the only thing that says "not the neutral state".
 */
if (process.env.FAKE_CHROME_START_CONTEXT === "1") {
  const id = `C${++contextCount}`;
  noteContext(id);
  trace({ t: "start-context", id });
}

/** A fresh target id for a type, skipping anything a test has already named itself. */
function nextTargetId(type) {
  let candidate;
  do { candidate = `${TARGET_PREFIX[type] || "OT"}${++targetCount}`; } while (targets.has(candidate));
  return candidate;
}

const targetInfo = (t) => ({
  targetId: t.id,
  type: t.type,
  url: t.url,
  ...(t.openerId ? { openerId: t.openerId } : {}),
  browserContextId: t.contextId,
});

const targetState = (t) => ({
  id: t.id,
  type: t.type,
  url: t.url,
  openerId: t.openerId,
  ownerId: t.ownerId,
  contextId: t.contextId,
  running: t.running,
  held: t.held,
  closed: t.closed,
  history: t.history.slice(),
  currentIndex: t.currentIndex,
  commit: t.commit,
  waiting: [...t.waiting],
});

// The start page AS THE BROWSER REPORTS IT (a key it does not carry is absent here too).
trace({ t: "start-page", ...targetInfo(firstTarget) });

const sessionState = (s) => ({
  id: s.id,
  kind: s.kind,
  targetId: s.targetId,
  seq: s.seq,
  parent: s.parent,
  discover: s.discover,
  fetch: s.fetch,
  autoAttach: { ...s.autoAttach },
  scripts: [...s.scripts.entries()].map(([identifier, v]) => ({ identifier, source: v.source, worldName: v.worldName })),
  pageEnabled: s.pageEnabled,
});

/**
 * One session. `parent` is the session its attach event was sent to (null for an explicit
 * attach); `owner` is the session whose ENVELOPE created it — the id `Target.detachFromTarget`
 * has to be sent on, and null for a session created sessionless (the root).
 */
function makeSession({ id, kind, targetId, parent = null, owner = null }) {
  const session = {
    id,
    kind,
    targetId,
    seq: nextSeq(),
    autoAttach: { on: false, waitForDebugger: false, flatten: false },
    fetch: null,
    scripts: new Map(),
    pageEnabled: false,
    discover: false,
    parent,
    owner,
  };
  sessions.set(id, session);
  return session;
}

/**
 * Which targets an auto-attacher may see. A browser session sees the top-level targets of
 * EVERY browser context — a page a bot opened in a context of its own included, which is what
 * a browser-level auto-attach reports in real Chromium (and what lets the gate reach such a
 * page at all) — plus ownerless workers such as a service worker. A target session sees that
 * target's children: the iframes and workers whose `ownerId` is it.
 */
function canSee(session, target) {
  if (target.closed) return false;
  if (session.kind === "browser") return target.ownerId === null;
  return target.ownerId === session.targetId;
}

/** Sessions that auto-attach and can see `target`, in attach (seq) order. */
function autoAttachersFor(target) {
  return [...sessions.values()]
    .filter((s) => s.autoAttach.on && canSee(s, target))
    .sort((a, b) => a.seq - b.seq);
}

const sessionsOfTarget = (targetId) => [...sessions.values()].filter((s) => s.targetId === targetId);

/** Send an event to every session attached to one target. */
function toTargetSessions(targetId, method, params, { onlyPageEnabled = false } = {}) {
  for (const s of sessionsOfTarget(targetId)) {
    if (onlyPageEnabled && !s.pageEnabled) continue;
    sendEvent(s.id, method, params);
  }
}

function announce(target, attacher) {
  // Announced BY this attacher's session, so that session owns the child: a detach of the
  // child has to be sent on `attacher.id`'s envelope, and a detach of `attacher.id` takes the
  // child with it.
  const child = makeSession({ id: `A${++autoSessions}`, kind: "target", targetId: target.id, parent: attacher.id, owner: attacher.id });
  const wait = attacher.autoAttach.waitForDebugger === true;
  if (wait) {
    // Held: nothing runs until every announcer-with-waiting has resumed it.
    target.waiting.add(child.id);
    target.held = true;
    target.running = false;
  }
  sendEvent(attacher.id, "Target.attachedToTarget", {
    sessionId: child.id,
    targetInfo: targetInfo(target),
    waitingForDebugger: wait,
  });
  return child;
}

/** Announce a target to every auto-attacher that can see it, in session attacher order. */
function announceToAutoAttachers(target) {
  // A listed-only target is never announced: it is the "listed but never attached" shape.
  if (target.listedOnly) return;
  for (const attacher of autoAttachersFor(target)) {
    if (!sessions.has(attacher.id) || !attacher.autoAttach.on) continue;
    announce(target, attacher);
  }
}

function notifyDiscoverers(target) {
  if (target.listedOnly) return;
  for (const s of sessions.values()) {
    if (s.discover) sendEvent(s.id, "Target.targetCreated", { targetInfo: targetInfo(target) });
  }
}

/** A target that lost a session it was waiting for: unheld, without a `resumed` trace. */
function forgetWaiter(target, sessionId) {
  if (!target.waiting.delete(sessionId)) return;
  target.held = target.waiting.size > 0;
  if (!target.held) target.running = true;
}

function dropSession(session, { detachEvent = false } = {}) {
  if (!session || !sessions.has(session.id)) return;
  sessions.delete(session.id);
  const target = session.targetId ? targets.get(session.targetId) : null;
  if (target) forgetWaiter(target, session.id);
  if (detachEvent && session.parent) {
    sendEvent(session.parent, "Target.detachedFromTarget", { sessionId: session.id, targetId: session.targetId });
  }
  releaseHeldBy(session);
}

/**
 * Drop a session AND every session it owns, in that order — the shape a real Chromium has: a
 * child session dies with the session that attached it. The children go silently (a session
 * that goes away with its parent is never announced as detached on its own), and each one's
 * held requests are released, so a request held below a detached session moves on instead of
 * hanging.
 */
function dropSessionTree(sessionId, { detachEvent = false } = {}) {
  const session = sessions.get(sessionId);
  if (!session) return false;
  const children = [...sessions.values()].filter((s) => s.owner === sessionId).map((s) => s.id);
  dropSession(session, { detachEvent });
  for (const child of children) dropSessionTree(child);
  return true;
}

// ---------------------------------------------------------------------------------------
// The Fetch chain
// ---------------------------------------------------------------------------------------

/**
 * Move the request past the session that currently holds it and pause it on the next OLDER
 * session that still has Fetch enabled, or pass it when there is none. A session that has
 * gone away or disabled Fetch while holding the request is skipped, which is exactly the
 * "a disabling session releases what it held" rule.
 */
function advance(state) {
  if (state.done) return;
  state.holder = null;
  state.index += 1;
  while (state.index < state.chain.length) {
    const session = state.chain[state.index];
    if (sessions.has(session.id) && session.fetch) {
      state.holder = session;
      state.via.push(session.id);
      sendEvent(session.id, "Fetch.requestPaused", {
        requestId: state.requestId,
        request: { url: state.url, method: "GET" },
        frameId: state.target.id,
        resourceType: state.kind,
      });
      return;
    }
    state.index += 1;
  }
  finish(state, "passed");
}

function finish(state, outcome) {
  if (state.done) return;
  state.done = true;
  state.holder = null;
  pausedRequests.delete(state.requestId);
  trace({
    t: "request",
    requestId: state.requestId,
    targetId: state.target.id,
    url: state.originalUrl,
    finalUrl: state.finalUrl,
    outcome,
    via: state.via.slice(),
  });
  state.reply({ outcome, finalUrl: state.finalUrl, via: state.via.slice() });
}

/** Release every request held by this session: it moves on to the next older session. */
function releaseHeldBy(session) {
  for (const state of [...pausedRequests.values()]) {
    if (state.holder === session) advance(state);
  }
}

// ---------------------------------------------------------------------------------------
// Closing targets
// ---------------------------------------------------------------------------------------

/** The close itself (no reply): used by `Target.closeTarget` and by context disposal. */
function closeTarget(target) {
  if (!target || target.closed) return false;
  target.closed = true;
  trace({
    t: "close-target",
    targetId: target.id,
    type: target.type,
    url: target.url,
    running: target.running,
    // Navigations that committed, i.e. history entries beyond the one the target was born
    // with. A test can read what state the page was in when it was closed.
    committedNavigations: Math.max(0, target.history.length - 1),
  });
  for (const s of sessions.values()) {
    if (s.discover) sendEvent(s.id, "Target.targetDestroyed", { targetId: target.id });
  }
  const mine = sessionsOfTarget(target.id);
  for (const s of mine) {
    if (s.parent) sendEvent(s.parent, "Target.detachedFromTarget", { sessionId: s.id, targetId: target.id });
  }
  for (const s of mine) sessions.delete(s.id);
  target.waiting.clear();
  target.held = false;
  // Every session of that target is gone, so a request it held has nowhere to go: it passes
  // (nothing older exists to stop it).
  for (const state of [...pausedRequests.values()]) {
    if (state.holder && mine.includes(state.holder)) advance(state);
  }
  return true;
}

/**
 * What `Browser.close` does once its reply is out: the shape of a real browser's close, with
 * `FAKE_CHROME_CLOSE_EXIT_MS` deciding whether the pipe goes first and the process a moment
 * later, or the process goes at once.
 */
function closeAfterReply() {
  if (CLOSE_EXIT_MS > 0) {
    // The pipe goes first, the process a moment later: the shape a real Chromium has while
    // it commits its cookie store.
    outputClosed = true;
    try { closeSync(4); } catch { /* gone */ }
    setTimeout(() => {
      trace({ t: "closed-by-itself", code: CLOSE_EXIT_CODE });
      process.exit(CLOSE_EXIT_CODE);
    }, CLOSE_EXIT_MS);
    return;
  }
  process.exit(0);
}

function maybeExitOnNoPages() {
  if (process.env.FAKE_EXIT_ON_NO_PAGES !== "1") return;
  const livePages = [...targets.values()].filter((t) => !t.closed && t.type === "page");
  if (livePages.length > 0) return;
  // Headful Chromium exits on its last page. After the reply, so the caller sees the result.
  trace({ t: "no-pages", exitCode: 0 });
  process.exit(0);
}

// ---------------------------------------------------------------------------------------
// A request on a target
// ---------------------------------------------------------------------------------------

/**
 * One request through the Fetch chain (newest interception first, oldest last).
 *
 * `oldestOnly` puts it straight at the OLDEST interception, which is where a request ends up
 * once every newer session has continued it — a page's own traffic whose guard answer was
 * already in flight when the relay started doing something else.
 */
function issueRequest(targetId, url, { kind = "Fetch", oldestOnly = false, reply = () => {} } = {}) {
  const target = targets.get(targetId);
  if (!target || target.closed) {
    trace({ t: "request", requestId: null, targetId: targetId ?? null, url, finalUrl: url, outcome: "closed", via: [] });
    reply({ outcome: "closed", finalUrl: url, via: [] });
    return;
  }
  if (!target.running) {
    // A held target runs nothing.
    trace({ t: "request", requestId: null, targetId: target.id, url, finalUrl: url, outcome: "held", via: [] });
    reply({ outcome: "held", finalUrl: url, via: [] });
    return;
  }
  // Chromium's measured order: the Fetch chain follows session ATTACH order, newest
  // session first, oldest last.
  let chain = [...sessions.values()]
    .filter((s) => s.kind === "target" && s.targetId === target.id && s.fetch)
    .sort((a, b) => b.seq - a.seq);
  if (oldestOnly && chain.length > 1) chain = chain.slice(-1);
  const state = {
    requestId: `R${++requestCount}`,
    target,
    originalUrl: url,
    url,
    finalUrl: url,
    kind,
    chain,
    index: -1,
    holder: null,
    via: [],
    done: false,
    reply,
  };
  pausedRequests.set(state.requestId, state);
  if (chain.length === 0) { finish(state, "passed"); return; }
  advance(state);
}

// ---------------------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------------------

function handle(msg) {
  trace({ t: "recv", id: msg.id === undefined ? null : msg.id, method: msg.method || null, sessionId: msg.sessionId ?? null, params: msg.params ?? null });
  if (msg.id === undefined) return; // a notification: nothing to answer
  const sid = typeof msg.sessionId === "string" ? msg.sessionId : null;
  const reply = (result) => {
    const delay = delayReplies.get(msg.method);
    const frame = { id: msg.id, ...(sid ? { sessionId: sid } : {}), result };
    if (delay) setTimeout(() => send(frame), Math.min(delay, 1000));
    else send(frame);
  };
  const fail = (code, message) => send({ id: msg.id, ...(sid ? { sessionId: sid } : {}), error: { code, message } });

  if (failMethods.has(msg.method)) { fail(-32000, "Test failure"); return; }

  const session = sid ? sessions.get(sid) || null : null;
  const sessionTarget = session && session.targetId ? targets.get(session.targetId) || null : null;

  switch (msg.method) {
    case "Browser.getVersion":
      reply(VERSION);
      return;
    case "Browser.close":
      trace({ t: "browser-close" });
      reply({});
      if (CLOSE_HANDLE_DELAY_MS > 0) {
        // The window a real Chromium has after Browser.close: the browser keeps running, its
        // pages keep making requests, and the relay's answers to them still arrive.
        setTimeout(closeAfterReply, CLOSE_HANDLE_DELAY_MS);
        return;
      }
      closeAfterReply();
      return;
    case "Browser.crash":
      // A crash answers NOTHING: the browser is gone the instant the command lands.
      trace({ t: "browser-crash", sessionId: sid });
      process.exit(139);
      return;
    case "Target.attachToBrowserTarget": {
      const created = makeSession({ id: `S${++browserSessions}`, kind: "browser", targetId: null });
      reply({ sessionId: created.id });
      return;
    }
    case "Target.attachToTarget": {
      const target = targets.get(msg.params?.targetId);
      if (!target || target.closed) { fail(-32602, "No target with given id found"); return; }
      // Whoever's envelope carried the command owns the session it creates (`sid` is null for a
      // sessionless attach, i.e. the root).
      const created = makeSession({ id: `T${++targetSessions}`, kind: "target", targetId: target.id, owner: sid });
      reply({ sessionId: created.id });
      return;
    }
    case "Target.setAutoAttach": {
      if (!session) { reply({}); return; }
      const on = msg.params?.autoAttach === true;
      const flatten = msg.params?.flatten === true;
      session.autoAttach = { on, waitForDebugger: msg.params?.waitForDebuggerOnStart === true, flatten };
      reply({});
      // Non-flat auto-attach routes its events through the root in a shape nothing here
      // models (the relay refuses `flatten:false` before it can reach Chromium), so it is
      // recorded and nothing is announced.
      if (on && flatten) {
        for (const target of [...targets.values()]) {
          if (target.closed || target.listedOnly || !canSee(session, target)) continue;
          if (!sessions.has(session.id) || !session.autoAttach.on) break;
          announce(target, session);
        }
      }
      return;
    }
    case "Runtime.runIfWaitingForDebugger": {
      reply({});
      if (!session || !sessionTarget || sessionTarget.closed) return;
      const target = sessionTarget;
      if (!target.waiting.has(session.id)) return; // not held by this session
      if (target.type === "shared_worker" || target.type === "service_worker") {
        // A shared or service worker runs as soon as the FIRST resumer resumes it.
        target.waiting.clear();
        target.held = false;
        target.running = true;
        trace({ t: "resumed", targetId: target.id });
        return;
      }
      forgetWaiter(target, session.id);
      if (!target.held) trace({ t: "resumed", targetId: target.id });
      return;
    }
    case "Target.createTarget": {
      const contextId = typeof msg.params?.browserContextId === "string" ? msg.params.browserContextId : DEFAULT_CONTEXT;
      noteContext(contextId);
      const url = typeof msg.params?.url === "string" && msg.params.url ? msg.params.url : "about:blank";
      const target = makeTarget({ id: nextTargetId("page"), type: "page", url, contextId });
      targets.set(target.id, target);
      createdPages.add(target.id);
      trace({ t: "create-target", targetId: target.id, url });
      notifyDiscoverers(target);
      announceToAutoAttachers(target);
      reply({ targetId: target.id });
      return;
    }
    case "Target.closeTarget": {
      const target = targets.get(msg.params?.targetId);
      const success = closeTarget(target);
      reply({ success });
      maybeExitOnNoPages();
      return;
    }
    case "Target.getTargets":
      reply({
        targetInfos: [...targets.values()].filter((t) => !t.closed).map(targetInfo),
      });
      // The real browser's component-extension workers attach a moment AFTER this answer, not
      // inside it. Scheduled on the first listing only (that is the one the relay's start
      // sequence makes).
      if (!EXTENSION_WORKERS_AT_START && !firstListingAnswered) {
        firstListingAnswered = true;
        if (EXTENSION_IDS.length > 0) setTimeout(createExtensionWorkers, EXTENSION_WORKER_DELAY_MS);
      }
      return;
    case "Target.detachFromTarget": {
      const victimId = msg.params?.sessionId;
      const victim = typeof victimId === "string" ? sessions.get(victimId) || null : null;
      // Chromium looks a session up only in the session the command was sent on: the one that
      // ATTACHED the victim. Sent on any other envelope (the root included) it finds nothing,
      // answers "No session with given id" and detaches nothing — which is why the relay has to
      // name the owner, and why detaching a client's child from the root used to do nothing.
      if (victim && victim.owner !== sid) {
        trace({ t: "detached", sessionId: victimId, from: sid, refused: "not-owner" });
        fail(-32602, "No session with given id");
        return;
      }
      trace({ t: "detached", sessionId: victimId ?? null, from: sid });
      // A detach takes the detached session's own children with it.
      if (victim) dropSessionTree(victim.id, { detachEvent: true });
      reply({});
      return;
    }
    case "Target.getBrowserContexts":
      reply(
        LEGACY_DEFAULT_CONTEXT
          // An older build: the default context is the literal "default", and it IS listed.
          ? { browserContextIds: [DEFAULT_CONTEXT, ...createdContexts] }
          // The real shape: only contexts something created, plus the id of the default one.
          : { browserContextIds: [...createdContexts], defaultBrowserContextId: DEFAULT_CONTEXT },
      );
      return;
    case "Target.createBrowserContext": {
      const browserContextId = `C${++contextCount}`;
      noteContext(browserContextId);
      reply({ browserContextId });
      return;
    }
    case "Target.disposeBrowserContext": {
      const id = msg.params?.browserContextId;
      for (const target of [...targets.values()]) {
        if (!target.closed && target.contextId === id) closeTarget(target);
      }
      const at = createdContexts.indexOf(id);
      if (at >= 0) createdContexts.splice(at, 1);
      trace({ t: "dispose-context", id });
      reply({});
      maybeExitOnNoPages();
      return;
    }
    case "Target.setDiscoverTargets": {
      if (session) session.discover = msg.params?.discover === true;
      reply({});
      return;
    }
    case "Target.sendMessageToTarget":
      // Non-flat command transport. The relay refuses it; a test asserts it never arrives.
      trace({ t: "send-message-to-target", sessionId: msg.params?.sessionId ?? null, from: sid });
      reply({});
      return;
    case "Fetch.enable": {
      if (!session) { reply({}); return; }
      const patterns = Array.isArray(msg.params?.patterns) ? msg.params.patterns : [];
      session.fetch = { patterns };
      trace({ t: "fetch-enable", sessionId: session.id, targetId: session.targetId, patterns });
      // The gate's own interception place on a page `Target.createTarget` just made, and the
      // FIRST such interception for that target (see FAKE_CHROME_NEW_PAGE_ACK_*).
      const newPage = !!(sessionTarget && createdPages.has(sessionTarget.id) && !newPageAckServed.has(sessionTarget.id));
      if (newPage) {
        newPageAckServed.add(sessionTarget.id);
        trace({ t: "new-page-ack", sessionId: session.id, targetId: sessionTarget.id, delayMs: NEW_PAGE_ACK_DELAY_MS, fail: NEW_PAGE_ACK_FAIL });
        if (NEW_PAGE_ACK_FAIL) { fail(-32000, "Test failure"); return; }
      }
      // The knob's delay ADDS to the ordinary reply delay (`FAKE_CHROME_DELAY_METHODS`), so a
      // test that arms one of them still sees the other; both are capped at 1000 ms.
      if (newPage && NEW_PAGE_ACK_DELAY_MS > 0) {
        const ms = Math.min(1000, Number(delayReplies.get(msg.method) || 0) + NEW_PAGE_ACK_DELAY_MS);
        const frame = { id: msg.id, ...(sid ? { sessionId: sid } : {}), result: {} };
        setTimeout(() => send(frame), ms);
        return;
      }
      reply({});
      return;
    }
    case "Fetch.disable": {
      if (!session) { reply({}); return; }
      session.fetch = null;
      trace({ t: "fetch-disable", sessionId: session.id, targetId: session.targetId });
      reply({});
      // A disabling session releases what it held: the request moves on to the next older
      // session, or passes when there is none.
      releaseHeldBy(session);
      return;
    }
    case "Fetch.continueRequest":
    case "Fetch.failRequest": {
      const requestId = msg.params?.requestId;
      const state = typeof requestId === "string" ? pausedRequests.get(requestId) : null;
      // Request ids are scoped per session: only the session holding it may answer it.
      if (!state || !session || state.holder !== session) { fail(-32602, "Invalid InterceptionId"); return; }
      if (msg.method === "Fetch.failRequest") {
        reply({});
        finish(state, "failed");
        return;
      }
      const override = msg.params?.url;
      reply({});
      if (typeof override === "string" && override) {
        state.url = override;
        state.finalUrl = override;
      }
      advance(state);
      return;
    }
    case "Page.enable":
    case "Page.disable":
      if (session) session.pageEnabled = msg.method === "Page.enable";
      reply({});
      return;
    case "Page.addScriptToEvaluateOnNewDocument": {
      if (!session) { reply({}); return; }
      const identifier = `I${++scriptCount}`;
      session.scripts.set(identifier, {
        source: String(msg.params?.source ?? ""),
        worldName: typeof msg.params?.worldName === "string" ? msg.params.worldName : null,
      });
      reply({ identifier });
      return;
    }
    case "Page.removeScriptToEvaluateOnNewDocument": {
      if (session) session.scripts.delete(String(msg.params?.identifier ?? ""));
      reply({});
      return;
    }
    case "Page.navigate": {
      if (!sessionTarget || sessionTarget.closed) { reply({}); return; }
      const target = sessionTarget;
      const url = String(msg.params?.url ?? "about:blank");
      const loaderId = `L${++loaderCount}`;
      reply({ frameId: target.id, loaderId });
      const committed = target.commit === true;
      if (committed) {
        target.url = url;
        target.history.push(url);
        target.currentIndex = target.history.length - 1;
        toTargetSessions(
          target.id,
          "Page.frameNavigated",
          { frame: { id: target.id, loaderId, url, mimeType: "text/html" } },
          { onlyPageEnabled: true },
        );
      }
      trace({ t: "navigate", targetId: target.id, url, loaderId, committed });
      return;
    }
    case "Page.getNavigationHistory": {
      if (!sessionTarget) { reply({ currentIndex: 0, entries: [] }); return; }
      reply({
        currentIndex: sessionTarget.currentIndex,
        entries: sessionTarget.history.map((url, i) => ({ id: i + 1, url })),
      });
      return;
    }
    case "Test.echo":
      reply({ value: msg.params?.value ?? null, got: sid });
      return;
    case "Test.event":
      // Emit an event addressed to a session the TEST chooses (or to none at all).
      send({ method: "Test.event", ...(msg.params?.to ? { sessionId: msg.params.to } : {}), params: { payload: msg.params?.payload ?? null } });
      reply({ sent: true });
      return;
    case "Test.stream": {
      const count = Number(msg.params?.count ?? 1);
      const body = "x".repeat(Number(msg.params?.size ?? 1024));
      for (let i = 0; i < count; i++) send({ method: "Test.chunk", ...(sid ? { sessionId: sid } : {}), params: { i, body } });
      reply({ chunks: count });
      return;
    }
    case "Test.detachChild":
      sendEvent(sid, "Target.detachedFromTarget", { sessionId: msg.params?.child, targetId: msg.params?.child });
      reply({});
      return;
    case "Test.exit":
      trace({ t: "exiting", code: Number(msg.params?.code ?? 0) });
      process.exit(Number(msg.params?.code ?? 0));
      return;

    // -- the gate fixture's own hooks ------------------------------------------------

    case "Test.request": {
      issueRequest(msg.params?.targetId, String(msg.params?.url ?? "about:blank"), {
        kind: typeof msg.params?.kind === "string" ? msg.params.kind : "Fetch",
        reply,
      });
      return;
    }
    case "Test.armPageRequest": {
      // A request the PAGE makes on its own, `ms` from now: the traffic a page still issues
      // while the relay is cleaning up. It enters the chain at the oldest interception (the
      // guard's continue for it was already in flight), so no client command is needed to
      // drive it there.
      const targetId = typeof msg.params?.targetId === "string" ? msg.params.targetId : null;
      const url = String(msg.params?.url ?? "about:blank");
      const ms = Math.max(0, Math.min(5000, Math.trunc(Number(msg.params?.ms ?? 0)) || 0));
      const timer = setTimeout(() => {
        trace({ t: "page-request", targetId, url });
        issueRequest(targetId, url, { oldestOnly: true });
      }, ms);
      if (typeof timer.unref === "function") timer.unref();
      reply({ armed: ms, targetId });
      return;
    }
    case "Test.spawnTarget": {
      const type = String(msg.params?.type ?? "page");
      const givenId = typeof msg.params?.id === "string" && msg.params.id ? msg.params.id : null;
      const id = givenId || nextTargetId(type);
      const url = typeof msg.params?.url === "string" && msg.params.url ? msg.params.url : "about:blank";
      const contextId = typeof msg.params?.contextId === "string" && msg.params.contextId ? msg.params.contextId : DEFAULT_CONTEXT;
      noteContext(contextId);
      const target = makeTarget({
        id,
        type,
        url,
        openerId: typeof msg.params?.openerId === "string" ? msg.params.openerId : null,
        ownerId: typeof msg.params?.ownerId === "string" ? msg.params.ownerId : null,
        contextId,
      });
      targets.set(id, target);
      trace({ t: "spawn-target", targetId: id, type, url, ownerId: target.ownerId });
      notifyDiscoverers(target);
      announceToAutoAttachers(target);
      reply({ targetId: id });
      return;
    }
    case "Test.swapIframe": {
      const target = targets.get(msg.params?.targetId);
      if (!target || target.closed) { reply({}); return; }
      const order = msg.params?.order === "detach-attach" ? "detach-attach" : "attach-detach";
      const attachers = autoAttachersFor(target);
      const children = sessionsOfTarget(target.id).filter((s) => s.parent).sort((a, b) => a.seq - b.seq);
      const old = children.length ? children[children.length - 1] : null;
      const detachOld = () => { if (old) dropSession(old, { detachEvent: true }); };
      trace({ t: "swap-iframe", targetId: target.id, order });
      if (order === "detach-attach") {
        // The same targetId, detached and then announced again: the new session is only
        // held when the auto-attacher's waitForDebuggerOnStart says so.
        detachOld();
        for (const attacher of attachers) {
          if (!sessions.has(attacher.id) || !attacher.autoAttach.on) continue;
          announce(target, attacher);
        }
      } else {
        // A fresh child session first (the target is listed throughout), then the old one's
        // detach.
        for (const attacher of attachers) {
          if (!sessions.has(attacher.id) || !attacher.autoAttach.on) continue;
          announce(target, attacher);
        }
        detachOld();
      }
      reply({});
      return;
    }
    case "Test.dropSession": {
      const victimId = msg.params?.sessionId;
      const victim = typeof victimId === "string" ? sessions.get(victimId) || null : null;
      trace({ t: "drop-session", sessionId: victimId ?? null });
      if (victim) dropSession(victim, { detachEvent: true });
      reply({});
      return;
    }
    case "Test.setCommit": {
      const target = targets.get(msg.params?.targetId);
      if (target) target.commit = msg.params?.commit !== false;
      reply({});
      return;
    }
    case "Test.state": {
      const only = msg.params?.targetId;
      if (only) {
        const target = targets.get(only) || null;
        reply({
          target: target ? targetState(target) : null,
          sessions: target ? sessionsOfTarget(target.id).map(sessionState) : [],
        });
        return;
      }
      reply({
        targets: [...targets.values()].map(targetState),
        sessions: [...sessions.values()].map(sessionState),
        defaultContextId: DEFAULT_CONTEXT,
        legacyDefaultContext: LEGACY_DEFAULT_CONTEXT,
        contexts: [...createdContexts],
        extensionWorkers: [...targets.values()].filter((t) => t.url.startsWith("chrome-extension://")).map((t) => t.id),
      });
      return;
    }
    case "Test.failCommands": {
      const methods = Array.isArray(msg.params?.methods) ? msg.params.methods : [];
      for (const m of methods) failMethods.add(m);
      reply({});
      return;
    }
    case "Test.delayReplies": {
      const method = String(msg.params?.method ?? "");
      if (method) delayReplies.set(method, Number(msg.params?.ms ?? 0));
      reply({});
      return;
    }
    default:
      reply({});
  }
}

// ---------------------------------------------------------------------------------------
// The pipe
// ---------------------------------------------------------------------------------------

let parts = [];
// The same reader the relay uses for this fd: a libuv stream, whose reads are non-blocking, so
// a `process.exit` from a timer is not left waiting on a filesystem read that never returns.
// fds 3 and 4 are always a socketpair here (they come from a `pipe` stdio).
const input = new net.Socket({ fd: 3, readable: true, writable: true });
input.on("error", () => process.exit(0));
input.on("data", (chunk) => {
  let start = 0;
  for (;;) {
    const nul = chunk.indexOf(0, start);
    if (nul === -1) { parts.push(chunk.subarray(start)); return; }
    parts.push(chunk.subarray(start, nul));
    const frame = Buffer.concat(parts).toString("utf8");
    parts = [];
    start = nul + 1;
    let msg;
    try { msg = JSON.parse(frame); } catch { trace({ t: "unparsable", frame: frame.slice(0, 200) }); continue; }
    handle(msg);
  }
});
input.on("end", () => process.exit(0));