/**
 * The MCP side of the browser relay gate — bundles/browser/server/gate-client.js
 *
 * The relay gate (cdp-relay.mjs --attach) fails every request from a page whose
 * guard-bearing MCP has gone or has not hooked it. "Guard-bearing" is not something the
 * relay may simply be told: the MCP declares intent with the header
 * `X-Crow-Guard-Client: 1` on its `connectOverCDP`, and then, once
 * `installPrivateAddressGuard` has resolved, sends ONE relay-handled command
 * `Crow.guardReady {v: 1, exceptionsHash}`. The relay verifies the declaration against
 * what it sees on the wire (the client's own `Fetch.enable` plus the marker-bearing init
 * script), so the helper here is small on purpose: it opens a browser-level CDP session,
 * sends the one command, detaches, and never throws.
 *
 * Two shapes matter as much as the happy path:
 *   - an OLDER relay answers `Crow.guardReady` with a CDP error (no `Crow.*` commands
 *     exist there). That must come back as `{ ok: false, unsupported: true }` so the
 *     caller carries on exactly as before, and the session must STILL be detached — a
 *     session leaked per connect is a session leaked per turn.
 *   - the status read (`/json/version` → `Crow-Guard: gate/1`) is a diagnosis line, never
 *     a control: any odd body, any non-200, any network failure reads "no", never throws.
 *
 * Plain stubs only: no Playwright, no browser, no container. The module itself must be
 * importable without Playwright (it ships in the bundle's server/ tree and is imported by
 * server.js), which is why the import is asserted here and not in a live test.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const ROOT = join(import.meta.dirname, "..");
const MODULE_PATH = join(ROOT, "bundles", "browser", "server", "gate-client.js");

/** The module under test. It does not exist yet: every test fails here, for that reason. */
async function gateClient() {
  assert.ok(
    existsSync(MODULE_PATH),
    "bundles/browser/server/gate-client.js must exist: it is the MCP's gate client (intent header, Crow.guardReady, Crow-Guard status read)",
  );
  try {
    return await import(pathToFileURL(MODULE_PATH).href);
  } catch (err) {
    assert.fail(`bundles/browser/server/gate-client.js must load with no Playwright import: ${err?.message || err}`);
  }
}

/** The hash the helper must produce: 16 hex chars of sha256 over the sorted list, as strings. */
function expectedHash(exceptions) {
  const list = Array.isArray(exceptions) ? exceptions : [];
  const canonical = JSON.stringify([...list].map(String).sort());
  return createHash("sha256").update(canonical, "utf8").digest("hex").slice(0, 16);
}

/**
 * A fake Playwright Browser: `newBrowserCDPSession()` hands back one recorder session.
 * Nothing else exists on it, so a `sendGuardReady` that reaches for anything else throws
 * (and the helper's own "never throws" contract turns that into a failure of `ok`).
 */
function fakeBrowser({ sendFails = false, detachFails = false } = {}) {
  const calls = { sessions: 0, sent: [], detached: 0 };
  const session = {
    async send(method, params) {
      calls.sent.push({ method, params });
      if (sendFails) throw new Error(`'${method}' wasn't found`);
      return {};
    },
    async detach() {
      calls.detached += 1;
      if (detachFails) throw new Error("detach failed");
    },
  };
  const browser = {
    async newBrowserCDPSession() {
      calls.sessions += 1;
      return session;
    },
  };
  return { browser, calls };
}

/** A fake `fetch` that answers from `answer(url, opts)` and records every call. */
function fakeFetch(answer) {
  const calls = [];
  const impl = async (url, opts) => {
    calls.push({ url, opts });
    return answer(url, opts);
  };
  impl.calls = calls;
  return impl;
}

/** A Response-shaped stub: both `json()` and `text()` answer, so either reader works. */
function responseOf(body, { status = 200 } = {}) {
  const ok = status >= 200 && status < 300;
  return {
    ok,
    status,
    async json() {
      if (body === undefined) throw new SyntaxError("not JSON");
      return body;
    },
    async text() {
      if (body === undefined) throw new SyntaxError("not JSON");
      return typeof body === "string" ? body : JSON.stringify(body);
    },
  };
}

/** The header named in `opts.headers`, whether it was handed in as a record or a Headers. */
function headerValue(headers, name) {
  if (!headers) return undefined;
  if (typeof headers.get === "function") return headers.get(name) ?? undefined;
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === name.toLowerCase()) return value;
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// The constants server.js connects with
// ---------------------------------------------------------------------------

test("the intent header and its value are the ones the relay reads", async () => {
  const { GATE_INTENT_HEADER, GATE_INTENT_VALUE } = await gateClient();
  assert.equal(GATE_INTENT_HEADER, "X-Crow-Guard-Client");
  assert.equal(GATE_INTENT_VALUE, "1");
});

// ---------------------------------------------------------------------------
// exceptionsHash
// ---------------------------------------------------------------------------

test("exceptionsHash is 16 hex characters of sha256 over the sorted list", async () => {
  const { exceptionsHash } = await gateClient();
  assert.equal(typeof exceptionsHash, "function");

  const list = ["10.0.0.0/8", "192.168.1.50", "intranet.example"];
  const hash = exceptionsHash(list);

  assert.equal(typeof hash, "string");
  assert.match(hash, /^[0-9a-f]{16}$/, "16 lowercase hex characters");
  assert.equal(hash, expectedHash(list), "sha256(JSON.stringify(sorted)) first 16 hex chars");
});

test("the same list in another order hashes the same; a different list does not", async () => {
  const { exceptionsHash } = await gateClient();
  const a = ["b.example", "a.example", "10.1.0.0/16"];
  const b = ["10.1.0.0/16", "a.example", "b.example"];

  assert.equal(exceptionsHash(a), exceptionsHash(b), "order is not part of the hash (it is an identity for the list)");
  assert.notEqual(exceptionsHash(a), exceptionsHash(["a.example", "b.example"]), "a shorter list is a different list");
  assert.notEqual(exceptionsHash(["1", "2"]), exceptionsHash(["12"]), "the hash is over the list, not a concatenation");
});

test("an empty or missing list hashes the string []", async () => {
  const { exceptionsHash } = await gateClient();
  const empty = expectedHash([]);
  assert.equal(empty, createHash("sha256").update("[]").digest("hex").slice(0, 16), "the fixture itself");

  assert.equal(exceptionsHash([]), empty);
  assert.equal(exceptionsHash(undefined), empty, "a missing list is the empty one");
  assert.equal(exceptionsHash(null), empty);
});

// ---------------------------------------------------------------------------
// sendGuardReady
// ---------------------------------------------------------------------------

test("sendGuardReady sends Crow.guardReady once on a browser session, then detaches", async () => {
  const { sendGuardReady, exceptionsHash } = await gateClient();
  const { browser, calls } = fakeBrowser();
  const lines = [];
  const exceptions = ["192.168.1.50"];

  const result = await sendGuardReady(browser, { exceptions, log: (line) => lines.push(line) });

  assert.equal(result.ok, true);
  assert.equal(result.unsupported, undefined);
  assert.equal(calls.sessions, 1, "one browser-level session (browser.newBrowserCDPSession)");
  assert.equal(calls.sent.length, 1, "exactly one command: nothing else is sent");
  assert.equal(calls.sent[0].method, "Crow.guardReady");
  assert.deepEqual(calls.sent[0].params, { v: 1, exceptionsHash: exceptionsHash(exceptions) });
  assert.equal(calls.detached, 1, "the session is always detached, once");
});

// CONTROL: an older relay has no Crow.* commands, so it answers with a CDP error. The
// caller carries on as before — and the session is STILL detached.
test("CONTROL: a relay that answers an error reads as unsupported, and the session is still detached", async () => {
  const { sendGuardReady } = await gateClient();
  const { browser, calls } = fakeBrowser({ sendFails: true });
  const lines = [];

  const result = await sendGuardReady(browser, { exceptions: [], log: (line) => lines.push(line) });

  assert.equal(result.ok, false, "not a hard failure: an old relay is a known state");
  assert.equal(result.unsupported, true, "the caller uses this to carry on exactly as before");
  assert.equal(calls.sent.length, 1, "it did try the handshake");
  assert.equal(calls.detached, 1, "the session goes away in this path too");
});

test("sendGuardReady never throws, even when the browser will not give a session", async () => {
  const { sendGuardReady } = await gateClient();
  const browser = {
    async newBrowserCDPSession() {
      throw new Error("no browser session");
    },
  };

  const result = await sendGuardReady(browser, { exceptions: [], log: () => {} });

  assert.equal(result.ok, false, "a tool turn must not fail because the handshake could not be sent");
});

// ---------------------------------------------------------------------------
// readGateStatus
// ---------------------------------------------------------------------------

test("readGateStatus reads Crow-Guard from /json/version, with the bearer, and strips a trailing slash", async () => {
  const { readGateStatus } = await gateClient();
  const headers = { Authorization: "Bearer token" };
  const fetchImpl = fakeFetch(() => responseOf({ Browser: "Chrome/130", "Crow-Guard": "gate/1" }));

  const status = await readGateStatus("http://127.0.0.1:9222/", headers, fetchImpl);

  assert.equal(status, "yes");
  assert.equal(fetchImpl.calls.length, 1);
  assert.equal(fetchImpl.calls[0].url, "http://127.0.0.1:9222/json/version", "no double slash");
  assert.equal(headerValue(fetchImpl.calls[0].opts?.headers, "Authorization"), "Bearer token", "the CDP bearer rides in the headers");
  assert.equal(String(fetchImpl.calls[0].opts?.method ?? "GET").toUpperCase(), "GET");

  const noSlash = fakeFetch(() => responseOf({ "Crow-Guard": "gate/1" }));
  assert.equal(await readGateStatus("http://127.0.0.1:9222", {}, noSlash), "yes");
  assert.equal(noSlash.calls[0].url, "http://127.0.0.1:9222/json/version");
});

test("readGateStatus reads no for any other body, any non-200, and any failure", async () => {
  const { readGateStatus } = await gateClient();
  const at = (answer) => readGateStatus("http://127.0.0.1:9222", {}, fakeFetch(answer));

  // The control for every "no" below: the same shape with gate/1 reads yes.
  assert.equal(await at(() => responseOf({ "Crow-Guard": "gate/1" })), "yes", "control: the reader can say yes");

  assert.equal(await at(() => responseOf({ "Crow-Guard": "gate/2" })), "no", "another gate version is not this gate");
  assert.equal(await at(() => responseOf({ Browser: "Chrome/130" })), "no", "an old relay advertises nothing");
  assert.equal(await at(() => responseOf({ "Crow-Guard": 1 })), "no", "only the string counts");
  assert.equal(await at(() => responseOf({ "Crow-Guard": "gate/1" }, { status: 500 })), "no", "a non-200 body is not evidence");
  assert.equal(await at(() => responseOf(undefined)), "no", "a body that is not JSON is not evidence");
  assert.equal(await at(() => { throw new Error("ECONNREFUSED"); }), "no", "a dead relay is not an exception");
});